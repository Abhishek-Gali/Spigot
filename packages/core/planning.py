"""Tool planning, safe identifier mapping, and runtime policy models for Spigot (T09/T11).

Implements tool selection, collision-free safe naming, and policy configuration
per DATA_CONTRACTS.md and GENERATOR_RUNTIME.md.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from packages.core.contracts import (
     SCHEMA_VERSION,
    ApiContract,
    DependencyEdge,
    OperationContract,
    ToolPlan,
    canonical_json_bytes,
    sha256_hex,
    to_safe_identifier,
)

RESERVED_TOOL_NAMES = frozenset(
    {
        "initialize",
        "ping",
        "list_tools",
        "call_tool",
        "list_resources",
        "read_resource",
        "list_prompts",
        "get_prompt",
        "server",
        "client",
        "main",
        "run",
        "policy",
        "contract",
        "manifest",
        "approve",
        "self_approve",
    }
)


class RuntimePolicy(BaseModel):
    """Frozen runtime policy configuration enforced by the generated MCP server."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str = Field(min_length=1)
    revision: int = Field(default=1, ge=1)
    mode: Literal["read_only", "restricted_write", "approval_required"] = "read_only"
    allowed_write_operations: list[str] = Field(default_factory=list)
    disabled_operations: list[str] = Field(default_factory=list)
    network_profile: Literal["STRICT_OFFLINE", "CONNECTED_SERVICES"] = "STRICT_OFFLINE"
    allowed_origins: list[str] = Field(default_factory=list)
    request_deadline_sec: float = Field(default=30.0, gt=0.0, le=300.0)
    connect_timeout_sec: float = Field(default=5.0, gt=0.0, le=60.0)
    max_response_bytes: int = Field(default=1_048_576, ge=1024)
    max_retries: int = Field(default=3, ge=0, le=10)
    policy_hash: str = ""

    def compute_policy_hash(self) -> str:
        raw_dict = self.model_dump()
        return sha256_hex(canonical_json_bytes(raw_dict, exclude_keys={"policy_hash"}))

    @model_validator(mode="after")
    def _populate_or_verify_hash(self) -> RuntimePolicy:
        computed = self.compute_policy_hash()
        if not self.policy_hash:
            self.policy_hash = computed
        elif self.policy_hash != computed:
            raise ValueError(
                f"RuntimePolicy policy_hash mismatch: expected {computed}, got {self.policy_hash}"
            )
        return self


def normalize_safe_tool_name(raw_id: str, used_names: set[str]) -> str:
    """Normalize an operation ID into a safe, collision-free MCP tool identifier."""
    base = to_safe_identifier(raw_id, fallback="tool")
    if base in RESERVED_TOOL_NAMES:
        base = f"api_{base}"
    base = base[:56]
    candidate = base
    if candidate in used_names:
        suffix = 2
        while f"{base}_{suffix}" in used_names:
            suffix += 1
        candidate = f"{base}_{suffix}"
    used_names.add(candidate)
    return candidate


def build_tool_input_schema(op: OperationContract) -> dict[str, Any]:
    """Construct the JSON Schema for an MCP tool's arguments from an OperationContract."""
    properties: dict[str, Any] = {}
    required: list[str] = []

    for param in op.parameters:
        prop_schema = dict(param.schema_def)
        if param.description and "description" not in prop_schema:
            prop_schema["description"] = param.description
        if param.default_value is not None and "default" not in prop_schema:
            prop_schema["default"] = param.default_value
        properties[param.safe_argument_name] = prop_schema
        if param.required:
            required.append(param.safe_argument_name)

    if op.request_body is not None:
        body_schema = dict(op.request_body.schema_def)
        if op.request_body.description and "description" not in body_schema:
            body_schema["description"] = op.request_body.description
        # Avoid collision if a parameter is already named 'body'
        body_arg_name = "body" if "body" not in properties else "request_body"
        properties[body_arg_name] = body_schema
        if op.request_body.required:
            required.append(body_arg_name)

    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


class DependencyViolationError(ValueError):
    """Raised when a ToolPlan drops a required prerequisite lookup operation without override."""


class ToolPackSuggestion(BaseModel):
    """Result of suggesting a use-case tool pack with prerequisite dependency preservation (T28)."""

    model_config = ConfigDict(extra="forbid")

    use_case: str
    requested_operation_ids: list[str]
    resolved_operation_ids: list[str]
    auto_included_prerequisites: list[str] = Field(default_factory=list)
    dependency_edges: list[DependencyEdge] = Field(default_factory=list)
    rewritten_descriptions: dict[str, str] = Field(default_factory=dict)


def _extract_resource_tokens(relative_path: str) -> list[str]:
    """Extract lowercase resource segment tokens (excluding version prefixes and path params)."""
    tokens: list[str] = []
    for seg in relative_path.strip("/").split("/"):
        if not seg or (seg.startswith("{") and seg.endswith("}")):
            continue
        lower = seg.lower()
        if lower in {"v1", "v2", "v3", "api", "rest"}:
            continue
        tokens.append(lower)
    return tokens


def _singularize(token: str) -> str:
    if token.endswith("ies") and len(token) > 3:
        return token[:-3] + "y"
    if token.endswith("ses") and len(token) > 3:
        return token[:-2]
    if token.endswith("s") and not token.endswith("ss") and len(token) > 2:
        return token[:-1]
    return token


def infer_operation_dependencies(contract: ApiContract) -> list[DependencyEdge]:
    """Infer prerequisite read/lookup dependencies between supported operations (T28).

    An operation `B` depends on read collection/search operation `A` when:
    1. `B` requires a path/query/body identifier parameter (e.g., `ticket_id`, `doctor_id`, `id`)
       or operates on an item path `/resources/{id}` or sub-resource `/resources/{id}/action`, and
    2. `A` is a supported `GET` collection/search operation for that resource (`/resources`)
       that does not itself require that item path parameter.
    """
    supported_ops = [op for op in contract.operations if op.support_status == "supported"]
    # Index collection GET operations by singularized resource noun
    collection_getters: dict[str, list[OperationContract]] = {}
    for op in supported_ops:
        if op.method != "GET":
            continue
        path_params = [p for p in op.parameters if p.location == "path"]
        res_tokens = _extract_resource_tokens(op.relative_path)
        if not path_params and res_tokens:
            primary_noun = _singularize(res_tokens[-1])
            collection_getters.setdefault(primary_noun, []).append(op)

    edges: list[DependencyEdge] = []
    seen_pairs: set[tuple[str, str]] = set()

    for op in supported_ops:
        res_tokens = _extract_resource_tokens(op.relative_path)
        primary_noun = _singularize(res_tokens[0]) if res_tokens else ""

        # Check path parameters and required body/query *_id fields
        id_clues: list[ tuple[str, str] ] = []
        for param in op.parameters:
            p_name = param.safe_argument_name.lower()
            if param.location == "path" or (param.required and p_name.endswith("_id")):
                if p_name == "id" and primary_noun:
                    id_clues.append((primary_noun, param.safe_argument_name))
                elif p_name.endswith("_id"):
                    noun = _singularize(p_name[:-3])
                    id_clues.append((noun, param.safe_argument_name))
                elif primary_noun:
                    id_clues.append((primary_noun, param.safe_argument_name))

        if op.request_body and isinstance(op.request_body.schema_def, dict):
            req_fields = set(op.request_body.schema_def.get("required", []))
            for field_name in req_fields:
                f_lower = str(field_name).lower()
                if f_lower.endswith("_id"):
                    noun = _singularize(f_lower[:-3])
                    id_clues.append((noun, str(field_name)))

        for noun, param_label in id_clues:
            for getter in collection_getters.get(noun, []):
                if getter.stable_id == op.stable_id:
                    continue
                pair = (op.stable_id, getter.stable_id)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    edges.append(
                        DependencyEdge(
                            from_operation_id=op.stable_id,
                            to_operation_id=getter.stable_id,
                            reason=(
                                f"Operation '{op.stable_id}' requires identifier '{param_label}', "
                                f"which is looked up via '{getter.stable_id}'."
                            ),
                        )
                    )
    return edges


def rewrite_operation_description(
    op: OperationContract,
    *,
    prerequisite_tool_names: list[str] | None = None,
) -> str:
    """Create a deterministic, schema-grounded description for Condition C tool packs (T28)."""
    req_params = [
        f"{p.safe_argument_name} ({p.location})"
        for p in op.parameters
        if p.required
    ]
    if op.request_body and op.request_body.required:
        body_req = op.request_body.schema_def.get("required", [])
        if body_req:
            req_params.append(f"body[{', '.join(str(x) for x in body_req)}]")
        else:
            req_params.append("body (json)")

    req_summary = ", ".join(req_params) if req_params else "none"
    parts = [
        f"[{op.method} {op.relative_path} | effect={op.semantic_effect}] {op.display_name.strip()}",
        f"Required inputs: {req_summary}.",
    ]
    if prerequisite_tool_names:
        parts.append(
            f"Prerequisite lookup tool(s): {', '.join(sorted(set(prerequisite_tool_names)))}."
        )
    return " ".join(parts)


def resolve_tool_pack_dependencies(
    contract: ApiContract,
    selected_operation_ids: list[str],
    *,
    explicit_edges: list[DependencyEdge] | None = None,
    preserve_dependencies: bool = True,
) -> tuple[list[str], list[str], list[DependencyEdge]]:
    """Resolve prerequisite lookup dependencies for a set of selected operations (T28).

    Returns `(resolved_operation_ids, auto_included_prerequisites, active_edges)`.
    If `preserve_dependencies=False` and a required prerequisite is missing from
    `selected_operation_ids`, raises `DependencyViolationError`.
    """
    all_edges = list(explicit_edges) if explicit_edges is not None else infer_operation_dependencies(contract)
    edges_by_from: dict[str, list[DependencyEdge]] = {}
    for edge in all_edges:
        edges_by_from.setdefault(edge.from_operation_id, []).append(edge)

    selected_set = set(selected_operation_ids)
    auto_included: list[str] = []
    active_edges: list[DependencyEdge] = []

    # Transitive closure over prerequisite lookup edges
    queue = list(selected_operation_ids)
    visited = set(selected_operation_ids)
    while queue:
        curr_id = queue.pop(0)
        for edge in edges_by_from.get(curr_id, []):
            active_edges.append(edge)
            prereq_id = edge.to_operation_id
            if prereq_id not in selected_set:
                if not preserve_dependencies:
                    raise DependencyViolationError(
                        f"Cannot exclude prerequisite lookup operation '{prereq_id}' "
                        f"required by '{curr_id}': {edge.reason}"
                    )
                selected_set.add(prereq_id)
                if prereq_id not in auto_included:
                    auto_included.append(prereq_id)
            if prereq_id not in visited:
                visited.add(prereq_id)
                queue.append(prereq_id)

    # Preserve contract ordering for deterministic plans
    ordered_resolved = [
        op.stable_id
        for op in contract.operations
        if op.stable_id in selected_set and op.support_status == "supported"
    ]
    return ordered_resolved, auto_included, active_edges


def suggest_tool_pack(
    contract: ApiContract,
    policy: RuntimePolicy,
    *,
    use_case: str,
    seed_operation_ids: list[str] | None = None,
    preserve_dependencies: bool = True,
) -> ToolPackSuggestion:
    """Suggest a focused tool pack for a use-case while preserving required lookup dependencies (T28)."""
    disabled = set(policy.disabled_operations)
    supported_ops = [
        op
        for op in contract.operations
        if op.support_status == "supported" and op.stable_id not in disabled
    ]

    if seed_operation_ids is not None:
        requested_ids = [op_id for op_id in seed_operation_ids if op_id not in disabled]
    else:
        uc_lower = use_case.lower()
        keywords = {
            tok
            for tok in to_safe_identifier(uc_lower, fallback="").split("_")
            if len(tok) >= 3 and tok not in {"the", "and", "for", "with", "from", "into", "api", "tool", "tools"}
        }
        matched: list[str] = []
        for op in supported_ops:
            if policy.mode == "read_only" and op.semantic_effect != "read":
                continue
            if (
                policy.mode == "restricted_write"
                and op.semantic_effect != "read"
                and op.stable_id not in set(policy.allowed_write_operations)
            ):
                continue
            haystack = f"{op.stable_id} {op.display_name} {op.relative_path}".lower()
            if not keywords or any(
                kw in haystack or _singularize(kw) in haystack for kw in keywords
            ):
                matched.append(op.stable_id)
        if not matched:
            matched = [
                op.stable_id
                for op in supported_ops
                if policy.mode != "read_only" or op.semantic_effect == "read"
            ]
        requested_ids = matched

    resolved_ids, auto_included, active_edges = resolve_tool_pack_dependencies(
        contract,
        requested_ids,
        preserve_dependencies=preserve_dependencies,
    )

    used_names: set[str] = set()
    all_assigned: dict[str, str] = {}
    for op in contract.operations:
        all_assigned[op.stable_id] = normalize_safe_tool_name(op.stable_id, used_names)

    prereq_names_by_op: dict[str, list[str]] = {}
    for edge in active_edges:
        p_name = all_assigned.get(edge.to_operation_id, edge.to_operation_id)
        prereq_names_by_op.setdefault(edge.from_operation_id, []).append(p_name)

    ops_by_id = {op.stable_id: op for op in contract.operations}
    rewritten: dict[str, str] = {}
    for op_id in resolved_ids:
        op = ops_by_id[op_id]
        rewritten[op_id] = rewrite_operation_description(
            op,
            prerequisite_tool_names=prereq_names_by_op.get(op_id),
        )

    return ToolPackSuggestion(
        use_case=use_case,
        requested_operation_ids=requested_ids,
        resolved_operation_ids=resolved_ids,
        auto_included_prerequisites=auto_included,
        dependency_edges=active_edges,
        rewritten_descriptions=rewritten,
    )


def create_tool_plan(
    contract: ApiContract,
    policy: RuntimePolicy,
    *,
    plan_id: str = "plan_default",
    selected_operation_ids: list[str] | None = None,
    dependency_edges: list[DependencyEdge] | None = None,
    preserve_dependencies: bool = False,
    enforce_dependencies: bool = False,
    rewrite_descriptions: bool = False,
    preserved_tool_names: dict[str, str] | None = None,
) -> ToolPlan:
    """Create a validated ToolPlan with stable safe tool names for selected operations."""
    ops_by_id = {op.stable_id: op for op in contract.operations}
    if selected_operation_ids is None:
        chosen_ids = [
            op.stable_id
            for op in contract.operations
            if op.support_status == "supported"
            and op.stable_id not in set(policy.disabled_operations)
        ]
    else:
        chosen_ids = list(selected_operation_ids)

    for op_id in chosen_ids:
        if op_id not in ops_by_id:
            raise KeyError(f"Selected operation '{op_id}' does not exist in contract")
        op = ops_by_id[op_id]
        if op.support_status != "supported":
            raise ValueError(
                f"Cannot include non-supported operation '{op_id}' "
                f"(status={op.support_status}) in ToolPlan"
            )

    resolved_edges = list(dependency_edges) if dependency_edges is not None else []
    if preserve_dependencies or enforce_dependencies:
        chosen_ids, _, resolved_edges = resolve_tool_pack_dependencies(
            contract,
            chosen_ids,
            explicit_edges=dependency_edges,
            preserve_dependencies=preserve_dependencies,
        )

    used_names: set[str] = set()
    tool_names: dict[str, str] = {}
    descriptions: dict[str, str] = {}

    # Reserve any frozen tool names from previous revision first so existing tools
    # are never renamed when descriptions or display names change (T31).
    frozen_map = dict(preserved_tool_names or {})
    all_assigned: dict[str, str] = {}
    for op in contract.operations:
        if op.stable_id in frozen_map:
            frozen_name = frozen_map[op.stable_id]
            used_names.add(frozen_name)
            all_assigned[op.stable_id] = frozen_name

    # Assign safe tool names across remaining operations in contract order
    for op in contract.operations:
        if op.stable_id not in all_assigned:
            all_assigned[op.stable_id] = normalize_safe_tool_name(op.stable_id, used_names)

    prereq_names_by_op: dict[str, list[str]] = {}
    for edge in resolved_edges:
        prereq_names_by_op.setdefault(edge.from_operation_id, []).append(
            all_assigned.get(edge.to_operation_id, edge.to_operation_id)
        )

    for op_id in chosen_ids:
        op = ops_by_id[op_id]
        tool_names[op_id] = all_assigned[op_id]
        if rewrite_descriptions:
            descriptions[op_id] = rewrite_operation_description(
                op,
                prerequisite_tool_names=prereq_names_by_op.get(op_id),
            )
        else:
            descriptions[op_id] = op.display_name

    return ToolPlan(
        id=plan_id,
        contract_hash=contract.canonical_hash,
        operation_ids=chosen_ids,
        tool_names=tool_names,
        descriptions=descriptions,
        dependency_edges=resolved_edges,
        policy_hash=policy.policy_hash,
    )

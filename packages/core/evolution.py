"""Semantic Contract Diff, Affected-Tool Mapping, and Safe Regeneration Engine (T30 & T31).

Implements Phase P7 requirements from IMPLEMENTATION.md, PRODUCT_REQUIREMENTS.md (FR-12, FR-13),
and DATA_CONTRACTS.md:
1. T30 — Normalized Semantic Contract Diff & Affected-Tool Mapping:
   - Compares two `ApiContract` versions (`compare_contracts`) across servers, security schemes,
     and operations.
   - Distinguishes breaking semantic changes (`operation_removed`, `required_parameter_added`,
     `parameter_removed`, `parameter_modified`, `request_body_modified`, `auth_changed`,
     `server_changed`, `semantic_effect_changed`, `support_status_changed`) from non-breaking
     additions (`operation_added`, optional parameter additions) and formatting/description-only
     edits (`format_or_description_only`, `semantically_identical=True`).
   - Detects ambiguous endpoint renames (`operation_renamed_ambiguous`, `severity="review_required"`)
     when an endpoint is removed and a new endpoint with the same HTTP verb and overlapping
     parameter or path structure is added.
   - Maps impacted operations to advertised MCP tool names in `ToolPlan` (including tools that
     transitively depend on an impacted prerequisite lookup operation via `dependency_edges`).
   - Emits executable regression test descriptors (`regression_cases`) for changed critical fields.
2. T31 — Safe Regeneration, Override Carry-Forward, Stale Policy Invalidation, & Reproducibility:
   - Evaluates existing `UserOverride` records against the new un-overridden extraction bundle:
     carries forward still-valid overrides (`old_value_hash` matches the new raw extraction)
     and invalidates stale overrides (`STALE_OVERRIDE` blocker finding) when the target field
     or operation changed in the new document revision.
   - Preserves frozen tool names (`preserved_tool_names`) across regeneration so description or
     heading edits never rename existing tools.
   - Invalidates stale runtime policies (`policy_invalidated=True`) and previously issued action
     approvals when contract or policy semantics change.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from packages.core.contracts import (
    SCHEMA_VERSION,
    ApiContract,
    EvidenceRef,
    Finding,
    OperationContract,
    ParameterContract,
    RequestBodyContract,
    ToolPlan,
    UserOverride,
    canonical_json_bytes,
    sha256_hex,
)
from packages.core.extraction import DocumentExtractionBundle
from packages.core.planning import RuntimePolicy, create_tool_plan
from packages.core.reconciliation import (
    compute_field_value_hash,
    reconcile_bundles_to_contract,
)
from packages.templates.generator import (
    export_reproducible_zip,
    generate_server_package,
)

PATH_PARAM_TOKEN_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ContractChangeItem(BaseModel):
    """Structured change entry between two ApiContract revisions (T30)."""

    model_config = ConfigDict(extra="forbid")

    change_id: str
    category: Literal[
        "operation_added",
        "operation_removed",
        "operation_renamed_ambiguous",
        "required_parameter_added",
        "parameter_removed",
        "parameter_modified",
        "request_body_modified",
        "auth_changed",
        "server_changed",
        "semantic_effect_changed",
        "support_status_changed",
        "format_or_description_only",
    ]
    severity: Literal["breaking", "non_breaking", "review_required", "cosmetic"]
    old_operation_id: str | None = None
    new_operation_id: str | None = None
    affected_field: str
    old_value: Any = None
    new_value: Any = None
    explanation: str
    affected_tools: list[str] = Field(default_factory=list)


class ContractDiffReport(BaseModel):
    """Normalized semantic diff report between two ApiContract revisions (T30)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    old_contract_id: str
    new_contract_id: str
    old_contract_hash: str
    new_contract_hash: str
    semantically_identical: bool
    has_breaking_changes: bool
    requires_review: bool
    changes: list[ContractChangeItem] = Field(default_factory=list)
    affected_operation_ids: list[str] = Field(default_factory=list)
    affected_tool_names: list[str] = Field(default_factory=list)
    regression_cases: list[dict[str, Any]] = Field(default_factory=list)
    diff_hash: str


class SafeRegenerationResult(BaseModel):
    """Result of safe contract regeneration and override/policy reconciliation (T31)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    old_contract_hash: str
    new_contract_hash: str
    diff_report: ContractDiffReport
    carried_forward_overrides: list[UserOverride] = Field(default_factory=list)
    invalidated_overrides: list[UserOverride] = Field(default_factory=list)
    preserved_tool_names: dict[str, str] = Field(default_factory=dict)
    policy_invalidated: bool = False
    policy_invalidation_reasons: list[str] = Field(default_factory=list)
    approvals_invalidated: bool = False
    regenerated_contract: ApiContract
    regenerated_tool_plan: ToolPlan | None = None


def _strip_schema_descriptions(obj: Any) -> Any:
    """Recursively strip prose 'description' and 'title' keys from a JSON Schema dict."""
    if isinstance(obj, dict):
        return {
            k: _strip_schema_descriptions(v)
            for k, v in obj.items()
            if k not in {"description", "title"}
        }
    if isinstance(obj, list):
        return [_strip_schema_descriptions(item) for item in obj]
    return obj


def _normalize_param_semantics(param: ParameterContract) -> dict[str, Any]:
    return {
        "external_name": param.external_name,
        "location": param.location,
        "required": param.required,
        "schema": _strip_schema_descriptions(param.schema_def),
        "style": param.style,
        "explode": param.explode,
        "allow_reserved": param.allow_reserved,
        "default_value": param.default_value,
    }


def _normalize_body_semantics(body: RequestBodyContract | None) -> dict[str, Any] | None:
    if body is None:
        return None
    return {
        "media_type": body.media_type,
        "required": body.required,
        "schema": _strip_schema_descriptions(body.schema_def),
    }


def _extract_static_path_tokens(relative_path: str) -> set[str]:
    tokens: set[str] = set()
    for seg in relative_path.strip("/").split("/"):
        if not seg or seg.startswith("{"):
            continue
        if re.fullmatch(r"v\d+", seg.lower()):
            continue
        tokens.add(seg.lower())
    return tokens


def _is_ambiguous_rename_pair(old_op: OperationContract, new_op: OperationContract) -> bool:
    """Detect whether a removed operation and a newly added operation look like an ambiguous rename."""
    if old_op.method != new_op.method:
        return False
    old_placeholders = set(PATH_PARAM_TOKEN_RE.findall(old_op.relative_path))
    new_placeholders = set(PATH_PARAM_TOKEN_RE.findall(new_op.relative_path))
    if old_placeholders and old_placeholders == new_placeholders:
        return True

    old_static = _extract_static_path_tokens(old_op.relative_path)
    new_static = _extract_static_path_tokens(new_op.relative_path)
    if old_static and new_static and (old_static & new_static):
        return True

    old_params = {(p.external_name, p.location) for p in old_op.parameters}
    new_params = {(p.external_name, p.location) for p in new_op.parameters}
    if old_params and old_params == new_params:
        return True

    return False


def _resolve_affected_tools(
    operation_id: str | None,
    old_tool_plan: ToolPlan | None,
    *,
    include_dependents: bool = True,
) -> list[str]:
    if operation_id is None:
        if old_tool_plan is not None:
            return sorted(set(old_tool_plan.tool_names.values()))
        return []

    if old_tool_plan is None:
        return [operation_id]

    impacted_ops = {operation_id}
    if include_dependents:
        # Transitively include any tools in the plan that depend on `operation_id` as a prerequisite
        added = True
        while added:
            added = False
            for edge in old_tool_plan.dependency_edges:
                if (
                    edge.to_operation_id in impacted_ops
                    and edge.from_operation_id not in impacted_ops
                ):
                    impacted_ops.add(edge.from_operation_id)
                    added = True

    names: list[str] = []
    for op_id in sorted(impacted_ops):
        if op_id in old_tool_plan.tool_names:
            names.append(old_tool_plan.tool_names[op_id])
        elif op_id == operation_id:
            names.append(op_id)
    return sorted(set(names))


def compare_contracts(
    old_contract: ApiContract,
    new_contract: ApiContract,
    *,
    old_tool_plan: ToolPlan | None = None,
) -> ContractDiffReport:
    """Compute a normalized semantic diff and affected-tool report between two contracts (T30)."""
    changes: list[ContractChangeItem] = []
    regression_cases: list[dict[str, Any]] = []

    # 1. Compare base server URLs
    old_urls = sorted({s.base_url.rstrip("/") for s in old_contract.servers})
    new_urls = sorted({s.base_url.rstrip("/") for s in new_contract.servers})
    if old_urls != new_urls:
        all_tools = _resolve_affected_tools(None, old_tool_plan)
        changes.append(
            ContractChangeItem(
                change_id="chg_servers_base_url",
                category="server_changed",
                severity="breaking",
                affected_field="servers",
                old_value=old_urls,
                new_value=new_urls,
                explanation=f"Base server URLs changed from {old_urls} to {new_urls}.",
                affected_tools=all_tools,
            )
        )
        regression_cases.append(
            {
                "case_id": "reg_servers_base_url",
                "type": "server_url_change",
                "old_servers": old_urls,
                "new_servers": new_urls,
                "affected_tools": all_tools,
            }
        )

    # 2. Match operations by (method, relative_path)
    old_ops_by_mp: dict[tuple[str, str], OperationContract] = {
        (op.method, op.relative_path): op for op in old_contract.operations
    }
    new_ops_by_mp: dict[tuple[str, str], OperationContract] = {
        (op.method, op.relative_path): op for op in new_contract.operations
    }

    matched_keys = sorted(set(old_ops_by_mp.keys()) & set(new_ops_by_mp.keys()))
    removed_keys = sorted(set(old_ops_by_mp.keys()) - set(new_ops_by_mp.keys()))
    added_keys = sorted(set(new_ops_by_mp.keys()) - set(old_ops_by_mp.keys()))

    # 3. Check for ambiguous renames between removed_keys and added_keys
    paired_removed: set[tuple[str, str]] = set()
    paired_added: set[tuple[str, str]] = set()

    for r_key in removed_keys:
        old_op = old_ops_by_mp[r_key]
        for a_key in added_keys:
            if a_key in paired_added:
                continue
            new_op = new_ops_by_mp[a_key]
            if _is_ambiguous_rename_pair(old_op, new_op):
                paired_removed.add(r_key)
                paired_added.add(a_key)
                tools = _resolve_affected_tools(old_op.stable_id, old_tool_plan)
                changes.append(
                    ContractChangeItem(
                        change_id=f"chg_rename_{old_op.stable_id}_to_{new_op.stable_id}",
                        category="operation_renamed_ambiguous",
                        severity="review_required",
                        old_operation_id=old_op.stable_id,
                        new_operation_id=new_op.stable_id,
                        affected_field="relative_path",
                        old_value=f"{old_op.method} {old_op.relative_path}",
                        new_value=f"{new_op.method} {new_op.relative_path}",
                        explanation=(
                            f"Endpoint '{old_op.method} {old_op.relative_path}' was removed while "
                            f"similar endpoint '{new_op.method} {new_op.relative_path}' was added; "
                            "owner review required to confirm whether this is an endpoint rename."
                        ),
                        affected_tools=tools,
                    )
                )
                regression_cases.append(
                    {
                        "case_id": f"reg_rename_{old_op.stable_id}",
                        "type": "ambiguous_endpoint_rename",
                        "old_operation_id": old_op.stable_id,
                        "new_operation_id": new_op.stable_id,
                        "affected_tools": tools,
                    }
                )
                break

    # 4. Purely removed operations
    for r_key in removed_keys:
        if r_key in paired_removed:
            continue
        old_op = old_ops_by_mp[r_key]
        tools = _resolve_affected_tools(old_op.stable_id, old_tool_plan)
        changes.append(
            ContractChangeItem(
                change_id=f"chg_removed_{old_op.stable_id}",
                category="operation_removed",
                severity="breaking",
                old_operation_id=old_op.stable_id,
                affected_field="operation",
                old_value=f"{old_op.method} {old_op.relative_path}",
                new_value=None,
                explanation=(
                    f"Operation '{old_op.stable_id}' ({old_op.method} {old_op.relative_path}) "
                    "was removed from the contract."
                ),
                affected_tools=tools,
            )
        )
        regression_cases.append(
            {
                "case_id": f"reg_removed_{old_op.stable_id}",
                "type": "operation_removed",
                "operation_id": old_op.stable_id,
                "affected_tools": tools,
            }
        )

    # 5. Purely added operations
    for a_key in added_keys:
        if a_key in paired_added:
            continue
        new_op = new_ops_by_mp[a_key]
        changes.append(
            ContractChangeItem(
                change_id=f"chg_added_{new_op.stable_id}",
                category="operation_added",
                severity="non_breaking",
                new_operation_id=new_op.stable_id,
                affected_field="operation",
                old_value=None,
                new_value=f"{new_op.method} {new_op.relative_path}",
                explanation=(
                    f"New operation '{new_op.stable_id}' ({new_op.method} {new_op.relative_path}) "
                    "was added."
                ),
                affected_tools=[],
            )
        )

    # 6. Compare matched operations field by field
    for m_key in matched_keys:
        old_op = old_ops_by_mp[m_key]
        new_op = new_ops_by_mp[m_key]
        op_id = old_op.stable_id
        op_tools = _resolve_affected_tools(op_id, old_tool_plan)
        op_had_semantic_diff = False

        # 6a. Security requirement
        old_sec = old_op.security_requirement.model_dump()
        new_sec = new_op.security_requirement.model_dump()
        if old_sec != new_sec:
            op_had_semantic_diff = True
            changes.append(
                ContractChangeItem(
                    change_id=f"chg_auth_{op_id}",
                    category="auth_changed",
                    severity="breaking",
                    old_operation_id=op_id,
                    new_operation_id=new_op.stable_id,
                    affected_field="security_requirement",
                    old_value=old_sec,
                    new_value=new_sec,
                    explanation=f"Authentication requirement changed on '{op_id}'.",
                    affected_tools=op_tools,
                )
            )
            regression_cases.append(
                {
                    "case_id": f"reg_auth_{op_id}",
                    "type": "auth_requirement_changed",
                    "operation_id": op_id,
                    "affected_tools": op_tools,
                }
            )

        # 6b. Semantic effect
        if old_op.semantic_effect != new_op.semantic_effect:
            op_had_semantic_diff = True
            changes.append(
                ContractChangeItem(
                    change_id=f"chg_effect_{op_id}",
                    category="semantic_effect_changed",
                    severity="breaking",
                    old_operation_id=op_id,
                    new_operation_id=new_op.stable_id,
                    affected_field="semantic_effect",
                    old_value=old_op.semantic_effect,
                    new_value=new_op.semantic_effect,
                    explanation=(
                        f"Semantic effect of '{op_id}' changed from "
                        f"'{old_op.semantic_effect}' to '{new_op.semantic_effect}'."
                    ),
                    affected_tools=op_tools,
                )
            )

        # 6c. Support status
        if old_op.support_status != new_op.support_status:
            op_had_semantic_diff = True
            sev: Literal["breaking", "non_breaking"] = (
                "breaking" if new_op.support_status != "supported" else "non_breaking"
            )
            changes.append(
                ContractChangeItem(
                    change_id=f"chg_support_{op_id}",
                    category="support_status_changed",
                    severity=sev,
                    old_operation_id=op_id,
                    new_operation_id=new_op.stable_id,
                    affected_field="support_status",
                    old_value=old_op.support_status,
                    new_value=new_op.support_status,
                    explanation=(
                        f"Support status of '{op_id}' changed from "
                        f"'{old_op.support_status}' to '{new_op.support_status}'."
                    ),
                    affected_tools=op_tools if sev == "breaking" else [],
                )
            )

        # 6d. Parameters
        old_params = {(p.external_name, p.location): p for p in old_op.parameters}
        new_params = {(p.external_name, p.location): p for p in new_op.parameters}

        for p_key in sorted(set(new_params.keys()) - set(old_params.keys())):
            np = new_params[p_key]
            op_had_semantic_diff = True
            if np.required:
                changes.append(
                    ContractChangeItem(
                        change_id=f"chg_req_param_{op_id}_{np.location}_{np.external_name}",
                        category="required_parameter_added",
                        severity="breaking",
                        old_operation_id=op_id,
                        new_operation_id=new_op.stable_id,
                        affected_field=f"parameters.{np.location}.{np.external_name}",
                        old_value=None,
                        new_value=_normalize_param_semantics(np),
                        explanation=(
                            f"New required {np.location} parameter '{np.external_name}' "
                            f"added to '{op_id}'."
                        ),
                        affected_tools=op_tools,
                    )
                )
                regression_cases.append(
                    {
                        "case_id": f"reg_req_param_{op_id}_{np.external_name}",
                        "type": "missing_new_required_parameter_rejected",
                        "operation_id": op_id,
                        "parameter": np.external_name,
                        "location": np.location,
                        "affected_tools": op_tools,
                    }
                )
            else:
                changes.append(
                    ContractChangeItem(
                        change_id=f"chg_opt_param_{op_id}_{np.location}_{np.external_name}",
                        category="parameter_modified",
                        severity="non_breaking",
                        old_operation_id=op_id,
                        new_operation_id=new_op.stable_id,
                        affected_field=f"parameters.{np.location}.{np.external_name}",
                        old_value=None,
                        new_value=_normalize_param_semantics(np),
                        explanation=(
                            f"New optional {np.location} parameter '{np.external_name}' "
                            f"added to '{op_id}'."
                        ),
                        affected_tools=[],
                    )
                )

        for p_key in sorted(set(old_params.keys()) - set(new_params.keys())):
            op_p = old_params[p_key]
            op_had_semantic_diff = True
            changes.append(
                ContractChangeItem(
                    change_id=f"chg_rem_param_{op_id}_{op_p.location}_{op_p.external_name}",
                    category="parameter_removed",
                    severity="breaking",
                    old_operation_id=op_id,
                    new_operation_id=new_op.stable_id,
                    affected_field=f"parameters.{op_p.location}.{op_p.external_name}",
                    old_value=_normalize_param_semantics(op_p),
                    new_value=None,
                    explanation=(
                        f"Parameter '{op_p.external_name}' ({op_p.location}) was removed from '{op_id}'."
                    ),
                    affected_tools=op_tools,
                )
            )
            regression_cases.append(
                {
                    "case_id": f"reg_rem_param_{op_id}_{op_p.external_name}",
                    "type": "removed_parameter_rejected",
                    "operation_id": op_id,
                    "parameter": op_p.external_name,
                    "affected_tools": op_tools,
                }
            )

        for p_key in sorted(set(old_params.keys()) & set(new_params.keys())):
            old_p = old_params[p_key]
            new_p = new_params[p_key]
            old_norm = _normalize_param_semantics(old_p)
            new_norm = _normalize_param_semantics(new_p)
            if old_norm != new_norm:
                op_had_semantic_diff = True
                if not old_p.required and new_p.required:
                    cat: Literal["required_parameter_added", "parameter_modified"] = (
                        "required_parameter_added"
                    )
                    expl = (
                        f"Optional parameter '{new_p.external_name}' on '{op_id}' "
                        "became required."
                    )
                else:
                    cat = "parameter_modified"
                    expl = (
                        f"Parameter '{new_p.external_name}' ({new_p.location}) on '{op_id}' "
                        "changed schema or serialization semantics."
                    )
                changes.append(
                    ContractChangeItem(
                        change_id=f"chg_mod_param_{op_id}_{new_p.location}_{new_p.external_name}",
                        category=cat,
                        severity="breaking",
                        old_operation_id=op_id,
                        new_operation_id=new_op.stable_id,
                        affected_field=f"parameters.{new_p.location}.{new_p.external_name}",
                        old_value=old_norm,
                        new_value=new_norm,
                        explanation=expl,
                        affected_tools=op_tools,
                    )
                )
                regression_cases.append(
                    {
                        "case_id": f"reg_mod_param_{op_id}_{new_p.external_name}",
                        "type": "parameter_semantics_changed",
                        "operation_id": op_id,
                        "parameter": new_p.external_name,
                        "affected_tools": op_tools,
                    }
                )

        # 6e. Request body
        old_body = _normalize_body_semantics(old_op.request_body)
        new_body = _normalize_body_semantics(new_op.request_body)
        if old_body != new_body:
            op_had_semantic_diff = True
            changes.append(
                ContractChangeItem(
                    change_id=f"chg_body_{op_id}",
                    category="request_body_modified",
                    severity="breaking",
                    old_operation_id=op_id,
                    new_operation_id=new_op.stable_id,
                    affected_field="request_body",
                    old_value=old_body,
                    new_value=new_body,
                    explanation=f"Request body schema or requirement changed on '{op_id}'.",
                    affected_tools=op_tools,
                )
            )
            regression_cases.append(
                {
                    "case_id": f"reg_body_{op_id}",
                    "type": "request_body_changed",
                    "operation_id": op_id,
                    "affected_tools": op_tools,
                }
            )

        # 6f. Cosmetic / description-only changes when operational semantics are identical
        old_param_descs = {
            (p.external_name, p.location): p.description for p in old_op.parameters
        }
        new_param_descs = {
            (p.external_name, p.location): p.description for p in new_op.parameters
        }
        old_raw_body_schema = (
            old_op.request_body.schema_def if old_op.request_body is not None else None
        )
        new_raw_body_schema = (
            new_op.request_body.schema_def if new_op.request_body is not None else None
        )
        if not op_had_semantic_diff and (
            old_op.display_name != new_op.display_name
            or old_param_descs != new_param_descs
            or old_raw_body_schema != new_raw_body_schema
        ):
            changes.append(
                ContractChangeItem(
                    change_id=f"chg_cosmetic_{op_id}",
                    category="format_or_description_only",
                    severity="cosmetic",
                    old_operation_id=op_id,
                    new_operation_id=new_op.stable_id,
                    affected_field="display_name_or_description",
                    old_value=old_op.display_name,
                    new_value=new_op.display_name,
                    explanation=(
                        f"Only prose display name or parameter/body descriptions changed on '{op_id}'; "
                        "operational execution semantics are unchanged."
                    ),
                    affected_tools=[],
                )
            )

    non_cosmetic_changes = [c for c in changes if c.severity != "cosmetic"]
    semantically_identical = len(non_cosmetic_changes) == 0
    has_breaking = any(c.severity == "breaking" for c in changes)
    requires_review = any(c.severity == "review_required" for c in changes)

    affected_op_ids = sorted(
        {
            op_id
            for c in changes
            if c.severity in {"breaking", "review_required"}
            for op_id in (c.old_operation_id, c.new_operation_id)
            if op_id is not None
        }
    )
    affected_tools = sorted(
        {
            t
            for c in changes
            if c.severity in {"breaking", "review_required"}
            for t in c.affected_tools
        }
    )

    diff_payload = {
        "schema_version": SCHEMA_VERSION,
        "old_contract_hash": old_contract.canonical_hash,
        "new_contract_hash": new_contract.canonical_hash,
        "semantically_identical": semantically_identical,
        "has_breaking_changes": has_breaking,
        "requires_review": requires_review,
        "changes": [c.model_dump() for c in changes],
        "affected_operation_ids": affected_op_ids,
        "affected_tool_names": affected_tools,
        "regression_cases": regression_cases,
    }
    diff_hash = sha256_hex(canonical_json_bytes(diff_payload))

    return ContractDiffReport(
        old_contract_id=old_contract.id,
        new_contract_id=new_contract.id,
        old_contract_hash=old_contract.canonical_hash,
        new_contract_hash=new_contract.canonical_hash,
        semantically_identical=semantically_identical,
        has_breaking_changes=has_breaking,
        requires_review=requires_review,
        changes=changes,
        affected_operation_ids=affected_op_ids,
        affected_tool_names=affected_tools,
        regression_cases=regression_cases,
        diff_hash=diff_hash,
    )


def _extract_raw_override_target_hash(
    unoverridden_contract: ApiContract,
    override: UserOverride,
) -> str | None:
    """Compute the field value hash on an un-overridden contract to check override compatibility."""
    if override.operation_id is None:
        if override.target_field == "servers":
            return compute_field_value_hash(unoverridden_contract.servers)
        val = getattr(unoverridden_contract, override.target_field, None)
        return compute_field_value_hash(val) if val is not None else None

    ops_by_id = {op.stable_id: op for op in unoverridden_contract.operations}
    target_op = ops_by_id.get(override.operation_id)
    if target_op is None:
        return None

    if override.target_field == "method_path":
        return compute_field_value_hash(
            {
                "method": target_op.method,
                "relative_path": target_op.relative_path,
            }
        )
    val = getattr(target_op, override.target_field, None)
    return compute_field_value_hash(val)


def reconcile_and_regenerate(
    new_bundles: list[DocumentExtractionBundle],
    *,
    old_contract: ApiContract,
    old_tool_plan: ToolPlan | None = None,
    old_policy: RuntimePolicy | None = None,
    new_contract_id: str | None = None,
    new_revision: int | None = None,
) -> tuple[SafeRegenerationResult, list[EvidenceRef]]:
    """Safely reconcile updated document bundles while carrying forward valid overrides (T31).

    - Evaluates each `UserOverride` in `old_contract.overrides` against the un-overridden
      extraction of `new_bundles`:
      * If the target field still exists and its un-overridden value hash matches `old_value_hash`,
        the override is carried forward to `new_revision` (`carried_forward_overrides`).
      * Otherwise, the override is rejected as stale (`invalidated_overrides`) and surfaced
        as a `STALE_OVERRIDE` blocker finding on `regenerated_contract`.
    - Freezes tool names from `old_tool_plan.tool_names` (`preserved_tool_names`) so description
      or display name changes never rename existing tools.
    - Invalidates `old_policy` and action approvals when breaking or security-relevant contract
      changes occur.
    """
    target_rev = (
        new_revision if new_revision is not None else old_contract.revision + 1
    )
    target_cid = new_contract_id or old_contract.id

    # 1. Reconcile without overrides first to inspect raw extracted values in the new revision
    raw_new_contract, _ = reconcile_bundles_to_contract(
        new_bundles,
        contract_id=target_cid,
        project_id=old_contract.project_id,
        revision=target_rev,
        overrides=[],
    )

    carried_forward: list[UserOverride] = []
    invalidated: list[UserOverride] = []
    stale_findings: list[Finding] = []

    for ov in old_contract.overrides:
        raw_hash = _extract_raw_override_target_hash(raw_new_contract, ov)
        if raw_hash is not None and raw_hash == ov.old_value_hash:
            migrated = ov.model_copy(update={"source_revision": target_rev})
            carried_forward.append(migrated)
        else:
            invalidated.append(ov)
            stale_findings.append(
                Finding(
                    id=f"fnd_stale_regen_{ov.id}_r{target_rev}",
                    code="STALE_OVERRIDE",
                    severity="blocker",
                    affected_field=ov.target_field,
                    operation_id=ov.operation_id,
                    explanation=(
                        f"Previous override '{ov.id}' on '{ov.target_field}' (from revision "
                        f"{ov.source_revision}) is stale because the underlying document "
                        f"content changed in revision {target_rev} (expected hash "
                        f"{ov.old_value_hash}, got {raw_hash})."
                    ),
                    suggested_resolution=(
                        "Review the updated document section and issue a fresh override for "
                        f"revision {target_rev}."
                    ),
                )
            )

    # 2. Reconcile with carried-forward overrides
    regenerated_contract, all_evidence = reconcile_bundles_to_contract(
        new_bundles,
        contract_id=target_cid,
        project_id=old_contract.project_id,
        revision=target_rev,
        overrides=carried_forward,
    )

    # If any overrides were invalidated, attach their STALE_OVERRIDE blocker findings
    # and mark the affected operation as blocked!
    if stale_findings:
        raw_dump = regenerated_contract.model_dump(by_alias=True)
        for sf in stale_findings:
            raw_dump["findings"].append(sf.model_dump())
            if sf.operation_id is not None:
                for op_dict in raw_dump["operations"]:
                    if op_dict["stable_id"] == sf.operation_id:
                        op_dict["support_status"] = "blocked"
        raw_dump["canonical_hash"] = ""
        regenerated_contract = ApiContract.model_validate(raw_dump)

    # 3. Compute semantic diff report between old_contract and regenerated_contract
    diff_report = compare_contracts(
        old_contract,
        regenerated_contract,
        old_tool_plan=old_tool_plan,
    )

    # 4. Evaluate policy & approval invalidation
    policy_invalidated = False
    policy_reasons: list[str] = []

    if diff_report.requires_review:
        policy_invalidated = True
        policy_reasons.append(
            "Contract diff contains ambiguous endpoint rename(s) requiring owner review."
        )
    if stale_findings:
        policy_invalidated = True
        policy_reasons.append(
            "One or more previous owner overrides became stale due to document changes."
        )

    for chg in diff_report.changes:
        if chg.category in {"auth_changed", "server_changed", "semantic_effect_changed"}:
            policy_invalidated = True
            policy_reasons.append(chg.explanation)
        elif (
            old_policy is not None
            and chg.severity == "breaking"
            and chg.old_operation_id in set(old_policy.allowed_write_operations)
        ):
            policy_invalidated = True
            policy_reasons.append(
                f"Authorized write operation '{chg.old_operation_id}' had a breaking change: "
                f"{chg.explanation}"
            )

    approvals_invalidated = (
        regenerated_contract.canonical_hash != old_contract.canonical_hash
        or policy_invalidated
    )

    preserved_names: dict[str, str] = (
        dict(old_tool_plan.tool_names) if old_tool_plan is not None else {}
    )

    regenerated_plan: ToolPlan | None = None
    if not policy_invalidated and old_policy is not None:
        eff_policy = old_policy.model_copy(update={"revision": target_rev, "policy_hash": ""})
        eff_policy = RuntimePolicy.model_validate(eff_policy.model_dump())

        # Keep previously selected operations that still exist and are supported
        regen_ops_by_id = {op.stable_id: op for op in regenerated_contract.operations}
        if old_tool_plan is not None:
            candidate_ids = [
                op_id
                for op_id in old_tool_plan.operation_ids
                if op_id in regen_ops_by_id
                and regen_ops_by_id[op_id].support_status == "supported"
            ]
        else:
            candidate_ids = [
                op.stable_id
                for op in regenerated_contract.operations
                if op.support_status == "supported"
            ]

        if candidate_ids:
            regenerated_plan = create_tool_plan(
                regenerated_contract,
                eff_policy,
                plan_id=f"plan_{old_contract.project_id}_r{target_rev}",
                selected_operation_ids=candidate_ids,
                preserve_dependencies=True,
                preserved_tool_names=preserved_names,
            )

    result = SafeRegenerationResult(
        old_contract_hash=old_contract.canonical_hash,
        new_contract_hash=regenerated_contract.canonical_hash,
        diff_report=diff_report,
        carried_forward_overrides=carried_forward,
        invalidated_overrides=invalidated,
        preserved_tool_names=preserved_names,
        policy_invalidated=policy_invalidated,
        policy_invalidation_reasons=policy_reasons,
        approvals_invalidated=approvals_invalidated,
        regenerated_contract=regenerated_contract,
        regenerated_tool_plan=regenerated_plan,
    )
    return result, all_evidence


def verify_reproducible_regeneration(
    contract: ApiContract,
    tool_plan: ToolPlan,
    policy: RuntimePolicy,
    work_dir: Path,
    *,
    package_slug: str = "spigot_repro_server",
) -> dict[str, Any]:
    """Generate a server package and ZIP twice from frozen inputs and verify identical hashes (T31)."""
    dir_a = work_dir / "run_a" / "pkg"
    zip_a = work_dir / "run_a" / f"{package_slug}.zip"

    dir_b = work_dir / "run_b" / "pkg"
    zip_b = work_dir / "run_b" / f"{package_slug}.zip"

    manifest_a = generate_server_package(
        contract, tool_plan, policy, dir_a, package_slug=package_slug
    )
    bytes_a = export_reproducible_zip(dir_a, zip_a)
    sha_a = sha256_hex(bytes_a)

    manifest_b = generate_server_package(
        contract, tool_plan, policy, dir_b, package_slug=package_slug
    )
    bytes_b = export_reproducible_zip(dir_b, zip_b)
    sha_b = sha256_hex(bytes_b)

    reproducible = (
        manifest_a.manifest_hash == manifest_b.manifest_hash
        and manifest_a.artifact_hashes == manifest_b.artifact_hashes
        and sha_a == sha_b
    )
    return {
        "reproducible": reproducible,
        "manifest_hash_a": manifest_a.manifest_hash,
        "manifest_hash_b": manifest_b.manifest_hash,
        "zip_sha256_a": sha_a,
        "zip_sha256_b": sha_b,
        "artifact_count": len(manifest_a.artifact_hashes),
    }

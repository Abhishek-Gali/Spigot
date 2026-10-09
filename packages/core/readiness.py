"""Semantic Readiness Validator for Spigot / DocForge MCP (T08).

Validates an ApiContract (from OpenAPI normalization or prose extraction) before
contract freeze and deterministic code generation:
- Verifies server_ref resolves to a valid http/https server base_url.
- Verifies path template placeholders `{param}` match required `location="path"` parameters.
- Blocks operations with `unknown` authentication status (`UNKNOWN_AUTH`).
- Verifies at least one security alternative is satisfied by defined & supported schemes.
- Blocks operations with `unknown` semantic effect (`UNKNOWN_SEMANTIC_EFFECT`).
- Blocks operations with unsupported request body media types or open blocker findings.
- Isolates blockers to affected operations so supported operations remain selectable.
"""

from __future__ import annotations

import re
import uuid
from urllib.parse import urlparse

from packages.core.contracts import (
    ApiContract,
    Finding,
    OperationContract,
    SecurityScheme,
)
from packages.core.support_registry import (
    SUPPORTED_PARAMETER_LOCATIONS,
    SUPPORTED_PARAMETER_STYLES,
    SUPPORTED_REQUEST_MEDIA_TYPES,
    UNSUPPORTED_COMPOSITION_KEYWORDS,
)

PATH_PLACEHOLDER_RE = re.compile(r"\{([^{}]+)\}")


def _is_scheme_supported(scheme: SecurityScheme) -> bool:
    if scheme.type == "http" and (scheme.scheme or "").lower() == "bearer":
        return True
    if scheme.type == "apiKey" and scheme.location in {"header", "query"}:
        return True
    return False


def _has_unsupported_composition(schema: object) -> str | None:
    if isinstance(schema, dict):
        for k, v in schema.items():
            if k in UNSUPPORTED_COMPOSITION_KEYWORDS:
                return str(k)
            nested = _has_unsupported_composition(v)
            if nested:
                return nested
    elif isinstance(schema, list):
        for item in schema:
            nested = _has_unsupported_composition(item)
            if nested:
                return nested
    return None


def validate_contract_readiness(contract: ApiContract) -> ApiContract:
    """Run semantic readiness checks across an ApiContract and return an updated copy."""
    raw = contract.model_dump(by_alias=True)
    existing_findings: list[Finding] = list(contract.findings)
    existing_keys = {
        (f.operation_id, f.code, f.affected_field) for f in existing_findings if f.status == "open"
    }

    def add_blocker(
        code: str,
        affected_field: str,
        explanation: str,
        resolution: str,
        operation_id: str | None = None,
        evidence_refs: list[str] | None = None,
    ) -> None:
        key = (operation_id, code, affected_field)
        if key in existing_keys:
            return
        existing_keys.add(key)
        existing_findings.append(
            Finding(
                id=f"fnd_{uuid.uuid4().hex[:10]}",
                code=code,
                severity="blocker",
                affected_field=affected_field,
                operation_id=operation_id,
                evidence_refs=evidence_refs or [],
                explanation=explanation,
                suggested_resolution=resolution,
                status="open",
            )
        )

    servers_by_id = {s.server_id: s for s in contract.servers}
    schemes_by_id = {s.scheme_id: s for s in contract.security_schemes}

    if not contract.servers:
        add_blocker(
            "MISSING_BASE_URL",
            "servers",
            "Contract defines no server base URL.",
            "Configure a reviewed https:// or http:// server base URL.",
        )
    else:
        for srv in contract.servers:
            parsed_url = urlparse(srv.base_url)
            if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
                add_blocker(
                    "INVALID_BASE_URL",
                    f"servers.{srv.server_id}.base_url",
                    f"Server '{srv.server_id}' has invalid base_url '{srv.base_url}'.",
                    "Specify a complete http:// or https:// base URL.",
                )

    for op in contract.operations:
        op_id = op.stable_id
        ev_refs = op.provenance.get("relative_path", [])

        # 1. Server reference
        srv = servers_by_id.get(op.server_ref)
        if srv is None:
            add_blocker(
                "UNRESOLVED_SERVER_REF",
                "server_ref",
                f"Operation '{op_id}' references unknown server '{op.server_ref}'.",
                "Point server_ref to a defined server in contract.servers.",
                operation_id=op_id,
                evidence_refs=ev_refs,
            )
        else:
            parsed_url = urlparse(srv.base_url)
            if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
                add_blocker(
                    "INVALID_BASE_URL",
                    "server_ref",
                    f"Operation '{op_id}' server '{srv.server_id}' has invalid base URL.",
                    "Provide a valid http:// or https:// base URL.",
                    operation_id=op_id,
                    evidence_refs=ev_refs,
                )

        # 2. Relative path and placeholder consistency
        if not op.relative_path.startswith("/"):
            add_blocker(
                "INVALID_RELATIVE_PATH",
                "relative_path",
                f"Operation '{op_id}' path '{op.relative_path}' must start with '/'.",
                "Normalize relative_path to begin with '/'.",
                operation_id=op_id,
                evidence_refs=ev_refs,
            )

        placeholders = set(PATH_PLACEHOLDER_RE.findall(op.relative_path))
        path_params = {p.external_name: p for p in op.parameters if p.location == "path"}

        for ph in sorted(placeholders):
            if ph not in path_params:
                add_blocker(
                    "UNMATCHED_PATH_PLACEHOLDER",
                    f"relative_path.{ph}",
                    f"Path placeholder '{{{ph}}}' in '{op.relative_path}' has no matching path parameter.",
                    f"Add required path parameter '{ph}' or fix the endpoint path.",
                    operation_id=op_id,
                    evidence_refs=ev_refs,
                )

        for p_name in sorted(path_params.keys()):
            if p_name not in placeholders:
                add_blocker(
                    "ORPHAN_PATH_PARAMETER",
                    f"parameters.{p_name}",
                    f"Path parameter '{p_name}' does not appear as '{{{p_name}}}' in '{op.relative_path}'.",
                    f"Change parameter location to query/header or add '{{{p_name}}}' to the path.",
                    operation_id=op_id,
                    evidence_refs=ev_refs,
                )

        # 3. Parameter location, style, and schema checks
        for param in op.parameters:
            if param.location not in SUPPORTED_PARAMETER_LOCATIONS:
                add_blocker(
                    "UNSUPPORTED_PARAMETER_LOCATION",
                    f"parameters.{param.external_name}",
                    f"Parameter '{param.external_name}' uses unsupported location '{param.location}'.",
                    "Remove cookie parameter requirement or exclude this operation.",
                    operation_id=op_id,
                    evidence_refs=param.evidence,
                )
            else:
                allowed_styles = SUPPORTED_PARAMETER_STYLES.get(param.location, frozenset())
                if param.style not in allowed_styles:
                    add_blocker(
                        "UNSUPPORTED_PARAMETER_STYLE",
                        f"parameters.{param.external_name}.style",
                        f"Parameter '{param.external_name}' uses unsupported style '{param.style}'.",
                        f"Use a supported style ({sorted(allowed_styles)}).",
                        operation_id=op_id,
                        evidence_refs=param.evidence,
                    )
            comp_kw = _has_unsupported_composition(param.schema_def)
            if comp_kw:
                add_blocker(
                    "UNSUPPORTED_SCHEMA_COMPOSITION",
                    f"parameters.{param.external_name}.schema",
                    f"Parameter '{param.external_name}' schema uses unsupported keyword '{comp_kw}'.",
                    "Replace polymorphic composition with an explicit schema.",
                    operation_id=op_id,
                    evidence_refs=param.evidence,
                )

        # 4. Request body encoding and schema checks
        if op.request_body is not None:
            if op.request_body.media_type not in SUPPORTED_REQUEST_MEDIA_TYPES:
                add_blocker(
                    "UNSUPPORTED_MEDIA_TYPE",
                    "request_body.media_type",
                    f"Request body media type '{op.request_body.media_type}' is unsupported.",
                    "Only application/json request bodies are supported in v1.",
                    operation_id=op_id,
                    evidence_refs=op.request_body.evidence,
                )
            comp_kw = _has_unsupported_composition(op.request_body.schema_def)
            if comp_kw:
                add_blocker(
                    "UNSUPPORTED_SCHEMA_COMPOSITION",
                    "request_body.schema",
                    f"Request body schema uses unsupported composition keyword '{comp_kw}'.",
                    "Replace composition keyword with an explicit object schema.",
                    operation_id=op_id,
                    evidence_refs=op.request_body.evidence,
                )

        # 5. Authentication status & scheme support
        sec = op.security_requirement
        if sec.status == "unknown":
            add_blocker(
                "UNKNOWN_AUTH",
                "security_requirement",
                f"Authentication requirement for '{op_id}' is unknown.",
                "Specify an explicit authentication scheme or confirm public access.",
                operation_id=op_id,
                evidence_refs=op.provenance.get("security_requirement", []),
            )
        elif sec.status == "authenticated":
            has_valid_alt = False
            for alt in sec.alternatives:
                if all(
                    sid in schemes_by_id and _is_scheme_supported(schemes_by_id[sid])
                    for sid in alt.all_of
                ):
                    has_valid_alt = True
                    break
            if not has_valid_alt:
                add_blocker(
                    "UNSUPPORTED_SECURITY_SCHEME",
                    "security_requirement",
                    f"No authentication alternative for '{op_id}' is supported by the v1 runtime.",
                    "Configure an HTTP Bearer or Header/Query API Key scheme.",
                    operation_id=op_id,
                    evidence_refs=op.provenance.get("security_requirement", []),
                )

        # 6. Semantic effect classification
        if op.semantic_effect == "unknown":
            add_blocker(
                "UNKNOWN_SEMANTIC_EFFECT",
                "semantic_effect",
                f"Semantic effect for '{op_id}' is unknown (disabled by default).",
                "Review and classify the operation as read, write, or destructive.",
                operation_id=op_id,
                evidence_refs=ev_refs,
            )

    # Update per-operation support_status based on open blocker findings
    global_open_blockers = [
        f
        for f in existing_findings
        if f.operation_id is None and f.severity == "blocker" and f.status == "open"
    ]
    updated_ops: list[dict[str, object]] = []
    for op_dict, op_model in zip(raw["operations"], contract.operations, strict=True):
        op_open_blockers = [
            f
            for f in existing_findings
            if f.operation_id == op_model.stable_id
            and f.severity == "blocker"
            and f.status == "open"
        ]
        if global_open_blockers or op_open_blockers:
            op_dict["support_status"] = "blocked"
        elif op_dict["support_status"] == "blocked":
            op_dict["support_status"] = "supported"
        updated_ops.append(op_dict)

    raw["operations"] = updated_ops
    raw["findings"] = [f.model_dump() for f in existing_findings]
    raw["canonical_hash"] = ""
    return ApiContract.model_validate(raw)


def check_contract_freeze_readiness(
    contract: ApiContract,
    selected_operation_ids: list[str] | None = None,
) -> tuple[bool, list[Finding]]:
    """Verify whether the selected operations in a contract can be frozen for generation."""
    validated = validate_contract_readiness(contract)
    target_ids = (
        set(selected_operation_ids)
        if selected_operation_ids is not None
        else {op.stable_id for op in validated.operations}
    )

    blocking_findings: list[Finding] = []
    for f in validated.findings:
        if f.severity == "blocker" and f.status == "open":
            if f.operation_id is None or f.operation_id in target_ids:
                blocking_findings.append(f)

    ops_by_id: dict[str, OperationContract] = {op.stable_id: op for op in validated.operations}
    for tid in sorted(target_ids):
        op = ops_by_id.get(tid)
        if op is None or op.support_status != "supported":
            if not any(bf.operation_id == tid for bf in blocking_findings):
                blocking_findings.append(
                    Finding(
                        id=f"fnd_{uuid.uuid4().hex[:10]}",
                        code="OPERATION_NOT_SUPPORTED",
                        severity="blocker",
                        affected_field="support_status",
                        operation_id=tid,
                        explanation=f"Selected operation '{tid}' is not in 'supported' state.",
                        suggested_resolution="Resolve open blockers or deselect this operation.",
                    )
                )

    return len(blocking_findings) == 0, blocking_findings

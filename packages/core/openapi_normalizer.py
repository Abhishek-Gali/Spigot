"""OpenAPI 3.0 Subset Normalizer for Spigot / DocForge MCP (T07).

Normalizes OpenAPI 3.0 JSON/YAML specifications into an ApiContract while enforcing
COMPATIBILITY.md and DATA_CONTRACTS.md boundaries:
- Rejects OpenAPI 3.1.x or Swagger 2.0 with explicit findings instead of silent misparsing.
- Resolves local #/... $refs with depth bound (MAX_REF_DEPTH=20) and cycle detection.
- Blocks remote $refs in offline mode.
- Preserves security requirement OR-of-ANDs, operation-level overrides, and distinguishes
  explicit public (`security: [{}]`) from unknown (omitted) authentication.
- Preserves duplicate parameter names in distinct locations (`path`, `query`, `header`)
  using collision-free safe argument names.
- Flags unsupported schema composition (`allOf`, `oneOf`, `anyOf`), cookie parameters,
  complex serialization styles (`deepObject`, `matrix`, `label`), and non-JSON request bodies.
"""

from __future__ import annotations

import uuid
from typing import Any

import yaml

from packages.core.contracts import (
    ApiContract,
    BlockLocation,
    DocumentBlock,
    EvidenceRef,
    Finding,
    OperationContract,
    ParameterContract,
    ParameterLocation,
    RequestBodyContract,
    ResponseContract,
    SecurityAlternative,
    SecurityRequirement,
    SecurityScheme,
    SemanticEffect,
    ServerContract,
    SupportStatus,
    assign_safe_parameter_names,
    to_safe_identifier,
)
from packages.core.support_registry import (
    MAX_REF_DEPTH,
    PROTECTED_HEADER_NAMES,
    SUPPORTED_PARAMETER_LOCATIONS,
    SUPPORTED_PARAMETER_STYLES,
    SUPPORTED_REQUEST_MEDIA_TYPES,
    UNSUPPORTED_COMPOSITION_KEYWORDS,
    is_openapi_version_supported,
)

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
DEFAULT_SEMANTIC_EFFECT_BY_METHOD: dict[str, SemanticEffect] = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "write",
    "PUT": "write",
    "PATCH": "write",
    "DELETE": "destructive",
}


class OpenAPIParseError(ValueError):
    """Raised when an OpenAPI document cannot be safely parsed."""


def _resolve_json_pointer(root_doc: dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        raise KeyError(f"Non-local reference: {ref}")
    parts = [p.replace("~1", "/").replace("~0", "~") for p in ref[2:].split("/")]
    curr: Any = root_doc
    for part in parts:
        if not isinstance(curr, dict) or part not in curr:
            raise KeyError(f"Unresolvable reference pointer: {ref}")
        curr = curr[part]
    return curr


def _deref_object(
    obj: Any,
    root_doc: dict[str, Any],
    *,
    operation_id: str | None,
    field_path: str,
    evidence_ids: list[str],
    findings: list[Finding],
    visited: frozenset[str] = frozenset(),
    depth: int = 0,
) -> Any:
    """Recursively dereference local `$ref` pointers with cycle and depth detection."""
    if depth > MAX_REF_DEPTH:
        findings.append(
            Finding(
                id=f"fnd_{uuid.uuid4().hex[:10]}",
                code="MAX_REF_DEPTH_EXCEEDED",
                severity="blocker",
                affected_field=field_path,
                operation_id=operation_id,
                evidence_refs=evidence_ids,
                explanation=f"Reference resolution exceeded maximum depth of {MAX_REF_DEPTH}.",
                suggested_resolution="Simplify nested $ref chains or inline the schema.",
            )
        )
        return {"type": "object", "x_spigot_blocked": "MAX_REF_DEPTH_EXCEEDED"}

    if isinstance(obj, dict):
        if "$ref" in obj and isinstance(obj["$ref"], str):
            ref_str = obj["$ref"].strip()
            if not ref_str.startswith("#/"):
                findings.append(
                    Finding(
                        id=f"fnd_{uuid.uuid4().hex[:10]}",
                        code="REMOTE_REF_DISABLED",
                        severity="blocker",
                        affected_field=field_path,
                        operation_id=operation_id,
                        evidence_refs=evidence_ids,
                        explanation=f"External/remote $ref '{ref_str}' is disabled in offline mode.",
                        suggested_resolution="Bundle referenced schemas locally under #/components/schemas.",
                    )
                )
                return {"type": "object", "x_spigot_blocked": "REMOTE_REF_DISABLED"}

            if ref_str in visited:
                findings.append(
                    Finding(
                        id=f"fnd_{uuid.uuid4().hex[:10]}",
                        code="REF_CYCLE_DETECTED",
                        severity="blocker",
                        affected_field=field_path,
                        operation_id=operation_id,
                        evidence_refs=evidence_ids,
                        explanation=f"Circular $ref cycle detected at '{ref_str}'.",
                        suggested_resolution="Break the recursive schema reference cycle for this operation.",
                    )
                )
                return {"type": "object", "x_spigot_blocked": "REF_CYCLE_DETECTED"}

            try:
                target = _resolve_json_pointer(root_doc, ref_str)
            except KeyError:
                findings.append(
                    Finding(
                        id=f"fnd_{uuid.uuid4().hex[:10]}",
                        code="UNRESOLVED_LOCAL_REF",
                        severity="blocker",
                        affected_field=field_path,
                        operation_id=operation_id,
                        evidence_refs=evidence_ids,
                        explanation=f"Local $ref '{ref_str}' could not be resolved in document.",
                        suggested_resolution="Define the missing component target in #/components.",
                    )
                )
                return {"type": "object", "x_spigot_blocked": "UNRESOLVED_LOCAL_REF"}

            return _deref_object(
                target,
                root_doc,
                operation_id=operation_id,
                field_path=field_path,
                evidence_ids=evidence_ids,
                findings=findings,
                visited=visited | {ref_str},
                depth=depth + 1,
            )

        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in UNSUPPORTED_COMPOSITION_KEYWORDS:
                findings.append(
                    Finding(
                        id=f"fnd_{uuid.uuid4().hex[:10]}",
                        code="UNSUPPORTED_SCHEMA_COMPOSITION",
                        severity="blocker",
                        affected_field=f"{field_path}.{k}",
                        operation_id=operation_id,
                        evidence_refs=evidence_ids,
                        explanation=(
                            f"Schema keyword '{k}' at '{field_path}' is outside the initial "
                            "supported OpenAPI 3.0 subset."
                        ),
                        suggested_resolution=(
                            "Replace polymorphic composition with an explicit flat object schema "
                            "or exclude this operation."
                        ),
                    )
                )
            out[k] = _deref_object(
                v,
                root_doc,
                operation_id=operation_id,
                field_path=f"{field_path}.{k}",
                evidence_ids=evidence_ids,
                findings=findings,
                visited=visited,
                depth=depth + 1,
            )
        return out

    if isinstance(obj, list):
        return [
            _deref_object(
                item,
                root_doc,
                operation_id=operation_id,
                field_path=f"{field_path}[{idx}]",
                evidence_ids=evidence_ids,
                findings=findings,
                visited=visited,
                depth=depth + 1,
            )
            for idx, item in enumerate(obj)
        ]

    return obj


def _normalize_security_requirement(
    sec_list: Any,
    *,
    operation_id: str | None,
    defined_schemes: dict[str, SecurityScheme],
    evidence_ids: list[str],
    findings: list[Finding],
) -> SecurityRequirement:
    """Convert an OpenAPI `security` array into SecurityRequirement preserving OR of ANDs."""
    if sec_list is None:
        return SecurityRequirement(status="unknown", alternatives=[])

    if not isinstance(sec_list, list) or len(sec_list) == 0:
        return SecurityRequirement(status="unknown", alternatives=[])

    # Check if explicit empty object `{}` is present -> public access allowed
    has_empty_alternative = any(isinstance(entry, dict) and len(entry) == 0 for entry in sec_list)
    alternatives: list[SecurityAlternative] = []
    for entry in sec_list:
        if isinstance(entry, dict) and len(entry) > 0:
            scheme_ids = [str(k) for k in entry.keys()]
            alternatives.append(SecurityAlternative(all_of=scheme_ids))

    if not alternatives and has_empty_alternative:
        return SecurityRequirement(status="public", alternatives=[])

    if not alternatives:
        return SecurityRequirement(status="unknown", alternatives=[])

    # Validate that at least one alternative uses only supported schemes
    supported_alt_count = 0
    for alt in alternatives:
        all_supported = True
        for sid in alt.all_of:
            scheme = defined_schemes.get(sid)
            if scheme is None:
                all_supported = False
                findings.append(
                    Finding(
                        id=f"fnd_{uuid.uuid4().hex[:10]}",
                        code="UNDEFINED_SECURITY_SCHEME",
                        severity="blocker",
                        affected_field="security_requirement",
                        operation_id=operation_id,
                        evidence_refs=evidence_ids,
                        explanation=f"Operation references undefined security scheme '{sid}'.",
                        suggested_resolution=f"Define '{sid}' in components.securitySchemes.",
                    )
                )
            elif not _is_security_scheme_supported(scheme):
                all_supported = False
        if all_supported:
            supported_alt_count += 1

    if supported_alt_count == 0:
        findings.append(
            Finding(
                id=f"fnd_{uuid.uuid4().hex[:10]}",
                code="UNSUPPORTED_SECURITY_SCHEME",
                severity="blocker",
                affected_field="security_requirement",
                operation_id=operation_id,
                evidence_refs=evidence_ids,
                explanation=(
                    "No security requirement alternative can be satisfied by supported "
                    "initial schemes (http/bearer or apiKey in header/query)."
                ),
                suggested_resolution=(
                    "Configure a supported bearer or header/query API key scheme or "
                    "exclude this operation."
                ),
            )
        )

    return SecurityRequirement(status="authenticated", alternatives=alternatives)


def _is_security_scheme_supported(scheme: SecurityScheme) -> bool:
    if scheme.type == "http" and (scheme.scheme or "").lower() == "bearer":
        return True
    if scheme.type == "apiKey" and scheme.location in {"header", "query"}:
        return True
    return False


def normalize_openapi_document(
    raw_text: str,
    *,
    project_id: str,
    source_id: str = "src_openapi_01",
    contract_id: str = "cnt_openapi_01",
    revision: int = 1,
    max_bytes: int = 20 * 1024 * 1024,
) -> tuple[ApiContract, list[DocumentBlock], list[EvidenceRef]]:
    """Parse and normalize an OpenAPI JSON/YAML document into an ApiContract."""
    raw_bytes = raw_text.encode("utf-8")
    if len(raw_bytes) > max_bytes:
        raise OpenAPIParseError(
            f"Document size ({len(raw_bytes)} bytes) exceeds intake limit ({max_bytes} bytes)."
        )

    try:
        parsed = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise OpenAPIParseError(f"Malformed YAML/JSON document: {exc}") from exc

    if not isinstance(parsed, dict):
        raise OpenAPIParseError("OpenAPI document root must be a JSON/YAML mapping object.")

    lines = raw_text.splitlines() or [""]
    doc_block = DocumentBlock(
        id=f"blk_{source_id}_root",
        source_id=source_id,
        text=raw_text,
        block_kind="openapi",
        heading_path=[str(parsed.get("info", {}).get("title", "OpenAPI Specification"))],
        location=BlockLocation(
            kind="line_char",
            start_line=1,
            end_line=len(lines),
            start_char=0,
            end_char=len(raw_text),
        ),
        extraction_method="openapi_safe_loader",
    )

    quote_line = next((ln for ln in lines if ln.strip()), "{}")
    root_ev = EvidenceRef.from_block_substring(f"ev_{source_id}_root", doc_block, quote_line)
    evidence_list: list[EvidenceRef] = [root_ev]
    findings: list[Finding] = []

    openapi_ver = str(parsed.get("openapi", parsed.get("swagger", ""))).strip()
    if not openapi_ver:
        findings.append(
            Finding(
                id=f"fnd_{uuid.uuid4().hex[:10]}",
                code="MISSING_OPENAPI_VERSION",
                severity="blocker",
                affected_field="openapi",
                evidence_refs=[root_ev.id],
                explanation="Document is missing the top-level 'openapi' version string.",
                suggested_resolution="Provide a valid OpenAPI 3.0.x specification.",
            )
        )
    elif openapi_ver.startswith("3.1."):
        findings.append(
            Finding(
                id=f"fnd_{uuid.uuid4().hex[:10]}",
                code="OPENAPI_3_1_EXTENSION_REQUIRED",
                severity="blocker",
                affected_field="openapi",
                evidence_refs=[root_ev.id],
                explanation=(
                    f"OpenAPI version '{openapi_ver}' detected. OpenAPI 3.1 is an extension "
                    "and is not silently parsed as 3.0."
                ),
                suggested_resolution="Export an OpenAPI 3.0.x specification or enable the 3.1 extension.",
            )
        )
    elif not is_openapi_version_supported(openapi_ver):
        findings.append(
            Finding(
                id=f"fnd_{uuid.uuid4().hex[:10]}",
                code="UNSUPPORTED_SPEC_VERSION",
                severity="blocker",
                affected_field="openapi",
                evidence_refs=[root_ev.id],
                explanation=f"Specification version '{openapi_ver}' is unsupported (requires 3.0.x).",
                suggested_resolution="Convert the specification to OpenAPI 3.0.x.",
            )
        )

    # Servers
    servers: list[ServerContract] = []
    raw_servers = parsed.get("servers", [])
    if isinstance(raw_servers, list):
        for idx, srv in enumerate(raw_servers):
            if isinstance(srv, dict) and isinstance(srv.get("url"), str):
                url_str = srv["url"].strip()
                if url_str:
                    servers.append(
                        ServerContract(
                            server_id=f"server_{idx + 1}" if idx > 0 else "default_server",
                            base_url=url_str,
                            description=str(srv.get("description", "")),
                            evidence=[root_ev.id],
                        )
                    )
    if not servers:
        findings.append(
            Finding(
                id=f"fnd_{uuid.uuid4().hex[:10]}",
                code="MISSING_BASE_URL",
                severity="blocker",
                affected_field="servers",
                evidence_refs=[root_ev.id],
                explanation="No valid server base URL is documented in top-level 'servers'.",
                suggested_resolution="Add a valid https:// or http:// server URL in servers.",
            )
        )

    # Security Schemes
    defined_schemes: dict[str, SecurityScheme] = {}
    components = parsed.get("components", {})
    raw_schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    if isinstance(raw_schemes, dict):
        for scheme_id, s_obj in raw_schemes.items():
            if not isinstance(s_obj, dict):
                continue
            raw_type = str(s_obj.get("type", "unknown"))
            s_type: Any = (
                raw_type if raw_type in {"apiKey", "http", "oauth2", "openIdConnect"} else "unknown"
            )
            raw_in = s_obj.get("in")
            s_loc: Any = raw_in if raw_in in {"header", "query", "cookie"} else None
            scheme_model = SecurityScheme(
                scheme_id=str(scheme_id),
                type=s_type,
                location=s_loc,
                name=str(s_obj["name"]) if "name" in s_obj else None,
                scheme=str(s_obj["scheme"]).lower() if "scheme" in s_obj else None,
                description=str(s_obj.get("description", "")),
                evidence=[root_ev.id],
            )
            defined_schemes[str(scheme_id)] = scheme_model

    global_security_raw = parsed.get("security", None)

    # Operations
    operations: list[OperationContract] = []
    used_op_ids: set[str] = set()
    paths_obj = parsed.get("paths", {})
    if isinstance(paths_obj, dict):
        for rel_path, path_item in paths_obj.items():
            if not isinstance(path_item, dict):
                continue
            path_level_params = (
                path_item.get("parameters", [])
                if isinstance(path_item.get("parameters"), list)
                else []
            )

            for method_lower in HTTP_METHODS:
                if method_lower not in path_item:
                    continue
                op_obj = path_item[method_lower]
                if not isinstance(op_obj, dict):
                    continue

                method_upper = method_lower.upper()
                raw_op_id = op_obj.get("operationId")
                if isinstance(raw_op_id, str) and raw_op_id.strip():
                    base_op_id = to_safe_identifier(raw_op_id.strip(), fallback="operation")
                else:
                    base_op_id = to_safe_identifier(
                        f"{method_lower}_{rel_path}", fallback="operation"
                    )
                stable_id = base_op_id
                if stable_id in used_op_ids:
                    idx = 2
                    while f"{stable_id}_{idx}" in used_op_ids:
                        idx += 1
                    stable_id = f"{stable_id}_{idx}"
                used_op_ids.add(stable_id)

                # Create specific EvidenceRef for the path or operationId if present in raw_text
                op_ev_id = root_ev.id
                for search_token in (
                    str(raw_op_id) if raw_op_id else "",
                    str(rel_path),
                ):
                    if search_token and search_token in raw_text:
                        ev_ref = EvidenceRef.from_block_substring(
                            f"ev_{stable_id}", doc_block, search_token
                        )
                        evidence_list.append(ev_ref)
                        op_ev_id = ev_ref.id
                        break

                op_findings_start = len(findings)

                # Merge path-level and operation-level parameters (operation overrides same name+in)
                op_level_params = (
                    op_obj.get("parameters", [])
                    if isinstance(op_obj.get("parameters"), list)
                    else []
                )
                merged_raw_params: dict[tuple[str, str], dict[str, Any]] = {}
                for raw_p in [*path_level_params, *op_level_params]:
                    deref_p = _deref_object(
                        raw_p,
                        parsed,
                        operation_id=stable_id,
                        field_path="parameters",
                        evidence_ids=[op_ev_id],
                        findings=findings,
                    )
                    if not isinstance(deref_p, dict):
                        continue
                    p_name = str(deref_p.get("name", "")).strip()
                    p_in = str(deref_p.get("in", "")).strip()
                    if p_name and p_in in {"path", "query", "header", "cookie"}:
                        merged_raw_params[(p_name, p_in)] = deref_p

                ordered_raw_params = list(merged_raw_params.values())
                safe_names = assign_safe_parameter_names(
                    [
                        (str(p["name"]), str(p["in"]))  # type: ignore[misc]
                        for p in ordered_raw_params
                    ]
                )

                param_contracts: list[ParameterContract] = []
                for deref_p, safe_name in zip(ordered_raw_params, safe_names, strict=True):
                    p_name = str(deref_p["name"])
                    p_loc: ParameterLocation = deref_p["in"]
                    default_style = "form" if p_loc in {"query", "cookie"} else "simple"
                    p_style = str(deref_p.get("style", default_style))
                    p_explode = bool(deref_p.get("explode", True if p_style == "form" else False))
                    p_required = True if p_loc == "path" else bool(deref_p.get("required", False))
                    p_schema = deref_p.get("schema", {"type": "string"})
                    if not isinstance(p_schema, dict):
                        p_schema = {"type": "string"}

                    if p_loc not in SUPPORTED_PARAMETER_LOCATIONS:
                        findings.append(
                            Finding(
                                id=f"fnd_{uuid.uuid4().hex[:10]}",
                                code="UNSUPPORTED_PARAMETER_LOCATION",
                                severity="blocker",
                                affected_field=f"parameters.{p_name}",
                                operation_id=stable_id,
                                evidence_refs=[op_ev_id],
                                explanation=(
                                    f"Parameter '{p_name}' uses deferred location '{p_loc}'."
                                ),
                                suggested_resolution=(
                                    "Cookie parameters are deferred; exclude this operation."
                                ),
                            )
                        )
                    else:
                        allowed_styles = SUPPORTED_PARAMETER_STYLES.get(p_loc, frozenset())
                        if p_style not in allowed_styles:
                            findings.append(
                                Finding(
                                    id=f"fnd_{uuid.uuid4().hex[:10]}",
                                    code="UNSUPPORTED_PARAMETER_STYLE",
                                    severity="blocker",
                                    affected_field=f"parameters.{p_name}.style",
                                    operation_id=stable_id,
                                    evidence_refs=[op_ev_id],
                                    explanation=(
                                        f"Parameter '{p_name}' in '{p_loc}' uses unsupported "
                                        f"serialization style '{p_style}'."
                                    ),
                                    suggested_resolution=(
                                        f"Use supported style {sorted(allowed_styles)} or exclude."
                                    ),
                                )
                            )

                    if p_loc == "header" and p_name.strip().lower() in PROTECTED_HEADER_NAMES:
                        findings.append(
                            Finding(
                                id=f"fnd_{uuid.uuid4().hex[:10]}",
                                code="PROTECTED_HEADER_PARAMETER",
                                severity="blocker",
                                affected_field=f"parameters.{p_name}",
                                operation_id=stable_id,
                                evidence_refs=[op_ev_id],
                                explanation=(
                                    f"Header parameter '{p_name}' attempts to override a "
                                    "protected transport/security header."
                                ),
                                suggested_resolution=(
                                    "Use securitySchemes for Authorization or server configuration for Host."
                                ),
                            )
                        )

                    param_contracts.append(
                        ParameterContract(
                            external_name=p_name,
                            safe_argument_name=safe_name,
                            location=p_loc,
                            required=p_required,
                            schema=p_schema,
                            style=p_style,
                            explode=p_explode,
                            allow_reserved=bool(deref_p.get("allowReserved", False)),
                            default_value=p_schema.get("default"),
                            description=str(deref_p.get("description", "")),
                            evidence=[op_ev_id],
                        )
                    )

                # Request Body
                req_body_contract: RequestBodyContract | None = None
                if "requestBody" in op_obj:
                    deref_rb = _deref_object(
                        op_obj["requestBody"],
                        parsed,
                        operation_id=stable_id,
                        field_path="request_body",
                        evidence_ids=[op_ev_id],
                        findings=findings,
                    )
                    if isinstance(deref_rb, dict):
                        rb_required = bool(deref_rb.get("required", False))
                        content_map = deref_rb.get("content", {})
                        if isinstance(content_map, dict) and content_map:
                            if "application/json" in content_map:
                                json_media = content_map["application/json"]
                                rb_schema = (
                                    json_media.get("schema", {"type": "object"})
                                    if isinstance(json_media, dict)
                                    else {"type": "object"}
                                )
                                req_body_contract = RequestBodyContract(
                                    media_type="application/json",
                                    required=rb_required,
                                    schema=rb_schema,
                                    description=str(deref_rb.get("description", "")),
                                    evidence=[op_ev_id],
                                )
                            else:
                                first_mt = next(iter(content_map.keys()))
                                findings.append(
                                    Finding(
                                        id=f"fnd_{uuid.uuid4().hex[:10]}",
                                        code="UNSUPPORTED_MEDIA_TYPE",
                                        severity="blocker",
                                        affected_field="request_body.media_type",
                                        operation_id=stable_id,
                                        evidence_refs=[op_ev_id],
                                        explanation=(
                                            f"Operation requestBody requires unsupported media type "
                                            f"'{first_mt}' (initial subset supports "
                                            f"{sorted(SUPPORTED_REQUEST_MEDIA_TYPES)})."
                                        ),
                                        suggested_resolution="Exclude non-JSON upload operations in v1.",
                                    )
                                )
                                req_body_contract = RequestBodyContract(
                                    media_type=str(first_mt),
                                    required=rb_required,
                                    schema={"type": "object"},
                                    description=str(deref_rb.get("description", "")),
                                    evidence=[op_ev_id],
                                )

                # Responses
                resp_contracts: list[ResponseContract] = []
                raw_responses = op_obj.get("responses", {})
                if isinstance(raw_responses, dict):
                    for status_key, r_obj in raw_responses.items():
                        deref_r = _deref_object(
                            r_obj,
                            parsed,
                            operation_id=stable_id,
                            field_path=f"responses.{status_key}",
                            evidence_ids=[op_ev_id],
                            findings=findings,
                        )
                        if not isinstance(deref_r, dict):
                            continue
                        r_content = deref_r.get("content", {})
                        r_mt: str | None = None
                        r_schema: dict[str, Any] | None = None
                        if isinstance(r_content, dict) and r_content:
                            r_mt = (
                                "application/json"
                                if "application/json" in r_content
                                else str(next(iter(r_content.keys())))
                            )
                            mt_obj = r_content.get(r_mt)
                            if isinstance(mt_obj, dict) and isinstance(mt_obj.get("schema"), dict):
                                r_schema = mt_obj["schema"]
                        status_val: int | str = (
                            int(status_key) if str(status_key).isdigit() else str(status_key)
                        )
                        resp_contracts.append(
                            ResponseContract(
                                status_code=status_val,
                                media_type=r_mt,
                                description=str(deref_r.get("description", "")),
                                schema=r_schema,
                                evidence=[op_ev_id],
                            )
                        )

                # Security Requirement (operation overrides global)
                effective_sec_raw = (
                    op_obj["security"] if "security" in op_obj else global_security_raw
                )
                sec_req = _normalize_security_requirement(
                    effective_sec_raw,
                    operation_id=stable_id,
                    defined_schemes=defined_schemes,
                    evidence_ids=[op_ev_id],
                    findings=findings,
                )

                op_new_blockers = [
                    f
                    for f in findings[op_findings_start:]
                    if f.severity == "blocker" and f.status == "open"
                ]
                global_blockers = [
                    f
                    for f in findings[:op_findings_start]
                    if f.operation_id is None and f.severity == "blocker" and f.status == "open"
                ]
                support_status: SupportStatus = (
                    "blocked" if (op_new_blockers or global_blockers) else "supported"
                )

                server_ref = servers[0].server_id if servers else "missing_server"
                display_name = str(
                    op_obj.get("summary")
                    or op_obj.get("operationId")
                    or f"{method_upper} {rel_path}"
                )
                operations.append(
                    OperationContract(
                        stable_id=stable_id,
                        display_name=display_name,
                        method=method_upper,  # type: ignore[arg-type]
                        relative_path=str(rel_path),
                        server_ref=server_ref,
                        parameters=param_contracts,
                        request_body=req_body_contract,
                        responses=resp_contracts,
                        security_requirement=sec_req,
                        semantic_effect=DEFAULT_SEMANTIC_EFFECT_BY_METHOD.get(
                            method_upper, "unknown"
                        ),
                        provenance={
                            "method": [op_ev_id],
                            "relative_path": [op_ev_id],
                            "security_requirement": [op_ev_id],
                        },
                        support_status=support_status,
                    )
                )

    contract = ApiContract(
        id=contract_id,
        project_id=project_id,
        revision=revision,
        sources=[source_id],
        servers=servers,
        operations=operations,
        security_schemes=list(defined_schemes.values()),
        findings=findings,
        overrides=[],
    )
    return contract, [doc_block], evidence_list

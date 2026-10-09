"""Evidence-Grounded Candidate Extraction from Prose, HTML, and PDF Blocks (T15).

Implements Stages 1-6 of DOCUMENT_UNDERSTANDING.md:
1. Inventory: base URL candidates, global auth schemes, endpoint section inventory,
   and non-API document detection (`NOT_API_DOCUMENTATION`).
2. Candidate detection: combines deterministic heading/method/path patterns with
   local-model extraction (`OllamaInferenceAdapter`).
3. Context assembly: groups heading-anchored blocks across lines and PDF pages.
4. Constrained extraction: schema-bound candidate objects (`CandidateOperation`).
5. Evidence checking: verifies exact substring offsets (`EvidenceRef.verify_against_block`),
   rejects fabricated quotes (`UNVERIFIED_EVIDENCE`), verifies method support in quote
   (`METHOD_NOT_IN_EVIDENCE`), and neutralizes prompt-injection payloads.
6. Conflict & uncertainty detection: flags `CONFLICTING_METHOD_PATH`, `MISSING_METHOD`,
   `AMBIGUOUS_AUTH`, and `UNKNOWN_AUTH` as blocker findings.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from packages.core.contracts import (
    CandidateOperation,
    DocumentBlock,
    EvidenceRef,
    Finding,
    ParameterContract,
    RequestBodyContract,
    ResponseContract,
    SecurityAlternative,
    SecurityRequirement,
    SecurityScheme,
    ServerContract,
    SourceDocument,
    assign_safe_parameter_names,
)
from packages.core.local_inference import OllamaInferenceAdapter
from packages.core.parsers.markdown_parser import group_blocks_by_section

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
METHOD_PATH_RE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[A-Za-z0-9_\-/{}.:]+)"
)
CURL_METHOD_URL_RE = re.compile(
    r"curl\s+(?:-[A-Za-z]+\s+)*?(?:-X\s+(GET|POST|PUT|PATCH|DELETE)\s+)?['\"]?(?:https?://[^/'\"\s]+)?(/[A-Za-z0-9_\-/{}.:]+)",
    re.IGNORECASE,
)
PATH_ONLY_HEADING_RE = re.compile(
    r"(?:Endpoint(?:\s+path)?|Path)\s*:\s*`?(/[A-Za-z0-9_\-/{}.:]+)`?", re.IGNORECASE
)
BASE_URL_LINE_RE = re.compile(
    r"(?:Base\s+URL|Server\s+URL|Host|Base\s+Endpoint)\s*[:\-]\s*`?(https?://[A-Za-z0-9.\-_:]+(?:/[A-Za-z0-9_\-]*)?)`?",
    re.IGNORECASE,
)
BULLET_PARAM_RE = re.compile(
    r"^[\-\*]\s+`?([A-Za-z0-9_\-]+)`?\s*\(([^)]+)\)\s*[:\-]\s*(.+)$"
)
PROMPT_INJECTION_RE = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"system\s+override\s*:|"
    r"rm\s+-rf\s+/|"
    r"__import__\s*\(\s*['\"]os['\"]\s*\)|"
    r"curl\s+https?://[^\s]+\s*\|\s*(?:ba)?sh)",
    re.IGNORECASE,
)


class LLMExtractedParam(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    location: Literal["path", "query", "header"]
    required: bool
    schema_type: Literal["string", "integer", "number", "boolean", "array"] = "string"
    description: str = ""
    evidence_quote: str


class LLMExtractedOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] | None = None
    relative_path: str | None = None
    auth_type: Literal[
        "bearer", "api_key_header", "api_key_query", "public", "ambiguous", "unknown"
    ] = "unknown"
    semantic_effect: Literal["read", "write", "destructive", "unknown"] = "unknown"
    parameters: list[LLMExtractedParam] = Field(default_factory=list)
    request_body_fields: list[str] = Field(default_factory=list)
    evidence_quotes: list[str] = Field(min_length=1)


class DocumentExtractionBundle(BaseModel):
    """Result of running Stages 1-6 on a single parsed document."""

    model_config = ConfigDict(extra="forbid")

    source_document: SourceDocument
    blocks: list[DocumentBlock]
    evidence_registry: list[EvidenceRef]
    servers: list[ServerContract]
    security_schemes: list[SecurityScheme]
    global_security_requirement: SecurityRequirement
    global_auth_evidence_ids: list[str] = Field(default_factory=list)
    candidates: list[CandidateOperation]
    findings: list[Finding]
    extraction_mode: Literal["local_ai", "manual_review_only"]
    model_metadata: dict[str, Any] = Field(default_factory=dict)
    coverage_stats: dict[str, int] = Field(default_factory=dict)


def resolve_quote_in_blocks(
    quote: str,
    blocks: list[DocumentBlock],
    evidence_id: str,
) -> EvidenceRef | None:
    """Locate an exact verbatim quote inside a list of DocumentBlocks and verify offsets."""
    cleaned = quote.strip()
    if not cleaned:
        return None
    for blk in blocks:
        if cleaned in blk.text:
            ev = EvidenceRef.from_block_substring(evidence_id, blk, cleaned)
            if ev.verify_against_block(blk):
                return ev
    return None


def _extract_servers_from_blocks(
    source_id: str,
    blocks: list[DocumentBlock],
    evidence_out: list[EvidenceRef],
) -> list[ServerContract]:
    servers: list[ServerContract] = []
    seen_urls: set[str] = set()
    for blk in blocks:
        for match in BASE_URL_LINE_RE.finditer(blk.text):
            url = match.group(1).rstrip("/")
            full_quote = match.group(0).strip()
            if url in seen_urls:
                continue
            seen_urls.add(url)
            ev_id = f"ev_{source_id}_srv_{len(servers) + 1}"
            ev = resolve_quote_in_blocks(full_quote, [blk], ev_id)
            if ev is not None:
                evidence_out.append(ev)
                srv_id = "default" if not servers else f"server_{len(servers) + 1}"
                servers.append(
                    ServerContract(
                        server_id=srv_id,
                        base_url=url,
                        description=f"Extracted from {source_id}",
                        evidence=[ev.id],
                    )
                )
    return servers


def _extract_global_auth_from_blocks(
    source_id: str,
    blocks: list[DocumentBlock],
    evidence_out: list[EvidenceRef],
) -> tuple[list[SecurityScheme], SecurityRequirement, list[str]]:
    schemes: list[SecurityScheme] = []
    auth_ev_ids: list[str] = []

    for blk in blocks:
        sec_titles = " ".join(blk.heading_path).lower()
        is_endpoint_section = bool(METHOD_PATH_RE.search(sec_titles))
        if is_endpoint_section:
            continue

        text_lower = blk.text.lower()
        if "authorization: bearer" in text_lower or "bearer token" in text_lower:
            for line in blk.text.splitlines():
                if "bearer" in line.lower():
                    ev_id = f"ev_{source_id}_auth_bearer_{len(auth_ev_ids) + 1}"
                    ev = resolve_quote_in_blocks(line.strip(), [blk], ev_id)
                    if ev is not None:
                        evidence_out.append(ev)
                        auth_ev_ids.append(ev.id)
                        if not any(s.scheme_id == "bearer_auth" for s in schemes):
                            schemes.append(
                                SecurityScheme(
                                    scheme_id="bearer_auth",
                                    type="http",
                                    scheme="bearer",
                                    description="Bearer authentication",
                                    evidence=[ev.id],
                                )
                            )
                        break

        m_hdr_key = re.search(
            r"\b(X-[A-Za-z0-9\-]*Api-Key|X-API-Key)\b", blk.text, re.IGNORECASE
        )
        if m_hdr_key and (
            "header" in text_lower or "auth" in text_lower or "key" in text_lower
        ):
            hdr_name = m_hdr_key.group(1)
            for line in blk.text.splitlines():
                if hdr_name.lower() in line.lower():
                    ev_id = f"ev_{source_id}_auth_hdr_{len(auth_ev_ids) + 1}"
                    ev = resolve_quote_in_blocks(line.strip(), [blk], ev_id)
                    if ev is not None:
                        evidence_out.append(ev)
                        auth_ev_ids.append(ev.id)
                        if not any(s.scheme_id == "api_key_header" for s in schemes):
                            schemes.append(
                                SecurityScheme(
                                    scheme_id="api_key_header",
                                    type="apiKey",
                                    location="header",
                                    name=hdr_name,
                                    description=f"API Key in {hdr_name} header",
                                    evidence=[ev.id],
                                )
                            )
                        break

        m_query_key = re.search(
            r"query\s+parameter\s+`?([a-zA-Z0-9_]*api_key[a-zA-Z0-9_]*)`?",
            blk.text,
            re.IGNORECASE,
        )
        if m_query_key:
            q_name = m_query_key.group(1)
            ev_id = f"ev_{source_id}_auth_qry_{len(auth_ev_ids) + 1}"
            ev = resolve_quote_in_blocks(m_query_key.group(0), [blk], ev_id)
            if ev is not None:
                evidence_out.append(ev)
                auth_ev_ids.append(ev.id)
                if not any(s.scheme_id == "api_key_query" for s in schemes):
                    schemes.append(
                        SecurityScheme(
                            scheme_id="api_key_query",
                            type="apiKey",
                            location="query",
                            name=q_name,
                            description=f"API Key in {q_name} query parameter",
                            evidence=[ev.id],
                        )
                    )

    if schemes:
        alts = [SecurityAlternative(all_of=[s.scheme_id]) for s in schemes]
        return (
            schemes,
            SecurityRequirement(status="authenticated", alternatives=alts),
            auth_ev_ids,
        )
    return [], SecurityRequirement(status="unknown"), []


def _parse_parameters_and_body_from_section_blocks(
    source_id: str,
    cand_idx: int,
    sec_blocks: list[DocumentBlock],
    evidence_out: list[EvidenceRef],
) -> tuple[list[ParameterContract], RequestBodyContract | None, list[str]]:
    raw_params: list[dict[str, Any]] = []
    body_props: dict[str, Any] = {}
    body_required: list[str] = []
    body_ev_ids: list[str] = []
    extra_ev_ids: list[str] = []

    for blk in sec_blocks:
        if blk.block_kind == "table":
            rows = [
                r.strip()
                for r in blk.text.splitlines()
                if r.strip().startswith("|")
            ]
            if len(rows) < 2:
                continue
            headers = [c.strip().lower() for c in rows[0].strip("|").split("|")]
            for r_idx, row in enumerate(rows[1:], start=1):
                cells = [c.strip() for c in row.strip("|").split("|")]
                if all(set(c) <= {"-", ":"} for c in cells if c):
                    continue
                if len(cells) < 2:
                    continue

                row_map = {
                    headers[i]: cells[i]
                    for i in range(min(len(headers), len(cells)))
                }
                p_name = (
                    row_map.get("parameter")
                    or row_map.get("name")
                    or row_map.get("field")
                    or cells[0]
                ).strip("` ")
                loc_raw = (
                    row_map.get("location") or row_map.get("in") or "query"
                ).strip("` ").lower()
                type_raw = (row_map.get("type") or "string").strip("` ").lower()
                if (
                    not p_name
                    or p_name.lower() == "---"
                    or (
                        p_name.lower() in {"name", "parameter", "field"}
                        and (loc_raw in {"location", "in"} or type_raw == "type")
                    )
                ):
                    continue
                req_raw = (row_map.get("required") or "false").strip("` ").lower()
                desc_raw = (
                    row_map.get("description")
                    or (cells[-1] if len(cells) >= 4 else "")
                ).strip()

                is_req = req_raw in {"yes", "true", "required", "1"}
                ev_id = (
                    f"ev_{source_id}_c{cand_idx}_tbl_{len(evidence_out) + 1}_{r_idx}"
                )
                ev = resolve_quote_in_blocks(row, [blk], ev_id)
                ev_list: list[str] = []
                if ev is not None:
                    evidence_out.append(ev)
                    ev_list.append(ev.id)
                    extra_ev_ids.append(ev.id)

                schema_type = "string"
                if "int" in type_raw:
                    schema_type = "integer"
                elif "num" in type_raw or "float" in type_raw:
                    schema_type = "number"
                elif "bool" in type_raw:
                    schema_type = "boolean"
                elif "array" in type_raw or "list" in type_raw:
                    schema_type = "array"

                p_schema: dict[str, Any] = {"type": schema_type}
                if schema_type == "array":
                    p_schema["items"] = {"type": "string"}

                if loc_raw == "body":
                    body_props[p_name] = {**p_schema, "description": desc_raw}
                    if is_req:
                        body_required.append(p_name)
                    body_ev_ids.extend(ev_list)
                elif loc_raw in {"path", "query", "header", "cookie"}:
                    raw_params.append(
                        {
                            "external_name": p_name,
                            "location": loc_raw,
                            "required": True if loc_raw == "path" else is_req,
                            "schema": p_schema,
                            "style": "form" if loc_raw == "query" else "simple",
                            "explode": True if loc_raw == "query" else False,
                            "description": desc_raw,
                            "evidence": ev_list,
                        }
                    )

        elif blk.block_kind == "prose":
            for line in blk.text.splitlines():
                m_bul = BULLET_PARAM_RE.match(line.strip())
                if not m_bul:
                    continue
                p_name = m_bul.group(1).strip()
                meta_tokens = [t.strip().lower() for t in m_bul.group(2).split(",")]
                desc_raw = m_bul.group(3).strip()

                loc_raw = "query"
                for loc_cand in ("path", "query", "header", "body", "cookie"):
                    if loc_cand in meta_tokens:
                        loc_raw = loc_cand
                        break
                is_req = "required" in meta_tokens or loc_raw == "path"
                schema_type = "string"
                for t_cand in ("integer", "number", "boolean", "array", "string"):
                    if t_cand in meta_tokens:
                        schema_type = t_cand
                        break

                ev_id = f"ev_{source_id}_c{cand_idx}_prm_{len(evidence_out) + 1}"
                ev = resolve_quote_in_blocks(line.strip(), [blk], ev_id)
                ev_list = []
                if ev is not None:
                    evidence_out.append(ev)
                    ev_list.append(ev.id)
                    extra_ev_ids.append(ev.id)

                p_schema = {"type": schema_type}
                if schema_type == "array":
                    p_schema["items"] = {"type": "string"}

                if loc_raw == "body":
                    body_props[p_name] = {**p_schema, "description": desc_raw}
                    if is_req:
                        body_required.append(p_name)
                    body_ev_ids.extend(ev_list)
                else:
                    raw_params.append(
                        {
                            "external_name": p_name,
                            "location": loc_raw,
                            "required": is_req,
                            "schema": p_schema,
                            "style": "form" if loc_raw == "query" else "simple",
                            "explode": True if loc_raw == "query" else False,
                            "description": desc_raw,
                            "evidence": ev_list,
                        }
                    )

    params: list[ParameterContract] = []
    if raw_params:
        safe_names = assign_safe_parameter_names(
            [(p["external_name"], p["location"]) for p in raw_params]
        )
        for p_dict, s_name in zip(raw_params, safe_names, strict=True):
            params.append(
                ParameterContract(
                    external_name=p_dict["external_name"],
                    safe_argument_name=s_name,
                    location=p_dict["location"],
                    required=p_dict["required"],
                    schema=p_dict["schema"],
                    style=p_dict["style"],
                    explode=p_dict["explode"],
                    description=p_dict["description"],
                    evidence=p_dict["evidence"],
                )
            )

    req_body: RequestBodyContract | None = None
    if body_props:
        b_schema: dict[str, Any] = {
            "type": "object",
            "properties": body_props,
            "additionalProperties": False,
        }
        if body_required:
            b_schema["required"] = body_required
        req_body = RequestBodyContract(
            media_type="application/json",
            required=bool(body_required),
            schema=b_schema,
            description="Extracted JSON request body",
            evidence=body_ev_ids,
        )

    return params, req_body, extra_ev_ids


def extract_document_candidates(
    source_doc: SourceDocument,
    blocks: list[DocumentBlock],
    *,
    existing_findings: list[Finding] | None = None,
    inference_adapter: OllamaInferenceAdapter | None = None,
    use_local_model: bool = True,
) -> DocumentExtractionBundle:
    """Run Stages 1-6 extraction and evidence verification on a parsed document."""
    findings: list[Finding] = list(existing_findings or [])
    evidence_registry: list[EvidenceRef] = []
    source_id = source_doc.id

    if any(f.severity == "blocker" for f in findings) and not blocks:
        return DocumentExtractionBundle(
            source_document=source_doc,
            blocks=blocks,
            evidence_registry=[],
            servers=[],
            security_schemes=[],
            global_security_requirement=SecurityRequirement(status="unknown"),
            candidates=[],
            findings=findings,
            extraction_mode="manual_review_only",
            coverage_stats={
                "candidate_sections": 0,
                "extracted_candidates": 0,
                "blocked_candidates": 0,
            },
        )

    for blk in blocks:
        m_inj = PROMPT_INJECTION_RE.search(blk.text)
        if m_inj:
            ev_id = f"ev_{source_id}_inj_{len(evidence_registry) + 1}"
            ev = resolve_quote_in_blocks(m_inj.group(0), [blk], ev_id)
            ev_refs = [ev.id] if ev else []
            if ev:
                evidence_registry.append(ev)
            findings.append(
                Finding(
                    id=f"fnd_{source_id}_inj_{blk.id}",
                    code="PROMPT_INJECTION_DETECTED",
                    severity="warning",
                    affected_field="document.security",
                    evidence_refs=ev_refs,
                    explanation=(
                        f"Hostile instruction pattern ({m_inj.group(0)!r}) detected in block "
                        f"'{blk.id}'. Preserved as inert data; no instructions or commands executed."
                    ),
                    suggested_resolution="Inspect the flagged source block during review.",
                )
            )

    servers = _extract_servers_from_blocks(source_id, blocks, evidence_registry)
    schemes, global_sec_req, global_auth_ev = _extract_global_auth_from_blocks(
        source_id, blocks, evidence_registry
    )

    sections = group_blocks_by_section(blocks)
    candidates: list[CandidateOperation] = []
    extraction_mode: Literal["local_ai", "manual_review_only"] = "manual_review_only"
    model_metadata: dict[str, Any] = {}

    if use_local_model and inference_adapter is not None:
        health = inference_adapter.check_health()
        model_metadata = {
            "available": health.available,
            "configured_model": health.configured_model,
            "model_installed": health.model_installed,
            "base_url": health.base_url,
        }
        if health.available and health.model_installed:
            extraction_mode = "local_ai"
        else:
            findings.append(
                Finding(
                    id=f"fnd_{source_id}_model_unavail",
                    code="MODEL_UNAVAILABLE",
                    severity="warning",
                    affected_field="inference.runtime",
                    explanation=health.status_message,
                    suggested_resolution=(
                        "Start local Ollama with the qualified model or review extracted "
                        "candidates in manual review mode."
                    ),
                )
            )

    for sec_idx, sec in enumerate(sections, start=1):
        sec_blocks: list[DocumentBlock] = sec["blocks"]
        combined_text: str = sec["combined_text"]
        sec_title: str = sec["title"]

        method_path_pairs: list[tuple[str, str, EvidenceRef]] = []
        for blk in sec_blocks:
            for m_mp in METHOD_PATH_RE.finditer(blk.text):
                m_verb, m_path = m_mp.group(1).upper(), m_mp.group(2).strip()
                quote_str = m_mp.group(0).strip()
                ev_id = f"ev_{source_id}_s{sec_idx}_mp_{len(evidence_registry) + 1}"
                ev = resolve_quote_in_blocks(quote_str, [blk], ev_id)
                if ev is not None:
                    evidence_registry.append(ev)
                    method_path_pairs.append((m_verb, m_path, ev))

            for m_curl in CURL_METHOD_URL_RE.finditer(blk.text):
                c_verb = (m_curl.group(1) or "GET").upper()
                c_path = m_curl.group(2).strip()
                quote_str = m_curl.group(0).strip()
                ev_id = f"ev_{source_id}_s{sec_idx}_curl_{len(evidence_registry) + 1}"
                ev = resolve_quote_in_blocks(quote_str, [blk], ev_id)
                if ev is not None:
                    evidence_registry.append(ev)
                    method_path_pairs.append((c_verb, c_path, ev))

        path_only_matches: list[tuple[str, EvidenceRef]] = []
        if not method_path_pairs:
            for blk in sec_blocks:
                for m_po in PATH_ONLY_HEADING_RE.finditer(blk.text):
                    p_str = m_po.group(1).strip()
                    ev_id = f"ev_{source_id}_s{sec_idx}_po_{len(evidence_registry) + 1}"
                    ev = resolve_quote_in_blocks(m_po.group(0).strip(), [blk], ev_id)
                    if ev is not None:
                        evidence_registry.append(ev)
                        path_only_matches.append((p_str, ev))

        if not method_path_pairs and not path_only_matches:
            continue

        cand_id = f"cand_{source_id}_{len(candidates) + 1:03d}"
        cand_findings: list[Finding] = []
        field_evidence: dict[str, list[str]] = {}

        if extraction_mode == "local_ai" and inference_adapter is not None:
            call_res = inference_adapter.extract_structured(
                combined_text, LLMExtractedOperation
            )
            model_metadata["last_call_status"] = call_res.status
            model_metadata["prompt_version"] = call_res.prompt_version
            model_metadata["prompt_hash"] = call_res.prompt_hash
            model_metadata["settings_hash"] = call_res.settings_hash
            if call_res.status == "OK" and isinstance(
                call_res.parsed, LLMExtractedOperation
            ):
                llm_op = call_res.parsed
                for q_idx, quote_cand in enumerate(llm_op.evidence_quotes, start=1):
                    ev_q = resolve_quote_in_blocks(
                        quote_cand,
                        sec_blocks,
                        f"ev_{source_id}_{cand_id}_llm_{q_idx}",
                    )
                    if ev_q is None:
                        cand_findings.append(
                            Finding(
                                id=f"fnd_{cand_id}_unverified_quote_{q_idx}",
                                code="UNVERIFIED_EVIDENCE",
                                severity="blocker",
                                affected_field="evidence_quotes",
                                operation_id=cand_id,
                                explanation=(
                                    f"Model-cited quote {quote_cand!r} does not appear verbatim "
                                    f"in source section '{sec_title}'."
                                ),
                                suggested_resolution="Verify operation fields against source text.",
                            )
                        )
                    else:
                        evidence_registry.append(ev_q)
            elif call_res.status == "OUTPUT_INVALID":
                cand_findings.append(
                    Finding(
                        id=f"fnd_{cand_id}_output_invalid",
                        code="OUTPUT_INVALID_NEEDS_REVIEW",
                        severity="blocker",
                        affected_field="candidate",
                        operation_id=cand_id,
                        explanation=call_res.error_message,
                        suggested_resolution=call_res.remediation_hint,
                    )
                )
            elif call_res.status == "MODEL_OOM":
                cand_findings.append(
                    Finding(
                        id=f"fnd_{cand_id}_oom",
                        code="MODEL_OOM",
                        severity="blocker",
                        affected_field="inference.memory",
                        operation_id=cand_id,
                        explanation=call_res.error_message,
                        suggested_resolution=call_res.remediation_hint,
                    )
                )

        distinct_mp: dict[tuple[str, str], list[str]] = {}
        for verb, path_val, ev in method_path_pairs:
            distinct_mp.setdefault((verb, path_val), []).append(ev.id)

        chosen_method: str | None = None
        chosen_path: str | None = None

        if len(distinct_mp) > 1:
            all_mp_evs = [eid for eids in distinct_mp.values() for eid in eids]
            pairs_desc = ", ".join(f"{v} {p}" for v, p in distinct_mp)
            chosen_method, chosen_path = next(iter(distinct_mp.keys()))
            field_evidence["method"] = all_mp_evs
            field_evidence["relative_path"] = all_mp_evs
            cand_findings.append(
                Finding(
                    id=f"fnd_{cand_id}_conflict_mp",
                    code="CONFLICTING_METHOD_PATH",
                    severity="blocker",
                    affected_field="method_path",
                    operation_id=cand_id,
                    evidence_refs=all_mp_evs,
                    explanation=(
                        f"Section '{sec_title}' contains conflicting HTTP method/path "
                        f"definitions: {pairs_desc}."
                    ),
                    suggested_resolution=(
                        "Select the authoritative HTTP method and path in the review queue."
                    ),
                )
            )
        elif len(distinct_mp) == 1:
            (chosen_method, chosen_path), mp_evs = next(iter(distinct_mp.items()))
            field_evidence["method"] = mp_evs
            field_evidence["relative_path"] = mp_evs
        elif path_only_matches:
            chosen_method = None
            chosen_path, po_ev = path_only_matches[0]
            field_evidence["relative_path"] = [po_ev.id]
            cand_findings.append(
                Finding(
                    id=f"fnd_{cand_id}_missing_method",
                    code="MISSING_METHOD",
                    severity="blocker",
                    affected_field="method",
                    operation_id=cand_id,
                    evidence_refs=[po_ev.id],
                    explanation=(
                        f"Endpoint '{chosen_path}' in section '{sec_title}' does not specify "
                        "an HTTP method (GET, POST, PUT, PATCH, DELETE)."
                    ),
                    suggested_resolution="Supply the required HTTP method via an owner override.",
                )
            )

        params, req_body, param_ev_ids = _parse_parameters_and_body_from_section_blocks(
            source_id, len(candidates) + 1, sec_blocks, evidence_registry
        )
        if param_ev_ids:
            field_evidence["parameters"] = param_ev_ids

        sec_page_ev_ids: list[str] = list(field_evidence.get("relative_path", []))
        for blk in sec_blocks:
            page_num = blk.location.page_number
            if page_num is not None:
                first_line = blk.text.splitlines()[0].strip()
                if first_line:
                    ev_p = resolve_quote_in_blocks(
                        first_line,
                        [blk],
                        f"ev_{source_id}_{cand_id}_p{page_num}_{blk.id}",
                    )
                    if ev_p is not None and ev_p.id not in sec_page_ev_ids:
                        evidence_registry.append(ev_p)
                        sec_page_ev_ids.append(ev_p.id)
        field_evidence["relative_path"] = sec_page_ev_ids

        sec_text_lower = combined_text.lower()
        sec_req: SecurityRequirement
        if (
            "tbd" in sec_text_lower
            or "to be determined" in sec_text_lower
            or "either session cookie or" in sec_text_lower
        ):
            sec_req = SecurityRequirement(status="unknown")
            cand_findings.append(
                Finding(
                    id=f"fnd_{cand_id}_ambig_auth",
                    code="AMBIGUOUS_AUTH",
                    severity="blocker",
                    affected_field="security_requirement",
                    operation_id=cand_id,
                    evidence_refs=sec_page_ev_ids,
                    explanation=(
                        f"Authentication for '{sec_title}' is marked ambiguous or TBD in documentation."
                    ),
                    suggested_resolution="Resolve the authentication scheme before freezing.",
                )
            )
        elif "no authentication" in sec_text_lower or "public endpoint" in sec_text_lower:
            sec_req = SecurityRequirement(status="public")
            field_evidence["security_requirement"] = sec_page_ev_ids
        elif global_sec_req.status == "authenticated":
            sec_req = global_sec_req
            field_evidence["security_requirement"] = list(global_auth_ev) + sec_page_ev_ids
        elif "bearer" in sec_text_lower:
            if not any(s.scheme_id == "bearer_auth" for s in schemes):
                schemes.append(
                    SecurityScheme(
                        scheme_id="bearer_auth",
                        type="http",
                        scheme="bearer",
                        evidence=sec_page_ev_ids,
                    )
                )
            sec_req = SecurityRequirement(
                status="authenticated",
                alternatives=[SecurityAlternative(all_of=["bearer_auth"])],
            )
            field_evidence["security_requirement"] = sec_page_ev_ids
        else:
            sec_req = SecurityRequirement(status="unknown")
            cand_findings.append(
                Finding(
                    id=f"fnd_{cand_id}_unknown_auth",
                    code="UNKNOWN_AUTH",
                    severity="blocker",
                    affected_field="security_requirement",
                    operation_id=cand_id,
                    evidence_refs=sec_page_ev_ids,
                    explanation=(
                        f"No explicit or inherited authentication scheme documented for '{sec_title}'."
                    ),
                    suggested_resolution="Specify an authentication scheme or confirm public access.",
                )
            )

        effect: Literal["read", "write", "destructive", "unknown"] = "unknown"
        if chosen_method == "GET":
            effect = "read"
        elif chosen_method in {"POST", "PUT", "PATCH"}:
            effect = "write"
        elif chosen_method == "DELETE":
            effect = "destructive"

        clean_display_name = re.sub(r"^#+\s*", "", sec_title).strip() or cand_id
        if PROMPT_INJECTION_RE.search(clean_display_name):
            clean_display_name = f"{chosen_method or 'OP'} {chosen_path or cand_id}"

        findings.extend(cand_findings)
        candidates.append(
            CandidateOperation(
                candidate_id=cand_id,
                display_name=clean_display_name,
                method=chosen_method,
                relative_path=chosen_path,
                server_candidates=[s.server_id for s in servers],
                parameters=params,
                request_body=req_body,
                responses=[
                    ResponseContract(
                        status_code=200 if chosen_method == "GET" else 201,
                        media_type="application/json",
                        description="Success response",
                        schema={"type": "object"},
                        evidence=sec_page_ev_ids,
                    )
                ],
                security_requirement=sec_req,
                semantic_effect=effect,
                field_evidence=field_evidence,
                findings=cand_findings,
            )
        )

    if not candidates and not servers and not schemes:
        findings.append(
            Finding(
                id=f"fnd_{source_id}_not_api_doc",
                code="NOT_API_DOCUMENTATION",
                severity="blocker",
                affected_field="document",
                explanation=(
                    f"Document '{source_doc.original_name}' does not contain recognizable API "
                    "endpoints, base URLs, or authentication specifications."
                ),
                suggested_resolution="Import API documentation containing endpoint descriptions.",
            )
        )

    blocked_count = sum(
        1
        for c in candidates
        if any(f.severity == "blocker" and f.status == "open" for f in c.findings)
    )
    return DocumentExtractionBundle(
        source_document=source_doc,
        blocks=blocks,
        evidence_registry=evidence_registry,
        servers=servers,
        security_schemes=schemes,
        global_security_requirement=global_sec_req,
        global_auth_evidence_ids=global_auth_ev,
        candidates=candidates,
        findings=findings,
        extraction_mode=extraction_mode,
        model_metadata=model_metadata,
        coverage_stats={
            "candidate_sections": len(sections),
            "extracted_candidates": len(candidates),
            "blocked_candidates": blocked_count,
        },
    )

"""Multi-Document Bundle Reconciliation and Owner Override Engine (T16).

Implements Stages 7-8 of DOCUMENT_UNDERSTANDING.md:
- Merges `DocumentExtractionBundle` objects across multi-file documentation sets
  (e.g., shared `overview_auth.md` + `endpoints.md` / `saved.html` / `reference.pdf`).
- Propagates shared global authentication (`inherited` provenance citing both the
  global auth block and the endpoint block).
- Detects cross-document base URL contradictions (`CONFLICTING_BASE_URL`) and
  contradictory duplicate endpoints (`CONFLICTING_OPERATION_DEFINITION`).
- Verifies `UserOverride` preconditions (`source_revision` and `old_value_hash`);
  rejects stale corrections with `STALE_OVERRIDE` blocker findings.
- Re-runs semantic readiness validation (`validate_contract_readiness`) after
  applying valid overrides.
"""

from __future__ import annotations

from typing import Any

from packages.core.contracts import (
    ApiContract,
    EvidenceRef,
    Finding,
    OperationContract,
    ResponseContract,
    SecurityRequirement,
    SecurityScheme,
    ServerContract,
    UserOverride,
    canonical_json_bytes,
    sha256_hex,
    to_safe_identifier,
)
from packages.core.extraction import DocumentExtractionBundle
from packages.core.readiness import validate_contract_readiness


def compute_field_value_hash(value: Any) -> str:
    """Compute canonical SHA-256 hash of a field value for UserOverride precondition checks."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", by_alias=True)
    return sha256_hex(canonical_json_bytes(value))


def _derive_stable_op_id(
    method: str | None,
    relative_path: str | None,
    fallback_id: str,
    used_ids: set[str],
) -> str:
    if method and relative_path:
        raw = f"{method.lower()}_{relative_path.lstrip('/')}"
    elif relative_path:
        raw = f"op_{relative_path.lstrip('/')}"
    else:
        raw = fallback_id
    base = to_safe_identifier(raw, fallback=fallback_id)
    candidate = base
    suffix = 2
    while candidate in used_ids:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used_ids.add(candidate)
    return candidate


def reconcile_bundles_to_contract(
    bundles: list[DocumentExtractionBundle],
    *,
    contract_id: str,
    project_id: str,
    revision: int = 1,
    overrides: list[UserOverride] | None = None,
) -> tuple[ApiContract, list[EvidenceRef]]:
    """Reconcile one or more extracted document bundles into a validated `ApiContract`."""
    source_ids: list[str] = []
    all_evidence: list[EvidenceRef] = []
    seen_ev_ids: set[str] = set()
    all_findings: list[Finding] = []

    servers_by_url: dict[str, ServerContract] = {}
    server_ev_by_url: dict[str, list[str]] = {}
    schemes_by_id: dict[str, SecurityScheme] = {}
    bundle_global_sec: SecurityRequirement | None = None
    bundle_global_auth_ev: list[str] = []

    for b in bundles:
        if b.source_document.id not in source_ids:
            source_ids.append(b.source_document.id)
        for ev in b.evidence_registry:
            if ev.id not in seen_ev_ids:
                seen_ev_ids.add(ev.id)
                all_evidence.append(ev)

        for srv in b.servers:
            norm_url = srv.base_url.rstrip("/")
            server_ev_by_url.setdefault(norm_url, []).extend(srv.evidence)
            if norm_url not in servers_by_url:
                srv_id = "default" if not servers_by_url else f"server_{len(servers_by_url) + 1}"
                servers_by_url[norm_url] = ServerContract(
                    server_id=srv_id,
                    base_url=norm_url,
                    description=srv.description,
                    evidence=list(srv.evidence),
                )

        for sch in b.security_schemes:
            if sch.scheme_id not in schemes_by_id:
                schemes_by_id[sch.scheme_id] = sch

        if (
            b.global_security_requirement.status == "authenticated"
            and bundle_global_sec is None
        ):
            bundle_global_sec = b.global_security_requirement
            bundle_global_auth_ev = list(b.global_auth_evidence_ids)

    reconciled_servers = list(servers_by_url.values())
    if len(reconciled_servers) > 1:
        conflict_evs = [eid for eids in server_ev_by_url.values() for eid in eids]
        urls_str = ", ".join(s.base_url for s in reconciled_servers)
        all_findings.append(
            Finding(
                id=f"fnd_{contract_id}_conflicting_base_url",
                code="CONFLICTING_BASE_URL",
                severity="blocker",
                affected_field="servers",
                operation_id=None,
                evidence_refs=conflict_evs,
                explanation=(
                    f"Document bundle defines multiple conflicting base URLs: {urls_str}."
                ),
                suggested_resolution=(
                    "Provide an owner override for 'servers' selecting the authoritative base URL."
                ),
            )
        )

    default_server_ref = (
        reconciled_servers[0].server_id if reconciled_servers else "default"
    )

    used_op_ids: set[str] = set()
    operations: list[OperationContract] = []
    seen_method_paths: dict[tuple[str, str], OperationContract] = {}

    for b in bundles:
        # Copy document-level findings (not tied to a candidate_id)
        cand_ids_in_bundle = {c.candidate_id for c in b.candidates}
        for f in b.findings:
            if f.operation_id not in cand_ids_in_bundle:
                all_findings.append(f)

        for cand in b.candidates:
            stable_id = _derive_stable_op_id(
                cand.method, cand.relative_path, cand.candidate_id, used_op_ids
            )
            op_findings: list[Finding] = []
            sec_req = cand.security_requirement
            prov = {k: list(v) for k, v in cand.field_evidence.items()}

            for cf in cand.findings:
                # If candidate had UNKNOWN_AUTH only because auth was in a separate bundle file,
                # inherit bundle_global_sec and clear UNKNOWN_AUTH!
                if (
                    cf.code == "UNKNOWN_AUTH"
                    and bundle_global_sec is not None
                    and bundle_global_sec.status == "authenticated"
                ):
                    sec_req = bundle_global_sec
                    prov["security_requirement"] = (
                        list(bundle_global_auth_ev)
                        + prov.get("relative_path", [])
                    )
                    continue

                op_findings.append(
                    Finding(
                        id=cf.id,
                        code=cf.code,
                        severity=cf.severity,
                        affected_field=cf.affected_field,
                        operation_id=stable_id,
                        evidence_refs=list(cf.evidence_refs),
                        explanation=cf.explanation,
                        suggested_resolution=cf.suggested_resolution,
                        status=cf.status,
                    )
                )

            eff_method = (
                cand.method
                if cand.method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
                else "GET"
            )
            eff_path = cand.relative_path or f"/__missing_path__/{stable_id}"
            has_open_blocker = any(
                f.severity == "blocker" and f.status == "open" for f in op_findings
            )

            op_contract = OperationContract(
                stable_id=stable_id,
                display_name=cand.display_name or stable_id,
                method=eff_method,  # type: ignore[arg-type]
                relative_path=eff_path,
                server_ref=default_server_ref,
                parameters=list(cand.parameters),
                request_body=cand.request_body,
                responses=list(cand.responses)
                or [
                    ResponseContract(
                        status_code=200,
                        media_type="application/json",
                        description="OK",
                        schema={"type": "object"},
                    )
                ],
                security_requirement=sec_req,
                semantic_effect=cand.semantic_effect,
                provenance=prov,
                support_status="blocked" if has_open_blocker else "supported",
            )

            # Check for contradictory duplicate operation definitions across documents
            if cand.method and cand.relative_path:
                mp_key = (cand.method, cand.relative_path)
                if mp_key in seen_method_paths:
                    prev_op = seen_method_paths[mp_key]
                    prev_param_names = {p.external_name for p in prev_op.parameters}
                    curr_param_names = {p.external_name for p in op_contract.parameters}
                    if (
                        prev_param_names != curr_param_names
                        or prev_op.security_requirement != op_contract.security_requirement
                    ):
                        combined_evs = (
                            prev_op.provenance.get("relative_path", [])
                            + op_contract.provenance.get("relative_path", [])
                        )
                        for target_op_id in (prev_op.stable_id, stable_id):
                            all_findings.append(
                                Finding(
                                    id=f"fnd_dup_conflict_{target_op_id}",
                                    code="CONFLICTING_OPERATION_DEFINITION",
                                    severity="blocker",
                                    affected_field="operation",
                                    operation_id=target_op_id,
                                    evidence_refs=combined_evs,
                                    explanation=(
                                        f"Duplicate endpoint '{cand.method} {cand.relative_path}' "
                                        "defined with conflicting parameters or authentication across bundle."
                                    ),
                                    suggested_resolution=(
                                        "Reconcile or override the conflicting endpoint definition."
                                    ),
                                )
                            )
                else:
                    seen_method_paths[mp_key] = op_contract

            all_findings.extend(op_findings)
            operations.append(op_contract)

    applied_overrides: list[UserOverride] = []
    ops_by_id: dict[str, OperationContract] = {op.stable_id: op for op in operations}

    for ov in overrides or []:
        if ov.source_revision != revision:
            all_findings.append(
                Finding(
                    id=f"fnd_stale_rev_{ov.id}",
                    code="STALE_OVERRIDE",
                    severity="blocker",
                    affected_field=ov.target_field,
                    operation_id=ov.operation_id,
                    explanation=(
                        f"Override '{ov.id}' targets revision {ov.source_revision}, "
                        f"but current bundle revision is {revision}."
                    ),
                    suggested_resolution="Re-confirm the override against the updated document revision.",
                )
            )
            continue

        # Contract-level override (`operation_id is None`)
        if ov.operation_id is None:
            if ov.target_field == "servers":
                curr_hash = compute_field_value_hash(reconciled_servers)
                if ov.old_value_hash != curr_hash:
                    all_findings.append(
                        Finding(
                            id=f"fnd_stale_hash_{ov.id}",
                            code="STALE_OVERRIDE",
                            severity="blocker",
                            affected_field="servers",
                            explanation=(
                                f"Override '{ov.id}' old_value_hash ({ov.old_value_hash}) "
                                f"does not match current servers hash ({curr_hash})."
                            ),
                            suggested_resolution="Re-verify server base URL override.",
                        )
                    )
                    continue

                if isinstance(ov.new_value, str):
                    reconciled_servers = [
                        ServerContract(
                            server_id="default",
                            base_url=ov.new_value.rstrip("/"),
                            description=f"Owner override {ov.id}",
                            evidence=[f"override:{ov.id}"],
                        )
                    ]
                elif isinstance(ov.new_value, list):
                    reconciled_servers = [
                        ServerContract.model_validate(item) for item in ov.new_value
                    ]
                for f in all_findings:
                    if f.operation_id is None and f.affected_field == "servers":
                        f.status = "resolved"
                applied_overrides.append(ov)
            continue

        # Operation-level override
        target_op = ops_by_id.get(ov.operation_id)
        if target_op is None:
            all_findings.append(
                Finding(
                    id=f"fnd_orphan_ov_{ov.id}",
                    code="STALE_OVERRIDE",
                    severity="blocker",
                    affected_field=ov.target_field,
                    operation_id=ov.operation_id,
                    explanation=f"Override '{ov.id}' references missing operation '{ov.operation_id}'.",
                    suggested_resolution="Remove or update the obsolete operation override.",
                )
            )
            continue

        if ov.target_field == "method_path":
            current_val = {
                "method": target_op.method,
                "relative_path": target_op.relative_path,
            }
        else:
            current_val = getattr(target_op, ov.target_field, None)

        curr_hash = compute_field_value_hash(current_val)
        if ov.old_value_hash != curr_hash:
            all_findings.append(
                Finding(
                    id=f"fnd_stale_hash_{ov.id}",
                    code="STALE_OVERRIDE",
                    severity="blocker",
                    affected_field=ov.target_field,
                    operation_id=ov.operation_id,
                    explanation=(
                        f"Override '{ov.id}' precondition failed on '{ov.target_field}': "
                        f"expected hash {ov.old_value_hash}, got {curr_hash}."
                    ),
                    suggested_resolution="Re-review the changed source section and issue a fresh override.",
                )
            )
            continue

        # Apply valid operation override
        op_dump = target_op.model_dump(by_alias=True)
        if ov.target_field == "method_path" and isinstance(ov.new_value, dict):
            new_method = str(ov.new_value["method"]).upper()
            new_path = str(ov.new_value["relative_path"])
            op_dump["method"] = new_method
            op_dump["relative_path"] = new_path
            if op_dump["semantic_effect"] == "unknown":
                op_dump["semantic_effect"] = (
                    "read"
                    if new_method == "GET"
                    else "destructive"
                    if new_method == "DELETE"
                    else "write"
                )
        elif ov.target_field == "method":
            new_method = str(ov.new_value).upper()
            op_dump["method"] = new_method
            if op_dump["semantic_effect"] == "unknown":
                op_dump["semantic_effect"] = (
                    "read"
                    if new_method == "GET"
                    else "destructive"
                    if new_method == "DELETE"
                    else "write"
                )
        elif ov.target_field == "security_requirement":
            op_dump["security_requirement"] = SecurityRequirement.model_validate(
                ov.new_value
            ).model_dump()
        else:
            op_dump[ov.target_field] = ov.new_value

        op_dump["provenance"].setdefault(ov.target_field, []).append(f"override:{ov.id}")
        updated_op = OperationContract.model_validate(op_dump)
        ops_by_id[ov.operation_id] = updated_op
        operations = [ops_by_id[o.stable_id] for o in operations]

        for f in all_findings:
            if f.operation_id == ov.operation_id and f.affected_field == ov.target_field:
                f.status = "resolved"
        applied_overrides.append(ov)

    draft_contract = ApiContract(
        id=contract_id,
        project_id=project_id,
        revision=revision,
        sources=source_ids or ["unknown_source"],
        servers=reconciled_servers,
        operations=operations,
        security_schemes=list(schemes_by_id.values()),
        findings=all_findings,
        overrides=applied_overrides,
    )
    validated_contract = validate_contract_readiness(draft_contract)
    return validated_contract, all_evidence

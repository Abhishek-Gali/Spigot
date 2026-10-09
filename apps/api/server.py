"""Local Product API and Job/Review/Export Orchestrator for Spigot / DocForge MCP (T19-T21).

Implements the local HTTP API and security controls specified in API_UI_SPEC.md and SECURITY.md:
- Single-owner loopback binding (`127.0.0.1`, `localhost`, `[::1]`) with DNS-rebinding `Host` guard.
- Cross-origin mutation protection (`Origin` and `Sec-Fetch-Site` validation; no wildcard CORS).
- Per-launch capability token (`X-Spigot-Token` / `X-DocForge-Token`) required on all state-changing
  endpoints (`POST`, `PATCH`, `PUT`, `DELETE`).
- Bounded request sizes and server-generated download filenames (no arbitrary path traversal).
- Full lifecycle endpoints:
  - `GET /api/session`, `GET /api/local-models`
  - `POST /api/projects`, `GET /api/projects/{id}`, `DELETE /api/projects/{id}`
  - `POST /api/projects/{id}/sources`, `POST /api/projects/{id}/fetch`, `POST /api/projects/{id}/extract`
  - `GET /api/projects/{id}/findings`, `PATCH /api/projects/{id}/review`
  - `POST /api/projects/{id}/contracts/freeze`, `POST /api/projects/{id}/tool-plans`
  - `POST /api/projects/{id}/generate`
  - `POST /api/artifacts/{id}/validate`, `GET /api/artifacts/{id}/download`
  - `GET /api/jobs/{id}`, `POST /api/jobs/{id}/cancel`, `GET /api/jobs/{id}/events`
"""

from __future__ import annotations

import base64
import json
import secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from packages.core.approval import ApprovalAuthority, compute_action_digest
from packages.core.contracts import (
    ErrorEnvelope,
    EvidenceRef,
    GenerationManifest,
    sha256_hex,
    to_safe_identifier,
)
from packages.core.evaluation import evaluate_agent_conditions, evaluate_extraction_corpus
from packages.core.evolution import compare_contracts, reconcile_and_regenerate
from packages.core.extraction import (
    DocumentExtractionBundle,
    extract_document_candidates,
)
from packages.core.jobs import JobCancelledError, JobCoordinator, JobRecord, JobStatus
from packages.core.local_inference import OllamaInferenceAdapter
from packages.core.openapi_normalizer import normalize_openapi_document
from packages.core.parsers import parse_document_bytes
from packages.core.planning import RuntimePolicy, create_tool_plan, suggest_tool_pack
from packages.core.reconciliation import reconcile_bundles_to_contract
from packages.core.storage import (
    ArtifactIntegrityError,
    RevisionConflictError,
    SpigotStorage,
    utc_now_iso,
)
from packages.templates.generator import (
    export_reproducible_zip,
    generate_server_package,
)
from workers.validation_worker import IsolatedValidationWorker

ALLOWED_LOOPBACK_HOSTS = frozenset(
    {
        "127.0.0.1",
        "localhost",
        "[::1]",
        "::1",
        "testserver",
    }
)
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB


@dataclass
class LocalApiConfig:
    workspace_dir: Path = field(
        default_factory=lambda: Path.cwd() / ".spigot" / "workspace"
    )
    capability_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    approval_secret: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    default_network_profile: Literal["STRICT_OFFLINE", "CONNECTED_SERVICES"] = "STRICT_OFFLINE"
    use_local_model_by_default: bool = False
    web_assets_dir: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent.parent / "web"
    )
    examples_dir: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent.parent.parent / "examples"
    )


class CreateProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    network_profile: Literal["STRICT_OFFLINE", "CONNECTED_SERVICES"] | None = None


class LoadExampleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    example_id: Literal["pdf", "markdown", "html", "openapi"]


class InlineSourceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1, max_length=255)
    content_base64: str | None = None
    content_text: str | None = None
    license_note: str | None = None


class UploadSourcesJsonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    files: list[InlineSourceItem] = Field(min_length=1)


class FetchUrlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1)
    explicit_connected_permission: bool = False


class ExtractProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ids: list[str] | None = None
    use_local_model: bool | None = None
    config_version: str = "1.0"
    defer_execution: bool = False


class ReviewOverrideRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=1)
    operation_id: str | None = None
    target_field: str = Field(min_length=1)
    new_value: Any
    rationale: str = Field(min_length=1)
    resolve_finding_codes: list[str] = Field(default_factory=list)


class FreezeContractRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=1)
    selected_operation_ids: list[str] | None = None


class CreateToolPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_hash: str = Field(min_length=1)
    selected_operation_ids: list[str] | None = None
    use_case: str = "default"
    policy_mode: Literal["read_only", "restricted_write", "approval_required"] = "read_only"
    allowed_write_operations: list[str] = Field(default_factory=list)
    disabled_operations: list[str] = Field(default_factory=list)
    preserve_dependencies: bool = False
    enforce_dependencies: bool = False
    rewrite_descriptions: bool = False


class SuggestToolPackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    use_case: str = Field(min_length=1)
    seed_operation_ids: list[str] | None = None
    policy_mode: Literal["read_only", "restricted_write", "approval_required"] = "read_only"
    allowed_write_operations: list[str] = Field(default_factory=list)
    disabled_operations: list[str] = Field(default_factory=list)
    preserve_dependencies: bool = True


class CompareContractsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    old_contract_hash: str | None = None
    new_contract_hash: str | None = None
    old_revision: int | None = None
    new_revision: int | None = None
    old_plan_hash: str | None = None


class RegenerateProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ids: list[str] | None = None
    old_revision: int | None = None
    old_contract_hash: str | None = None
    old_plan_hash: str | None = None
    use_local_model: bool = False


class EvaluateProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    split: Literal["dev", "held_out"] = "held_out"
    repetitions: int = Field(default=1, ge=1, le=10)


class GenerateServerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_hash: str = Field(min_length=1)
    idempotency_key: str | None = None
    package_slug: str | None = None


class ValidateArtifactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suite_profile: Literal["standard", "strict_offline"] = "strict_offline"
    idempotency_key: str | None = None


class ApprovalActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    target_url: str = Field(min_length=1)
    contract_hash: str = Field(min_length=1)
    policy_hash: str = Field(min_length=1)
    ttl_sec: float = Field(default=120.0, gt=0.0, le=3600.0)


def _error_response(
    status_code: int,
    code: Any,
    user_message: str,
    stage: str,
    *,
    retryable: bool = False,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    env = ErrorEnvelope(
        code=code,
        user_message=user_message,
        retryable=retryable,
        stage=stage,
        correlation_id=f"req-{uuid.uuid4().hex[:12]}",
        redacted_details=details or {},
    )
    return JSONResponse(status_code=status_code, content=env.model_dump())


def _is_loopback_host_header(host_header: str) -> bool:
    if not host_header:
        return False
    raw = host_header.strip().lower()
    if raw.startswith("["):
        end_bracket = raw.find("]")
        if end_bracket < 0:
            return False
        hostname = raw[: end_bracket + 1]
    else:
        hostname = raw.split(":", 1)[0]
    return hostname in ALLOWED_LOOPBACK_HOSTS


def _is_allowed_origin(origin_header: str) -> bool:
    if not origin_header:
        return True
    parsed = urlparse(origin_header.strip())
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1", "testserver"}


def _job_to_dict(job: JobRecord) -> dict[str, Any]:
    return {
        "job_id": job.id,
        "project_id": job.project_id,
        "job_type": job.job_type,
        "idempotency_key": job.idempotency_key,
        "status": job.status.value,
        "stage": job.stage,
        "progress_pct": job.progress_pct,
        "checkpoints": job.checkpoints,
        "result": job.result,
        "error": job.error,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "status_url": f"/api/jobs/{job.id}",
    }


def create_local_app(
    config: LocalApiConfig | None = None,
    *,
    inference_adapter: OllamaInferenceAdapter | None = None,
) -> FastAPI:
    """Create the local-only FastAPI application for Spigot / DocForge MCP."""
    if config is None:
        config = LocalApiConfig()
    storage = SpigotStorage(config.workspace_dir)
    jobs = JobCoordinator(storage)
    ollama = inference_adapter or OllamaInferenceAdapter()

    # Metadata store for evidence registries and generated artifacts in workspace
    meta_dir = config.workspace_dir / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    generated_dir = config.workspace_dir / "generated"
    generated_dir.mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="Spigot (DocForge MCP) Local Compiler API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.config = config
    app.state.storage = storage
    app.state.jobs = jobs
    app.state.ollama = ollama

    def _save_evidence_registry(project_id: str, evidence_list: list[EvidenceRef]) -> None:
        ev_file = meta_dir / f"evidence_{project_id}.json"
        payload = [e.model_dump() for e in evidence_list]
        ev_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def _load_evidence_registry(project_id: str) -> dict[str, EvidenceRef]:
        ev_file = meta_dir / f"evidence_{project_id}.json"
        if not ev_file.exists():
            return {}
        raw_list = json.loads(ev_file.read_text(encoding="utf-8"))
        return {
            str(item["id"]): EvidenceRef.model_validate(item)
            for item in raw_list
        }

    def _save_artifact_record(record: dict[str, Any]) -> None:
        art_file = meta_dir / f"artifact_{record['artifact_id']}.json"
        art_file.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        proj_idx = meta_dir / f"project_latest_artifact_{record['project_id']}.json"
        proj_idx.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    def _load_artifact_record(artifact_id: str) -> dict[str, Any] | None:
        art_file = meta_dir / f"artifact_{artifact_id}.json"
        if not art_file.exists():
            return None
        return json.loads(art_file.read_text(encoding="utf-8"))

    def _load_latest_project_artifact(project_id: str) -> dict[str, Any] | None:
        proj_idx = meta_dir / f"project_latest_artifact_{project_id}.json"
        if not proj_idx.exists():
            return None
        return json.loads(proj_idx.read_text(encoding="utf-8"))

    @app.middleware("http")
    async def loopback_and_capability_guard(request: Request, call_next: Any) -> Response:
        # 1. DNS Rebinding / Host header check
        host_hdr = request.headers.get("host", "")
        if not _is_loopback_host_header(host_hdr):
            return _error_response(
                403,
                "POLICY_DENIED",
                f"Rejected non-loopback Host header '{host_hdr}'.",
                "http_host_guard",
            )

        # 2. Cross-Origin / Sec-Fetch-Site check
        origin_hdr = request.headers.get("origin", "")
        sec_fetch_site = request.headers.get("sec-fetch-site", "").lower()
        if not _is_allowed_origin(origin_hdr) or sec_fetch_site == "cross-site":
            return _error_response(
                403,
                "POLICY_DENIED",
                "Rejected cross-origin request to local Spigot / DocForge MCP API.",
                "http_origin_guard",
            )

        # 3. Capability token check on all state-changing /api/* requests
        if request.url.path.startswith("/api/") and request.method in {
            "POST",
            "PATCH",
            "PUT",
            "DELETE",
        }:
            token = (
                request.headers.get("x-spigot-token")
                or request.headers.get("x-docforge-token")
                or ""
            )
            if not token or not secrets.compare_digest(token, config.capability_token):
                return _error_response(
                    403,
                    "POLICY_DENIED",
                    "Missing or invalid local session capability token (X-Spigot-Token).",
                    "http_capability_guard",
                )

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def serve_index() -> Response:
        index_path = config.web_assets_dir / "index.html"
        if not index_path.exists():
            return HTMLResponse(
                "<h1>Spigot / DocForge MCP Local UI assets not found</h1>",
                status_code=404,
            )
        return HTMLResponse(index_path.read_text(encoding="utf-8"))

    @app.get("/static/{asset_name}")
    async def serve_static_asset(asset_name: str) -> Response:
        if "/" in asset_name or "\\" in asset_name or ".." in asset_name:
            raise HTTPException(status_code=400, detail="Invalid asset name")
        target = (config.web_assets_dir / asset_name).resolve()
        if not str(target).startswith(str(config.web_assets_dir.resolve())) or not target.exists():
            raise HTTPException(status_code=404, detail="Asset not found")
        media_type = "text/plain"
        if asset_name.endswith(".js"):
            media_type = "application/javascript"
        elif asset_name.endswith(".css"):
            media_type = "text/css"
        elif asset_name.endswith(".html"):
            media_type = "text/html"
        return FileResponse(target, media_type=media_type)

    @app.get("/api/session")
    async def get_session_bootstrap() -> dict[str, Any]:
        health = ollama.check_health()
        return {
            "product_name": "Spigot (DocForge MCP)",
            "brandings": ["Spigot", "DocForge MCP"],
            "capability_token": config.capability_token,
            "default_network_profile": config.default_network_profile,
            "sandbox_available": False,
            "sandbox_status_reason": (
                "Container sandbox unavailable on Windows host; static validation enabled, "
                "isolated execution marked unavailable."
            ),
            "local_model": {
                "available": health.available,
                "configured_model": health.configured_model,
                "model_installed": health.model_installed,
                "status_message": health.status_message,
            },
        }

    @app.get("/api/local-models")
    async def get_local_models() -> dict[str, Any]:
        health = ollama.check_health()
        return {
            "available": health.available,
            "base_url": health.base_url,
            "configured_model": health.configured_model,
            "model_installed": health.model_installed,
            "installed_models": health.installed_models,
            "status_message": health.status_message,
            "remote_catalog_queried": False,
        }

    @app.post("/api/projects", status_code=201)
    async def create_project(req: CreateProjectRequest) -> dict[str, Any]:
        profile = req.network_profile or config.default_network_profile
        proj = storage.create_project(req.name.strip(), network_profile=profile)
        return {
            "project_id": proj["id"],
            "name": proj["name"],
            "network_profile": proj["network_profile"],
            "current_revision": proj["current_revision"],
            "created_at": proj["created_at"],
        }

    @app.get("/api/projects/{project_id}")
    async def get_project_summary(project_id: str) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "get_project",
            )
        sources = storage.list_source_documents(project_id)
        contract_data: dict[str, Any] | None = None
        is_frozen = False
        try:
            contract, is_frozen = storage.get_contract_revision(project_id)
            # Only treat contract as matching current project state if revision matches
            if contract.revision != int(proj["current_revision"]):
                is_frozen = False
            contract_data = contract.model_dump(by_alias=True)
        except KeyError:
            contract_data = None

        latest_plan = storage.get_latest_tool_plan(project_id)
        plan_data: dict[str, Any] | None = None
        if latest_plan is not None:
            # Invalidate tool plan if contract canonical_hash changed
            if (
                contract_data is not None
                and is_frozen
                and latest_plan.contract_hash == contract_data.get("canonical_hash")
            ):
                plan_data = latest_plan.model_dump()

        previous_good_artifact = _load_latest_project_artifact(project_id)
        latest_artifact = previous_good_artifact
        if latest_artifact is not None and (
            plan_data is None or latest_artifact.get("plan_hash") != plan_data.get("plan_hash")
        ):
            latest_artifact = None

        latest_val = storage.get_latest_validation_report(project_id)
        val_data = latest_val.model_dump() if latest_val is not None else None
        contract_revisions = storage.list_contract_revisions(project_id)

        # Also list active/recent jobs for this project so refreshing the UI preserves job state
        with storage.connect() as conn:
            job_rows = conn.execute(
                "SELECT id FROM jobs WHERE project_id = ? ORDER BY created_at DESC LIMIT 10",
                (project_id,),
            ).fetchall()
        project_jobs = [_job_to_dict(jobs.get_job(str(r["id"]))) for r in job_rows]

        return JSONResponse(
            status_code=200,
            content={
                "project_id": proj["id"],
                "name": proj["name"],
                "network_profile": proj["network_profile"],
                "current_revision": int(proj["current_revision"]),
                "created_at": proj["created_at"],
                "updated_at": proj["updated_at"],
                "sources": [s.model_dump() for s in sources],
                "contract": contract_data,
                "contract_revisions": contract_revisions,
                "is_contract_frozen": is_frozen,
                "tool_plan": plan_data,
                "latest_artifact": latest_artifact,
                "previous_good_artifact": previous_good_artifact,
                "latest_validation": val_data,
                "jobs": project_jobs,
            },
        )

    @app.delete("/api/projects/{project_id}")
    async def delete_project_endpoint(
        project_id: str,
        preview: bool = Query(default=False),
        confirm: bool = Query(default=False),
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "delete_project",
            )
        sources = storage.list_source_documents(project_id)
        if preview or not confirm:
            return JSONResponse(
                status_code=200,
                content={
                    "preview": True,
                    "project_id": project_id,
                    "source_count": len(sources),
                    "source_digests": sorted({s.content_sha256 for s in sources}),
                    "message": "Pass ?confirm=true to execute reference-counted project deletion.",
                },
            )
        summary = storage.delete_project(project_id)
        return JSONResponse(status_code=200, content=summary)

    @app.post("/api/projects/{project_id}/sources")
    async def upload_project_sources(
        project_id: str,
        request: Request,
        files: list[UploadFile] | None = File(default=None),  # noqa: B008
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "upload_sources",
            )

        existing_sources = storage.list_source_documents(project_id)
        raw_items: list[tuple[str, bytes, str | None]] = []

        content_type = request.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            body_bytes = await request.body()
            if len(body_bytes) > MAX_UPLOAD_BYTES:
                return _error_response(
                    413,
                    "DOCUMENT_UNREADABLE",
                    f"Upload payload exceeds maximum size ({MAX_UPLOAD_BYTES} bytes).",
                    "upload_sources",
                )
            parsed_req = UploadSourcesJsonRequest.model_validate_json(body_bytes)
            for item in parsed_req.files:
                if item.content_base64 is not None:
                    data = base64.b64decode(item.content_base64)
                elif item.content_text is not None:
                    data = item.content_text.encode("utf-8")
                else:
                    return _error_response(
                        400,
                        "DOCUMENT_UNREADABLE",
                        f"File '{item.filename}' must supply content_base64 or content_text.",
                        "upload_sources",
                    )
                if len(data) > MAX_UPLOAD_BYTES:
                    return _error_response(
                        413,
                        "DOCUMENT_UNREADABLE",
                        f"File '{item.filename}' exceeds maximum size ({MAX_UPLOAD_BYTES} bytes).",
                        "upload_sources",
                    )
                raw_items.append((item.filename, data, item.license_note))
        elif files:
            for uf in files:
                data = await uf.read()
                if len(data) > MAX_UPLOAD_BYTES:
                    return _error_response(
                        413,
                        "DOCUMENT_UNREADABLE",
                        f"File '{uf.filename}' exceeds maximum size ({MAX_UPLOAD_BYTES} bytes).",
                        "upload_sources",
                    )
                raw_items.append((uf.filename or "document.md", data, None))
        else:
            return _error_response(
                400,
                "DOCUMENT_UNREADABLE",
                "No local files provided in request.",
                "upload_sources",
            )

        stored_docs = []
        intake_findings = []
        for idx, (fname, data, lic) in enumerate(raw_items, start=len(existing_sources) + 1):
            src_id = f"src_{project_id}_{idx:03d}_{sha256_hex(data)[:8]}"
            parsed_doc, blocks, parse_fnds = parse_document_bytes(
                src_id, fname, data, project_id=project_id
            )
            saved_doc = storage.store_source_document(
                project_id,
                fname,
                parsed_doc.media_type,
                data,
                source_id=src_id,
                license_note=lic,
            )
            storage.store_document_blocks(project_id, blocks)
            stored_docs.append(saved_doc.model_dump())
            intake_findings.extend(f.model_dump() for f in parse_fnds)

        # If project already had a contract revision, adding new sources increments revision
        # and invalidates any previously frozen contract or tool plan!
        new_rev = int(proj["current_revision"])
        if existing_sources:
            new_rev = storage.increment_project_revision(project_id)

        return JSONResponse(
            status_code=201,
            content={
                "project_id": project_id,
                "current_revision": new_rev,
                "source_ids": [d["id"] for d in stored_docs],
                "sources": stored_docs,
                "intake_findings": intake_findings,
            },
        )

    def _clear_project_sources_internal(project_id: str) -> int:
        with storage.connect() as conn:
            conn.execute(
                "DELETE FROM document_blocks WHERE project_id = ?",
                (project_id,),
            )
            conn.execute(
                "DELETE FROM source_documents WHERE project_id = ?",
                (project_id,),
            )
        return storage.increment_project_revision(project_id)

    @app.post("/api/projects/{project_id}/sources/clear")
    async def clear_project_sources(project_id: str) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "clear_sources",
            )
        new_rev = _clear_project_sources_internal(project_id)
        return JSONResponse(
            status_code=200,
            content={
                "project_id": project_id,
                "current_revision": new_rev,
                "sources": [],
                "message": "Cleared all project source documents and advanced revision.",
            },
        )

    @app.post("/api/projects/{project_id}/load-example", status_code=201)
    async def load_project_example(
        project_id: str, req: LoadExampleRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "load_example",
            )
        example_map = {
            "pdf": "01_payments_api_manual.pdf",
            "markdown": "02_support_tickets_api.md",
            "html": "03_incident_response_api.html",
            "openapi": "04_inventory_openapi_3_0.yaml",
        }
        fname = example_map[req.example_id]
        sample_path = (config.examples_dir / fname).resolve()
        if not sample_path.exists():
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Sample document '{fname}' not found in examples directory.",
                "load_example",
            )
        data = sample_path.read_bytes()
        new_rev = _clear_project_sources_internal(project_id)
        src_id = f"src_{project_id}_001_{sha256_hex(data)[:8]}"
        parsed_doc, blocks, parse_fnds = parse_document_bytes(
            src_id, fname, data, project_id=project_id
        )
        saved_doc = storage.store_source_document(
            project_id,
            fname,
            parsed_doc.media_type,
            data,
            source_id=src_id,
            license_note="Spigot built-in sample API documentation",
        )
        storage.store_document_blocks(project_id, blocks)
        return JSONResponse(
            status_code=201,
            content={
                "project_id": project_id,
                "current_revision": new_rev,
                "source_ids": [saved_doc.id],
                "sources": [saved_doc.model_dump()],
                "intake_findings": [f.model_dump() for f in parse_fnds],
            },
        )

    @app.post("/api/projects/{project_id}/fetch")
    async def fetch_remote_documentation(
        project_id: str, req: FetchUrlRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "fetch_url",
            )
        if (
            proj["network_profile"] == "STRICT_OFFLINE"
            or not req.explicit_connected_permission
        ):
            return _error_response(
                403,
                "POLICY_DENIED",
                "Remote URL fetching is disabled under STRICT_OFFLINE network policy.",
                "fetch_url",
                details={
                    "network_profile": proj["network_profile"],
                    "requested_url": req.url,
                },
            )
        return _error_response(
            422,
            "FEATURE_UNSUPPORTED",
            "Connected URL acquisition is deferred to extension X02; import local files instead.",
            "fetch_url",
        )

    def _execute_extraction_job(
        job_id: str,
        project_id: str,
        source_ids: list[str] | None,
        use_local_model: bool,
    ) -> JobRecord:
        worker_id = f"wrk_extract_{uuid.uuid4().hex[:8]}"
        claimed = jobs.claim_next_job(worker_id)
        if claimed is None or claimed.id != job_id:
            return jobs.get_job(job_id)

        try:
            proj = storage.get_project(project_id)
            if proj is None:
                raise KeyError(f"Unknown project '{project_id}'")
            all_sources = storage.list_source_documents(project_id)
            if source_ids:
                wanted = set(source_ids)
                selected_sources = [s for s in all_sources if s.id in wanted]
            else:
                selected_sources = all_sources

            if not selected_sources:
                return jobs.complete_job(
                    job_id,
                    worker_id,
                    final_status=JobStatus.FAILED,
                    error={"code": "DOCUMENT_UNREADABLE", "message": "No source documents in project."},
                )

            target_rev = int(proj["current_revision"])
            try:
                storage.get_contract_revision(project_id, target_rev)
                target_rev += 1
            except KeyError:
                pass

            # Check if single source is an OpenAPI 3.0 YAML/JSON specification
            if len(selected_sources) == 1 and selected_sources[0].original_name.lower().endswith(
                (".yaml", ".yml", ".json")
            ):
                src = selected_sources[0]
                raw_bytes = storage.artifacts.get_bytes(src.content_sha256)
                raw_text = raw_bytes.decode("utf-8", errors="replace")
                contract, oa_blocks, all_evidence = normalize_openapi_document(
                    raw_text,
                    project_id=project_id,
                    source_id=src.id,
                    contract_id=f"cnt_{project_id}",
                    revision=target_rev,
                )
                storage.store_document_blocks(project_id, oa_blocks)
                storage.save_contract_revision(contract, is_frozen=False)
                _save_evidence_registry(project_id, all_evidence)
                open_blockers = [
                    f for f in contract.findings if f.severity == "blocker" and f.status == "open"
                ]
                final_state = JobStatus.NEEDS_REVIEW if open_blockers else JobStatus.SUCCEEDED
                return jobs.complete_job(
                    job_id,
                    worker_id,
                    final_status=final_state,
                    result={
                        "contract_id": contract.id,
                        "revision": contract.revision,
                        "canonical_hash": contract.canonical_hash,
                        "operation_count": len(contract.operations),
                        "open_blocker_count": len(open_blockers),
                        "extraction_mode": "openapi_normalizer",
                    },
                )

            bundles: list[DocumentExtractionBundle] = []
            total = len(selected_sources)
            for idx, src in enumerate(selected_sources, start=1):
                raw_bytes = storage.artifacts.get_bytes(src.content_sha256)
                _, blocks, parse_findings = parse_document_bytes(
                    src.id, src.original_name, raw_bytes, project_id=project_id
                )
                bundle = extract_document_candidates(
                    src,
                    blocks,
                    existing_findings=parse_findings,
                    inference_adapter=ollama,
                    use_local_model=use_local_model,
                )
                bundles.append(bundle)
                prog = int((idx / total) * 80)
                jobs.save_checkpoint(
                    job_id,
                    worker_id,
                    f"source_{src.id}",
                    {"candidates": len(bundle.candidates)},
                    stage=f"extracted_{src.original_name}",
                    progress_pct=prog,
                )

            contract, all_evidence = reconcile_bundles_to_contract(
                bundles,
                contract_id=f"cnt_{project_id}",
                project_id=project_id,
                revision=target_rev,
            )
            storage.save_contract_revision(contract, is_frozen=False)
            _save_evidence_registry(project_id, all_evidence)

            open_blockers = [
                f for f in contract.findings if f.severity == "blocker" and f.status == "open"
            ]
            final_state = JobStatus.NEEDS_REVIEW if open_blockers else JobStatus.SUCCEEDED
            return jobs.complete_job(
                job_id,
                worker_id,
                final_status=final_state,
                result={
                    "contract_id": contract.id,
                    "revision": contract.revision,
                    "canonical_hash": contract.canonical_hash,
                    "operation_count": len(contract.operations),
                    "open_blocker_count": len(open_blockers),
                    "extraction_mode": (
                        "local_ai"
                        if any(b.extraction_mode == "local_ai" for b in bundles)
                        else "manual_review_only"
                    ),
                },
            )
        except JobCancelledError:
            return jobs.acknowledge_cancel(job_id, worker_id)
        except Exception as exc:
            return jobs.complete_job(
                job_id,
                worker_id,
                final_status=JobStatus.FAILED,
                error={"code": "EXTRACTION_INVALID", "message": str(exc)},
            )

    @app.post("/api/projects/{project_id}/extract", status_code=202)
    async def extract_project(
        project_id: str, req: ExtractProjectRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "extract_project",
            )
        sources = storage.list_source_documents(project_id)
        if not sources:
            return _error_response(
                400,
                "DOCUMENT_UNREADABLE",
                "Cannot start extraction before importing local source documents.",
                "extract_project",
            )

        use_model = (
            req.use_local_model
            if req.use_local_model is not None
            else config.use_local_model_by_default
        )
        frozen_input = json.dumps(
            {
                "revision": int(proj["current_revision"]),
                "sources": [s.content_sha256 for s in sources],
                "source_ids": sorted(req.source_ids or [s.id for s in sources]),
                "use_local_model": use_model,
            },
            sort_keys=True,
        )
        job_rec, created = jobs.enqueue_job(
            project_id,
            "extract_documentation",
            sha256_hex(frozen_input),
            config_version=req.config_version,
            initial_stage="queued_extraction",
        )
        if created and not req.defer_execution:
            job_rec = _execute_extraction_job(
                job_rec.id, project_id, req.source_ids, use_model
            )
        return JSONResponse(status_code=202, content=_job_to_dict(job_rec))

    @app.get("/api/projects/{project_id}/findings")
    async def list_project_findings(
        project_id: str,
        status: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        operation_id: str | None = Query(default=None),
        cursor: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "list_findings",
            )
        try:
            contract, _ = storage.get_contract_revision(project_id)
        except KeyError:
            return JSONResponse(
                status_code=200,
                content={"findings": [], "next_cursor": None, "total_count": 0},
            )

        ev_map = _load_evidence_registry(project_id)
        blocks_by_id = {b.id: b for b in storage.list_document_blocks(project_id)}

        filtered = []
        for f in contract.findings:
            if status and f.status != status:
                continue
            if severity and f.severity != severity:
                continue
            if operation_id and f.operation_id != operation_id:
                continue
            enriched_ev = []
            for eid in f.evidence_refs:
                ev = ev_map.get(eid)
                if ev is not None:
                    blk = blocks_by_id.get(ev.block_id)
                    enriched_ev.append(
                        {
                            "evidence_id": ev.id,
                            "source_id": ev.source_id,
                            "block_id": ev.block_id,
                            "exact_quote": ev.exact_quote,
                            "start_offset": ev.start_offset,
                            "end_offset": ev.end_offset,
                            "heading_path": blk.heading_path if blk else [],
                            "location": blk.location.model_dump() if blk else None,
                        }
                    )
            f_dict = f.model_dump()
            f_dict["evidence_details"] = enriched_ev
            filtered.append(f_dict)

        sliced = filtered[cursor : cursor + limit]
        next_cursor = cursor + limit if (cursor + limit) < len(filtered) else None
        return JSONResponse(
            status_code=200,
            content={
                "project_id": project_id,
                "revision": contract.revision,
                "findings": sliced,
                "total_count": len(filtered),
                "next_cursor": next_cursor,
            },
        )

    @app.patch("/api/projects/{project_id}/review")
    async def submit_review_override(
        project_id: str, req: ReviewOverrideRequest
    ) -> Response:
        try:
            updated_contract = storage.apply_review_override(
                project_id,
                req.expected_revision,
                operation_id=req.operation_id,
                target_field=req.target_field,
                new_value=req.new_value,
                rationale=req.rationale,
                resolve_finding_codes=req.resolve_finding_codes,
            )
        except RevisionConflictError as exc:
            return JSONResponse(
                status_code=409,
                content=exc.envelope.model_dump(),
            )
        except KeyError as exc:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                str(exc),
                "review_override",
            )
        except ValueError as exc:
            return _error_response(
                422,
                "EXTRACTION_INVALID",
                str(exc),
                "review_override",
            )

        open_blockers = [
            f.model_dump()
            for f in updated_contract.findings
            if f.severity == "blocker" and f.status == "open"
        ]
        return JSONResponse(
            status_code=200,
            content={
                "project_id": project_id,
                "revision": updated_contract.revision,
                "canonical_hash": updated_contract.canonical_hash,
                "is_frozen": False,
                "contract": updated_contract.model_dump(by_alias=True),
                "open_blockers": open_blockers,
            },
        )

    @app.post("/api/projects/{project_id}/contracts/freeze")
    async def freeze_project_contract(
        project_id: str, req: FreezeContractRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "freeze_contract",
            )
        current_rev = int(proj["current_revision"])
        if req.expected_revision != current_rev:
            conflict = RevisionConflictError(project_id, req.expected_revision, current_rev)
            return JSONResponse(status_code=409, content=conflict.envelope.model_dump())

        try:
            contract, _ = storage.get_contract_revision(project_id, req.expected_revision)
        except KeyError as exc:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                str(exc),
                "freeze_contract",
            )

        # Contract-level blockers always block freeze
        contract_level_blockers = [
            f
            for f in contract.findings
            if f.operation_id is None and f.severity == "blocker" and f.status == "open"
        ]
        if contract_level_blockers:
            return _error_response(
                422,
                "CONTRACT_INCOMPLETE",
                "Cannot freeze contract while contract-level blocker findings remain open.",
                "freeze_contract",
                details={
                    "open_blockers": [f.model_dump() for f in contract_level_blockers]
                },
            )

        selected_ids = (
            set(req.selected_operation_ids)
            if req.selected_operation_ids is not None
            else {
                op.stable_id
                for op in contract.operations
                if op.support_status in {"supported", "partial"}
            }
        )
        if not selected_ids:
            return _error_response(
                422,
                "CONTRACT_INCOMPLETE",
                "Cannot freeze contract with zero supported operations.",
                "freeze_contract",
                details={
                    "open_blockers": [
                        f.model_dump()
                        for f in contract.findings
                        if f.severity == "blocker" and f.status == "open"
                    ]
                },
            )

        selected_blockers = [
            f
            for f in contract.findings
            if f.operation_id in selected_ids
            and f.severity == "blocker"
            and f.status == "open"
        ]
        if selected_blockers:
            return _error_response(
                422,
                "CONTRACT_INCOMPLETE",
                "Cannot freeze contract while selected operations have unresolved blocker findings.",
                "freeze_contract",
                details={
                    "open_blockers": [f.model_dump() for f in selected_blockers]
                },
            )

        frozen_contract = storage.freeze_contract_revision(
            project_id, req.expected_revision
        )
        return JSONResponse(
            status_code=200,
            content={
                "project_id": project_id,
                "revision": frozen_contract.revision,
                "canonical_hash": frozen_contract.canonical_hash,
                "is_frozen": True,
                "supported_operation_ids": [
                    op.stable_id
                    for op in frozen_contract.operations
                    if op.support_status in {"supported", "partial"}
                ],
                "blocked_operation_ids": [
                    op.stable_id
                    for op in frozen_contract.operations
                    if op.support_status == "blocked"
                ],
            },
        )

    @app.post("/api/projects/{project_id}/tool-plans")
    async def create_project_tool_plan(
        project_id: str, req: CreateToolPlanRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "create_tool_plan",
            )
        try:
            contract, is_frozen = storage.get_contract_revision(project_id)
        except KeyError:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                "No contract exists for project.",
                "create_tool_plan",
            )

        if not is_frozen or contract.revision != int(proj["current_revision"]):
            return _error_response(
                422,
                "CONTRACT_INCOMPLETE",
                "Contract must be frozen at the current project revision before creating a ToolPlan.",
                "create_tool_plan",
            )
        if contract.canonical_hash != req.contract_hash:
            return _error_response(
                409,
                "REVISION_CONFLICT",
                (
                    f"Contract hash mismatch: expected {req.contract_hash}, "
                    f"current frozen hash is {contract.canonical_hash}."
                ),
                "create_tool_plan",
            )

        policy = RuntimePolicy(
            id=f"pol_{project_id}_r{contract.revision}",
            revision=contract.revision,
            mode=req.policy_mode,
            allowed_write_operations=req.allowed_write_operations,
            disabled_operations=req.disabled_operations,
            network_profile=proj["network_profile"],
        )
        storage.save_policy_revision(project_id, policy)

        try:
            plan = create_tool_plan(
                contract,
                policy,
                plan_id=f"plan_{project_id}_r{contract.revision}",
                selected_operation_ids=req.selected_operation_ids,
                preserve_dependencies=req.preserve_dependencies,
                enforce_dependencies=req.enforce_dependencies,
                rewrite_descriptions=req.rewrite_descriptions,
            )
        except (ValueError, KeyError) as exc:
            return _error_response(
                422,
                "CONTRACT_INCOMPLETE",
                str(exc),
                "create_tool_plan",
            )

        if not plan.operation_ids:
            return _error_response(
                422,
                "CONTRACT_INCOMPLETE",
                "ToolPlan must select at least one supported operation.",
                "create_tool_plan",
            )

        storage.save_tool_plan(project_id, plan)
        return JSONResponse(
            status_code=201,
            content={
                "project_id": project_id,
                "tool_plan": plan.model_dump(),
                "policy": policy.model_dump(),
            },
        )

    @app.post("/api/projects/{project_id}/tool-packs/suggest")
    async def suggest_project_tool_pack(
        project_id: str, req: SuggestToolPackRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "suggest_tool_pack",
            )
        try:
            contract, _ = storage.get_contract_revision(project_id)
        except KeyError:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                "No contract exists for project.",
                "suggest_tool_pack",
            )

        policy = RuntimePolicy(
            id=f"pol_pack_{project_id}_r{contract.revision}",
            revision=contract.revision,
            mode=req.policy_mode,
            allowed_write_operations=req.allowed_write_operations,
            disabled_operations=req.disabled_operations,
            network_profile=proj["network_profile"],
        )
        try:
            suggestion = suggest_tool_pack(
                contract,
                policy,
                use_case=req.use_case,
                seed_operation_ids=req.seed_operation_ids,
                preserve_dependencies=req.preserve_dependencies,
            )
        except ValueError as exc:
            return _error_response(
                422,
                "CONTRACT_INCOMPLETE",
                str(exc),
                "suggest_tool_pack",
            )
        return JSONResponse(content=suggestion.model_dump())

    @app.post("/api/projects/{project_id}/generate", status_code=202)
    async def generate_project_server(
        project_id: str, req: GenerateServerRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "generate_server",
            )
        plan = storage.get_tool_plan_by_hash(project_id, req.plan_hash)
        if plan is None:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                f"ToolPlan with hash '{req.plan_hash}' not found for project '{project_id}'.",
                "generate_server",
            )

        contract, is_frozen = storage.get_contract_revision(project_id)
        if not is_frozen or contract.canonical_hash != plan.contract_hash:
            return _error_response(
                409,
                "REVISION_CONFLICT",
                "ToolPlan references a stale or unfrozen contract revision.",
                "generate_server",
            )

        policy_dict = storage.get_policy_by_hash(project_id, plan.policy_hash)
        if policy_dict is None:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                "Policy revision referenced by ToolPlan was not found.",
                "generate_server",
            )
        policy = RuntimePolicy.model_validate(policy_dict)

        idem_input = req.idempotency_key or f"{plan.plan_hash}:{contract.canonical_hash}"
        job_rec, created = jobs.enqueue_job(
            project_id,
            "generate_server",
            sha256_hex(idem_input),
            initial_stage="queued_generation",
        )
        if created:
            worker_id = f"wrk_gen_{uuid.uuid4().hex[:8]}"
            claimed = jobs.claim_next_job(worker_id)
            if claimed and claimed.id == job_rec.id:
                pkg_slug = to_safe_identifier(
                    req.package_slug or f"spigot_{proj['name']}_server",
                    fallback="spigot_generated_server",
                )
                artifact_id = f"art_{project_id}_r{contract.revision}_{plan.plan_hash[:8]}"
                out_dir = generated_dir / artifact_id / "package"
                zip_file = generated_dir / artifact_id / f"{pkg_slug}.zip"

                manifest = generate_server_package(
                    contract,
                    plan,
                    policy,
                    out_dir,
                    package_slug=pkg_slug,
                )
                zip_bytes = export_reproducible_zip(out_dir, zip_file)
                zip_sha256, zip_rel_path = storage.artifacts.put_bytes(zip_bytes)

                art_record = {
                    "artifact_id": artifact_id,
                    "project_id": project_id,
                    "revision": contract.revision,
                    "package_slug": pkg_slug,
                    "contract_hash": contract.canonical_hash,
                    "plan_hash": plan.plan_hash,
                    "policy_hash": policy.policy_hash,
                    "manifest": manifest.model_dump(),
                    "zip_sha256": zip_sha256,
                    "zip_relative_path": zip_rel_path,
                    "zip_byte_size": len(zip_bytes),
                    "package_dir": str(out_dir),
                    "created_at": utc_now_iso(),
                }
                _save_artifact_record(art_record)
                job_rec = jobs.complete_job(
                    job_rec.id,
                    worker_id,
                    final_status=JobStatus.SUCCEEDED,
                    result={
                        "artifact_id": artifact_id,
                        "manifest_hash": manifest.manifest_hash,
                        "zip_sha256": zip_sha256,
                        "download_url": f"/api/artifacts/{artifact_id}/download",
                    },
                )
        return JSONResponse(status_code=202, content=_job_to_dict(job_rec))

    @app.post("/api/artifacts/{artifact_id}/validate", status_code=202)
    async def validate_generated_artifact(
        artifact_id: str, req: ValidateArtifactRequest
    ) -> Response:
        art_record = _load_artifact_record(artifact_id)
        if art_record is None:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                f"Generated artifact '{artifact_id}' not found.",
                "validate_artifact",
            )
        project_id = str(art_record["project_id"])
        manifest = GenerationManifest.model_validate(art_record["manifest"])
        idem_input = req.idempotency_key or f"{artifact_id}:{manifest.manifest_hash}:{req.suite_profile}"

        job_rec, created = jobs.enqueue_job(
            project_id,
            "validate_artifact",
            sha256_hex(idem_input),
            initial_stage="queued_validation",
        )
        if created:
            worker_id = f"wrk_val_{uuid.uuid4().hex[:8]}"
            claimed = jobs.claim_next_job(worker_id)
            if claimed and claimed.id == job_rec.id:
                pkg_dir = Path(art_record["package_dir"])
                zip_bytes: bytes | None = None
                try:
                    zip_bytes = storage.artifacts.get_bytes(str(art_record["zip_sha256"]))
                except Exception:
                    zip_bytes = None

                val_worker = IsolatedValidationWorker()
                report = val_worker.validate_package(
                    artifact_id=artifact_id,
                    package_dir=pkg_dir,
                    manifest=manifest,
                    zip_bytes=zip_bytes,
                    suite_profile=req.suite_profile,
                )
                storage.save_validation_report(project_id, report)
                checks_by_name = {c.check_name: c.status for c in report.checks}
                all_passed = (
                    checks_by_name.get("build_status") == "passed"
                    and checks_by_name.get("static_check_status") == "passed"
                    and checks_by_name.get("protocol_check_status") == "passed"
                    and checks_by_name.get("security_suite_status") == "passed"
                )
                final_job_status = (
                    JobStatus.SUCCEEDED if all_passed else JobStatus.FAILED
                )
                job_rec = jobs.complete_job(
                    job_rec.id,
                    worker_id,
                    final_status=final_job_status,
                    result={"validation_report": report.model_dump(mode="json")},
                )
        return JSONResponse(status_code=202, content=_job_to_dict(job_rec))

    @app.get("/api/artifacts/{artifact_id}/download")
    async def download_artifact_zip(artifact_id: str) -> Response:
        art_record = _load_artifact_record(artifact_id)
        if art_record is None:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                f"Artifact '{artifact_id}' not found.",
                "download_artifact",
            )
        try:
            zip_bytes = storage.artifacts.get_bytes(str(art_record["zip_sha256"]))
        except ArtifactIntegrityError as exc:
            return _error_response(
                500,
                "CONTRACT_INCOMPLETE",
                f"Artifact integrity check failed: {exc}",
                "download_artifact",
            )

        safe_slug = to_safe_identifier(
            str(art_record.get("package_slug", "spigot_server")),
            fallback="spigot_server",
        )
        filename = f"{safe_slug}_r{art_record.get('revision', 1)}.zip"
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Artifact-SHA256": str(art_record["zip_sha256"]),
            },
        )

    @app.get("/api/jobs/{job_id}")
    async def get_job_status(job_id: str) -> Response:
        try:
            job = jobs.get_job(job_id)
        except KeyError:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                f"Job '{job_id}' not found.",
                "get_job",
            )
        return JSONResponse(status_code=200, content=_job_to_dict(job))

    @app.post("/api/jobs/{job_id}/cancel")
    async def cancel_job_endpoint(job_id: str) -> Response:
        try:
            job = jobs.request_cancel(job_id)
        except KeyError:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                f"Job '{job_id}' not found.",
                "cancel_job",
            )
        return JSONResponse(status_code=200, content=_job_to_dict(job))

    @app.get("/api/jobs/{job_id}/events")
    async def get_job_events_endpoint(
        job_id: str,
        cursor: int = Query(default=0, ge=0),
    ) -> Response:
        try:
            jobs.get_job(job_id)
        except KeyError:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                f"Job '{job_id}' not found.",
                "get_job_events",
            )
        events = jobs.list_job_events(job_id, after_id=cursor)
        next_cursor = max((int(e["id"]) for e in events), default=cursor)
        return JSONResponse(
            status_code=200,
            content={
                "job_id": job_id,
                "events": events,
                "next_cursor": next_cursor,
            },
        )

    @app.post("/api/projects/{project_id}/approvals/prepare")
    async def prepare_action_approval(
        project_id: str, req: ApprovalActionRequest
    ) -> Response:
        try:
            storage.get_project(project_id)
        except KeyError:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                f"Project '{project_id}' not found.",
                "prepare_approval",
            )
        action_digest = compute_action_digest(
            operation_id=req.operation_id,
            arguments=req.arguments,
            target_url=req.target_url,
            contract_hash=req.contract_hash,
            policy_hash=req.policy_hash,
        )
        return JSONResponse(
            status_code=200,
            content={
                "project_id": project_id,
                "action_digest": action_digest,
                "operation_id": req.operation_id,
                "arguments": req.arguments,
                "target_url": req.target_url,
                "contract_hash": req.contract_hash,
                "policy_hash": req.policy_hash,
            },
        )

    @app.post("/api/projects/{project_id}/approvals/issue")
    async def issue_action_approval(
        project_id: str, req: ApprovalActionRequest
    ) -> Response:
        try:
            storage.get_project(project_id)
        except KeyError:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                f"Project '{project_id}' not found.",
                "issue_approval",
            )
        authority = ApprovalAuthority(config.approval_secret)
        token = authority.issue_token(
            operation_id=req.operation_id,
            arguments=req.arguments,
            target_url=req.target_url,
            contract_hash=req.contract_hash,
            policy_hash=req.policy_hash,
            ttl_sec=req.ttl_sec,
        )
        return JSONResponse(
            status_code=200,
            content={
                "project_id": project_id,
                "approval_token": token,
                "approval_token_json": json.dumps(token, sort_keys=True),
            },
        )

    @app.post("/api/projects/{project_id}/compare")
    async def compare_project_contracts(
        project_id: str, req: CompareContractsRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "compare_contracts",
            )

        try:
            if req.old_contract_hash is not None:
                old_contract, _ = storage.get_contract_by_hash(
                    project_id, req.old_contract_hash
                )
            elif req.old_revision is not None:
                old_contract, _ = storage.get_contract_revision(
                    project_id, req.old_revision
                )
            else:
                revs = storage.list_contract_revisions(project_id)
                if len(revs) < 2:
                    return _error_response(
                        400,
                        "CONTRACT_INCOMPLETE",
                        "Provide old_contract_hash or old_revision when project has fewer than 2 revisions.",
                        "compare_contracts",
                    )
                old_contract, _ = storage.get_contract_revision(
                    project_id, int(revs[-2]["revision"])
                )

            if req.new_contract_hash is not None:
                new_contract, _ = storage.get_contract_by_hash(
                    project_id, req.new_contract_hash
                )
            elif req.new_revision is not None:
                new_contract, _ = storage.get_contract_revision(
                    project_id, req.new_revision
                )
            else:
                new_contract, _ = storage.get_contract_revision(project_id)
        except KeyError as exc:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                str(exc),
                "compare_contracts",
            )

        old_plan = None
        if req.old_plan_hash is not None:
            old_plan = storage.get_tool_plan_by_hash(project_id, req.old_plan_hash)
        if old_plan is None:
            old_plan = storage.get_latest_tool_plan(project_id)

        diff_report = compare_contracts(
            old_contract,
            new_contract,
            old_tool_plan=old_plan,
        )
        return JSONResponse(status_code=200, content=diff_report.model_dump())

    @app.post("/api/projects/{project_id}/regenerate")
    async def regenerate_project_contract(
        project_id: str, req: RegenerateProjectRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "regenerate_project",
            )

        try:
            if req.old_contract_hash is not None:
                old_contract, _ = storage.get_contract_by_hash(
                    project_id, req.old_contract_hash
                )
            elif req.old_revision is not None:
                old_contract, _ = storage.get_contract_revision(
                    project_id, req.old_revision
                )
            else:
                old_contract, _ = storage.get_contract_revision(project_id)
        except KeyError as exc:
            return _error_response(
                404,
                "CONTRACT_INCOMPLETE",
                str(exc),
                "regenerate_project",
            )

        old_plan = None
        if req.old_plan_hash is not None:
            old_plan = storage.get_tool_plan_by_hash(project_id, req.old_plan_hash)
        if old_plan is None:
            old_plan = storage.get_latest_tool_plan(project_id)

        old_policy = None
        if old_plan is not None:
            pol_dict = storage.get_policy_by_hash(project_id, old_plan.policy_hash)
            if pol_dict is not None:
                old_policy = RuntimePolicy.model_validate(pol_dict)

        all_sources = storage.list_source_documents(project_id)
        if req.source_ids:
            wanted = set(req.source_ids)
            selected_sources = [s for s in all_sources if s.id in wanted]
        else:
            selected_sources = all_sources

        if not selected_sources:
            return _error_response(
                400,
                "DOCUMENT_UNREADABLE",
                "No source documents found to regenerate from.",
                "regenerate_project",
            )

        bundles: list[DocumentExtractionBundle] = []
        active_adapter = inference_adapter if req.use_local_model else None
        for src in selected_sources:
            raw_bytes = storage.artifacts.get_bytes(src.content_sha256)
            parsed_doc, blocks, parse_findings = parse_document_bytes(
                src.id, src.original_name, raw_bytes, project_id=project_id
            )
            bundle = extract_document_candidates(
                parsed_doc,
                blocks,
                inference_adapter=active_adapter,
                use_local_model=req.use_local_model,
            )
            if parse_findings:
                bundle.findings.extend(parse_findings)
            bundles.append(bundle)

        new_rev = max(int(proj["current_revision"]), old_contract.revision) + 1
        regen_result, _ = reconcile_and_regenerate(
            bundles,
            old_contract=old_contract,
            old_tool_plan=old_plan,
            old_policy=old_policy,
            new_contract_id=f"ct_{project_id}",
            new_revision=new_rev,
        )

        storage.save_contract_revision(
            regen_result.regenerated_contract,
            is_frozen=False,
        )
        if regen_result.regenerated_tool_plan is not None and old_policy is not None:
            eff_policy = old_policy.model_copy(
                update={"revision": new_rev, "policy_hash": ""}
            )
            eff_policy = RuntimePolicy.model_validate(eff_policy.model_dump())
            storage.save_policy_revision(project_id, eff_policy)
            storage.save_tool_plan(project_id, regen_result.regenerated_tool_plan)

        return JSONResponse(
            status_code=200,
            content=regen_result.model_dump(by_alias=True),
        )

    @app.post("/api/projects/{project_id}/evaluate", status_code=202)
    async def evaluate_project_endpoint(
        project_id: str, req: EvaluateProjectRequest
    ) -> Response:
        proj = storage.get_project(project_id)
        if proj is None:
            return _error_response(
                404,
                "DOCUMENT_UNREADABLE",
                f"Project '{project_id}' not found.",
                "evaluate_project",
            )

        idem_input = f"eval:{project_id}:{req.split}:{req.repetitions}"
        job_rec, created = jobs.enqueue_job(
            project_id,
            "evaluate",
            sha256_hex(idem_input),
            initial_stage="queued_evaluation",
        )
        if created:
            worker_id = f"wrk_eval_{uuid.uuid4().hex[:8]}"
            claimed = jobs.claim_next_job(worker_id)
            if claimed and claimed.id == job_rec.id:
                ext_report = evaluate_extraction_corpus(split=req.split)
                eval_run, agent_summary = await evaluate_agent_conditions(
                    split=req.split,
                    repetitions=req.repetitions,
                )
                storage.save_evaluation_run(project_id, eval_run)
                job_rec = jobs.complete_job(
                    job_rec.id,
                    worker_id,
                    final_status=JobStatus.SUCCEEDED,
                    result={
                        "evaluation_id": eval_run.id,
                        "extraction_summary": ext_report["metrics"],
                        "agent_summary": agent_summary,
                    },
                )
        return JSONResponse(status_code=202, content=_job_to_dict(job_rec))

    return app


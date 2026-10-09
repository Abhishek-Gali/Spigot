"""Typed Local API Client for Spigot / DocForge MCP (T19-T21).

Wraps `httpx.Client` (or FastAPI `TestClient`) with:
- Automatic session capability token bootstrap (`GET /api/session`) and `X-Spigot-Token`
  header injection on state-changing requests.
- Structured `SpigotApiError` raising parsed `ErrorEnvelope` on non-2xx responses.
- Typed methods covering project creation, multi-file upload, extraction jobs,
  findings inspection, precondition-guarded review overrides (`409` on stale revision),
  contract freezing, tool plan creation, deterministic package generation,
  truthful validation reporting, and verified `.zip` download.
"""

from __future__ import annotations

import base64
from typing import Any, Literal

from packages.core.contracts import ErrorEnvelope


class SpigotApiError(RuntimeError):
    """Structured error raised when the local Spigot / DocForge MCP API returns non-2xx."""

    def __init__(self, status_code: int, envelope: ErrorEnvelope) -> None:
        self.status_code = status_code
        self.envelope = envelope
        super().__init__(f"[{status_code} {envelope.code}] {envelope.user_message}")


class SpigotApiClient:
    """Typed client for the single-owner local Spigot / DocForge MCP API."""

    def __init__(
        self,
        http_client: Any,
        *,
        capability_token: str | None = None,
    ) -> None:
        self._client = http_client
        self.capability_token = capability_token

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        hdrs: dict[str, str] = {}
        if self.capability_token:
            hdrs["X-Spigot-Token"] = self.capability_token
        if extra:
            hdrs.update(extra)
        return hdrs

    def _unwrap(self, response: Any) -> dict[str, Any]:
        if response.status_code >= 400:
            try:
                payload = response.json()
                envelope = ErrorEnvelope.model_validate(payload)
            except Exception:
                envelope = ErrorEnvelope(
                    code="EXTRACTION_INVALID",
                    user_message=response.text or f"HTTP {response.status_code}",
                    retryable=False,
                    stage="api_client",
                    correlation_id="cli-err",
                )
            raise SpigotApiError(response.status_code, envelope)
        return dict(response.json())

    def bootstrap_session(self) -> dict[str, Any]:
        res = self._client.get("/api/session")
        data = self._unwrap(res)
        self.capability_token = str(data["capability_token"])
        return data

    def get_local_models(self) -> dict[str, Any]:
        res = self._client.get("/api/local-models")
        return self._unwrap(res)

    def create_project(
        self,
        name: str,
        *,
        network_profile: Literal["STRICT_OFFLINE", "CONNECTED_SERVICES"] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"name": name}
        if network_profile is not None:
            body["network_profile"] = network_profile
        res = self._client.post(
            "/api/projects",
            json=body,
            headers=self._headers(),
        )
        return self._unwrap(res)

    def get_project(self, project_id: str) -> dict[str, Any]:
        res = self._client.get(f"/api/projects/{project_id}")
        return self._unwrap(res)

    def delete_project(
        self,
        project_id: str,
        *,
        preview: bool = False,
        confirm: bool = False,
    ) -> dict[str, Any]:
        res = self._client.delete(
            f"/api/projects/{project_id}",
            params={
                "preview": "true" if preview else "false",
                "confirm": "true" if confirm else "false",
            },
            headers=self._headers(),
        )
        return self._unwrap(res)

    def upload_sources(
        self,
        project_id: str,
        files: list[tuple[str, bytes]],
    ) -> dict[str, Any]:
        payload = {
            "files": [
                {
                    "filename": fname,
                    "content_base64": base64.b64encode(raw).decode("ascii"),
                }
                for fname, raw in files
            ]
        }
        res = self._client.post(
            f"/api/projects/{project_id}/sources",
            json=payload,
            headers=self._headers(),
        )
        return self._unwrap(res)

    def fetch_remote_url(
        self,
        project_id: str,
        url: str,
        *,
        explicit_connected_permission: bool = False,
    ) -> dict[str, Any]:
        res = self._client.post(
            f"/api/projects/{project_id}/fetch",
            json={
                "url": url,
                "explicit_connected_permission": explicit_connected_permission,
            },
            headers=self._headers(),
        )
        return self._unwrap(res)

    def extract_project(
        self,
        project_id: str,
        *,
        source_ids: list[str] | None = None,
        use_local_model: bool | None = None,
        defer_execution: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"defer_execution": defer_execution}
        if source_ids is not None:
            body["source_ids"] = source_ids
        if use_local_model is not None:
            body["use_local_model"] = use_local_model
        res = self._client.post(
            f"/api/projects/{project_id}/extract",
            json=body,
            headers=self._headers(),
        )
        return self._unwrap(res)

    def list_findings(
        self,
        project_id: str,
        *,
        status: str | None = None,
        severity: str | None = None,
        operation_id: str | None = None,
        cursor: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"cursor": cursor, "limit": limit}
        if status is not None:
            params["status"] = status
        if severity is not None:
            params["severity"] = severity
        if operation_id is not None:
            params["operation_id"] = operation_id
        res = self._client.get(
            f"/api/projects/{project_id}/findings",
            params=params,
        )
        return self._unwrap(res)

    def submit_review_override(
        self,
        project_id: str,
        *,
        expected_revision: int,
        operation_id: str | None,
        target_field: str,
        new_value: Any,
        rationale: str,
        resolve_finding_codes: list[str] | None = None,
    ) -> dict[str, Any]:
        res = self._client.patch(
            f"/api/projects/{project_id}/review",
            json={
                "expected_revision": expected_revision,
                "operation_id": operation_id,
                "target_field": target_field,
                "new_value": new_value,
                "rationale": rationale,
                "resolve_finding_codes": resolve_finding_codes or [],
            },
            headers=self._headers(),
        )
        return self._unwrap(res)

    def freeze_contract(
        self,
        project_id: str,
        *,
        expected_revision: int,
        selected_operation_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"expected_revision": expected_revision}
        if selected_operation_ids is not None:
            body["selected_operation_ids"] = selected_operation_ids
        res = self._client.post(
            f"/api/projects/{project_id}/contracts/freeze",
            json=body,
            headers=self._headers(),
        )
        return self._unwrap(res)

    def create_tool_plan(
        self,
        project_id: str,
        *,
        contract_hash: str,
        selected_operation_ids: list[str] | None = None,
        use_case: str = "default",
        policy_mode: Literal["read_only", "restricted_write", "approval_required"] = "read_only",
        allowed_write_operations: list[str] | None = None,
        disabled_operations: list[str] | None = None,
        preserve_dependencies: bool = False,
        enforce_dependencies: bool = False,
        rewrite_descriptions: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "contract_hash": contract_hash,
            "use_case": use_case,
            "policy_mode": policy_mode,
            "allowed_write_operations": allowed_write_operations or [],
            "disabled_operations": disabled_operations or [],
            "preserve_dependencies": preserve_dependencies,
            "enforce_dependencies": enforce_dependencies,
            "rewrite_descriptions": rewrite_descriptions,
        }
        if selected_operation_ids is not None:
            body["selected_operation_ids"] = selected_operation_ids
        res = self._client.post(
            f"/api/projects/{project_id}/tool-plans",
            json=body,
            headers=self._headers(),
        )
        return self._unwrap(res)

    def suggest_tool_pack(
        self,
        project_id: str,
        *,
        use_case: str,
        seed_operation_ids: list[str] | None = None,
        policy_mode: Literal["read_only", "restricted_write", "approval_required"] = "read_only",
        allowed_write_operations: list[str] | None = None,
        disabled_operations: list[str] | None = None,
        preserve_dependencies: bool = True,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "use_case": use_case,
            "policy_mode": policy_mode,
            "allowed_write_operations": allowed_write_operations or [],
            "disabled_operations": disabled_operations or [],
            "preserve_dependencies": preserve_dependencies,
        }
        if seed_operation_ids is not None:
            body["seed_operation_ids"] = seed_operation_ids
        res = self._client.post(
            f"/api/projects/{project_id}/tool-packs/suggest",
            json=body,
            headers=self._headers(),
        )
        return self._unwrap(res)

    def generate_artifact(
        self,
        project_id: str,
        *,
        plan_hash: str,
        idempotency_key: str | None = None,
        package_slug: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"plan_hash": plan_hash}
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        if package_slug is not None:
            body["package_slug"] = package_slug
        res = self._client.post(
            f"/api/projects/{project_id}/generate",
            json=body,
            headers=self._headers(),
        )
        return self._unwrap(res)

    def validate_artifact(
        self,
        artifact_id: str,
        *,
        suite_profile: Literal["standard", "strict_offline"] = "strict_offline",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"suite_profile": suite_profile}
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        res = self._client.post(
            f"/api/artifacts/{artifact_id}/validate",
            json=body,
            headers=self._headers(),
        )
        return self._unwrap(res)

    def download_artifact_zip(self, artifact_id: str) -> bytes:
        res = self._client.get(f"/api/artifacts/{artifact_id}/download")
        if res.status_code >= 400:
            self._unwrap(res)
        return bytes(res.content)

    def get_job(self, job_id: str) -> dict[str, Any]:
        res = self._client.get(f"/api/jobs/{job_id}")
        return self._unwrap(res)

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        res = self._client.post(
            f"/api/jobs/{job_id}/cancel",
            headers=self._headers(),
        )
        return self._unwrap(res)

    def get_job_events(self, job_id: str, *, cursor: int = 0) -> dict[str, Any]:
        res = self._client.get(
            f"/api/jobs/{job_id}/events",
            params={"cursor": cursor},
        )
        return self._unwrap(res)

    def prepare_approval(
        self,
        project_id: str,
        *,
        operation_id: str,
        arguments: dict[str, Any],
        target_url: str,
        contract_hash: str,
        policy_hash: str,
    ) -> dict[str, Any]:
        res = self._client.post(
            f"/api/projects/{project_id}/approvals/prepare",
            headers=self._headers(),
            json={
                "operation_id": operation_id,
                "arguments": arguments,
                "target_url": target_url,
                "contract_hash": contract_hash,
                "policy_hash": policy_hash,
            },
        )
        return self._unwrap(res)

    def issue_approval(
        self,
        project_id: str,
        *,
        operation_id: str,
        arguments: dict[str, Any],
        target_url: str,
        contract_hash: str,
        policy_hash: str,
        ttl_sec: float = 120.0,
        expected_action_digest: str | None = None,
        human_confirmed: bool = True,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "operation_id": operation_id,
            "arguments": arguments,
            "target_url": target_url,
            "contract_hash": contract_hash,
            "policy_hash": policy_hash,
            "ttl_sec": ttl_sec,
            "human_confirmed": human_confirmed,
        }
        if expected_action_digest is not None:
            payload["expected_action_digest"] = expected_action_digest
        res = self._client.post(
            f"/api/projects/{project_id}/approvals/issue",
            headers=self._headers(),
            json=payload,
        )
        return self._unwrap(res)

    def compare_contracts(
        self,
        project_id: str,
        *,
        old_contract_hash: str | None = None,
        new_contract_hash: str | None = None,
        old_revision: int | None = None,
        new_revision: int | None = None,
        old_plan_hash: str | None = None,
    ) -> dict[str, Any]:
        res = self._client.post(
            f"/api/projects/{project_id}/compare",
            headers=self._headers(),
            json={
                "old_contract_hash": old_contract_hash,
                "new_contract_hash": new_contract_hash,
                "old_revision": old_revision,
                "new_revision": new_revision,
                "old_plan_hash": old_plan_hash,
            },
        )
        return self._unwrap(res)

    def regenerate_project(
        self,
        project_id: str,
        *,
        source_ids: list[str] | None = None,
        old_revision: int | None = None,
        old_contract_hash: str | None = None,
        old_plan_hash: str | None = None,
        use_local_model: bool = False,
    ) -> dict[str, Any]:
        res = self._client.post(
            f"/api/projects/{project_id}/regenerate",
            headers=self._headers(),
            json={
                "source_ids": source_ids,
                "old_revision": old_revision,
                "old_contract_hash": old_contract_hash,
                "old_plan_hash": old_plan_hash,
                "use_local_model": use_local_model,
            },
        )
        return self._unwrap(res)

    def evaluate_project(
        self,
        project_id: str,
        *,
        split: Literal["dev", "held_out"] = "held_out",
        repetitions: int = 1,
    ) -> dict[str, Any]:
        res = self._client.post(
            f"/api/projects/{project_id}/evaluate",
            headers=self._headers(),
            json={
                "split": split,
                "repetitions": repetitions,
            },
        )
        return self._unwrap(res)


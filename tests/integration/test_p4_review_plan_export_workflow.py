"""Phase P4 Integration Tests: Import, Blocker Review, Freeze, ToolPlan, Validation, and Export (T20-T21)."""

from __future__ import annotations

import json
import os
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from fastapi.testclient import TestClient
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from apps.api import LocalApiConfig, SpigotApiClient, SpigotApiError, create_local_app


class AccountsMockOracle:
    """Independent HTTP mock oracle for Phase P4 full product workflow verification."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url: str = ""

    def start(self) -> str:
        oracle = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def _record(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b""
                parsed = urlparse(self.path)
                req = {
                    "method": self.command,
                    "path": parsed.path,
                    "query": parse_qs(parsed.query, keep_blank_values=True),
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": raw_body,
                }
                oracle.requests.append(req)
                return req

            def _send_json(self, status: int, payload: dict[str, Any]) -> None:
                data = json.dumps(payload, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                req = self._record()
                if req["headers"].get("authorization") != "Bearer p4-billing-token":
                    self._send_json(401, {"error": "unauthorized"})
                    return
                if req["path"].startswith("/v1/accounts/"):
                    acc_id = unquote(req["path"][len("/v1/accounts/") :])
                    self._send_json(
                        200,
                        {"account_id": acc_id, "status": "active", "balance_cents": 4200},
                    )
                    return
                self._send_json(404, {"error": "not_found"})

            def do_POST(self) -> None:
                req = self._record()
                if req["headers"].get("authorization") != "Bearer p4-billing-token":
                    self._send_json(401, {"error": "unauthorized"})
                    return
                if req["path"].startswith("/v1/accounts/") and req["path"].endswith("/freeze"):
                    acc_id = unquote(
                        req["path"][len("/v1/accounts/") : -len("/freeze")]
                    )
                    self._send_json(
                        200,
                        {"account_id": acc_id, "status": "frozen"},
                    )
                    return
                self._send_json(404, {"error": "not_found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        host, port = self._server.server_address
        self.base_url = f"http://{host}:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3.0)


@pytest.fixture()
def accounts_oracle():
    oracle = AccountsMockOracle()
    oracle.start()
    yield oracle
    oracle.stop()


@pytest.mark.anyio
async def test_t20_t21_owner_imports_resolves_blocker_freezes_plans_validates_and_exports(
    accounts_oracle: AccountsMockOracle,
    tmp_path: Path,
) -> None:
    """Phase P4 Gate: Multi-file import -> resolve blocker -> freeze -> tool plan -> validate -> export -> MCP call."""
    config = LocalApiConfig(workspace_dir=tmp_path / "p4_workspace")
    app = create_local_app(config)
    raw_http = TestClient(app)
    client = SpigotApiClient(raw_http)
    client.bootstrap_session()

    # 1. Create project and upload multi-file documentation bundle
    proj = client.create_project("Customer Accounts API")
    project_id = proj["project_id"]

    auth_doc = (
        f"# Customer Accounts Overview\n"
        f"Base URL: {accounts_oracle.base_url}\n"
        f"Authentication: Send `Authorization: Bearer <token>` header.\n"
    ).encode()

    endpoints_doc = (
        b"# Accounts Endpoints\n\n"
        b"### GET /v1/accounts/{account_id}\n"
        b"Fetches account status and balance.\n"
        b"- account_id (path, required, string): Account ID\n\n"
        b"### Freeze Account\n"
        b"POST /v1/accounts/{account_id}/freeze freezes an account.\n"
        b"- account_id (path, required, string): Account ID\n"
        b"```bash\n"
        b"curl -X DELETE http://127.0.0.1:9999/v1/accounts/{account_id}\n"
        b"```\n\n"
        b"### Legacy Endpoint\n"
        b"Endpoint: /v1/accounts/legacy\n"
        b"Legacy archive endpoint without a documented method.\n"
    )

    up_res = client.upload_sources(
        project_id,
        [
            ("overview.md", auth_doc),
            ("endpoints.md", endpoints_doc),
        ],
    )
    assert len(up_res["source_ids"]) == 2
    assert up_res["current_revision"] == 1

    # 2. Run extraction job and verify job state persists across page refresh (`get_project`)
    ext_job = client.extract_project(project_id, use_local_model=False)
    assert ext_job["status"] == "NEEDS_REVIEW"
    assert ext_job["result"]["open_blocker_count"] == 3

    refreshed = client.get_project(project_id)
    assert refreshed["current_revision"] == 1
    assert refreshed["is_contract_frozen"] is False
    assert refreshed["jobs"][0]["job_id"] == ext_job["job_id"]
    assert refreshed["jobs"][0]["status"] == "NEEDS_REVIEW"

    # 3. Inspect open blocker findings and their source-linked evidence quotes
    findings_res = client.list_findings(project_id, status="open", severity="blocker")
    assert findings_res["total_count"] == 3
    by_code = {f["code"]: f for f in findings_res["findings"]}
    assert "CONFLICTING_METHOD_PATH" in by_code
    assert "MISSING_METHOD" in by_code
    assert "UNKNOWN_SEMANTIC_EFFECT" in by_code

    conflict_finding = by_code["CONFLICTING_METHOD_PATH"]
    assert conflict_finding["operation_id"] == "post_v1_accounts_account_id_freeze"
    assert len(conflict_finding["evidence_details"]) >= 2

    # 4. Attempting to freeze contract with the blocked operation selected fails with 422
    with pytest.raises(SpigotApiError) as freeze_err:
        client.freeze_contract(
            project_id,
            expected_revision=1,
            selected_operation_ids=[
                "get_v1_accounts_account_id",
                "post_v1_accounts_account_id_freeze",
            ],
        )
    assert freeze_err.value.status_code == 422
    assert freeze_err.value.envelope.code == "CONTRACT_INCOMPLETE"

    # 5. Owner resolves CONFLICTING_METHOD_PATH on post_v1_accounts_account_id_freeze
    review_res = client.submit_review_override(
        project_id,
        expected_revision=1,
        operation_id="post_v1_accounts_account_id_freeze",
        target_field="method_path",
        new_value={
            "method": "POST",
            "relative_path": "/v1/accounts/{account_id}/freeze",
        },
        rationale="Confirmed POST /v1/accounts/{account_id}/freeze with Accounts team.",
    )
    assert review_res["revision"] == 2
    ops_by_id = {op["stable_id"]: op for op in review_res["contract"]["operations"]}
    assert ops_by_id["post_v1_accounts_account_id_freeze"]["support_status"] == "supported"

    # 6. Stale revision precondition check returns 409 Conflict (REVISION_CONFLICT)
    with pytest.raises(SpigotApiError) as stale_err:
        client.submit_review_override(
            project_id,
            expected_revision=1,
            operation_id="post_v1_accounts_account_id_freeze",
            target_field="method",
            new_value="POST",
            rationale="Stale edit using old revision 1.",
        )
    assert stale_err.value.status_code == 409
    assert stale_err.value.envelope.code == "REVISION_CONFLICT"

    # 7. Freeze contract at revision 2 (selecting the 2 supported operations and excluding the blocked legacy op)
    freeze_res = client.freeze_contract(
        project_id,
        expected_revision=2,
        selected_operation_ids=[
            "get_v1_accounts_account_id",
            "post_v1_accounts_account_id_freeze",
        ],
    )
    assert freeze_res["is_frozen"] is True
    assert freeze_res["revision"] == 2
    contract_hash = freeze_res["canonical_hash"]
    assert "op_v1_accounts_legacy" in freeze_res["blocked_operation_ids"]

    # 8. Create ToolPlan with restricted_write allowing post_v1_accounts_account_id_freeze
    plan_res = client.create_tool_plan(
        project_id,
        contract_hash=contract_hash,
        selected_operation_ids=[
            "get_v1_accounts_account_id",
            "post_v1_accounts_account_id_freeze",
        ],
        policy_mode="restricted_write",
        allowed_write_operations=["post_v1_accounts_account_id_freeze"],
    )
    plan_hash = plan_res["tool_plan"]["plan_hash"]
    assert set(plan_res["tool_plan"]["operation_ids"]) == {
        "get_v1_accounts_account_id",
        "post_v1_accounts_account_id_freeze",
    }

    # 9. Generate server package and validate artifact
    gen_job = client.generate_artifact(
        project_id,
        plan_hash=plan_hash,
        package_slug="accounts_mcp_server",
    )
    assert gen_job["status"] == "SUCCEEDED"
    artifact_id = gen_job["result"]["artifact_id"]

    val_job = client.validate_artifact(artifact_id, suite_profile="strict_offline")
    assert val_job["status"] == "SUCCEEDED"
    val_report = val_job["result"]["validation_report"]
    checks_by_name = {c["check_name"]: c["status"] for c in val_report["checks"]}
    assert checks_by_name["build_status"] == "passed"
    assert checks_by_name["static_check_status"] == "passed"
    assert checks_by_name["protocol_check_status"] == "passed"
    assert checks_by_name["sandbox_status"] == "unavailable"
    assert checks_by_name["live_smoke_status"] == "skipped"

    # 10. Download verified ZIP and execute both read & write tools over real MCP stdio
    zip_bytes = client.download_artifact_zip(artifact_id)
    zip_path = tmp_path / "exported_accounts.zip"
    zip_path.write_bytes(zip_bytes)

    unpacked_dir = tmp_path / "unpacked_accounts"
    unpacked_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(unpacked_dir)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(unpacked_dir)
    env["PYTHONUTF8"] = "1"
    env["SPIGOT_CRED_BEARER_AUTH"] = "p4-billing-token"

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "accounts_mcp_server.server"],
        cwd=str(unpacked_dir),
        env=env,
    )
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools_list = await session.list_tools()
            tool_names = {t.name for t in tools_list.tools}
            assert tool_names == {
                "get_v1_accounts_account_id",
                "post_v1_accounts_account_id_freeze",
            }

            read_call = await session.call_tool(
                "get_v1_accounts_account_id", {"account_id": "ACC-900"}
            )
            assert read_call.is_error is False
            read_payload = json.loads(read_call.content[0].text)
            assert read_payload["status_code"] == 200
            assert read_payload["data"]["account_id"] == "ACC-900"
            assert read_payload["data"]["balance_cents"] == 4200

            write_call = await session.call_tool(
                "post_v1_accounts_account_id_freeze", {"account_id": "ACC-900"}
            )
            assert write_call.is_error is False
            write_payload = json.loads(write_call.content[0].text)
            assert write_payload["status_code"] == 200
            assert write_payload["data"]["status"] == "frozen"

    # 11. Uploading a new source file increments project revision and invalidates frozen state
    client.upload_sources(
        project_id,
        [("changelog.md", b"# Changelog\nAdded audit notes.\n")],
    )
    after_source_change = client.get_project(project_id)
    assert after_source_change["current_revision"] == 3
    assert after_source_change["is_contract_frozen"] is False
    assert after_source_change["tool_plan"] is None
    assert after_source_change["latest_artifact"] is None

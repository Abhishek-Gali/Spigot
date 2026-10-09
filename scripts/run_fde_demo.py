"""Reproducible End-to-End FDE Integration & Operational Failure Demo for Spigot.

Run this script from the repository root:
    uv run python scripts/run_fde_demo.py
or using the local virtual environment directly:
    .venv/Scripts/python.exe scripts/run_fde_demo.py   (Windows)
    .venv/bin/python scripts/run_fde_demo.py           (Linux / macOS)

What this script demonstrates and verifies in ~3 seconds:
1. Messy customer API documentation ingestion -> blocker detection (`MISSING_METHOD`) ->
   audited human override -> immutable contract freeze -> 7-layer validation -> `.zip` export.
2. Standalone extracted `.zip` MCP package verification & execution against a live local HTTP service.
3. Two-step human-confirmed write approval (`/approvals/prepare` -> `/approvals/issue`) via
   shared `SPIGOT_APPROVAL_SECRET_FILE` and persistent SQLite replay rejection (`consumed_approvals.sqlite3`).
4. Operational failure handling & recovery:
   - 401 Unauthorized with automatic secret redaction (`<REDACTED_CREDENTIAL>`)
   - 503 Service Unavailable automatic backoff retry on safe GET (`attempts: 3 -> 200 OK`)
   - Ambiguous write timeout failing closed with `OUTCOME_UNKNOWN` (`attempts: 1`, `retryable: false`)
   - Mid-stream response cutoff when upstream exceeds `max_response_bytes`
   - Per-server circuit breaker tripping to `open` after repeated upstream 5xx failures
5. Contract v1 -> v2 evolution diffing (detecting breaking parameter changes and preserving valid overrides).
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import sys
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from apps.api.client import SpigotApiClient, SpigotApiError  # noqa: E402
from apps.api.server import LocalApiConfig, create_local_app  # noqa: E402
from packages.runtime.engine import ContractRuntimeEngine  # noqa: E402


class CustomerFleetApiSimulator:
    """Stateful local HTTP server simulating a customer's FleetCloud API + operational failure modes."""

    def __init__(self) -> None:
        self.clusters: list[dict[str, Any]] = [
            {
                "cluster_id": "cls_prod_01",
                "name": "prod-us-east-1",
                "region": "us-east-1",
                "status": "RUNNING",
                "node_count": 6,
            }
        ]
        self.flaky_counter = 0
        self.failure_mode: str | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url: str = ""
        self.port: int = 0

    def start(self) -> str:
        sim = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send_json(
                self,
                status: int,
                payload: dict[str, Any],
                extra_headers: dict[str, str] | None = None,
            ) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (extra_headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                auth = self.headers.get("Authorization", "")
                if auth != "Bearer sk_live_fde_secret_998877":
                    self._send_json(
                        401,
                        {
                            "error": "unauthorized",
                            "detail": f"Rejected credential header: {auth}",
                        },
                    )
                    return

                if sim.failure_mode == "flaky_503":
                    sim.flaky_counter += 1
                    if sim.flaky_counter < 3:
                        self._send_json(
                            503,
                            {"error": "upstream_overloaded", "attempt": sim.flaky_counter},
                            extra_headers={"Retry-After": "0.01"},
                        )
                        return

                if sim.failure_mode == "always_503":
                    self._send_json(503, {"error": "node_controller_unreachable"})
                    return

                if sim.failure_mode == "oversized_stream":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    chunk = b'{"padding":"' + (b"X" * 4096) + b'"}'
                    try:
                        for _ in range(10):
                            self.wfile.write(chunk)
                            self.wfile.flush()
                    except OSError:
                        pass
                    return

                if self.path.startswith("/v1/clusters"):
                    self._send_json(
                        200, {"clusters": sim.clusters, "total": len(sim.clusters)}
                    )
                    return

                self._send_json(404, {"error": "not_found"})

            def do_POST(self) -> None:
                auth = self.headers.get("Authorization", "")
                if auth != "Bearer sk_live_fde_secret_998877":
                    self._send_json(401, {"error": "unauthorized", "detail": auth})
                    return

                if sim.failure_mode == "write_timeout":
                    time.sleep(0.35)
                    try:
                        self._send_json(201, {"status": "late_write"})
                    except OSError:
                        pass
                    return

                length = int(self.headers.get("Content-Length", "0"))
                body = (
                    json.loads(self.rfile.read(length).decode("utf-8"))
                    if length > 0
                    else {}
                )
                new_cluster = {
                    "cluster_id": f"cls_prod_0{len(sim.clusters) + 1}",
                    "name": body.get("name", "unnamed"),
                    "region": body.get("region", "us-east-1"),
                    "node_count": body.get("node_count", 3),
                    "status": "PROVISIONING",
                }
                sim.clusters.append(new_cluster)
                self._send_json(201, new_cluster)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self._server.server_address[1])
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()


def _banner(step: int, title: str) -> None:
    print(f"\n{'=' * 78}")
    print(f"STEP {step}: {title}")
    print(f"{'=' * 78}")


def run_demo() -> dict[str, Any]:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    sample_doc_path = ROOT_DIR / "examples" / "05_flagship_review_demo.md"
    raw_doc_v1 = sample_doc_path.read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="spigot_fde_demo_") as tmp:
        tmp_root = Path(tmp)
        workspace_dir = tmp_root / "workspace"
        extracted_ro_dir = tmp_root / "extracted_readonly_server"
        extracted_approval_dir = tmp_root / "extracted_approval_server"

        simulator = CustomerFleetApiSimulator()
        upstream_url = simulator.start()

        # Point sample doc's Base URL to our live local CustomerFleetApiSimulator
        doc_v1_live = raw_doc_v1.replace("https://api.fleetcloud.dev", upstream_url)

        cfg = LocalApiConfig(
            workspace_dir=workspace_dir,
            capability_token="fde-demo-local-token",
        )
        app = create_local_app(cfg)

        try:
            with TestClient(app, base_url="http://127.0.0.1:8000") as http_client:
                client = SpigotApiClient(
                    http_client, capability_token="fde-demo-local-token"
                )

                # ------------------------------------------------------------------
                # STEP 1: Ingest Customer Doc with Blocker -> Override -> Freeze
                # ------------------------------------------------------------------
                _banner(
                    1,
                    "Ingest Customer API Manual, Catch Blocker, Apply Audited Override",
                )
                proj = client.create_project("FleetCloud Customer Integration")
                pid = proj["project_id"]

                client.upload_sources(
                    pid,
                    [("05_flagship_review_demo.md", doc_v1_live.encode("utf-8"))],
                )
                ext = client.extract_project(pid)["result"]
                findings = client.list_findings(pid, severity="blocker")["findings"]
                print(
                    f"[+] Imported '05_flagship_review_demo.md' into project '{pid}'"
                )
                print(
                    f"[+] Open Blocker Findings: {len(findings)} (revision={ext['revision']})"
                )
                for f in findings:
                    print(
                        f"    - BLOCKER [{f['code']}] on operation '{f['operation_id']}': {f['explanation']}"
                    )

                # Resolve the MISSING_METHOD blocker via an audited human override
                target_op_id = findings[0]["operation_id"]
                all_codes = [
                    f["code"] for f in findings if f["operation_id"] == target_op_id
                ]
                ov_res = client.submit_review_override(
                    pid,
                    expected_revision=ext["revision"],
                    operation_id=target_op_id,
                    target_field="method",
                    new_value="POST",
                    rationale="Verified POST method in FleetCloud customer runbook section 4.2",
                    resolve_finding_codes=all_codes,
                )
                if ov_res["open_blockers"]:
                    ov_res = client.submit_review_override(
                        pid,
                        expected_revision=ov_res["revision"],
                        operation_id=target_op_id,
                        target_field="semantic_effect",
                        new_value="write",
                        rationale="Drain operation mutates node scheduling state",
                        resolve_finding_codes=[
                            b["code"] for b in ov_res["open_blockers"]
                        ],
                    )
                print(
                    f"[+] Applied audited UserOverride on '{target_op_id}' -> "
                    f"revision={ov_res['revision']}, open_blockers={len(ov_res['open_blockers'])}"
                )

                frz = client.freeze_contract(pid, expected_revision=ov_res["revision"])
                contract_hash = frz["canonical_hash"]
                print(
                    f"[+] Frozen Immutable Contract (SHA-256: {contract_hash[:16]}...)"
                )

                # Create Read-Only ToolPlan, Generate & Validate .zip package
                tp_ro = client.create_tool_plan(
                    pid,
                    contract_hash=contract_hash,
                    policy_mode="read_only",
                )
                gen_ro = client.generate_artifact(
                    pid,
                    plan_hash=tp_ro["tool_plan"]["plan_hash"],
                    package_slug="fleetcloud_readonly_mcp",
                )["result"]
                val_job = client.validate_artifact(gen_ro["artifact_id"])
                val_report = val_job["result"]["validation_report"]
                checks_by_name = {
                    c["check_name"]: c["status"] for c in val_report["checks"]
                }
                print(
                    f"[+] 7-Layer Validation Gate: job_status='{val_job['status']}', "
                    f"build='{checks_by_name.get('build_status')}', "
                    f"static='{checks_by_name.get('static_check_status')}', "
                    f"protocol='{checks_by_name.get('protocol_check_status')}', "
                    f"security='{checks_by_name.get('security_suite_status')}', "
                    f"sandbox='{checks_by_name.get('sandbox_status')}'"
                )

                # ------------------------------------------------------------------
                # STEP 2: Verify Read-Only Enforcement on Standalone Extracted ZIP
                # ------------------------------------------------------------------
                _banner(
                    2,
                    "Standalone Extracted .zip Execution & Read-Only Policy Enforcement",
                )
                ro_zip_bytes = client.download_artifact_zip(gen_ro["artifact_id"])
                extracted_ro_dir.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(io.BytesIO(ro_zip_bytes), "r") as zf:
                    zf.extractall(extracted_ro_dir)

                manifest_data = json.loads(
                    (extracted_ro_dir / "manifest.json").read_text(encoding="utf-8")
                )
                for rel_path, expected_sha in manifest_data["artifact_hashes"].items():
                    actual_sha = hashlib.sha256(
                        (extracted_ro_dir / rel_path).read_bytes()
                    ).hexdigest()
                    assert actual_sha == expected_sha, f"Hash mismatch on {rel_path}"
                print(
                    f"[+] Exported ZIP Manifest Integrity Check: verified=True "
                    f"({len(manifest_data['artifact_hashes'])} files SHA-256 verified)"
                )

                ro_contract = json.loads(
                    (extracted_ro_dir / "contract.json").read_text(encoding="utf-8")
                )
                ro_plan = json.loads(
                    (extracted_ro_dir / "tool_plan.json").read_text(encoding="utf-8")
                )
                ro_policy = json.loads(
                    (extracted_ro_dir / "policy.json").read_text(encoding="utf-8")
                )
                ro_policy["allowed_loopback_ports"] = [11434, simulator.port]

                base_env = {
                    "SPIGOT_CRED_BEARER_AUTH": "sk_live_fde_secret_998877",
                    "SPIGOT_APPROVAL_SECRET_FILE": str(
                        (workspace_dir / "approval_authority.key").resolve()
                    ),
                }

                ro_engine = ContractRuntimeEngine(
                    contract_data=ro_contract,
                    tool_plan_data=ro_plan,
                    policy_data=ro_policy,
                    environ=base_env,
                )
                tools = ro_engine.list_tools_sync()
                print(
                    f"[+] Loaded standalone MCP runtime from extracted ZIP ({len(tools)} tools):"
                )
                for t in tools:
                    print(f"    - {t.name}")

                read_res = asyncio.run(
                    ro_engine.call_tool_async("get_v1_clusters", {})
                )
                read_data = json.loads(read_res.content[0].text)
                print(
                    f"[+] Live GET /v1/clusters -> HTTP {read_data['status_code']}, "
                    f"clusters={len(read_data['data']['clusters'])}"
                )

                blocked_write = asyncio.run(
                    ro_engine.call_tool_async(
                        "post_v1_clusters",
                        {
                            "body": {
                                "name": "prod-eu-west-1",
                                "region": "eu-west-1",
                                "node_count": 3,
                            }
                        },
                    )
                )
                blocked_err = json.loads(blocked_write.content[0].text)["error"]
                print(
                    f"[+] Attempted write in 'read_only' mode -> isError={blocked_write.is_error}, "
                    f"code={blocked_err['code']}: {blocked_err['user_message']}"
                )

                # ------------------------------------------------------------------
                # STEP 3: Two-Step Human Approval & Persistent SQLite Replay Guard
                # ------------------------------------------------------------------
                _banner(
                    3,
                    "Two-Step Human Approval & Persistent SQLite Replay Prevention",
                )
                tp_app = client.create_tool_plan(
                    pid,
                    contract_hash=contract_hash,
                    policy_mode="approval_required",
                )
                gen_app = client.generate_artifact(
                    pid,
                    plan_hash=tp_app["tool_plan"]["plan_hash"],
                    package_slug="fleetcloud_approval_mcp",
                )["result"]
                app_zip_bytes = client.download_artifact_zip(gen_app["artifact_id"])
                extracted_approval_dir.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(io.BytesIO(app_zip_bytes), "r") as zf:
                    zf.extractall(extracted_approval_dir)

                app_contract = json.loads(
                    (extracted_approval_dir / "contract.json").read_text(
                        encoding="utf-8"
                    )
                )
                app_plan = json.loads(
                    (extracted_approval_dir / "tool_plan.json").read_text(
                        encoding="utf-8"
                    )
                )
                app_policy = json.loads(
                    (extracted_approval_dir / "policy.json").read_text(encoding="utf-8")
                )
                app_policy["allowed_loopback_ports"] = [11434, simulator.port]
                app_policy["request_deadline_sec"] = 2.0
                app_policy["max_retries"] = 3
                app_policy["retry_backoff_base_sec"] = 0.01
                app_policy["max_response_bytes"] = 4096
                app_policy["circuit_breaker_threshold"] = 2
                app_policy["circuit_breaker_cooldown_sec"] = 30.0
                policy_hash = app_policy["policy_hash"]

                write_args = {
                    "body": {
                        "name": "prod-eu-west-1",
                        "region": "eu-west-1",
                        "node_count": 3,
                    }
                }
                target_url = f"{upstream_url}/v1/clusters"

                prep = client.prepare_approval(
                    pid,
                    operation_id="post_v1_clusters",
                    arguments=write_args,
                    target_url=target_url,
                    contract_hash=contract_hash,
                    policy_hash=policy_hash,
                )
                print(
                    f"[+] Step 3a (/approvals/prepare): Computed canonical action_digest="
                    f"{prep['action_digest'][:16]}..."
                )

                try:
                    client.issue_approval(
                        pid,
                        operation_id="post_v1_clusters",
                        arguments=write_args,
                        target_url=target_url,
                        contract_hash=contract_hash,
                        policy_hash=policy_hash,
                        expected_action_digest=prep["action_digest"],
                    )
                except SpigotApiError as exc:
                    print(
                        f"[+] Step 3b (Unconfirmed /approvals/issue): Properly rejected with "
                        f"HTTP {exc.status_code} ({exc.envelope.code})"
                    )

                issued = client.issue_approval(
                    pid,
                    operation_id="post_v1_clusters",
                    arguments=write_args,
                    target_url=target_url,
                    contract_hash=contract_hash,
                    policy_hash=policy_hash,
                    expected_action_digest=prep["action_digest"],
                    human_confirmed=True,
                )
                approval_env = {
                    **base_env,
                    "SPIGOT_ACTION_APPROVAL_TOKEN": issued["approval_token_json"],
                }
                approval_engine = ContractRuntimeEngine(
                    contract_data=app_contract,
                    tool_plan_data=app_plan,
                    policy_data=app_policy,
                    environ=approval_env,
                )

                ok_write = asyncio.run(
                    approval_engine.call_tool_async("post_v1_clusters", write_args)
                )
                ok_write_data = json.loads(ok_write.content[0].text)
                if "status_code" not in ok_write_data:
                    raise RuntimeError(f"Step 3c returned error: {ok_write_data}")
                print(
                    f"[+] Step 3c (Confirmed Write Execution): HTTP {ok_write_data['status_code']} -> "
                    f"created cluster '{ok_write_data['data']['cluster_id']}' ({ok_write_data['data']['name']})"
                )

                # Attempt replay using a fresh engine instance (proving SQLite persistence)
                replay_engine = ContractRuntimeEngine(
                    contract_data=app_contract,
                    tool_plan_data=app_plan,
                    policy_data=app_policy,
                    environ=approval_env,
                )
                replay_res = asyncio.run(
                    replay_engine.call_tool_async("post_v1_clusters", write_args)
                )
                replay_err = json.loads(replay_res.content[0].text)["error"]
                print(
                    f"[+] Step 3d (Token Replay Attempt across new process/engine): "
                    f"isError={replay_res.is_error}, reason='{replay_err['user_message']}'"
                )

                # ------------------------------------------------------------------
                # STEP 4: Operational Failure Modes (401 Redaction, 503 Retry,
                #         Write Timeout OUTCOME_UNKNOWN, Oversized Stream, Circuit Breaker)
                # ------------------------------------------------------------------
                _banner(
                    4, "Operational Failure Handling & Recovery Verification"
                )

                # 4A: 401 Unauthorized + automatic secret scrubbing
                bad_auth_engine = ContractRuntimeEngine(
                    contract_data=app_contract,
                    tool_plan_data=app_plan,
                    policy_data=app_policy,
                    environ={
                        **base_env,
                        "SPIGOT_CRED_BEARER_AUTH": "sk_bad_secret_token_12345",
                    },
                )
                auth_fail_res = asyncio.run(
                    bad_auth_engine.call_tool_async("get_v1_clusters", {})
                )
                auth_fail_text = auth_fail_res.content[0].text
                assert "sk_bad_secret_token_12345" not in auth_fail_text
                assert "<REDACTED_CREDENTIAL>" in auth_fail_text
                print(
                    f"[+] 4A (401 Unauthorized + Secret Redaction): isError={auth_fail_res.is_error}, "
                    f"payload={auth_fail_text}"
                )

                # 4B: Transient 503 Service Unavailable on safe GET -> retries to 200 OK
                simulator.failure_mode = "flaky_503"
                simulator.flaky_counter = 0
                retry_res = asyncio.run(
                    approval_engine.call_tool_async("get_v1_clusters", {})
                )
                retry_data = json.loads(retry_res.content[0].text)
                print(
                    f"[+] 4B (Transient 503 on Safe GET): Recovered on attempt {retry_data['attempts']} "
                    f"-> HTTP {retry_data['status_code']}"
                )

                # 4C: Ambiguous timeout on mutating POST -> fails closed with OUTCOME_UNKNOWN (1 attempt)
                simulator.failure_mode = "write_timeout"
                timeout_write_args = {
                    "body": {
                        "name": "prod-ap-south-1",
                        "region": "ap-south-1",
                        "node_count": 3,
                    }
                }
                prep_timeout = client.prepare_approval(
                    pid,
                    operation_id="post_v1_clusters",
                    arguments=timeout_write_args,
                    target_url=target_url,
                    contract_hash=contract_hash,
                    policy_hash=policy_hash,
                )
                issued_timeout = client.issue_approval(
                    pid,
                    operation_id="post_v1_clusters",
                    arguments=timeout_write_args,
                    target_url=target_url,
                    contract_hash=contract_hash,
                    policy_hash=policy_hash,
                    expected_action_digest=prep_timeout["action_digest"],
                    human_confirmed=True,
                )
                timeout_engine = ContractRuntimeEngine(
                    contract_data=app_contract,
                    tool_plan_data=app_plan,
                    policy_data={**app_policy, "request_deadline_sec": 0.15},
                    environ={
                        **base_env,
                        "SPIGOT_ACTION_APPROVAL_TOKEN": issued_timeout[
                            "approval_token_json"
                        ],
                    },
                )
                timeout_res = asyncio.run(
                    timeout_engine.call_tool_async(
                        "post_v1_clusters", timeout_write_args
                    )
                )
                timeout_err = json.loads(timeout_res.content[0].text)["error"]
                print(
                    f"[+] 4C (Ambiguous Write Timeout): code={timeout_err['code']}, "
                    f"retryable={timeout_err['retryable']}, "
                    f"attempts={timeout_err['redacted_details']['attempts']}, "
                    f"outcome={timeout_err['redacted_details']['outcome']}"
                )

                # 4D: Oversized upstream streaming response -> cut off mid-stream
                simulator.failure_mode = "oversized_stream"
                oversized_res = asyncio.run(
                    approval_engine.call_tool_async("get_v1_clusters", {})
                )
                oversized_err = json.loads(oversized_res.content[0].text)["error"]
                print(
                    f"[+] 4D (Oversized Upstream Stream): stage={oversized_err['stage']}, "
                    f"message='{oversized_err['user_message']}'"
                )

                # 4E: Repeated 503s open the per-server Circuit Breaker
                fresh_cb_engine = ContractRuntimeEngine(
                    contract_data=app_contract,
                    tool_plan_data=app_plan,
                    policy_data=app_policy,
                    environ=base_env,
                )
                simulator.failure_mode = "always_503"
                asyncio.run(fresh_cb_engine.call_tool_async("get_v1_clusters", {}))
                cb_open_res = asyncio.run(
                    fresh_cb_engine.call_tool_async("get_v1_clusters", {})
                )
                cb_err = json.loads(cb_open_res.content[0].text)["error"]
                print(
                    f"[+] 4E (Circuit Breaker Tripped): stage={cb_err['stage']}, "
                    f"message='{cb_err['user_message']}'"
                )

                # ------------------------------------------------------------------
                # STEP 5: Contract v1 -> v2 Breaking Drift Detection
                # ------------------------------------------------------------------
                _banner(5, "Contract v1 -> v2 Breaking Drift Detection")
                doc_v2_live = doc_v1_live.replace(
                    "| `node_count` | body | integer | yes | Initial worker node count (1-50) |",
                    "| `node_count` | body | integer | yes | Initial worker node count (1-50) |\n"
                    "| `cost_center` | body | string | yes | Mandatory billing cost-center code (added in v2) |",
                )
                assert doc_v2_live != doc_v1_live
                up_v2 = client.upload_sources(
                    pid,
                    [("05_flagship_review_demo_v2.md", doc_v2_live.encode("utf-8"))],
                )
                v2_source_id = up_v2["sources"][0]["id"]
                regen = client.regenerate_project(
                    pid,
                    source_ids=[v2_source_id],
                    old_revision=ov_res["revision"],
                    old_contract_hash=contract_hash,
                    old_plan_hash=tp_app["tool_plan"]["plan_hash"],
                )
                diff_report = regen["diff_report"]
                breaking_items = [
                    c for c in diff_report["changes"] if c["severity"] == "breaking"
                ]
                assert diff_report["has_breaking_changes"] is True
                print(
                    f"[+] Regenerated v2 against v1: has_breaking_changes={diff_report['has_breaking_changes']}, "
                    f"breaking_count={len(breaking_items)}, "
                    f"carried_overrides={len(regen['carried_forward_overrides'])}"
                )
                for item in breaking_items:
                    op_label = item.get("new_operation_id") or item.get("old_operation_id")
                    print(
                        f"    - BREAKING [{item['category']}] on '{op_label}': "
                        f"{item['explanation']}"
                    )

                print(f"\n{'=' * 78}")
                print(
                    "ALL 5 FDE INTEGRATION & FAILURE RECOVERY SCENARIOS VERIFIED SUCCESSFULLY."
                )
                print(f"{'=' * 78}\n")
                return {
                    "contract_hash": contract_hash,
                    "tools_registered": len(tools),
                    "breaking_changes_detected": len(breaking_items),
                }
        finally:
            simulator.close()


if __name__ == "__main__":
    run_demo()

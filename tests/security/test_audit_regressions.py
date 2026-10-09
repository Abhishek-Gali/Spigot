"""Source-Level Security & Resource Audit Regression Suite.

Covers all findings from the source-level code audit:
1. Finding 1: Loopback port allowlisting in `NetworkPolicyGuard` and `ContractRuntimeEngine`.
2. Finding 2: DNS-pinned HTTP transport (`PinnedDNSAsyncTransport`) preventing DNS rebinding TOCTOU.
3. Finding 3: Re-entrant, thread-safe `enforce_socket_guard` stack across nested contexts.
4. Finding 4: Streaming response byte cap (`max_response_bytes`) enforced during chunk iteration.
5. Finding 5: Streaming/chunked upload size, file count (`MAX_UPLOAD_FILES`), and aggregate byte limits.
6. Finding 6: Default persistent SQLite approval ledger, fail-closed errors, and >=16-char secret.
7. Finding 7: `/approvals/prepare` and `/approvals/issue` validate project, contract, plan, and URL.
8. Finding 8: Generated `.env.example` includes approval secret, ledger path, and token vars.
9. Finding 9: `export_reproducible_zip` and `IsolatedValidationWorker` reject unmanifested files.
10. Storage fault-injection: mid-transaction rollback and corrupted blob detection (`ArtifactIntegrityError`).
"""

from __future__ import annotations

import io
import json
import socket
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from apps.api import server as api_server_mod
from apps.api.client import SpigotApiClient, SpigotApiError
from apps.api.server import LocalApiConfig, create_local_app
from packages.core.approval import ApprovalAuthority
from packages.core.contracts import (
    ApiContract,
    OperationContract,
    SecurityRequirement,
    ServerContract,
)
from packages.core.network_guard import (
    EgressDeniedError,
    NetworkPolicyGuard,
    NetworkProfile,
)
from packages.core.planning import RuntimePolicy, create_tool_plan
from packages.core.storage import ArtifactIntegrityError, SpigotStorage
from packages.runtime.engine import (
    ContractRuntimeEngine,
    PinnedDNSAsyncTransport,
    validate_url_against_policy,
)
from packages.templates.generator import (
    export_reproducible_zip,
    generate_server_package,
)
from workers.validation_worker import IsolatedValidationWorker


def test_finding_1_loopback_port_allowlist_in_guard_and_runtime() -> None:
    """Unregistered loopback ports are denied by default in both NetworkPolicyGuard and runtime engine."""
    guard = NetworkPolicyGuard(profile=NetworkProfile.STRICT_OFFLINE)
    assert guard.allow_any_loopback_port is False

    # Registered default Ollama port (11434) is permitted
    guard.validate_url("http://127.0.0.1:11434/api/tags")
    guard.validate_url("http://localhost:11434/api/generate")

    # Unregistered local service ports (e.g., Redis 6379, Admin 8080) are rejected
    for blocked_local in [
        "http://127.0.0.1:6379/info",
        "http://localhost:8080/admin",
        "http://[::1]:9200/_cluster/health",
    ]:
        with pytest.raises(EgressDeniedError, match="registered loopback ports"):
            guard.validate_url(blocked_local)

    # Explicitly registering a mock oracle port permits that port only
    guard.register_loopback_port(54321)
    guard.validate_url("http://127.0.0.1:54321/v1/health")

    # Runtime validate_url_against_policy also enforces allowed_loopback_ports in both profiles
    for profile in ("STRICT_OFFLINE", "CONNECTED_SERVICES"):
        with pytest.raises(PermissionError, match="allowed_loopback_ports"):
            validate_url_against_policy(
                "http://127.0.0.1:6379/v1/keys",
                {"network_profile": profile},
            )
        pinned_ip = validate_url_against_policy(
            "http://localhost:11434/api/tags",
            {"network_profile": profile},
        )
        assert pinned_ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_finding_1_runtime_blocks_unregistered_loopback_env_override() -> None:
    """Env override SPIGOT_SERVER_URL_* targeting an unregistered local port is blocked by policy."""
    contract_data = {
        "schema_version": "1.0",
        "id": "ct_local_port_guard",
        "canonical_hash": "a" * 64,
        "servers": [{"server_id": "srv_main", "base_url": "http://127.0.0.1:18123"}],
        "security_schemes": [],
        "operations": [
            {
                "stable_id": "get_ping",
                "display_name": "Ping",
                "method": "GET",
                "relative_path": "/ping",
                "server_ref": "srv_main",
                "parameters": [],
                "semantic_effect": "read",
                "support_status": "supported",
                "security_requirement": {"status": "public", "alternatives": []},
            }
        ],
    }
    plan_data = {
        "operation_ids": ["get_ping"],
        "tool_names": {"get_ping": "get_ping"},
        "descriptions": {"get_ping": "Ping"},
    }
    policy_data = {"id": "pol_1", "mode": "read_only", "network_profile": "STRICT_OFFLINE"}

    engine = ContractRuntimeEngine(
        contract_data=contract_data,
        tool_plan_data=plan_data,
        policy_data=policy_data,
        environ={"SPIGOT_SERVER_URL_SRV_MAIN": "http://127.0.0.1:6379"},
    )
    res = await engine.call_tool_async("get_ping", {})
    assert res.is_error is True
    err = json.loads(res.content[0].text)["error"]
    assert err["code"] == "POLICY_DENIED"
    assert err["stage"] == "network_policy"
    assert "6379" in err["user_message"]


@pytest.mark.asyncio
async def test_finding_2_dns_pinning_and_rebinding_protection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PinnedDNSAsyncTransport pins connection host to verified IP and blocks DNS rebinding."""
    captured_requests: list[httpx.Request] = []

    class CapturingInnerTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(200, json={"ok": True}, request=request)

    # 1. Verify hostname is resolved once, pinned to literal IP, and Host + SNI are preserved
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
        ],
    )
    policy = {
        "network_profile": "CONNECTED_SERVICES",
        "allowed_origins": ["https://api.partner.example"],
    }
    transport = PinnedDNSAsyncTransport(policy, inner=CapturingInnerTransport())
    req = httpx.Request("GET", "https://api.partner.example/v1/orders")
    resp = await transport.handle_async_request(req)
    assert resp.status_code == 200
    assert len(captured_requests) == 1
    pinned_req = captured_requests[0]
    assert pinned_req.url.host == "93.184.216.34"
    assert pinned_req.headers["Host"] == "api.partner.example"
    assert pinned_req.extensions.get("sni_hostname") == "api.partner.example"

    # 2. Simulate DNS rebinding: first resolution returns public IP, second returns 127.0.0.1
    dns_answers = iter(
        [
            [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
            [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
        ]
    )
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **kw: next(dns_answers))

    contract_data = {
        "schema_version": "1.0",
        "id": "ct_rebind",
        "canonical_hash": "a" * 64,
        "servers": [{"server_id": "srv_ext", "base_url": "https://api.partner.example"}],
        "security_schemes": [],
        "operations": [
            {
                "stable_id": "get_orders",
                "display_name": "Get Orders",
                "method": "GET",
                "relative_path": "/v1/orders",
                "server_ref": "srv_ext",
                "parameters": [],
                "semantic_effect": "read",
                "support_status": "supported",
                "security_requirement": {"status": "public", "alternatives": []},
            }
        ],
    }
    plan_data = {
        "operation_ids": ["get_orders"],
        "tool_names": {"get_orders": "get_orders"},
        "descriptions": {"get_orders": "Get Orders"},
    }
    engine = ContractRuntimeEngine(
        contract_data=contract_data,
        tool_plan_data=plan_data,
        policy_data=policy,
    )
    res = await engine.call_tool_async("get_orders", {})
    assert res.is_error is True
    err = json.loads(res.content[0].text)["error"]
    assert err["code"] == "POLICY_DENIED"
    assert err["stage"] == "network_policy"
    assert "non-public IP" in err["user_message"]


def test_finding_3_nested_socket_guard_reentrancy() -> None:
    """Nested enforce_socket_guard contexts preserve active guards and restore cleanly on exit."""
    orig_create_conn = socket.create_connection
    outer_guard = NetworkPolicyGuard(
        profile=NetworkProfile.STRICT_OFFLINE,
        registered_loopback_ports={11434, 18080},
    )
    inner_guard = NetworkPolicyGuard(
        profile=NetworkProfile.STRICT_OFFLINE,
        registered_loopback_ports={11434},
    )

    with outer_guard.enforce_socket_guard():
        assert socket.create_connection is not orig_create_conn
        with inner_guard.enforce_socket_guard():
            # Port 18080 is allowed by outer_guard but NOT by inner_guard -> must be denied while inner is active
            with pytest.raises(EgressDeniedError):
                socket.create_connection(("127.0.0.1", 18080), timeout=0.2)

        # After inner_guard exits, outer_guard is still active and continues blocking external IPs
        assert socket.create_connection is not orig_create_conn
        with pytest.raises(EgressDeniedError):
            socket.create_connection(("8.8.8.8", 53), timeout=0.2)

    # After outer_guard exits, original socket functions are restored
    assert socket.create_connection is orig_create_conn


@pytest.mark.asyncio
async def test_finding_4_streaming_response_size_cap_stops_early() -> None:
    """Oversized chunked response is aborted during streaming before buffering entire body."""
    chunks_sent = 0

    class OversizedStreamHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            nonlocal chunks_sent
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            # Attempt to stream 50 chunks of 4 KiB (200 KiB total) without Content-Length
            for _ in range(50):
                try:
                    self.wfile.write(b"X" * 4096)
                    self.wfile.flush()
                    chunks_sent += 1
                except OSError:
                    break

    server = HTTPServer(("127.0.0.1", 0), OversizedStreamHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        contract_data = {
            "schema_version": "1.0",
            "id": "ct_stream_cap",
            "canonical_hash": "a" * 64,
            "servers": [{"server_id": "srv_stream", "base_url": f"http://127.0.0.1:{port}"}],
            "security_schemes": [],
            "operations": [
                {
                    "stable_id": "get_large",
                    "display_name": "Get Large",
                    "method": "GET",
                    "relative_path": "/large",
                    "server_ref": "srv_stream",
                    "parameters": [],
                    "semantic_effect": "read",
                    "support_status": "supported",
                    "security_requirement": {"status": "public", "alternatives": []},
                }
            ],
        }
        plan_data = {
            "operation_ids": ["get_large"],
            "tool_names": {"get_large": "get_large"},
            "descriptions": {"get_large": "Get Large"},
        }
        policy_data = {
            "id": "pol_cap",
            "mode": "read_only",
            "network_profile": "STRICT_OFFLINE",
            "max_response_bytes": 8192,  # 8 KiB budget
        }
        engine = ContractRuntimeEngine(
            contract_data=contract_data,
            tool_plan_data=plan_data,
            policy_data=policy_data,
        )
        res = await engine.call_tool_async("get_large", {})
        assert res.is_error is True
        err = json.loads(res.content[0].text)["error"]
        assert err["code"] == "UPSTREAM_FAILED"
        assert err["stage"] == "response_bounds"
        assert "max_response_bytes" in err["user_message"]
    finally:
        server.shutdown()
        server.server_close()


def test_finding_5_upload_streaming_per_file_aggregate_and_count_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Upload endpoint enforces per-file, aggregate, and file-count limits via chunked reads."""
    monkeypatch.setattr(api_server_mod, "MAX_UPLOAD_BYTES", 1024)  # 1 KiB per file
    monkeypatch.setattr(api_server_mod, "MAX_TOTAL_UPLOAD_BYTES", 2048)  # 2 KiB aggregate
    monkeypatch.setattr(api_server_mod, "MAX_UPLOAD_FILES", 3)

    cfg = LocalApiConfig(
        workspace_dir=tmp_path / "ws_upload",
        capability_token="tok-upload-test",
    )
    app = create_local_app(cfg)
    with TestClient(app, base_url="http://127.0.0.1:8000") as http_client:
        client = SpigotApiClient(http_client, capability_token="tok-upload-test")
        proj = client.create_project("Upload Bounds Project")
        pid = proj["project_id"]

        # 1. Single file exceeding MAX_UPLOAD_BYTES (1024 bytes) -> HTTP 413
        with pytest.raises(SpigotApiError) as exc_single:
            client.upload_sources(pid, [("too_big.md", b"A" * 1500)])
        assert exc_single.value.status_code == 413

        # 2. Multipart upload with 3 files that individually pass (800 bytes each)
        #    but exceed MAX_TOTAL_UPLOAD_BYTES (2400 > 2048) -> HTTP 413
        multipart_resp = http_client.post(
            f"/api/projects/{pid}/sources",
            headers={"X-Spigot-Token": "tok-upload-test"},
            files=[
                ("files", ("part1.md", b"B" * 800, "text/markdown")),
                ("files", ("part2.md", b"C" * 800, "text/markdown")),
                ("files", ("part3.md", b"D" * 800, "text/markdown")),
            ],
        )
        assert multipart_resp.status_code == 413

        # 3. Multipart upload exceeding MAX_UPLOAD_FILES (4 > 3) -> HTTP 413
        too_many_resp = http_client.post(
            f"/api/projects/{pid}/sources",
            headers={"X-Spigot-Token": "tok-upload-test"},
            files=[
                ("files", (f"f{i}.md", b"# Doc\n", "text/markdown"))
                for i in range(4)
            ],
        )
        assert too_many_resp.status_code == 413


@pytest.mark.asyncio
async def test_finding_6_default_persistent_approval_ledger_and_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Runtime uses persistent SQLite ledger by default, blocks replay across restarts, and fails closed."""
    monkeypatch.chdir(tmp_path)

    # Short secrets (<16 chars) are rejected by ApprovalAuthority
    with pytest.raises(ValueError, match="at least 16 characters"):
        ApprovalAuthority("short-secret")

    secret = "owner-strong-approval-secret-2026"
    authority = ApprovalAuthority(secret)

    # Start a local mock server for the write call
    class WriteHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                self.rfile.read(length)
            body = b'{"created":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), WriteHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{port}"
        target_url = f"{base_url}/v1/transfers"
        args = {"body": {"amount": 100}}
        token_json = authority.issue_token_json(
            operation_id="post_transfer",
            arguments=args,
            target_url=target_url,
            contract_hash="a" * 64,
            policy_hash="b" * 64,
        )
        contract_data = {
            "schema_version": "1.0",
            "id": "ct_ledger",
            "canonical_hash": "a" * 64,
            "servers": [{"server_id": "srv_main", "base_url": base_url}],
            "security_schemes": [],
            "operations": [
                {
                    "stable_id": "post_transfer",
                    "display_name": "Post Transfer",
                    "method": "POST",
                    "relative_path": "/v1/transfers",
                    "server_ref": "srv_main",
                    "parameters": [],
                    "request_body": {
                        "content_type": "application/json",
                        "required": True,
                        "schema": {
                            "type": "object",
                            "properties": {"amount": {"type": "integer"}},
                            "required": ["amount"],
                        },
                    },
                    "semantic_effect": "create",
                    "support_status": "supported",
                    "security_requirement": {"status": "public", "alternatives": []},
                }
            ],
        }
        plan_data = {
            "operation_ids": ["post_transfer"],
            "tool_names": {"post_transfer": "post_transfer"},
            "descriptions": {"post_transfer": "Post Transfer"},
        }
        policy_data = {
            "id": "pol_ap",
            "mode": "approval_required",
            "network_profile": "STRICT_OFFLINE",
            "policy_hash": "b" * 64,
        }

        # Notice SPIGOT_APPROVAL_LEDGER_PATH is NOT set -> engine defaults to .spigot/consumed_approvals.sqlite3
        env_no_ledger_var = {
            "SPIGOT_APPROVAL_SECRET": secret,
            "SPIGOT_ACTION_APPROVAL_TOKEN": token_json,
        }
        engine1 = ContractRuntimeEngine(
            contract_data=contract_data,
            tool_plan_data=plan_data,
            policy_data=policy_data,
            environ=env_no_ledger_var,
        )
        res1 = await engine1.call_tool_async("post_transfer", args)
        assert res1.is_error is False
        assert (tmp_path / ".spigot" / "consumed_approvals.sqlite3").exists()

        # Brand-new engine instance (simulating process restart) without SPIGOT_APPROVAL_LEDGER_PATH
        # still rejects replay using the default persistent SQLite ledger!
        engine2 = ContractRuntimeEngine(
            contract_data=contract_data,
            tool_plan_data=plan_data,
            policy_data=policy_data,
            environ=env_no_ledger_var,
        )
        res2 = await engine2.call_tool_async("post_transfer", args)
        assert res2.is_error is True
        assert "already been consumed in ledger" in res2.content[0].text

        # Unwritable ledger path (pointing to a directory) fails closed
        bad_ledger_dir = tmp_path / "dir_not_sqlite_file"
        bad_ledger_dir.mkdir()
        fresh_token = authority.issue_token_json(
            operation_id="post_transfer",
            arguments=args,
            target_url=target_url,
            contract_hash="a" * 64,
            policy_hash="b" * 64,
        )
        engine_bad_ledger = ContractRuntimeEngine(
            contract_data=contract_data,
            tool_plan_data=plan_data,
            policy_data=policy_data,
            environ={
                "SPIGOT_APPROVAL_SECRET": secret,
                "SPIGOT_ACTION_APPROVAL_TOKEN": fresh_token,
                "SPIGOT_APPROVAL_LEDGER_PATH": str(bad_ledger_dir),
            },
        )
        res_bad = await engine_bad_ledger.call_tool_async("post_transfer", args)
        assert res_bad.is_error is True
        assert "fail-closed" in res_bad.content[0].text
    finally:
        server.shutdown()
        server.server_close()


def test_finding_7_approval_endpoints_validate_project_contract_plan_and_url(
    tmp_path: Path,
) -> None:
    """Approval prepare/issue endpoints return 404 on unknown project and validate frozen state."""
    cfg = LocalApiConfig(
        workspace_dir=tmp_path / "ws_approvals",
        capability_token="tok-approvals",
        approval_secret="owner-approval-secret-long-2026",
    )
    app = create_local_app(cfg)
    with TestClient(app, base_url="http://127.0.0.1:8000") as http_client:
        client = SpigotApiClient(http_client, capability_token="tok-approvals")

        # 1. Non-existent project returns 404 (not 200)
        with pytest.raises(SpigotApiError) as exc_404:
            client.issue_approval(
                "proj_nonexistent",
                operation_id="post_v1_transfers",
                arguments={},
                target_url="http://127.0.0.1:9000/v1/transfers",
                contract_hash="a" * 64,
                policy_hash="b" * 64,
            )
        assert exc_404.value.status_code == 404

        # 2. Project without frozen contract returns 409
        proj = client.create_project("Unfrozen Project")
        pid = proj["project_id"]
        with pytest.raises(SpigotApiError) as exc_unfrozen:
            client.issue_approval(
                pid,
                operation_id="post_v1_transfers",
                arguments={},
                target_url="http://127.0.0.1:9000/v1/transfers",
                contract_hash="a" * 64,
                policy_hash="b" * 64,
            )
        assert exc_unfrozen.value.status_code == 409

        # 3. Upload, extract, freeze, and create ToolPlan, then test mismatched hash/op/url
        client.upload_sources(
            pid,
            [
                (
                    "api.md",
                    (
                        b"# Payments API\n\n"
                        b"Base URL: `http://127.0.0.1:19000`\n\n"
                        b"Authentication: Send `X-API-Key: <your-api-key>` on every HTTP request.\n\n"
                        b"## Create Transfer\n\n"
                        b"`POST /v1/transfers`\n\n"
                        b"Create transfer.\n"
                    ),
                )
            ],
        )
        ext = client.extract_project(pid)
        frz = client.freeze_contract(pid, expected_revision=ext["result"]["revision"])
        tp = client.create_tool_plan(
            pid,
            contract_hash=frz["canonical_hash"],
            policy_mode="approval_required",
        )
        c_hash = frz["canonical_hash"]
        p_hash = tp["policy"]["policy_hash"]

        # Mismatched contract_hash -> 409
        with pytest.raises(SpigotApiError) as exc_chash:
            client.issue_approval(
                pid,
                operation_id="post_v1_transfers",
                arguments={},
                target_url="http://127.0.0.1:19000/v1/transfers",
                contract_hash="f" * 64,
                policy_hash=p_hash,
            )
        assert exc_chash.value.status_code == 409

        # Unknown operation_id -> 403
        with pytest.raises(SpigotApiError) as exc_op:
            client.issue_approval(
                pid,
                operation_id="delete_everything",
                arguments={},
                target_url="http://127.0.0.1:19000/v1/transfers",
                contract_hash=c_hash,
                policy_hash=p_hash,
            )
        assert exc_op.value.status_code == 403

        # Unapproved target_url host -> 403
        with pytest.raises(SpigotApiError) as exc_url:
            client.issue_approval(
                pid,
                operation_id="post_v1_transfers",
                arguments={},
                target_url="http://evil.example.com/v1/transfers",
                contract_hash=c_hash,
                policy_hash=p_hash,
            )
        assert exc_url.value.status_code == 403


def test_finding_8_and_9_env_example_and_unmanifested_zip_rejection(
    tmp_path: Path,
) -> None:
    """Generator emits approval vars in .env.example and rejects unmanifested files in ZIP/validation."""
    contract = ApiContract(
        id="ct_gen_audit",
        project_id="proj_audit",
        revision=1,
        sources=["src_1"],
        servers=[
            ServerContract(
                server_id="default",
                base_url="http://127.0.0.1:18080",
                evidence=["ev_1"],
            )
        ],
        operations=[
            OperationContract(
                stable_id="get_health",
                display_name="Get Health",
                method="GET",
                relative_path="/health",
                server_ref="default",
                security_requirement=SecurityRequirement(status="public"),
                semantic_effect="read",
                provenance={
                    "method": ["ev_1"],
                    "relative_path": ["ev_1"],
                    "server_ref": ["ev_1"],
                    "security_requirement": ["ev_1"],
                    "semantic_effect": ["ev_1"],
                },
                support_status="supported",
            )
        ],
    )
    policy = RuntimePolicy(id="pol_audit", mode="approval_required")
    plan = create_tool_plan(contract, policy)

    pkg_dir = tmp_path / "pkg"
    manifest = generate_server_package(
        contract, plan, policy, pkg_dir, package_slug="audit_pkg"
    )

    # Finding 8: .env.example documents SPIGOT_APPROVAL_SECRET and SPIGOT_APPROVAL_LEDGER_PATH
    env_example = (pkg_dir / ".env.example").read_text(encoding="utf-8")
    assert "SPIGOT_APPROVAL_SECRET=" in env_example
    assert "SPIGOT_APPROVAL_LEDGER_PATH=" in env_example
    assert "SPIGOT_ACTION_APPROVAL_TOKEN=" in env_example

    # Finding 9a: Injecting an unmanifested file into pkg_dir causes export_reproducible_zip to fail
    rogue_file = pkg_dir / "unmanifested_backdoor.py"
    rogue_file.write_text("import os\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unmanifested files"):
        export_reproducible_zip(pkg_dir, tmp_path / "rogue.zip")
    rogue_file.unlink()

    # Valid export succeeds
    valid_zip_bytes = export_reproducible_zip(pkg_dir, tmp_path / "valid.zip")

    # Finding 9b: Injecting an unmanifested member into the ZIP bytes fails IsolatedValidationWorker
    tampered_buf = io.BytesIO(valid_zip_bytes)
    with zipfile.ZipFile(tampered_buf, "a") as zf:
        zf.writestr("injected_unmanifested.py", b"print('pwned')\n")
    tampered_zip_bytes = tampered_buf.getvalue()

    worker = IsolatedValidationWorker(force_sandbox_unavailable=True)
    report = worker.validate_package(
        artifact_id="art_audit",
        package_dir=pkg_dir,
        manifest=manifest,
        zip_bytes=tampered_zip_bytes,
    )
    checks_by_name = {c.check_name: c.status for c in report.checks}
    assert checks_by_name["build_status"] == "failed"
    assert checks_by_name["security_suite_status"] == "failed"
    assert any(
        "Unmanifested ZIP member: injected_unmanifested.py" in r
        for r in report.environment["failure_reasons"]
    )


def test_storage_fault_injection_rollback_and_blob_corruption(tmp_path: Path) -> None:
    """SpigotStorage rolls back failed transactions cleanly and detects on-disk blob tampering."""
    storage = SpigotStorage(tmp_path / "storage_ws")
    proj = storage.create_project("Storage Fault Test")
    pid = proj["id"]

    # 1. Mid-transaction exception rolls back cleanly without partial rows
    with pytest.raises(RuntimeError, match="simulated crash"):
        with storage.connect() as conn:
            conn.execute(
                "UPDATE projects SET name = ? WHERE id = ?",
                ("Corrupted Name", pid),
            )
            raise RuntimeError("simulated crash")

    fetched = storage.get_project(pid)
    assert fetched is not None
    assert fetched["name"] == "Storage Fault Test"

    # 2. On-disk blob corruption raises ArtifactIntegrityError on read
    doc = storage.store_source_document(
        pid, "spec.md", "text/markdown", b"# Original Spec\n"
    )
    blob_path = storage.artifacts.root_dir / doc.local_artifact_ref
    blob_path.write_bytes(b"# Tampered Spec\n")

    with pytest.raises(ArtifactIntegrityError, match="Corrupted artifact"):
        storage.artifacts.get_bytes(doc.content_sha256)

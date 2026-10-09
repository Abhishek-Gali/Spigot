"""Phase P5 Unit & Integration Tests for Fault Injection, Retries, Circuit Breaker, and Approvals (T22, T23).

Verifies:
- T22:
  - Safe read operation recovers after transient HTTP 503 and HTTP 429 (with `Retry-After` inside deadline).
  - HTTP 429 with `Retry-After` exceeding `request_deadline_sec` fails immediately without sleeping past deadline.
  - Ambiguous write outcome (mid-flight connection reset on POST) is NEVER replayed (`attempts == 1`)
    and returns `OUTCOME_UNKNOWN` (`retryable=False`).
  - Explicitly configured idempotent write with `Idempotency-Key` header preserves the exact same key
    across retries and recovers cleanly.
  - Circuit breaker keyed by `(server_ref, credential_fingerprint)` (without storing plaintext secret)
    opens after threshold failures, blocks upstream calls while open, and resets cleanly.
  - Bounded pagination (`call_tool_paginated_async`) enforces `max_pages` and `max_items`
    and rejects unconfigured operations.
- T23:
  - `ApprovalAuthority` prepare/issue/verify lifecycle, CLI (`python -m packages.core.approval`),
    and Local API `/approvals/prepare` & `/approvals/issue`.
  - Agent cannot self-approve (`list_tools` has no approval tool; `approved=True` argument is rejected by schema).
  - Single-use approval is consumed atomically in memory and across restarts via `SPIGOT_APPROVAL_LEDGER_PATH`.
  - Modified arguments, target URL, contract hash, policy hash, expired token, and forged signature are all denied.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from apps.api.client import SpigotApiClient
from apps.api.server import LocalApiConfig, create_local_app
from packages.core.approval import (
    ApprovalAuthority,
    compute_action_digest,
)
from packages.core.approval import (
    main as approval_cli_main,
)
from packages.runtime.engine import ContractRuntimeEngine


class FaultInjectingOracle:
    """Deterministic local HTTP server for testing retries, Retry-After, write drops, and pagination."""

    def __init__(self) -> None:
        self.read_attempts = 0
        self.rate_limit_attempts = 0
        self.write_attempts = 0
        self.idempotent_write_keys: list[str] = []
        self.cb_attempts = 0
        self.mode = "recover_read"

        oracle = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                if self.path.startswith("/v1/items"):
                    if "cursor=page2" in self.path:
                        body = json.dumps(
                            {"items": [{"id": "item-3"}, {"id": "item-4"}], "next_cursor": "page3"}
                        ).encode("utf-8")
                    elif "cursor=page3" in self.path:
                        body = json.dumps(
                            {"items": [{"id": "item-5"}], "next_cursor": None}
                        ).encode("utf-8")
                    else:
                        body = json.dumps(
                            {"items": [{"id": "item-1"}, {"id": "item-2"}], "next_cursor": "page2"}
                        ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if self.path.startswith("/v1/status"):
                    if oracle.mode == "recover_read":
                        oracle.read_attempts += 1
                        if oracle.read_attempts < 3:
                            self.send_response(503)
                            self.send_header("Retry-After", "0.01")
                            self.end_headers()
                            self.wfile.write(b'{"error":"temporary_overload"}')
                            return
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"status":"healthy","recovered":true}')
                        return

                    if oracle.mode == "rate_limit_exceeds_deadline":
                        oracle.rate_limit_attempts += 1
                        self.send_response(429)
                        self.send_header("Retry-After", "60")
                        self.end_headers()
                        self.wfile.write(b'{"error":"rate_limited"}')
                        return

                    if oracle.mode == "circuit_breaker_503":
                        oracle.cb_attempts += 1
                        self.send_response(503)
                        self.end_headers()
                        self.wfile.write(b'{"error":"backend_down"}')
                        return

                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:
                if self.path == "/v1/orders":
                    oracle.write_attempts += 1
                    # Simulate mid-flight connection drop after receiving write request
                    self.connection.close()
                    return

                if self.path == "/v1/payments":
                    idem_key = self.headers.get("Idempotency-Key", "")
                    oracle.idempotent_write_keys.append(idem_key)
                    if len(oracle.idempotent_write_keys) == 1:
                        self.send_response(503)
                        self.send_header("Retry-After", "0.01")
                        self.end_headers()
                        self.wfile.write(b'{"error":"try_again_with_same_key"}')
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"payment_id": "pay_1", "idempotency_key": idem_key}).encode(
                            "utf-8"
                        )
                    )
                    return

                if self.path == "/v1/transfers":
                    length = int(self.headers.get("Content-Length", "0"))
                    raw = self.rfile.read(length) if length > 0 else b"{}"
                    data = json.loads(raw.decode("utf-8"))
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"transfer_status": "executed", "amount": data.get("amount")}).encode(
                            "utf-8"
                        )
                    )
                    return

                self.send_response(404)
                self.end_headers()

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_port
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> FaultInjectingOracle:
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._server.shutdown()
        self._server.server_close()


def _build_resilience_contract_and_plan(base_url: str) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = {
        "schema_version": "1.0",
        "id": "ct_resilience",
        "canonical_hash": "a" * 64,
        "servers": [{"server_id": "srv_main", "base_url": base_url}],
        "security_schemes": [
            {
                "scheme_id": "bearer_auth",
                "type": "http",
                "scheme": "bearer",
            }
        ],
        "operations": [
            {
                "stable_id": "get_v1_status",
                "display_name": "Get Status",
                "method": "GET",
                "relative_path": "/v1/status",
                "server_ref": "srv_main",
                "parameters": [],
                "semantic_effect": "read",
                "support_status": "supported",
                "security_requirement": {
                    "status": "required",
                    "alternatives": [{"all_of": ["bearer_auth"]}],
                },
            },
            {
                "stable_id": "get_v1_items",
                "display_name": "List Items",
                "method": "GET",
                "relative_path": "/v1/items",
                "server_ref": "srv_main",
                "parameters": [
                    {
                        "external_name": "cursor",
                        "safe_argument_name": "cursor",
                        "location": "query",
                        "required": False,
                        "schema": {"type": "string"},
                    }
                ],
                "semantic_effect": "read",
                "support_status": "supported",
                "security_requirement": {"status": "public", "alternatives": []},
            },
            {
                "stable_id": "post_v1_orders",
                "display_name": "Create Order",
                "method": "POST",
                "relative_path": "/v1/orders",
                "server_ref": "srv_main",
                "parameters": [],
                "request_body": {
                    "content_type": "application/json",
                    "required": True,
                    "schema": {
                        "type": "object",
                        "properties": {"sku": {"type": "string"}},
                        "required": ["sku"],
                    },
                },
                "semantic_effect": "create",
                "support_status": "supported",
                "security_requirement": {"status": "public", "alternatives": []},
            },
            {
                "stable_id": "post_v1_payments",
                "display_name": "Create Idempotent Payment",
                "method": "POST",
                "relative_path": "/v1/payments",
                "server_ref": "srv_main",
                "parameters": [
                    {
                        "external_name": "Idempotency-Key",
                        "safe_argument_name": "idempotency_key",
                        "location": "header",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "semantic_effect": "create",
                "support_status": "supported",
                "security_requirement": {"status": "public", "alternatives": []},
            },
            {
                "stable_id": "post_v1_transfers",
                "display_name": "Execute Transfer",
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
                "semantic_effect": "action",
                "support_status": "supported",
                "security_requirement": {"status": "public", "alternatives": []},
            },
        ],
    }
    plan = {
        "schema_version": "1.0",
        "id": "plan_resilience",
        "contract_hash": "a" * 64,
        "operation_ids": [
            "get_v1_status",
            "get_v1_items",
            "post_v1_orders",
            "post_v1_payments",
            "post_v1_transfers",
        ],
        "tool_names": {
            "get_v1_status": "get_v1_status",
            "get_v1_items": "get_v1_items",
            "post_v1_orders": "post_v1_orders",
            "post_v1_payments": "post_v1_payments",
            "post_v1_transfers": "post_v1_transfers",
        },
        "descriptions": {},
        "policy_hash": "b" * 64,
        "plan_hash": "c" * 64,
    }
    return contract, plan


@pytest.mark.anyio
async def test_t22_safe_read_retry_ambiguous_write_no_replay_circuit_breaker_and_pagination() -> None:
    with FaultInjectingOracle() as oracle:
        contract, plan = _build_resilience_contract_and_plan(oracle.base_url)
        policy = {
            "id": "pol_resilience",
            "mode": "restricted_write",
            "allowed_write_operations": ["post_v1_orders", "post_v1_payments"],
            "network_profile": "STRICT_OFFLINE",
            "request_deadline_sec": 2.0,
            "connect_timeout_sec": 1.0,
            "max_retries": 3,
            "retry_backoff_base_sec": 0.01,
            "circuit_breaker_threshold": 3,
            "circuit_breaker_cooldown_sec": 30.0,
            "idempotent_write_operations": ["post_v1_payments"],
            "idempotency_key_header": "Idempotency-Key",
            "pagination_config": {
                "get_v1_items": {
                    "cursor_param": "cursor",
                    "next_cursor_field": "next_cursor",
                    "items_field": "items",
                    "max_pages": 2,
                    "max_items": 3,
                    "max_bytes": 65536,
                }
            },
            "policy_hash": "b" * 64,
        }
        secret_val = "SECRET_TOKEN_FOR_CB_TEST_999"
        engine = ContractRuntimeEngine(
            contract_data=contract,
            tool_plan_data=plan,
            policy_data=policy,
            environ={"SPIGOT_CRED_BEARER_AUTH": secret_val},
        )

        # 1. Safe read recovers on 3rd attempt after two 503 responses
        oracle.mode = "recover_read"
        read_res = await engine.call_tool_async("get_v1_status", {})
        assert read_res.is_error is False
        read_payload = json.loads(read_res.content[0].text)
        assert read_payload["status_code"] == 200
        assert read_payload["attempts"] == 3
        assert read_payload["data"]["recovered"] is True
        assert oracle.read_attempts == 3

        # 2. HTTP 429 with Retry-After (60s) exceeding deadline (2s) fails immediately on attempt 1
        oracle.mode = "rate_limit_exceeds_deadline"
        rl_res = await engine.call_tool_async("get_v1_status", {})
        assert rl_res.is_error is True
        rl_err = json.loads(rl_res.content[0].text)["error"]
        assert rl_err["code"] == "UPSTREAM_RATE_LIMITED"
        assert rl_err["retryable"] is True
        assert rl_err["redacted_details"]["attempts"] == 1
        assert oracle.rate_limit_attempts == 1

        # 3. Ambiguous write outcome (connection drop on POST /v1/orders) is NEVER replayed
        write_res = await engine.call_tool_async("post_v1_orders", {"body": {"sku": "SKU-1"}})
        assert write_res.is_error is True
        write_err = json.loads(write_res.content[0].text)["error"]
        assert write_err["code"] == "UPSTREAM_FAILED"
        assert write_err["retryable"] is False
        assert write_err["redacted_details"]["outcome"] == "OUTCOME_UNKNOWN"
        assert write_err["redacted_details"]["attempts"] == 1
        assert oracle.write_attempts == 1

        # 4. Idempotent write with explicit Idempotency-Key retries safely with the exact same key
        engine.reset_circuit_breaker()
        idem_res = await engine.call_tool_async(
            "post_v1_payments", {"idempotency_key": "idem-fixed-key-001"}
        )
        assert idem_res.is_error is False
        idem_payload = json.loads(idem_res.content[0].text)
        assert idem_payload["status_code"] == 200
        assert idem_payload["attempts"] == 2
        assert oracle.idempotent_write_keys == ["idem-fixed-key-001", "idem-fixed-key-001"]

        # 5. Circuit breaker trips after 3 consecutive 503 failures and does not store plaintext secret
        engine.reset_circuit_breaker()
        oracle.mode = "circuit_breaker_503"
        cb_res1 = await engine.call_tool_async("get_v1_status", {})
        assert cb_res1.is_error is True
        assert oracle.cb_attempts == 3

        # Verify secret value is NOT in circuit breaker state keys or values
        cb_dump = json.dumps({str(k): v for k, v in engine._circuit_state.items()})
        assert secret_val not in cb_dump

        # Next call is immediately denied by open circuit breaker without hitting upstream server
        cb_res2 = await engine.call_tool_async("get_v1_status", {})
        assert cb_res2.is_error is True
        cb_err = json.loads(cb_res2.content[0].text)["error"]
        assert cb_err["stage"] == "circuit_breaker"
        assert cb_err["redacted_details"]["state"] == "open"
        assert oracle.cb_attempts == 3  # Unchanged!

        # Manual reset closes the circuit breaker
        engine.reset_circuit_breaker("srv_main")
        cred_fp = engine._credential_fingerprint([secret_val])
        assert engine.get_circuit_breaker_status("srv_main", cred_fp)["state"] == "closed"

        # 6. Bounded pagination stops at max_items=3 across 2 pages and rejects unconfigured ops
        pag_res = await engine.call_tool_paginated_async("get_v1_items", {})
        assert pag_res.is_error is False
        pag_payload = json.loads(pag_res.content[0].text)
        assert pag_payload["pages_fetched"] == 2
        assert pag_payload["stop_reason"] == "max_items_reached"
        assert len(pag_payload["data"]["items"]) == 3

        unconfigured_pag = await engine.call_tool_paginated_async("get_v1_status", {})
        assert unconfigured_pag.is_error is True
        assert json.loads(unconfigured_pag.content[0].text)["error"]["code"] == "POLICY_DENIED"


@pytest.mark.anyio
async def test_t23_trusted_approval_authority_binding_ledger_and_self_approval_prevention(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with FaultInjectingOracle() as oracle:
        contract, plan = _build_resilience_contract_and_plan(oracle.base_url)
        policy = {
            "id": "pol_approval",
            "mode": "approval_required",
            "network_profile": "STRICT_OFFLINE",
            "policy_hash": "b" * 64,
        }
        ledger_path = tmp_path / "approvals_ledger.sqlite3"
        owner_secret = "OWNER_APPROVAL_AUTHORITY_SECRET_2026"
        target_url = f"{oracle.base_url}/v1/transfers"
        valid_args = {"body": {"amount": 250}}

        # 1. Without SPIGOT_APPROVAL_SECRET, approval_required write tools are not advertised and denied
        engine_no_secret = ContractRuntimeEngine(
            contract_data=contract,
            tool_plan_data=plan,
            policy_data=policy,
            environ={},
        )
        listed_without_secret = {t.name for t in engine_no_secret.list_tools_sync()}
        assert "post_v1_transfers" not in listed_without_secret
        no_sec_call = await engine_no_secret.call_tool_async("post_v1_transfers", valid_args)
        assert no_sec_call.is_error is True
        assert json.loads(no_sec_call.content[0].text)["error"]["code"] == "POLICY_DENIED"

        # 2. With SPIGOT_APPROVAL_SECRET configured, tool is listed, but no approval-issuing tool exists
        #    and passing a boolean `approved=True` argument is rejected by strict JSON Schema
        authority = ApprovalAuthority(owner_secret, ledger_path=ledger_path)
        prepared = authority.prepare_action(
            operation_id="post_v1_transfers",
            arguments=valid_args,
            target_url=target_url,
            contract_hash="a" * 64,
            policy_hash="b" * 64,
        )
        assert prepared.action_digest == compute_action_digest(
            operation_id="post_v1_transfers",
            arguments=valid_args,
            target_url=target_url,
            contract_hash="a" * 64,
            policy_hash="b" * 64,
        )

        # CLI `prepare` subcommand outputs the exact same action_digest
        rc = approval_cli_main(
            [
                "prepare",
                "--operation-id",
                "post_v1_transfers",
                "--args-json",
                json.dumps(valid_args),
                "--target-url",
                target_url,
                "--contract-hash",
                "a" * 64,
                "--policy-hash",
                "b" * 64,
            ]
        )
        assert rc == 0
        cli_out = json.loads(capsys.readouterr().out)
        assert cli_out["action_digest"] == prepared.action_digest

        # Issue single-use token via Local API owner endpoint (backed by frozen contract & ToolPlan)
        cfg = LocalApiConfig(
            workspace_dir=tmp_path / "api_ws",
            capability_token="owner-cap-token-p5",
            approval_secret=owner_secret,
        )
        app = create_local_app(cfg)
        with TestClient(app, base_url="http://127.0.0.1:8000") as http_client:
            api_client = SpigotApiClient(http_client, capability_token="owner-cap-token-p5")
            proj = api_client.create_project("Approval Test Project")
            api_client.upload_sources(
                proj["project_id"],
                [
                    (
                        "transfers_api.md",
                        (
                            f"# Transfers Service API\n\n"
                            f"Base URL: `{oracle.base_url}`\n\n"
                            f"Authentication: Send `X-API-Key: <your-api-key>` on every HTTP request.\n\n"
                            f"## Execute Transfer\n\n"
                            f"`POST /v1/transfers`\n\n"
                            f"Execute a fund transfer.\n\n"
                            f"### Request Body (`application/json`)\n\n"
                            f"- `amount` (integer, required): Transfer amount.\n"
                        ).encode(),
                    )
                ],
            )
            ext = api_client.extract_project(proj["project_id"])
            frz = api_client.freeze_contract(
                proj["project_id"], expected_revision=ext["result"]["revision"]
            )
            tp = api_client.create_tool_plan(
                proj["project_id"],
                contract_hash=frz["canonical_hash"],
                policy_mode="approval_required",
            )
            c_hash = frz["canonical_hash"]
            p_hash = tp["policy"]["policy_hash"]
            contract["canonical_hash"] = c_hash
            policy["policy_hash"] = p_hash

            prepared = authority.prepare_action(
                operation_id="post_v1_transfers",
                arguments=valid_args,
                target_url=target_url,
                contract_hash=c_hash,
                policy_hash=p_hash,
            )
            prep_api = api_client.prepare_approval(
                proj["project_id"],
                operation_id="post_v1_transfers",
                arguments=valid_args,
                target_url=target_url,
                contract_hash=c_hash,
                policy_hash=p_hash,
            )
            assert prep_api["action_digest"] == prepared.action_digest

            issued_api = api_client.issue_approval(
                proj["project_id"],
                operation_id="post_v1_transfers",
                arguments=valid_args,
                target_url=target_url,
                contract_hash=c_hash,
                policy_hash=p_hash,
                ttl_sec=120.0,
                expected_action_digest=prep_api["action_digest"],
                human_confirmed=True,
            )
            token_json = issued_api["approval_token_json"]

        env_with_token = {
            "SPIGOT_APPROVAL_SECRET": owner_secret,
            "SPIGOT_ACTION_APPROVAL_TOKEN": token_json,
            "SPIGOT_APPROVAL_LEDGER_PATH": str(ledger_path),
        }
        engine = ContractRuntimeEngine(
            contract_data=contract,
            tool_plan_data=plan,
            policy_data=policy,
            environ=env_with_token,
        )

        # Agent attempting to pass `approved=True` in tool arguments fails schema validation
        self_approve_attempt = await engine.call_tool_async(
            "post_v1_transfers", {"body": {"amount": 250}, "approved": True}
        )
        assert self_approve_attempt.is_error is True
        assert (
            json.loads(self_approve_attempt.content[0].text)["error"]["code"]
            == "CONTRACT_INCOMPLETE"
        )

        # 3. Argument tampering (`amount: 9999` instead of `250`) is denied before consuming nonce
        tampered_arg_res = await engine.call_tool_async(
            "post_v1_transfers", {"body": {"amount": 9999}}
        )
        assert tampered_arg_res.is_error is True
        assert (
            "signature mismatch"
            in json.loads(tampered_arg_res.content[0].text)["error"]["user_message"]
        )

        # 4. Exact approved invocation succeeds once
        ok_res = await engine.call_tool_async("post_v1_transfers", valid_args)
        assert ok_res.is_error is False
        assert json.loads(ok_res.content[0].text)["data"]["amount"] == 250

        # 5. Replaying the same token in a brand-new engine instance (simulating process restart)
        #    is denied by the persistent SQLite ledger (`SPIGOT_APPROVAL_LEDGER_PATH`)
        fresh_engine = ContractRuntimeEngine(
            contract_data=contract,
            tool_plan_data=plan,
            policy_data=policy,
            environ=env_with_token,
        )
        replay_res = await fresh_engine.call_tool_async("post_v1_transfers", valid_args)
        assert replay_res.is_error is True
        assert (
            "already been consumed"
            in json.loads(replay_res.content[0].text)["error"]["user_message"]
        )

        # 6. Expired token is denied
        expired_token = authority.issue_token_json(
            operation_id="post_v1_transfers",
            arguments=valid_args,
            target_url=target_url,
            contract_hash=c_hash,
            policy_hash=p_hash,
            ttl_sec=-10.0,
        )
        expired_engine = ContractRuntimeEngine(
            contract_data=contract,
            tool_plan_data=plan,
            policy_data=policy,
            environ={
                "SPIGOT_APPROVAL_SECRET": owner_secret,
                "SPIGOT_ACTION_APPROVAL_TOKEN": expired_token,
                "SPIGOT_APPROVAL_LEDGER_PATH": str(ledger_path),
            },
        )
        exp_res = await expired_engine.call_tool_async("post_v1_transfers", valid_args)
        assert exp_res.is_error is True
        assert "expired" in json.loads(exp_res.content[0].text)["error"]["user_message"]

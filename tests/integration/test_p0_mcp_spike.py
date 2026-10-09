"""P0 Integration Tests: MCP Client <-> Stdio Fixture Server <-> Independent Mock Oracle (T03)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from fixtures.p0_support_tickets.mock_oracle import SupportTicketsMockServer

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


@pytest.mark.asyncio
async def test_mcp_stdio_read_only_and_policy_enforcement() -> None:
    with SupportTicketsMockServer(expected_bearer_token="secret-oracle-token-99") as mock:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT_DIR)
        env["SPIGOT_UPSTREAM_BASE_URL"] = mock.base_url
        env["SPIGOT_BEARER_TOKEN"] = "secret-oracle-token-99"
        env["SPIGOT_ALLOW_WRITES"] = "false"

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "packages.runtime.fixture_mcp_server"],
            env=env,
            cwd=str(ROOT_DIR),
        )

        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                init_result = await session.initialize()
                assert init_result.server_info.name == "spigot-support-tickets-p0"

                # Under read-only default policy, only support_get_ticket is advertised
                tools_result = await session.list_tools()
                tool_names = [t.name for t in tools_result.tools]
                assert tool_names == ["support_get_ticket"]

                # Valid read invocation against local mock oracle
                call_res = await session.call_tool(
                    "support_get_ticket",
                    {"ticket_id": "tkt_101", "include_comments": True},
                )
                assert not call_res.is_error
                payload = json.loads(call_res.content[0].text)  # type: ignore[union-attr]
                assert payload["status_code"] == 200
                assert payload["data"]["id"] == "tkt_101"
                assert len(payload["data"]["comments"]) == 1

                # Direct call to write tool when SPIGOT_ALLOW_WRITES=false -> POLICY_DENIED
                write_res = await session.call_tool(
                    "support_create_ticket",
                    {"subject": "Unauthorized write", "priority": "high"},
                )
                assert write_res.is_error
                write_err = json.loads(write_res.content[0].text)  # type: ignore[union-attr]
                assert write_err["error"]["code"] == "POLICY_DENIED"

                # Direct call to blocked tool support_close_ticket -> POLICY_DENIED
                blocked_res = await session.call_tool(
                    "support_close_ticket",
                    {"ticket_id": "tkt_101"},
                )
                assert blocked_res.is_error
                blocked_err = json.loads(blocked_res.content[0].text)  # type: ignore[union-attr]
                assert blocked_err["error"]["code"] == "POLICY_DENIED"
                assert "CONFLICTING_METHOD_PATH" in blocked_err["error"]["user_message"]

        # Verify independent mock oracle only received the single authorized GET request
        assert len(mock.state.calls) == 1
        recorded = mock.state.calls[0]
        assert recorded.method == "GET"
        assert recorded.path == "/v1/tickets/tkt_101"
        assert recorded.query == {"include_comments": ["true"]}


@pytest.mark.asyncio
async def test_mcp_stdio_authorized_write_matches_oracle() -> None:
    with SupportTicketsMockServer(expected_bearer_token="secret-oracle-token-99") as mock:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT_DIR)
        env["SPIGOT_UPSTREAM_BASE_URL"] = mock.base_url
        env["SPIGOT_BEARER_TOKEN"] = "secret-oracle-token-99"
        env["SPIGOT_ALLOW_WRITES"] = "true"

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "packages.runtime.fixture_mcp_server"],
            env=env,
            cwd=str(ROOT_DIR),
        )

        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                tool_names = sorted(t.name for t in tools_result.tools)
                assert tool_names == ["support_create_ticket", "support_get_ticket"]

                create_res = await session.call_tool(
                    "support_create_ticket",
                    {
                        "subject": "Printer offline on floor 3",
                        "priority": "normal",
                        "description": "Paper jam cleared but status remains offline.",
                    },
                )
                assert not create_res.is_error
                payload = json.loads(create_res.content[0].text)  # type: ignore[union-attr]
                assert payload["status_code"] == 201
                assert payload["data"]["id"] == "tkt_102"
                assert payload["data"]["status"] == "open"

        assert len(mock.state.calls) == 1
        rec = mock.state.calls[0]
        assert rec.method == "POST"
        assert rec.path == "/v1/tickets"
        assert rec.body_json == {
            "subject": "Printer offline on floor 3",
            "priority": "normal",
            "description": "Paper jam cleared but status remains offline.",
        }

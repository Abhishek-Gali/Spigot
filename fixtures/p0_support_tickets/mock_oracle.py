"""Independent HTTP mock oracle for the P0 Support Tickets API fixture (T02).

Authored independently of the extractor and generator templates to prevent
shared-assumption test blind spots. Binds strictly to 127.0.0.1 on an ephemeral
port and records all received HTTP requests for exact oracle assertions.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class RecordedHttpCall:
    """Immutable record of an inbound HTTP request captured by the mock oracle."""

    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body_text: str
    body_json: Any | None


@dataclass
class SupportTicketsOracleState:
    """State and call log for the Support Tickets mock server."""

    expected_bearer_token: str = "test-runtime-token-t02"
    tickets: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "tkt_101": {
                "id": "tkt_101",
                "subject": "Login error",
                "status": "open",
                "priority": "high",
                "description": "User cannot sign in from desktop app.",
                "comments": [{"author": "agent_1", "body": "Investigating session logs."}],
            }
        }
    )
    calls: list[RecordedHttpCall] = field(default_factory=list)
    _next_id: int = 102

    def allocate_ticket_id(self) -> str:
        ticket_id = f"tkt_{self._next_id}"
        self._next_id += 1
        return ticket_id


class SupportTicketsMockServer:
    """Context-managed local loopback HTTP server for Support Tickets API v1."""

    def __init__(self, expected_bearer_token: str = "test-runtime-token-t02") -> None:
        self.state = SupportTicketsOracleState(expected_bearer_token=expected_bearer_token)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._httpd is None:
            raise RuntimeError("Mock server is not running")
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/v1"

    def start(self) -> str:
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                # Silence default stderr logging during test runs
                return

            def _record_and_authenticate(self) -> tuple[bool, Any | None]:
                content_len = int(self.headers.get("Content-Length", "0"))
                raw_bytes = self.rfile.read(content_len) if content_len > 0 else b""
                body_text = raw_bytes.decode("utf-8", errors="replace")
                body_json: Any | None = None
                if body_text:
                    try:
                        body_json = json.loads(body_text)
                    except json.JSONDecodeError:
                        body_json = None

                parsed = urlparse(self.path)
                header_map = {k.lower(): v for k, v in self.headers.items()}
                state.calls.append(
                    RecordedHttpCall(
                        method=self.command,
                        path=parsed.path,
                        query=parse_qs(parsed.query, keep_blank_values=True),
                        headers=header_map,
                        body_text=body_text,
                        body_json=body_json,
                    )
                )

                auth_header = header_map.get("authorization", "")
                expected = f"Bearer {state.expected_bearer_token}"
                if auth_header != expected:
                    self._send_json(
                        401,
                        {
                            "error": "UNAUTHORIZED",
                            "message": "Missing or invalid Bearer token",
                        },
                    )
                    return False, body_json
                return True, body_json

            def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_GET(self) -> None:  # noqa: N802
                ok, _ = self._record_and_authenticate()
                if not ok:
                    return
                parsed = urlparse(self.path)
                prefix = "/v1/tickets/"
                if parsed.path.startswith(prefix):
                    ticket_id = parsed.path[len(prefix) :]
                    if "/" not in ticket_id and ticket_id in state.tickets:
                        ticket = dict(state.tickets[ticket_id])
                        query = parse_qs(parsed.query)
                        inc = query.get("include_comments", ["false"])[0].lower()
                        if inc != "true":
                            ticket.pop("comments", None)
                        self._send_json(200, ticket)
                        return
                    self._send_json(
                        404,
                        {
                            "error": "NOT_FOUND",
                            "message": f"Ticket '{ticket_id}' not found",
                        },
                    )
                    return
                self._send_json(404, {"error": "NOT_FOUND", "message": "Unknown route"})

            def do_POST(self) -> None:  # noqa: N802
                ok, body_json = self._record_and_authenticate()
                if not ok:
                    return
                parsed = urlparse(self.path)
                if parsed.path == "/v1/tickets":
                    if not isinstance(body_json, dict):
                        self._send_json(
                            400,
                            {
                                "error": "BAD_REQUEST",
                                "message": "Request body must be a JSON object",
                            },
                        )
                        return
                    subject = body_json.get("subject")
                    priority = body_json.get("priority")
                    if (
                        not isinstance(subject, str)
                        or not subject.strip()
                        or priority not in {"low", "normal", "high"}
                    ):
                        self._send_json(
                            400,
                            {
                                "error": "BAD_REQUEST",
                                "message": "Invalid subject or priority",
                            },
                        )
                        return
                    new_id = state.allocate_ticket_id()
                    created = {
                        "id": new_id,
                        "subject": subject,
                        "priority": priority,
                        "description": body_json.get("description", ""),
                        "status": "open",
                    }
                    state.tickets[new_id] = dict(created, comments=[])
                    self._send_json(201, created)
                    return
                self._send_json(404, {"error": "NOT_FOUND", "message": "Unknown route"})

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="support-tickets-mock-oracle",
            daemon=True,
        )
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def __enter__(self) -> SupportTicketsMockServer:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

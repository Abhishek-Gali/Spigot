"""P0 Offline Egress-Denial Tests (T03): socket guard, SSRF blocking, and loopback allowance."""

from __future__ import annotations

import socket

import httpx
import pytest

from fixtures.p0_support_tickets.mock_oracle import SupportTicketsMockServer
from packages.core.network_guard import (
    EgressDeniedError,
    NetworkPolicyGuard,
    NetworkProfile,
)


def test_strict_offline_denies_external_domains_and_ips() -> None:
    guard = NetworkPolicyGuard(profile=NetworkProfile.STRICT_OFFLINE)

    for blocked_url in [
        "https://api.openai.com/v1/chat/completions",
        "https://example.com/docs",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1:8080/internal",
        "http://192.168.1.1/admin",
        "http://8.8.8.8:53/",
        "ftp://127.0.0.1/file",
    ]:
        with pytest.raises(EgressDeniedError):
            guard.validate_url(blocked_url)


def test_socket_guard_blocks_outbound_connect_while_allowing_loopback_mock() -> None:
    guard = NetworkPolicyGuard(profile=NetworkProfile.STRICT_OFFLINE)

    with guard.enforce_socket_guard():
        # External IP socket connection must be blocked at the socket layer
        with pytest.raises(EgressDeniedError):
            socket.create_connection(("8.8.8.8", 53), timeout=1.0)

        # Cloud metadata IP must be blocked at the socket layer
        with pytest.raises(EgressDeniedError):
            socket.create_connection(("169.254.169.254", 80), timeout=1.0)

        # Loopback mock server communication must succeed under STRICT_OFFLINE socket guard
        with SupportTicketsMockServer(expected_bearer_token="offline-token") as mock:
            with httpx.Client(timeout=5.0, trust_env=False) as client:
                resp = client.get(
                    f"{mock.base_url}/tickets/tkt_101",
                    headers={"Authorization": "Bearer offline-token"},
                )
                assert resp.status_code == 200
                assert resp.json()["id"] == "tkt_101"

    denied = [a for a in guard.attempts if not a.allowed]
    allowed = [a for a in guard.attempts if a.allowed]
    assert len(denied) >= 2
    assert len(allowed) >= 1

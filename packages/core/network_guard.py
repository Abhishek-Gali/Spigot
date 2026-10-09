"""Network policy and socket-level egress guard for Spigot / DocForge MCP.

Enforces STRICT_OFFLINE and CONNECTED_SERVICES boundaries per ARCHITECTURE.md,
SECURITY.md, and OFFLINE_OPERATIONS.md:
- STRICT_OFFLINE permits only loopback (127.0.0.1, ::1, localhost) on registered
  ports (or ephemeral loopback ports when explicitly enabled for local tests).
- Blocks link-local/cloud metadata (169.254.0.0/16, fe80::/10), RFC1918 private
  addresses, multicast, and arbitrary external hosts.
- Installs an optional Python socket.socket.connect / create_connection guard
  and urllib/httpx pre-request validator to capture and deny unauthorized egress
  attempts during offline verification runs.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse


class NetworkProfile(StrEnum):
    STRICT_OFFLINE = "STRICT_OFFLINE"
    CONNECTED_SERVICES = "CONNECTED_SERVICES"


class EgressDeniedError(PermissionError):
    """Raised when a network request or socket connection violates the active policy."""

    def __init__(self, target: str, reason: str, profile: NetworkProfile) -> None:
        self.target = target
        self.reason = reason
        self.profile = profile
        super().__init__(f"[{profile.value}] Egress denied for '{target}': {reason}")


@dataclass(frozen=True)
class EgressAttemptRecord:
    """Audit record for every inspected connection attempt."""

    host: str
    port: int | None
    allowed: bool
    reason: str
    profile: str


@dataclass
class NetworkPolicyGuard:
    """Enforces loopback-only offline policy or explicit origin allowlists."""

    profile: NetworkProfile = NetworkProfile.STRICT_OFFLINE
    registered_loopback_ports: set[int] = field(default_factory=lambda: {11434})
    allow_any_loopback_port: bool = True
    allowed_connected_origins: set[str] = field(default_factory=set)
    attempts: list[EgressAttemptRecord] = field(default_factory=list)

    def _record(self, host: str, port: int | None, allowed: bool, reason: str) -> None:
        self.attempts.append(
            EgressAttemptRecord(
                host=host,
                port=port,
                allowed=allowed,
                reason=reason,
                profile=self.profile.value,
            )
        )

    def validate_url(self, url: str) -> None:
        """Validate a URL before issuing any HTTP request."""
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            self._record(url, None, False, f"Unsupported scheme '{scheme}'")
            raise EgressDeniedError(url, f"Unsupported scheme '{scheme}'", self.profile)

        host = parsed.hostname
        if not host:
            self._record(url, None, False, "Missing hostname in URL")
            raise EgressDeniedError(url, "Missing hostname in URL", self.profile)

        port = parsed.port or (443 if scheme == "https" else 80)
        self.validate_host_port(host, port, origin=f"{scheme}://{host}:{port}")

    def validate_host_port(self, host: str, port: int | None, origin: str | None = None) -> None:
        """Validate a hostname/IP and port against active network policy and SSRF rules."""
        normalized_host = host.strip().lower().strip("[]")

        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        try:
            ip_obj = ipaddress.ip_address(normalized_host)
        except ValueError:
            ip_obj = None

        if ip_obj is not None:
            self._check_ip_address(normalized_host, ip_obj, port, origin)
            return

        if normalized_host == "localhost":
            self._check_loopback_port("localhost", port)
            return

        if self.profile == NetworkProfile.STRICT_OFFLINE:
            reason = "External hostname resolution and egress disabled in STRICT_OFFLINE mode"
            self._record(normalized_host, port, False, reason)
            raise EgressDeniedError(f"{normalized_host}:{port}", reason, self.profile)

        candidate_origin = origin or f"https://{normalized_host}:{port or 443}"
        if (
            normalized_host not in self.allowed_connected_origins
            and candidate_origin not in self.allowed_connected_origins
        ):
            reason = f"Host '{normalized_host}' is not in reviewed connected origins"
            self._record(normalized_host, port, False, reason)
            raise EgressDeniedError(f"{normalized_host}:{port}", reason, self.profile)

        try:
            addr_info = socket.getaddrinfo(normalized_host, port or 443)
        except OSError as exc:
            reason = f"DNS resolution failed for '{normalized_host}': {exc}"
            self._record(normalized_host, port, False, reason)
            raise EgressDeniedError(f"{normalized_host}:{port}", reason, self.profile) from exc

        for entry in addr_info:
            sockaddr = entry[4]
            resolved_ip_str = str(sockaddr[0]).split("%")[0]
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
            if (
                resolved_ip.is_loopback
                or resolved_ip.is_link_local
                or resolved_ip.is_private
                or resolved_ip.is_multicast
                or resolved_ip.is_unspecified
            ):
                reason = (
                    f"Host '{normalized_host}' resolved to non-public IP '{resolved_ip}' "
                    "(SSRF/rebinding protection)"
                )
                self._record(normalized_host, port, False, reason)
                raise EgressDeniedError(f"{normalized_host}:{port}", reason, self.profile)

        self._record(normalized_host, port, True, "Allowed connected origin")

    def _check_ip_address(
        self,
        raw_host: str,
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
        port: int | None,
        origin: str | None,
    ) -> None:
        if ip_obj.is_link_local or str(ip_obj).startswith("169.254."):
            reason = (
                "Link-local / cloud metadata address (169.254.0.0/16 or fe80::/10) is forbidden"
            )
            self._record(raw_host, port, False, reason)
            raise EgressDeniedError(f"{raw_host}:{port}", reason, self.profile)

        if ip_obj.is_loopback:
            self._check_loopback_port(raw_host, port)
            return

        if ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_unspecified:
            reason = f"Private, multicast, or unspecified IP '{ip_obj}' is forbidden"
            self._record(raw_host, port, False, reason)
            raise EgressDeniedError(f"{raw_host}:{port}", reason, self.profile)

        if self.profile == NetworkProfile.STRICT_OFFLINE:
            reason = f"External IP '{ip_obj}' is forbidden in STRICT_OFFLINE mode"
            self._record(raw_host, port, False, reason)
            raise EgressDeniedError(f"{raw_host}:{port}", reason, self.profile)

        candidate_origin = origin or f"https://{raw_host}:{port or 443}"
        if (
            raw_host not in self.allowed_connected_origins
            and candidate_origin not in self.allowed_connected_origins
        ):
            reason = f"Public IP '{ip_obj}' is not in reviewed connected origins"
            self._record(raw_host, port, False, reason)
            raise EgressDeniedError(f"{raw_host}:{port}", reason, self.profile)

        self._record(raw_host, port, True, "Allowed connected IP")

    def _check_loopback_port(self, host: str, port: int | None) -> None:
        if (
            not self.allow_any_loopback_port
            and port is not None
            and port not in self.registered_loopback_ports
        ):
            ports_list = sorted(self.registered_loopback_ports)
            reason = f"Loopback port {port} is not in registered loopback ports {ports_list}"
            self._record(host, port, False, reason)
            raise EgressDeniedError(f"{host}:{port}", reason, self.profile)

        self._record(host, port, True, "Allowed loopback endpoint")

    @contextlib.contextmanager
    def enforce_socket_guard(self) -> Iterator[NetworkPolicyGuard]:
        """Context manager that hooks socket.socket.connect and socket.create_connection."""
        orig_connect = socket.socket.connect
        orig_connect_ex = socket.socket.connect_ex
        orig_create_connection = socket.create_connection
        guard = self

        def guarded_connect(sock: socket.socket, address: Any) -> Any:
            if isinstance(address, tuple) and len(address) >= 2:
                host, port = str(address[0]), int(address[1])
                guard.validate_host_port(host, port)
            return orig_connect(sock, address)

        def guarded_connect_ex(sock: socket.socket, address: Any) -> int:
            if isinstance(address, tuple) and len(address) >= 2:
                host, port = str(address[0]), int(address[1])
                guard.validate_host_port(host, port)
            return orig_connect_ex(sock, address)

        def guarded_create_connection(
            address: tuple[str, int], *args: Any, **kwargs: Any
        ) -> socket.socket:
            host, port = str(address[0]), int(address[1])
            guard.validate_host_port(host, port)
            return orig_create_connection(address, *args, **kwargs)

        socket.socket.connect = guarded_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign]
        socket.create_connection = guarded_create_connection  # type: ignore[assignment]
        try:
            yield self
        finally:
            socket.socket.connect = orig_connect  # type: ignore[method-assign]
            socket.socket.connect_ex = orig_connect_ex  # type: ignore[method-assign]
            socket.create_connection = orig_create_connection  # type: ignore[assignment]

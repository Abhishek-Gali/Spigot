"""Standalone Generated MCP Runtime Engine for Spigot / DocForge MCP (T10/T11/T12).

This module is self-contained (stdlib + `mcp`, `httpx`, `jsonschema` only) so it can be:
1. Imported directly in-workspace as `packages.runtime.engine`, AND
2. Vendored verbatim into exported server ZIP packages without requiring the Spigot
   backend, SQLite database, or local AI model.

Implements the exact execution sequence from GENERATOR_RUNTIME.md:
Validate tool identity -> load policy -> validate arguments -> normalize action/target ->
verify approval if required -> resolve credentials from runtime environment ->
construct HTTP request -> enforce network/domain limits -> execute within deadline ->
map response/error -> emit redacted stderr trace.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlparse

import httpx
import jsonschema
from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

PROTECTED_HEADERS = frozenset(
    {"host", "authorization", "content-length", "transfer-encoding", "connection"}
)
ENV_CRED_PREFIX = "SPIGOT_CRED_"
ENV_SERVER_URL_PREFIX = "SPIGOT_SERVER_URL_"


def env_var_for_scheme(scheme_id: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9]+", "_", scheme_id).strip("_").upper()
    return f"{ENV_CRED_PREFIX}{clean}"


def env_var_for_server(server_id: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9]+", "_", server_id).strip("_").upper()
    return f"{ENV_SERVER_URL_PREFIX}{clean}"


def redact_secrets(text: str, secrets_to_scrub: list[str]) -> str:
    """Scrub plaintext and URL-encoded secret values from logs and error strings."""
    out = text
    for secret in secrets_to_scrub:
        if not secret or len(secret) < 3:
            continue
        out = out.replace(secret, "<REDACTED_CREDENTIAL>")
        encoded = quote(secret, safe="")
        if encoded and len(encoded) >= 3:
            out = out.replace(encoded, "<REDACTED_CREDENTIAL>")
    return out


def emit_stderr_trace(
    event: str,
    secrets_to_scrub: list[str] | None = None,
    **fields: Any,
) -> None:
    """Write structured JSON trace strictly to stderr (stdout is reserved for MCP protocol)."""
    record = {"logger": "spigot.runtime", "event": event, **fields}
    raw_line = json.dumps(record, sort_keys=True, default=str)
    safe_line = redact_secrets(raw_line, secrets_to_scrub or [])
    sys.stderr.write(safe_line + "\n")
    sys.stderr.flush()


def make_error_call_result(
    code: str,
    user_message: str,
    *,
    stage: str = "runtime_execution",
    operation_id: str | None = None,
    retryable: bool = False,
    secrets_to_scrub: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> types.CallToolResult:
    scrub_list = secrets_to_scrub or []
    envelope = {
        "error": {
            "schema_version": "1.0",
            "code": code,
            "user_message": redact_secrets(user_message, scrub_list),
            "retryable": retryable,
            "stage": stage,
            "operation_id": operation_id,
            "redacted_details": json.loads(
                redact_secrets(json.dumps(details or {}, sort_keys=True), scrub_list)
            ),
        }
    }
    return types.CallToolResult(
        isError=True,
        content=[
            types.TextContent(
                type="text",
                text=json.dumps(envelope, sort_keys=True),
            )
        ],
    )


def _extract_loopback_ports_from_origins(origins: set[str]) -> set[int]:
    ports: set[int] = set()
    for orig in origins:
        parsed = urlparse(orig if "://" in orig else f"http://{orig}")
        host = (parsed.hostname or "").strip().lower().strip("[]")
        if not host:
            continue
        port = parsed.port or (443 if (parsed.scheme or "").lower() == "https" else 80)
        if host == "localhost":
            ports.add(port)
            continue
        try:
            if ipaddress.ip_address(host).is_loopback:
                ports.add(port)
        except ValueError:
            pass
    return ports


def validate_url_against_policy(url: str, policy: dict[str, Any]) -> str:
    """Enforce STRICT_OFFLINE or CONNECTED_SERVICES origin/SSRF rules on final request URL.

    Returns the verified destination IP address string to bind the outbound transport connection.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise PermissionError(f"Unsupported URL scheme '{scheme}'")

    host = (parsed.hostname or "").strip().lower().strip("[]")
    if not host:
        raise PermissionError("Missing hostname in request URL")

    port = parsed.port or (443 if scheme == "https" else 80)
    profile = policy.get("network_profile", "STRICT_OFFLINE")
    allowed_origins = set(policy.get("allowed_origins", []))
    allow_any_loopback_port = bool(policy.get("allow_any_loopback_port", False))
    allowed_loopback_ports = {
        int(p) for p in policy.get("allowed_loopback_ports", [11434])
    } | _extract_loopback_ports_from_origins(allowed_origins)

    def _check_loopback_port() -> None:
        if not allow_any_loopback_port and port not in allowed_loopback_ports:
            raise PermissionError(
                f"Loopback port {port} is not in policy allowed_loopback_ports {sorted(allowed_loopback_ports)}"
            )

    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if ip_obj.is_link_local or str(ip_obj).startswith("169.254."):
            raise PermissionError("Link-local/metadata IP address is forbidden")
        if ip_obj.is_loopback:
            _check_loopback_port()
            return str(ip_obj)
        if ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_unspecified:
            raise PermissionError(f"Private or reserved IP '{ip_obj}' is forbidden")
        if profile == "STRICT_OFFLINE":
            raise PermissionError(
                f"External IP '{ip_obj}' is denied in STRICT_OFFLINE mode"
            )
        origin = f"{scheme}://{host}:{port}"
        if host not in allowed_origins and origin not in allowed_origins:
            raise PermissionError(
                f"Origin '{origin}' is not in policy allowed_origins"
            )
        return str(ip_obj)

    if host == "localhost":
        _check_loopback_port()
        return "127.0.0.1"

    if profile == "STRICT_OFFLINE":
        raise PermissionError(
            f"External host '{host}' is denied in STRICT_OFFLINE mode"
        )

    origin = f"{scheme}://{host}:{port}"
    default_origin = f"{scheme}://{host}"
    if (
        host not in allowed_origins
        and origin not in allowed_origins
        and default_origin not in allowed_origins
    ):
        raise PermissionError(
            f"Host '{host}' is not in reviewed policy allowed_origins"
        )

    # Verify DNS resolution does not point to loopback, link-local, or private IPs
    try:
        addr_info = socket.getaddrinfo(host, port)
    except OSError as exc:
        raise PermissionError(f"DNS resolution failed for '{host}': {exc}") from exc

    verified_ips: list[str] = []
    for entry in addr_info:
        resolved_str = str(entry[4][0]).split("%")[0]
        resolved_ip = ipaddress.ip_address(resolved_str)
        if (
            resolved_ip.is_loopback
            or resolved_ip.is_link_local
            or resolved_ip.is_private
            or resolved_ip.is_multicast
            or resolved_ip.is_unspecified
        ):
            raise PermissionError(
                f"Host '{host}' resolved to non-public IP '{resolved_ip}' (SSRF denied)"
            )
        verified_ips.append(str(resolved_ip))

    if not verified_ips:
        raise PermissionError(f"Host '{host}' returned no valid IP addresses")
    return verified_ips[0]


class PinnedDNSAsyncTransport(httpx.AsyncBaseTransport):
    """HTTPX AsyncTransport wrapper that prevents DNS-rebinding TOCTOU by pinning the verified IP."""

    def __init__(
        self,
        policy: dict[str, Any],
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._policy = policy
        self._inner = inner or httpx.AsyncHTTPTransport(trust_env=False, retries=0)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        pinned_ip = validate_url_against_policy(str(request.url), self._policy)
        original_host = request.url.host
        ip_obj = ipaddress.ip_address(pinned_ip)
        connect_host = f"[{pinned_ip}]" if isinstance(ip_obj, ipaddress.IPv6Address) else pinned_ip
        if original_host.strip("[]") != pinned_ip:
            default_port = 443 if request.url.scheme == "https" else 80
            host_hdr = (
                original_host
                if request.url.port in (None, default_port)
                else f"{original_host}:{request.url.port}"
            )
            headers = request.headers.copy()
            if "host" not in headers:
                headers["Host"] = host_hdr
            extensions = dict(request.extensions)
            if request.url.scheme == "https" and "sni_hostname" not in extensions:
                extensions["sni_hostname"] = original_host
            pinned_request = httpx.Request(
                method=request.method,
                url=request.url.copy_with(host=connect_host),
                headers=headers,
                stream=request.stream,
                extensions=extensions,
            )
            return await self._inner.handle_async_request(pinned_request)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def build_operation_input_schema(op: dict[str, Any]) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []

    for param in op.get("parameters", []):
        p_schema = dict(param.get("schema", {"type": "string"}))
        if param.get("description") and "description" not in p_schema:
            p_schema["description"] = param["description"]
        if param.get("default_value") is not None and "default" not in p_schema:
            p_schema["default"] = param["default_value"]
        arg_name = param["safe_argument_name"]
        properties[arg_name] = p_schema
        if param.get("required", False):
            required.append(arg_name)

    req_body = op.get("request_body")
    if isinstance(req_body, dict):
        b_schema = dict(req_body.get("schema", {"type": "object"}))
        if req_body.get("description") and "description" not in b_schema:
            b_schema["description"] = req_body["description"]
        body_arg = "body" if "body" not in properties else "request_body"
        properties[body_arg] = b_schema
        if req_body.get("required", False):
            required.append(body_arg)

    out: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        out["required"] = required
    return out


class ContractRuntimeEngine:
    """Data-driven MCP server runtime executing frozen contract, tool plan, and policy."""

    def __init__(
        self,
        contract_data: dict[str, Any],
        tool_plan_data: dict[str, Any],
        policy_data: dict[str, Any],
        *,
        server_name: str = "spigot-generated-mcp",
        server_version: str = "0.1.0",
        environ: dict[str, str] | None = None,
    ) -> None:
        self.contract = contract_data
        self.tool_plan = tool_plan_data
        self.policy = policy_data
        self.server_name = server_name
        self.server_version = server_version
        self._explicit_environ = environ

        self.servers_by_id: dict[str, dict[str, Any]] = {
            s["server_id"]: s for s in self.contract.get("servers", [])
        }
        self.schemes_by_id: dict[str, dict[str, Any]] = {
            s["scheme_id"]: s for s in self.contract.get("security_schemes", [])
        }
        self.ops_by_id: dict[str, dict[str, Any]] = {
            op["stable_id"]: op for op in self.contract.get("operations", [])
        }

        # Map safe tool_name -> operation dict (including unselected/blocked ops so direct calls
        # to disabled tool names receive an explicit POLICY_DENIED error)
        self.tool_to_op: dict[str, dict[str, Any]] = {}
        self.enabled_tool_names: set[str] = set()

        plan_tool_names: dict[str, str] = self.tool_plan.get("tool_names", {})
        selected_op_ids = set(self.tool_plan.get("operation_ids", []))
        disabled_op_ids = set(self.policy.get("disabled_operations", []))

        for op_id, op in self.ops_by_id.items():
            t_name = plan_tool_names.get(op_id) or re.sub(
                r"[^a-zA-Z0-9_]+", "_", op_id
            ).strip("_").lower()
            self.tool_to_op[t_name] = op
            # Also register by stable_id so direct invocation by stable_id is caught by policy
            self.tool_to_op[op_id] = op
            if (
                op_id in selected_op_ids
                and op_id not in disabled_op_ids
                and op.get("support_status") == "supported"
                and self._is_effect_advertised(op)
            ):
                self.enabled_tool_names.add(t_name)

        self._contract_loopback_ports = _extract_loopback_ports_from_origins(
            {str(s.get("base_url", "")) for s in self.contract.get("servers", [])}
        )
        self._consumed_approvals: set[str] = set()
        self._circuit_state: dict[tuple[str, str], dict[str, Any]] = {}
        max_conc = max(1, int(self.policy.get("max_concurrent_calls", 5)))
        self._concurrency_sem = asyncio.Semaphore(max_conc)

    def _effective_network_policy(self) -> dict[str, Any]:
        eff = dict(self.policy)
        if "allowed_loopback_ports" not in eff:
            eff["allowed_loopback_ports"] = sorted(
                {11434, *self._contract_loopback_ports}
            )
        return eff

    def _env(self) -> dict[str, str]:
        if self._explicit_environ is not None:
            return self._explicit_environ
        return dict(os.environ)

    @staticmethod
    def _credential_fingerprint(secrets_list: list[str]) -> str:
        """Return a non-reversible SHA-256 fingerprint for circuit breaker keying without storing secrets."""
        if not secrets_list:
            return "public"
        joined = "|".join(secrets_list).encode("utf-8")
        return hashlib.sha256(joined).hexdigest()[:16]

    def get_circuit_breaker_status(
        self, server_ref: str, credential_fingerprint: str = "public"
    ) -> dict[str, Any]:
        key = (server_ref, credential_fingerprint)
        entry = self._circuit_state.get(key, {"failures": 0, "opened_until": 0.0})
        now = time.monotonic()
        opened_until = float(entry.get("opened_until", 0.0))
        is_open = now < opened_until
        return {
            "server_ref": server_ref,
            "credential_fingerprint": credential_fingerprint,
            "state": "open" if is_open else "closed",
            "consecutive_failures": int(entry.get("failures", 0)),
            "cooldown_remaining_sec": max(0.0, round(opened_until - now, 3)),
        }

    def reset_circuit_breaker(self, server_ref: str | None = None) -> None:
        if server_ref is None:
            self._circuit_state.clear()
            return
        keys_to_remove = [k for k in self._circuit_state if k[0] == server_ref]
        for k in keys_to_remove:
            self._circuit_state.pop(k, None)

    def _record_upstream_success(self, server_ref: str, cred_fp: str) -> None:
        key = (server_ref, cred_fp)
        if key in self._circuit_state:
            self._circuit_state[key] = {"failures": 0, "opened_until": 0.0}

    def _record_upstream_failure(self, server_ref: str, cred_fp: str) -> None:
        key = (server_ref, cred_fp)
        threshold = max(1, int(self.policy.get("circuit_breaker_threshold", 3)))
        cooldown = max(0.1, float(self.policy.get("circuit_breaker_cooldown_sec", 15.0)))
        entry = self._circuit_state.setdefault(key, {"failures": 0, "opened_until": 0.0})
        entry["failures"] = int(entry.get("failures", 0)) + 1
        if entry["failures"] >= threshold:
            entry["opened_until"] = time.monotonic() + cooldown
            emit_stderr_trace(
                "circuit_breaker_opened",
                server_ref=server_ref,
                credential_fingerprint=cred_fp,
                failures=entry["failures"],
                cooldown_sec=cooldown,
            )

    def _resolve_approval_secret(self) -> str:
        env = self._env()
        secret = env.get("SPIGOT_APPROVAL_SECRET", "").strip()
        if secret:
            return secret
        secret_file = env.get("SPIGOT_APPROVAL_SECRET_FILE", "").strip()
        if secret_file:
            sf_path = Path(secret_file)
            if sf_path.is_file():
                return sf_path.read_text(encoding="utf-8").strip()
            return ""
        if self._explicit_environ is None:
            for default_candidate in (
                Path.cwd() / ".spigot" / "workspace" / "approval_authority.key",
                Path.cwd() / ".spigot" / "approval_authority.key",
            ):
                if default_candidate.is_file():
                    return default_candidate.read_text(encoding="utf-8").strip()
        return ""

    def _is_effect_advertised(self, op: dict[str, Any]) -> bool:
        effect = op.get("semantic_effect", "unknown")
        if effect == "unknown":
            return False
        if effect == "read":
            return True
        mode = self.policy.get("mode", "read_only")
        if mode == "read_only":
            return False
        if mode == "restricted_write":
            return op["stable_id"] in set(
                self.policy.get("allowed_write_operations", [])
            )
        if mode == "approval_required":
            return len(self._resolve_approval_secret()) >= 16
        return False

    def list_tools_sync(self) -> list[types.Tool]:
        tools: list[types.Tool] = []
        plan_tool_names: dict[str, str] = self.tool_plan.get("tool_names", {})
        plan_descriptions: dict[str, str] = self.tool_plan.get("descriptions", {})

        for op_id in self.tool_plan.get("operation_ids", []):
            op = self.ops_by_id.get(op_id)
            if op is None:
                continue
            t_name = plan_tool_names.get(op_id, op_id)
            if t_name not in self.enabled_tool_names:
                continue
            desc = plan_descriptions.get(op_id) or op.get("display_name", t_name)
            input_schema = build_operation_input_schema(op)
            tools.append(
                types.Tool(
                    name=t_name,
                    description=str(desc),
                    inputSchema=input_schema,
                )
            )
        emit_stderr_trace("tools_listed", count=len(tools), mode=self.policy.get("mode"))
        return tools

    def _resolve_auth(
        self, op: dict[str, Any]
    ) -> tuple[dict[str, str], list[tuple[str, str]], list[str], str | None]:
        """Resolve runtime credentials from environment.

        Returns (auth_headers, auth_query_items, secret_values, error_message_or_none).
        """
        sec_req = op.get("security_requirement", {"status": "unknown", "alternatives": []})
        status = sec_req.get("status", "unknown")
        if status == "public":
            return {}, [], [], None
        if status == "unknown":
            return (
                {},
                [],
                [],
                f"Operation '{op['stable_id']}' has unknown authentication status.",
            )

        env = self._env()
        alternatives = sec_req.get("alternatives", [])
        missing_env_vars: list[str] = []

        for alt in alternatives:
            scheme_ids = alt.get("all_of", [])
            headers: dict[str, str] = {}
            queries: list[tuple[str, str]] = []
            secrets_found: list[str] = []
            alt_satisfied = True

            for sid in scheme_ids:
                scheme = self.schemes_by_id.get(sid)
                if scheme is None:
                    alt_satisfied = False
                    break
                env_name = env_var_for_scheme(sid)
                val = env.get(env_name, "").strip()
                if not val:
                    missing_env_vars.append(env_name)
                    alt_satisfied = False
                    break

                secrets_found.append(val)
                s_type = scheme.get("type")
                if s_type == "http" and (scheme.get("scheme") or "").lower() == "bearer":
                    headers["Authorization"] = f"Bearer {val}"
                elif s_type == "apiKey" and scheme.get("location") == "header":
                    hdr_name = scheme.get("name") or "X-API-Key"
                    headers[hdr_name] = val
                elif s_type == "apiKey" and scheme.get("location") == "query":
                    q_name = scheme.get("name") or "api_key"
                    queries.append((q_name, val))
                else:
                    alt_satisfied = False
                    break

            if alt_satisfied:
                return headers, queries, secrets_found, None

        unique_missing = sorted(set(missing_env_vars))
        return (
            {},
            [],
            [],
            f"Missing required runtime credential environment variable(s): {unique_missing}",
        )

    def _verify_approval_if_needed(
        self,
        op: dict[str, Any],
        arguments: dict[str, Any],
        target_url: str,
    ) -> str | None:
        """Verify argument-bound single-use approval token when policy mode is approval_required."""
        effect = op.get("semantic_effect", "unknown")
        if effect == "read":
            return None
        mode = self.policy.get("mode", "read_only")
        if mode != "approval_required":
            return None

        env = self._env()
        secret = self._resolve_approval_secret()
        if not secret or len(secret) < 16:
            return (
                "Approval-required write operation is disabled because "
                "SPIGOT_APPROVAL_SECRET authority is not configured or has <16 characters."
            )
        token_raw = env.get("SPIGOT_ACTION_APPROVAL_TOKEN", "")
        if not token_raw:
            return "Missing single-use owner approval token for mutating operation."

        try:
            token_data = json.loads(token_raw)
            nonce = str(token_data["nonce"])
            expires_at = float(token_data["expires_at"])
            provided_sig = str(token_data["signature"])
        except (KeyError, ValueError, TypeError):
            return "Malformed action approval token."

        if time.time() > expires_at:
            return "Action approval token has expired."
        if nonce in self._consumed_approvals:
            return "Action approval token has already been consumed (replay denied)."

        contract_hash = self.contract.get("canonical_hash", "")
        policy_hash = self.policy.get("policy_hash", "")

        digest_payload = json.dumps(
            {
                "operation_id": op["stable_id"],
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
        expected_sig = hmac.new(
            secret.encode("utf-8"), digest_payload, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(provided_sig, expected_sig):
            return "Action approval token signature mismatch for arguments/contract/policy."

        if "action_digest" in token_data:
            expected_action_digest = hashlib.sha256(
                json.dumps(
                    {
                        "arguments": arguments,
                        "contract_hash": contract_hash,
                        "operation_id": op["stable_id"],
                        "policy_hash": policy_hash,
                        "target_url": target_url,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            if str(token_data["action_digest"]) != expected_action_digest:
                return "Action approval token action_digest mismatch."

        ledger_file = (
            env.get("SPIGOT_APPROVAL_LEDGER_PATH", "").strip()
            or str(self.policy.get("approval_ledger_path", "")).strip()
        )
        if not ledger_file and not bool(
            self.policy.get("allow_ephemeral_approval_ledger", False)
        ):
            secret_file = env.get("SPIGOT_APPROVAL_SECRET_FILE", "").strip()
            if secret_file and Path(secret_file).is_file():
                ledger_file = str(
                    Path(secret_file).resolve().parent / "consumed_approvals.sqlite3"
                )
            else:
                ledger_file = str(Path.cwd() / ".spigot" / "consumed_approvals.sqlite3")

        if ledger_file:
            ledger_path = Path(ledger_file)
            try:
                ledger_path.parent.mkdir(parents=True, exist_ok=True)
                with contextlib.closing(sqlite3.connect(ledger_path)) as conn, conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS consumed_approvals (
                            nonce TEXT PRIMARY KEY,
                            action_digest TEXT NOT NULL,
                            consumed_at REAL NOT NULL,
                            expires_at REAL NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        INSERT INTO consumed_approvals (nonce, action_digest, consumed_at, expires_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (nonce, str(token_data.get("action_digest", "")), time.time(), expires_at),
                    )
            except sqlite3.IntegrityError:
                return "Action approval token has already been consumed in ledger (replay denied)."
            except (sqlite3.Error, OSError) as exc:
                return f"Action approval ledger unavailable or unwritable (fail-closed): {exc}"

        self._consumed_approvals.add(nonce)
        return None

    async def call_tool_async(
        self, tool_name: str, arguments: dict[str, Any] | None
    ) -> types.CallToolResult:
        args = dict(arguments or {})

        # 1. Validate tool identity
        op = self.tool_to_op.get(tool_name)
        if op is None:
            emit_stderr_trace("policy_denied_unknown_tool", tool_name=tool_name)
            return make_error_call_result(
                "POLICY_DENIED",
                f"Tool '{tool_name}' is not registered in this MCP server.",
                stage="tool_identity",
            )

        op_id = str(op["stable_id"])

        # 2. Enforce policy (support status, disabled list, tool plan membership, semantic effect)
        if op.get("support_status") != "supported":
            emit_stderr_trace("policy_denied_unsupported", tool_name=tool_name, operation_id=op_id)
            return make_error_call_result(
                "POLICY_DENIED",
                f"Operation '{op_id}' is blocked or unsupported and cannot be executed.",
                stage="policy_check",
                operation_id=op_id,
            )

        if op_id in set(self.policy.get("disabled_operations", [])) or (
            op_id not in set(self.tool_plan.get("operation_ids", []))
        ):
            emit_stderr_trace("policy_denied_disabled", tool_name=tool_name, operation_id=op_id)
            return make_error_call_result(
                "POLICY_DENIED",
                f"Operation '{op_id}' is disabled by the active tool plan or policy.",
                stage="policy_check",
                operation_id=op_id,
            )

        effect = op.get("semantic_effect", "unknown")
        if effect == "unknown":
            emit_stderr_trace("policy_denied_unknown_effect", operation_id=op_id)
            return make_error_call_result(
                "POLICY_DENIED",
                f"Operation '{op_id}' has unknown semantic effect and is disabled by default.",
                stage="policy_check",
                operation_id=op_id,
            )

        mode = self.policy.get("mode", "read_only")
        if effect != "read":
            if mode == "read_only":
                emit_stderr_trace("policy_denied_read_only", operation_id=op_id, effect=effect)
                return make_error_call_result(
                    "POLICY_DENIED",
                    f"Mutating operation '{op_id}' ({effect}) is denied in read_only policy mode.",
                    stage="policy_check",
                    operation_id=op_id,
                )
            if mode == "restricted_write" and op_id not in set(
                self.policy.get("allowed_write_operations", [])
            ):
                emit_stderr_trace("policy_denied_restricted_write", operation_id=op_id)
                return make_error_call_result(
                    "POLICY_DENIED",
                    f"Operation '{op_id}' is not in policy allowed_write_operations.",
                    stage="policy_check",
                    operation_id=op_id,
                )

        # 3. Validate arguments against JSON Schema
        input_schema = build_operation_input_schema(op)
        try:
            jsonschema.validate(instance=args, schema=input_schema)
        except jsonschema.ValidationError as exc:
            return make_error_call_result(
                "CONTRACT_INCOMPLETE",
                f"Invalid tool arguments for '{tool_name}': {exc.message}",
                stage="argument_validation",
                operation_id=op_id,
            )

        # 4. Resolve server base URL from reviewed configuration
        server_ref = op.get("server_ref", "")
        srv = self.servers_by_id.get(server_ref)
        if srv is None:
            return make_error_call_result(
                "CONTRACT_INCOMPLETE",
                f"Server reference '{server_ref}' not found in contract.",
                stage="url_construction",
                operation_id=op_id,
            )

        env = self._env()
        override_url = env.get(env_var_for_server(server_ref), "").strip()
        base_url = (override_url or str(srv["base_url"])).rstrip("/")

        # 5. Construct path, query, header, and JSON body
        rel_path = str(op["relative_path"])
        query_items: list[tuple[str, str]] = []
        req_headers: dict[str, str] = {"Accept": "application/json"}

        for param in op.get("parameters", []):
            safe_name = param["safe_argument_name"]
            ext_name = param["external_name"]
            loc = param["location"]

            if safe_name not in args:
                if param.get("default_value") is not None:
                    val = param["default_value"]
                else:
                    continue
            else:
                val = args[safe_name]

            if val is None:
                continue

            if loc == "path":
                str_val = str(val)
                if not str_val or str_val in {".", ".."} or "/" in str_val or "\\" in str_val:
                    return make_error_call_result(
                        "POLICY_DENIED",
                        f"Invalid or traversal path parameter value for '{ext_name}'.",
                        stage="request_serialization",
                        operation_id=op_id,
                    )
                encoded_val = quote(str_val, safe="")
                rel_path = rel_path.replace(f"{{{ext_name}}}", encoded_val)

            elif loc == "query":
                explode = bool(param.get("explode", True))
                if isinstance(val, list):
                    str_items = [
                        ("true" if x is True else "false" if x is False else str(x))
                        for x in val
                    ]
                    if explode:
                        for item_s in str_items:
                            query_items.append((ext_name, item_s))
                    else:
                        query_items.append((ext_name, ",".join(str_items)))
                elif isinstance(val, bool):
                    query_items.append((ext_name, "true" if val else "false"))
                else:
                    query_items.append((ext_name, str(val)))

            elif loc == "header":
                if ext_name.strip().lower() in PROTECTED_HEADERS:
                    return make_error_call_result(
                        "POLICY_DENIED",
                        f"Header parameter '{ext_name}' cannot override a protected header.",
                        stage="request_serialization",
                        operation_id=op_id,
                    )
                str_hdr = str(val)
                if "\r" in str_hdr or "\n" in str_hdr or "\x00" in str_hdr:
                    return make_error_call_result(
                        "POLICY_DENIED",
                        f"Header parameter '{ext_name}' contains forbidden control characters.",
                        stage="request_serialization",
                        operation_id=op_id,
                    )
                req_headers[ext_name] = str_hdr

        target_url = f"{base_url}{rel_path}"

        # 6. Verify action approval if required by policy
        approval_err = self._verify_approval_if_needed(op, args, target_url)
        if approval_err is not None:
            emit_stderr_trace("policy_denied_approval", operation_id=op_id, reason=approval_err)
            return make_error_call_result(
                "POLICY_DENIED",
                approval_err,
                stage="approval_verification",
                operation_id=op_id,
            )

        # 7. Resolve runtime credentials
        auth_headers, auth_queries, secrets_list, auth_err = self._resolve_auth(op)
        if auth_err is not None:
            emit_stderr_trace("auth_missing", operation_id=op_id)
            return make_error_call_result(
                "AUTH_MISSING",
                auth_err,
                stage="credential_resolution",
                operation_id=op_id,
            )

        req_headers.update(auth_headers)
        all_queries = [*query_items, *auth_queries]
        full_url = (
            f"{target_url}?{urlencode(all_queries, doseq=True)}"
            if all_queries
            else target_url
        )

        # 8. Validate final URL against network/domain policy
        net_policy = self._effective_network_policy()
        try:
            validate_url_against_policy(full_url, net_policy)
        except PermissionError as exc:
            emit_stderr_trace(
                "egress_denied",
                secrets_to_scrub=secrets_list,
                operation_id=op_id,
                url=full_url,
            )
            return make_error_call_result(
                "POLICY_DENIED",
                str(exc),
                stage="network_policy",
                operation_id=op_id,
                secrets_to_scrub=secrets_list,
            )

        json_body: Any = None
        if isinstance(op.get("request_body"), dict):
            body_key = (
                "request_body"
                if "request_body" in args and "body" not in args
                else "body"
            )
            json_body = args.get(body_key)

        # 9. Check circuit breaker and execute HTTP request within deadline, retry, and response size bounds
        cred_fp = self._credential_fingerprint(secrets_list)
        cb_status = self.get_circuit_breaker_status(server_ref, cred_fp)
        if cb_status["state"] == "open":
            emit_stderr_trace(
                "circuit_breaker_denied",
                operation_id=op_id,
                server_ref=server_ref,
                credential_fingerprint=cred_fp,
                cooldown_remaining_sec=cb_status["cooldown_remaining_sec"],
            )
            return make_error_call_result(
                "UPSTREAM_FAILED",
                (
                    f"Circuit breaker is OPEN for server '{server_ref}' "
                    f"(cooldown remaining: {cb_status['cooldown_remaining_sec']}s)."
                ),
                stage="circuit_breaker",
                operation_id=op_id,
                retryable=(effect == "read"),
                secrets_to_scrub=secrets_list,
                details=cb_status,
            )

        deadline = float(self.policy.get("request_deadline_sec", 30.0))
        connect_timeout = min(
            float(self.policy.get("connect_timeout_sec", 5.0)), deadline
        )
        max_bytes = int(self.policy.get("max_response_bytes", 1_048_576))
        max_retries_cfg = max(0, int(self.policy.get("max_retries", 3)))
        backoff_base = max(0.005, float(self.policy.get("retry_backoff_base_sec", 0.05)))

        is_read = effect == "read"
        idempotent_writes = set(self.policy.get("idempotent_write_operations", []))
        idempotency_hdr_name = str(
            self.policy.get("idempotency_key_header", "Idempotency-Key")
        )
        has_idempotency_key = (
            op_id in idempotent_writes and bool(req_headers.get(idempotency_hdr_name))
        )
        can_retry = is_read or has_idempotency_key
        max_attempts = max(1, max_retries_cfg) if can_retry else 1

        start_monotonic = time.monotonic()
        status_code: int | None = None
        resp_headers: httpx.Headers | None = None
        raw_content: bytes = b""
        attempts_made = 0

        async with self._concurrency_sem:
            for attempt in range(1, max_attempts + 1):
                attempts_made = attempt
                elapsed = time.monotonic() - start_monotonic
                remaining_budget = deadline - elapsed
                if remaining_budget <= 0.0:
                    return make_error_call_result(
                        "UPSTREAM_FAILED",
                        f"Request deadline ({deadline}s) exceeded for '{op_id}'.",
                        stage="http_transport",
                        operation_id=op_id,
                        retryable=can_retry,
                        secrets_to_scrub=secrets_list,
                        details={
                            "outcome": "retryable_read_error" if can_retry else "OUTCOME_UNKNOWN",
                            "attempts": attempts_made - 1,
                        },
                    )

                attempt_timeout = httpx.Timeout(
                    remaining_budget, connect=min(connect_timeout, remaining_budget)
                )
                try:
                    transport = PinnedDNSAsyncTransport(net_policy)
                    async with httpx.AsyncClient(
                        timeout=attempt_timeout,
                        trust_env=False,
                        follow_redirects=False,
                        transport=transport,
                    ) as client:
                        async with client.stream(
                            method=str(op["method"]),
                            url=full_url,
                            json=json_body,
                            headers=req_headers,
                        ) as response:
                            status_code = response.status_code
                            resp_headers = response.headers
                            cl_raw = response.headers.get("Content-Length", "").strip()
                            if cl_raw.isdigit() and int(cl_raw) > max_bytes:
                                return make_error_call_result(
                                    "UPSTREAM_FAILED",
                                    (
                                        f"Response from '{op_id}' ({cl_raw} bytes) exceeded "
                                        f"max_response_bytes budget ({max_bytes} bytes)."
                                    ),
                                    stage="response_bounds",
                                    operation_id=op_id,
                                    retryable=False,
                                    secrets_to_scrub=secrets_list,
                                )

                            chunks: list[bytes] = []
                            received_bytes = 0
                            async for chunk in response.aiter_bytes():
                                received_bytes += len(chunk)
                                if received_bytes > max_bytes:
                                    return make_error_call_result(
                                        "UPSTREAM_FAILED",
                                        (
                                            f"Response from '{op_id}' ({received_bytes} bytes) exceeded "
                                            f"max_response_bytes budget ({max_bytes} bytes)."
                                        ),
                                        stage="response_bounds",
                                        operation_id=op_id,
                                        retryable=False,
                                        secrets_to_scrub=secrets_list,
                                    )
                                chunks.append(chunk)
                            raw_content = b"".join(chunks)
                except PermissionError as exc:
                    emit_stderr_trace(
                        "egress_denied",
                        secrets_to_scrub=secrets_list,
                        operation_id=op_id,
                        url=full_url,
                    )
                    return make_error_call_result(
                        "POLICY_DENIED",
                        str(exc),
                        stage="network_policy",
                        operation_id=op_id,
                        secrets_to_scrub=secrets_list,
                    )
                except httpx.HTTPError as exc:
                    self._record_upstream_failure(server_ref, cred_fp)
                    if can_retry and attempt < max_attempts:
                        sleep_dur = backoff_base * (2 ** (attempt - 1))
                        if (time.monotonic() - start_monotonic) + sleep_dur < deadline:
                            await asyncio.sleep(sleep_dur)
                            continue
                    # Ambiguous outcome after a write must not be marked safely retryable
                    return make_error_call_result(
                        "UPSTREAM_FAILED",
                        (
                            f"Transport error during '{op_id}': {exc}"
                            if can_retry
                            else f"OUTCOME_UNKNOWN: Transport error during mutating call '{op_id}': {exc}"
                        ),
                        stage="http_transport",
                        operation_id=op_id,
                        retryable=can_retry,
                        secrets_to_scrub=secrets_list,
                        details={
                            "outcome": "retryable_read_error" if can_retry else "OUTCOME_UNKNOWN",
                            "attempts": attempts_made,
                        },
                    )

                assert status_code is not None and resp_headers is not None
                if status_code in {429, 502, 503, 504}:
                    if status_code >= 500:
                        self._record_upstream_failure(server_ref, cred_fp)
                    if can_retry and attempt < max_attempts:
                        retry_after_raw = resp_headers.get("Retry-After", "").strip()
                        sleep_dur = backoff_base * (2 ** (attempt - 1))
                        if retry_after_raw:
                            try:
                                sleep_dur = max(0.0, float(retry_after_raw))
                            except ValueError:
                                pass
                        if (time.monotonic() - start_monotonic) + sleep_dur < deadline:
                            await asyncio.sleep(sleep_dur)
                            continue
                break

        assert status_code is not None
        if status_code < 500 and status_code != 429:
            self._record_upstream_success(server_ref, cred_fp)

        if status_code == 429:
            return make_error_call_result(
                "UPSTREAM_RATE_LIMITED",
                f"Upstream rate limit (HTTP 429) on '{op_id}'.",
                stage="upstream_response",
                operation_id=op_id,
                retryable=can_retry,
                secrets_to_scrub=secrets_list,
                details={"status_code": 429, "attempts": attempts_made},
            )

        parsed_body: Any = None
        if raw_content:
            try:
                parsed_body = json.loads(raw_content.decode("utf-8"))
            except ValueError:
                parsed_body = {
                    "raw_text": redact_secrets(
                        raw_content.decode("utf-8", errors="replace"), secrets_list
                    )
                }

        is_http_err = status_code >= 400
        emit_stderr_trace(
            "tool_completed",
            secrets_to_scrub=secrets_list,
            operation_id=op_id,
            status_code=status_code,
            attempts=attempts_made,
            is_error=is_http_err,
        )
        result_envelope = {
            "operation_id": op_id,
            "status_code": status_code,
            "attempts": attempts_made,
            "data": parsed_body,
        }
        return types.CallToolResult(
            isError=is_http_err,
            content=[
                types.TextContent(
                    type="text",
                    text=redact_secrets(
                        json.dumps(result_envelope, sort_keys=True), secrets_list
                    ),
                )
            ],
        )

    async def call_tool_paginated_async(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> types.CallToolResult:
        """Bounded pagination traversal for explicitly configured read operations (T22).

        Refuses to invent cursor fields or loop without strict page/item/byte/deadline limits.
        """
        op = self.tool_to_op.get(tool_name)
        if op is None:
            return await self.call_tool_async(tool_name, arguments)

        op_id = str(op["stable_id"])
        pag_configs = self.policy.get("pagination_config", {})
        op_pag = pag_configs.get(op_id)
        if not isinstance(op_pag, dict):
            return make_error_call_result(
                "POLICY_DENIED",
                f"Bounded pagination is not configured for operation '{op_id}'.",
                stage="pagination_policy",
                operation_id=op_id,
            )

        cursor_param = str(op_pag.get("cursor_param", "cursor"))
        next_cursor_field = str(op_pag.get("next_cursor_field", "next_cursor"))
        items_field = str(op_pag.get("items_field", "items"))
        max_pages = max(1, int(op_pag.get("max_pages", 5)))
        max_items = max(1, int(op_pag.get("max_items", 100)))
        max_total_bytes = max(1024, int(op_pag.get("max_bytes", 524_288)))
        total_deadline = float(self.policy.get("request_deadline_sec", 30.0))

        start_ts = time.monotonic()
        current_args = dict(arguments or {})
        collected_items: list[Any] = []
        pages_fetched = 0
        total_bytes = 0
        next_cursor: str | None = None
        stop_reason = "completed"

        while pages_fetched < max_pages:
            if (time.monotonic() - start_ts) >= total_deadline:
                stop_reason = "deadline_reached"
                break

            page_result = await self.call_tool_async(tool_name, current_args)
            if page_result.is_error:
                return page_result

            raw_text = page_result.content[0].text
            total_bytes += len(raw_text.encode("utf-8"))
            if total_bytes > max_total_bytes:
                stop_reason = "max_bytes_reached"
                break

            pages_fetched += 1
            payload = json.loads(raw_text)
            data = payload.get("data") or {}
            page_items = data.get(items_field, [])
            if isinstance(page_items, list):
                for item in page_items:
                    if len(collected_items) >= max_items:
                        stop_reason = "max_items_reached"
                        break
                    collected_items.append(item)

            next_val = data.get(next_cursor_field)
            next_cursor = str(next_val) if next_val else None
            if stop_reason == "max_items_reached" or not next_cursor:
                break

            current_args[cursor_param] = next_cursor
        else:
            if next_cursor:
                stop_reason = "max_pages_reached"

        envelope = {
            "operation_id": op_id,
            "status_code": 200,
            "pages_fetched": pages_fetched,
            "stop_reason": stop_reason,
            "next_cursor": next_cursor,
            "data": {items_field: collected_items},
        }
        return types.CallToolResult(
            isError=False,
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps(envelope, sort_keys=True),
                )
            ],
        )

    def create_mcp_server(self) -> Server:
        async def _on_list_tools(
            ctx: ServerRequestContext[Any],
            params: types.PaginatedRequestParams | None,
        ) -> types.ListToolsResult:
            return types.ListToolsResult(tools=self.list_tools_sync())

        async def _on_call_tool(
            ctx: ServerRequestContext[Any],
            params: types.CallToolRequestParams,
        ) -> types.CallToolResult:
            return await self.call_tool_async(params.name, params.arguments)

        server = Server(
            name=self.server_name,
            version=self.server_version,
            on_list_tools=_on_list_tools,
            on_call_tool=_on_call_tool,
        )
        server.middleware.clear()
        return server

    async def run_stdio(self) -> None:
        server = self.create_mcp_server()
        init_opts = server.create_initialization_options()
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, init_opts)


def load_engine_from_package_dir(
    package_root: Path,
    *,
    server_name: str = "spigot-generated-mcp",
    server_version: str = "0.1.0",
) -> ContractRuntimeEngine:
    contract_data = json.loads(
        (package_root / "contract.json").read_text(encoding="utf-8")
    )
    tool_plan_data = json.loads(
        (package_root / "tool_plan.json").read_text(encoding="utf-8")
    )
    policy_data = json.loads(
        (package_root / "policy.json").read_text(encoding="utf-8")
    )
    return ContractRuntimeEngine(
        contract_data=contract_data,
        tool_plan_data=tool_plan_data,
        policy_data=policy_data,
        server_name=server_name,
        server_version=server_version,
    )

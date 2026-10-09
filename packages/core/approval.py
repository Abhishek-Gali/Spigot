"""Trusted Owner Approval Authority for Spigot / DocForge MCP (T23).

Implements prepare / approve / execute single-use, argument-bound action approvals
as specified in GENERATOR_RUNTIME.md and SECURITY.md:
- Canonicalizes exact `operation_id`, `arguments`, `target_url`, `contract_hash`,
  and `policy_hash` into a deterministic `action_digest`.
- Signs short-lived, single-use tokens with HMAC-SHA256 using the owner's
  `SPIGOT_APPROVAL_SECRET`.
- The MCP tool interface never exposes approval issuance; an agent cannot self-approve
  or pass a boolean `approved=True` parameter.
- Provides a persistent atomic consumed-nonce ledger (`ConsumedApprovalLedger`) so
  replayed tokens are rejected even across process restarts.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def compute_action_digest(
    *,
    operation_id: str,
    arguments: dict[str, Any],
    target_url: str,
    contract_hash: str,
    policy_hash: str,
) -> str:
    """Compute the deterministic SHA-256 action digest over canonical invocation parameters."""
    canonical_bytes = json.dumps(
        {
            "arguments": arguments,
            "contract_hash": contract_hash,
            "operation_id": operation_id,
            "policy_hash": policy_hash,
            "target_url": target_url,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_approval_signature(
    secret: str,
    *,
    operation_id: str,
    arguments: dict[str, Any],
    target_url: str,
    contract_hash: str,
    policy_hash: str,
    nonce: str,
    expires_at: float,
) -> str:
    """Compute HMAC-SHA256 signature over the exact invocation parameters, nonce, and expiry."""
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
    return hmac.new(secret.encode("utf-8"), digest_payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class PreparedActionApproval:
    """Prepared action summary presented to the local owner before signing."""

    action_digest: str
    operation_id: str
    arguments: dict[str, Any]
    target_url: str
    contract_hash: str
    policy_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_digest": self.action_digest,
            "operation_id": self.operation_id,
            "arguments": self.arguments,
            "target_url": self.target_url,
            "contract_hash": self.contract_hash,
            "policy_hash": self.policy_hash,
        }


class ConsumedApprovalLedger:
    """SQLite-backed atomic single-use nonce ledger preventing token replay across restarts."""

    def __init__(self, ledger_path: Path) -> None:
        self.ledger_path = ledger_path
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with contextlib.closing(sqlite3.connect(self.ledger_path)) as conn, conn:
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

    def try_consume(self, nonce: str, action_digest: str, expires_at: float) -> bool:
        """Atomically record a nonce as consumed. Returns False if already used."""
        now_ts = time.time()
        try:
            with contextlib.closing(sqlite3.connect(self.ledger_path)) as conn, conn:
                conn.execute(
                    """
                    INSERT INTO consumed_approvals (nonce, action_digest, consumed_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (nonce, action_digest, now_ts, expires_at),
                )
            return True
        except sqlite3.IntegrityError:
            return False


class ApprovalAuthority:
    """Owner-controlled local approval authority for `approval_required` policy mode."""

    def __init__(
        self,
        secret: str,
        *,
        ledger_path: Path | None = None,
        default_ttl_sec: float = 120.0,
    ) -> None:
        if not secret or len(secret.strip()) < 16:
            raise ValueError(
                "ApprovalAuthority secret must be at least 16 characters long."
            )
        self._secret = secret
        self.default_ttl_sec = default_ttl_sec
        self._ledger = ConsumedApprovalLedger(ledger_path) if ledger_path else None
        self._memory_nonces: set[str] = set()

    def prepare_action(
        self,
        *,
        operation_id: str,
        arguments: dict[str, Any],
        target_url: str,
        contract_hash: str,
        policy_hash: str,
    ) -> PreparedActionApproval:
        digest = compute_action_digest(
            operation_id=operation_id,
            arguments=arguments,
            target_url=target_url,
            contract_hash=contract_hash,
            policy_hash=policy_hash,
        )
        return PreparedActionApproval(
            action_digest=digest,
            operation_id=operation_id,
            arguments=arguments,
            target_url=target_url,
            contract_hash=contract_hash,
            policy_hash=policy_hash,
        )

    def issue_token(
        self,
        *,
        operation_id: str,
        arguments: dict[str, Any],
        target_url: str,
        contract_hash: str,
        policy_hash: str,
        ttl_sec: float | None = None,
        nonce: str | None = None,
        now_ts: float | None = None,
    ) -> dict[str, Any]:
        effective_now = time.time() if now_ts is None else now_ts
        effective_ttl = self.default_ttl_sec if ttl_sec is None else ttl_sec
        expires_at = round(effective_now + effective_ttl, 3)
        token_nonce = nonce or f" nonce_{secrets.token_hex(12)}".strip()
        action_digest = compute_action_digest(
            operation_id=operation_id,
            arguments=arguments,
            target_url=target_url,
            contract_hash=contract_hash,
            policy_hash=policy_hash,
        )
        signature = compute_approval_signature(
            self._secret,
            operation_id=operation_id,
            arguments=arguments,
            target_url=target_url,
            contract_hash=contract_hash,
            policy_hash=policy_hash,
            nonce=token_nonce,
            expires_at=expires_at,
        )
        return {
            "schema_version": "1.0",
            "action_digest": action_digest,
            "operation_id": operation_id,
            "contract_hash": contract_hash,
            "policy_hash": policy_hash,
            "nonce": token_nonce,
            "expires_at": expires_at,
            "signature": signature,
        }

    def issue_token_json(self, **kwargs: Any) -> str:
        return json.dumps(self.issue_token(**kwargs), sort_keys=True)

    def verify_and_consume(
        self,
        token_raw: str | dict[str, Any],
        *,
        operation_id: str,
        arguments: dict[str, Any],
        target_url: str,
        contract_hash: str,
        policy_hash: str,
        now_ts: float | None = None,
    ) -> str | None:
        """Verify token signature, arguments, hashes, expiry, and single-use nonce.

        Returns `None` on valid approval (and atomically consumes the nonce),
        or a descriptive denial reason string on failure.
        """
        try:
            token_data = (
                json.loads(token_raw) if isinstance(token_raw, str) else dict(token_raw)
            )
            nonce = str(token_data["nonce"])
            expires_at = float(token_data["expires_at"])
            provided_sig = str(token_data["signature"])
        except (KeyError, ValueError, TypeError):
            return "Malformed action approval token."

        check_now = time.time() if now_ts is None else now_ts
        if check_now > expires_at:
            return "Action approval token has expired."

        expected_sig = compute_approval_signature(
            self._secret,
            operation_id=operation_id,
            arguments=arguments,
            target_url=target_url,
            contract_hash=contract_hash,
            policy_hash=policy_hash,
            nonce=nonce,
            expires_at=expires_at,
        )
        if not hmac.compare_digest(provided_sig, expected_sig):
            return "Action approval token signature mismatch for arguments/contract/policy."

        expected_digest = compute_action_digest(
            operation_id=operation_id,
            arguments=arguments,
            target_url=target_url,
            contract_hash=contract_hash,
            policy_hash=policy_hash,
        )
        if "action_digest" in token_data and str(token_data["action_digest"]) != expected_digest:
            return "Action approval token action_digest mismatch."

        if nonce in self._memory_nonces:
            return "Action approval token has already been consumed (replay denied)."
        if self._ledger is not None:
            if not self._ledger.try_consume(nonce, expected_digest, expires_at):
                return "Action approval token has already been consumed in ledger (replay denied)."

        self._memory_nonces.add(nonce)
        return None


DEFAULT_APPROVAL_SECRET_FILENAME = "approval_authority.key"
DEFAULT_APPROVAL_LEDGER_FILENAME = "consumed_approvals.sqlite3"


def _write_secret_file(path: Path, secret: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secret.strip() + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def resolve_or_provision_approval_secret(
    workspace_dir: Path | None = None,
    *,
    explicit_secret: str | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[str, Path | None]:
    """Resolve or provision the shared owner approval secret between Local API and runtime.

    Order of precedence:
    1. `explicit_secret` argument (if provided and >=16 characters).
    2. `SPIGOT_APPROVAL_SECRET` in `environ` (or `os.environ`).
    3. `SPIGOT_APPROVAL_SECRET_FILE` in `environ` (or `os.environ`).
    4. `<workspace_dir>/approval_authority.key` (loaded if present, or generated with
       256-bit `secrets.token_urlsafe(32)` and persisted with 0600 permissions).
    """
    env = os.environ if environ is None else environ
    key_file_path = (
        (workspace_dir / DEFAULT_APPROVAL_SECRET_FILENAME).resolve()
        if workspace_dir is not None
        else None
    )

    candidate = (explicit_secret or "").strip()
    if not candidate:
        candidate = env.get("SPIGOT_APPROVAL_SECRET", "").strip()

    if not candidate:
        env_file_str = env.get("SPIGOT_APPROVAL_SECRET_FILE", "").strip()
        if env_file_str:
            env_file = Path(env_file_str).resolve()
            if env_file.is_file():
                candidate = env_file.read_text(encoding="utf-8").strip()
            else:
                candidate = secrets.token_urlsafe(32)
                _write_secret_file(env_file, candidate)
            if key_file_path is None:
                key_file_path = env_file

    if not candidate and key_file_path is not None and key_file_path.is_file():
        loaded = key_file_path.read_text(encoding="utf-8").strip()
        if len(loaded) >= 16:
            candidate = loaded

    if not candidate:
        candidate = secrets.token_urlsafe(32)

    if len(candidate) < 16:
        raise ValueError("ApprovalAuthority secret must be at least 16 characters long.")

    if key_file_path is not None:
        _write_secret_file(key_file_path, candidate)

    return candidate, key_file_path


def main(argv: list[str] | None = None) -> int:
    """Owner CLI utility to prepare or issue single-use action approvals for exported servers."""
    parser = argparse.ArgumentParser(
        prog="spigot-approval",
        description="Owner-controlled single-use approval utility for Spigot / DocForge MCP.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for cmd_name in ("prepare", "issue"):
        p = sub.add_parser(cmd_name)
        p.add_argument("--operation-id", required=True)
        p.add_argument("--args-json", default="{}")
        p.add_argument("--target-url", required=True)
        p.add_argument("--contract-hash", required=True)
        p.add_argument("--policy-hash", required=True)
        if cmd_name == "issue":
            p.add_argument("--ttl-sec", type=float, default=120.0)
            p.add_argument("--secret-file", default="")

    parsed = parser.parse_args(argv)
    arguments = json.loads(parsed.args_json)

    if parsed.command == "prepare":
        digest = compute_action_digest(
            operation_id=parsed.operation_id,
            arguments=arguments,
            target_url=parsed.target_url,
            contract_hash=parsed.contract_hash,
            policy_hash=parsed.policy_hash,
        )
        sys.stdout.write(
            json.dumps(
                {
                    "action_digest": digest,
                    "operation_id": parsed.operation_id,
                    "arguments": arguments,
                    "target_url": parsed.target_url,
                    "contract_hash": parsed.contract_hash,
                    "policy_hash": parsed.policy_hash,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        return 0

    secret = os.environ.get("SPIGOT_APPROVAL_SECRET", "").strip()
    secret_file = getattr(parsed, "secret_file", "") or os.environ.get(
        "SPIGOT_APPROVAL_SECRET_FILE", ""
    ).strip()
    if not secret and secret_file and Path(secret_file).is_file():
        secret = Path(secret_file).read_text(encoding="utf-8").strip()
    if not secret:
        sys.stderr.write(
            "ERROR: SPIGOT_APPROVAL_SECRET or SPIGOT_APPROVAL_SECRET_FILE is required.\n"
        )
        return 1

    authority = ApprovalAuthority(secret)
    token = authority.issue_token(
        operation_id=parsed.operation_id,
        arguments=arguments,
        target_url=parsed.target_url,
        contract_hash=parsed.contract_hash,
        policy_hash=parsed.policy_hash,
        ttl_sec=parsed.ttl_sec,
    )
    sys.stdout.write(json.dumps(token, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

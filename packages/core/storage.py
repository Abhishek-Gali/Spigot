"""SQLite persistence, schema migrations, optimistic revisions, and artifact storage (T05).

Implements the SQLite data model and content-addressed artifact store from
DATA_CONTRACTS.md and OFFLINE_OPERATIONS.md:
- 16 explicit tables managed via versioned SQL migrations.
- PRAGMA foreign_keys = ON on every connection.
- Content-addressed disk storage with atomic writes and SHA-256 verification.
- Optimistic revision concurrency control raising RevisionConflictError (409).
- Reference-counted artifact cleanup on project deletion.
- Consistent online SQLite backup + artifact manifest verification on restore.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packages.core.contracts import (
    ApiContract,
    DocumentBlock,
    ErrorEnvelope,
    EvaluationRun,
    SourceDocument,
    ToolPlan,
    UserOverride,
    ValidationReport,
    sha256_hex,
)


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class RevisionConflictError(RuntimeError):
    """Raised when an optimistic concurrency check fails on project/contract revision."""

    def __init__(
        self,
        project_id: str,
        expected_revision: int,
        actual_revision: int,
    ) -> None:
        self.project_id = project_id
        self.expected_revision = expected_revision
        self.actual_revision = actual_revision
        self.envelope = ErrorEnvelope(
            code="REVISION_CONFLICT",
            user_message=(
                f"Revision conflict for project '{project_id}': "
                f"expected revision {expected_revision}, but current is {actual_revision}."
            ),
            retryable=True,
            stage="review_concurrency",
            correlation_id=f"rev-{uuid.uuid4().hex[:12]}",
            redacted_details={
                "project_id": project_id,
                "expected_revision": expected_revision,
                "actual_revision": actual_revision,
            },
        )
        super().__init__(self.envelope.user_message)


class ArtifactIntegrityError(RuntimeError):
    """Raised when a content-addressed artifact is missing or fails SHA-256 verification."""


MIGRATIONS: list[tuple[int, str, str]] = [
    (
        1,
        "initial_schema_v1",
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            network_profile TEXT NOT NULL DEFAULT 'STRICT_OFFLINE',
            current_revision INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artifacts (
            sha256 TEXT PRIMARY KEY,
            byte_size INTEGER NOT NULL,
            media_type TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS source_documents (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            content_sha256 TEXT NOT NULL REFERENCES artifacts(sha256),
            original_name TEXT NOT NULL,
            media_type TEXT NOT NULL,
            imported_at TEXT NOT NULL,
            local_artifact_ref TEXT NOT NULL,
            source_uri TEXT,
            license_note TEXT
        );

        CREATE TABLE IF NOT EXISTS document_blocks (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL REFERENCES source_documents(id) ON DELETE CASCADE,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            block_kind TEXT NOT NULL,
            text TEXT NOT NULL,
            heading_path_json TEXT NOT NULL,
            location_json TEXT NOT NULL,
            extraction_method TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS extraction_runs (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            model_id TEXT NOT NULL,
            model_digest TEXT NOT NULL,
            prompt_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT
        );

        CREATE TABLE IF NOT EXISTS candidates (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            extraction_run_id TEXT REFERENCES extraction_runs(id) ON DELETE SET NULL,
            candidate_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            code TEXT NOT NULL,
            severity TEXT NOT NULL,
            affected_field TEXT NOT NULL,
            operation_id TEXT,
            status TEXT NOT NULL,
            finding_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS overrides (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            source_revision INTEGER NOT NULL,
            new_revision INTEGER NOT NULL,
            operation_id TEXT,
            target_field TEXT NOT NULL,
            old_value_hash TEXT NOT NULL,
            override_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS contract_revisions (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            canonical_hash TEXT NOT NULL,
            is_frozen INTEGER NOT NULL DEFAULT 0,
            contract_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(project_id, revision)
        );

        CREATE TABLE IF NOT EXISTS policy_revisions (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            policy_hash TEXT NOT NULL,
            policy_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(project_id, revision)
        );

        CREATE TABLE IF NOT EXISTS tool_plans (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            contract_hash TEXT NOT NULL,
            policy_hash TEXT NOT NULL,
            plan_hash TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            job_type TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            progress_pct INTEGER NOT NULL DEFAULT 0,
            lease_owner TEXT,
            lease_expires_at REAL,
            checkpoints_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT,
            error_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS job_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS validation_runs (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            manifest_hash TEXT NOT NULL,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evaluation_runs (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            task_set_hash TEXT NOT NULL,
            split TEXT NOT NULL,
            eval_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """,
    )
]


class ArtifactStore:
    """Content-addressed disk storage with atomic writes and SHA-256 verification."""

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir.resolve()
        self.objects_dir = self.root_dir / "sha256"
        self.objects_dir.mkdir(parents=True, exist_ok=True)

    def _path_for_digest(self, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"Invalid SHA-256 digest: {digest!r}")
        return self.objects_dir / digest[:2] / f"{digest}.bin"

    def put_bytes(self, data: bytes) -> tuple[str, str]:
        """Atomically store bytes by SHA-256 and return (sha256_hex, relative_path)."""
        digest = sha256_hex(data)
        target_path = self._path_for_digest(digest)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if not target_path.exists():
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".tmp_{digest[:8]}_", dir=str(target_path.parent)
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_name, target_path)
            finally:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)

        rel_path = target_path.relative_to(self.root_dir).as_posix()
        return digest, rel_path

    def get_bytes(self, digest: str) -> bytes:
        """Read and verify content-addressed artifact bytes."""
        target_path = self._path_for_digest(digest)
        if not target_path.exists():
            raise ArtifactIntegrityError(f"Missing artifact for digest {digest}")
        data = target_path.read_bytes()
        actual = sha256_hex(data)
        if actual != digest:
            raise ArtifactIntegrityError(
                f"Corrupted artifact for digest {digest}: actual SHA-256 is {actual}"
            )
        return data

    def remove_digest(self, digest: str) -> bool:
        target_path = self._path_for_digest(digest)
        if target_path.exists():
            target_path.unlink()
            return True
        return False


class SpigotStorage:
    """Transactional SQLite store and content-addressed artifact coordinator."""

    def __init__(self, workspace_dir: Path) -> None:
        self.workspace_dir = workspace_dir.resolve()
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.workspace_dir / "spigot.db"
        self.artifacts = ArtifactStore(self.workspace_dir / "artifacts")
        self.apply_migrations()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def apply_migrations(self) -> list[int]:
        applied_now: list[int] = []
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );
                """
            )
            existing = {
                int(row["version"]) for row in conn.execute("SELECT version FROM schema_migrations")
            }
            for version, name, sql in MIGRATIONS:
                if version not in existing:
                    conn.executescript(sql)
                    conn.execute("PRAGMA foreign_keys = ON;")
                    conn.execute(
                        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                        (version, name, utc_now_iso()),
                    )
                    applied_now.append(version)
        return applied_now

    def list_tables(self) -> list[str]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            return sorted(str(r["name"]) for r in rows)

    def create_project(
        self,
        name: str,
        *,
        project_id: str | None = None,
        network_profile: str = "STRICT_OFFLINE",
    ) -> dict[str, Any]:
        pid = project_id or f"proj_{uuid.uuid4().hex[:12]}"
        now = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO projects (id, name, network_profile, current_revision, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
                """,
                (pid, name, network_profile, now, now),
            )
        return {
            "id": pid,
            "name": name,
            "network_profile": network_profile,
            "current_revision": 1,
            "created_at": now,
        }

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            return dict(row) if row else None

    def store_source_document(
        self,
        project_id: str,
        original_name: str,
        media_type: str,
        content_bytes: bytes,
        *,
        source_id: str | None = None,
        source_uri: str | None = None,
        license_note: str | None = None,
    ) -> SourceDocument:
        digest, rel_path = self.artifacts.put_bytes(content_bytes)
        sid = source_id or f"src_{uuid.uuid4().hex[:12]}"
        now = utc_now_iso()
        doc = SourceDocument(
            id=sid,
            project_id=project_id,
            content_sha256=digest,
            original_name=original_name,
            media_type=media_type,
            imported_at=now,
            local_artifact_ref=rel_path,
            source_uri=source_uri,
            license_note=license_note,
        )
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO artifacts (sha256, byte_size, media_type, relative_path, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (digest, len(content_bytes), media_type, rel_path, now),
            )
            conn.execute(
                """
                INSERT INTO source_documents (
                    id, project_id, content_sha256, original_name, media_type,
                    imported_at, local_artifact_ref, source_uri, license_note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    doc.id,
                    doc.project_id,
                    doc.content_sha256,
                    doc.original_name,
                    doc.media_type,
                    doc.imported_at,
                    doc.local_artifact_ref,
                    doc.source_uri,
                    doc.license_note,
                ),
            )
        return doc

    def store_document_blocks(self, project_id: str, blocks: list[DocumentBlock]) -> None:
        with self.connect() as conn:
            for blk in blocks:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO document_blocks (
                        id, source_id, project_id, block_kind, text,
                        heading_path_json, location_json, extraction_method
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        blk.id,
                        blk.source_id,
                        project_id,
                        blk.block_kind,
                        blk.text,
                        json.dumps(blk.heading_path),
                        blk.location.model_dump_json(),
                        blk.extraction_method,
                    ),
                )

    def save_contract_revision(
        self,
        contract: ApiContract,
        *,
        is_frozen: bool = False,
    ) -> ApiContract:
        now = utc_now_iso()
        contract_json = contract.model_dump_json(by_alias=True)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO contract_revisions (
                    id, project_id, revision, canonical_hash, is_frozen, contract_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"{contract.id}:r{contract.revision}",
                    contract.project_id,
                    contract.revision,
                    contract.canonical_hash,
                    1 if is_frozen else 0,
                    contract_json,
                    now,
                ),
            )
            for finding in contract.findings:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        id, project_id, revision, code, severity,
                        affected_field, operation_id, status, finding_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"{finding.id}:r{contract.revision}",
                        contract.project_id,
                        contract.revision,
                        finding.code,
                        finding.severity,
                        finding.affected_field,
                        finding.operation_id,
                        finding.status,
                        finding.model_dump_json(),
                    ),
                )
            conn.execute(
                "UPDATE projects SET current_revision = ?, updated_at = ? WHERE id = ?",
                (contract.revision, now, contract.project_id),
            )
        return contract

    def get_contract_revision(
        self, project_id: str, revision: int | None = None
    ) -> tuple[ApiContract, bool]:
        with self.connect() as conn:
            if revision is None:
                row = conn.execute(
                    """
                    SELECT contract_json, is_frozen FROM contract_revisions
                    WHERE project_id = ? ORDER BY revision DESC LIMIT 1
                    """,
                    (project_id,),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT contract_json, is_frozen FROM contract_revisions
                    WHERE project_id = ? AND revision = ?
                    """,
                    (project_id, revision),
                ).fetchone()
            if row is None:
                raise KeyError(
                    f"No contract revision found for project '{project_id}' (revision={revision})"
                )
            contract = ApiContract.model_validate_json(row["contract_json"])
            return contract, bool(row["is_frozen"])

    def get_contract_by_hash(
        self, project_id: str, canonical_hash: str
    ) -> tuple[ApiContract, bool]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT contract_json, is_frozen FROM contract_revisions
                WHERE project_id = ? AND canonical_hash = ?
                ORDER BY revision DESC LIMIT 1
                """,
                (project_id, canonical_hash),
            ).fetchone()
            if row is None:
                raise KeyError(
                    f"No contract revision with hash '{canonical_hash}' found for project '{project_id}'"
                )
            contract = ApiContract.model_validate_json(row["contract_json"])
            return contract, bool(row["is_frozen"])

    def list_contract_revisions(self, project_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT revision, canonical_hash, is_frozen, created_at
                FROM contract_revisions
                WHERE project_id = ?
                ORDER BY revision ASC
                """,
                (project_id,),
            ).fetchall()
            return [
                {
                    "revision": int(r["revision"]),
                    "canonical_hash": str(r["canonical_hash"]),
                    "is_frozen": bool(r["is_frozen"]),
                    "created_at": str(r["created_at"]),
                }
                for r in rows
            ]

    def list_source_documents(self, project_id: str) -> list[SourceDocument]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM source_documents WHERE project_id = ? ORDER BY imported_at ASC, id ASC",
                (project_id,),
            ).fetchall()
            return [
                SourceDocument(
                    id=str(r["id"]),
                    project_id=str(r["project_id"]),
                    content_sha256=str(r["content_sha256"]),
                    original_name=str(r["original_name"]),
                    media_type=str(r["media_type"]),
                    imported_at=str(r["imported_at"]),
                    local_artifact_ref=str(r["local_artifact_ref"]),
                    source_uri=r["source_uri"],
                    license_note=r["license_note"],
                )
                for r in rows
            ]

    def list_document_blocks(
        self, project_id: str, source_id: str | None = None
    ) -> list[DocumentBlock]:
        with self.connect() as conn:
            if source_id is not None:
                rows = conn.execute(
                    "SELECT * FROM document_blocks WHERE project_id = ? AND source_id = ? ORDER BY id ASC",
                    (project_id, source_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM document_blocks WHERE project_id = ? ORDER BY id ASC",
                    (project_id,),
                ).fetchall()
            return [
                DocumentBlock.model_validate(
                    {
                        "id": str(r["id"]),
                        "source_id": str(r["source_id"]),
                        "text": str(r["text"]),
                        "block_kind": str(r["block_kind"]),
                        "heading_path": json.loads(r["heading_path_json"]),
                        "location": json.loads(r["location_json"]),
                        "extraction_method": str(r["extraction_method"]),
                    }
                )
                for r in rows
            ]

    def increment_project_revision(self, project_id: str) -> int:
        """Increment project revision when source documents change and unfreeze derived state."""
        now = utc_now_iso()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT current_revision FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown project '{project_id}'")
            new_rev = int(row["current_revision"]) + 1
            conn.execute(
                "UPDATE projects SET current_revision = ?, updated_at = ? WHERE id = ?",
                (new_rev, now, project_id),
            )
            conn.execute(
                "UPDATE contract_revisions SET is_frozen = 0 WHERE project_id = ?",
                (project_id,),
            )
            return new_rev

    def apply_review_override(
        self,
        project_id: str,
        expected_revision: int,
        *,
        operation_id: str | None,
        target_field: str,
        new_value: Any,
        rationale: str,
        resolve_finding_codes: list[str] | None = None,
    ) -> ApiContract:
        """Apply an owner review override with optimistic concurrency checking."""
        now = utc_now_iso()
        with self.connect() as conn:
            proj_row = conn.execute(
                "SELECT current_revision FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if proj_row is None:
                raise KeyError(f"Unknown project '{project_id}'")
            current_rev = int(proj_row["current_revision"])
            if current_rev != expected_revision:
                raise RevisionConflictError(project_id, expected_revision, current_rev)

            rev_row = conn.execute(
                """
                SELECT contract_json FROM contract_revisions
                WHERE project_id = ? AND revision = ?
                """,
                (project_id, expected_revision),
            ).fetchone()
            if rev_row is None:
                raise KeyError(
                    f"Contract revision {expected_revision} not found for '{project_id}'"
                )

            current_contract = ApiContract.model_validate_json(rev_row["contract_json"])
            raw = current_contract.model_dump(by_alias=True)
            new_rev = expected_revision + 1

            old_val: Any = None
            ovr_id = f"ovr_{uuid.uuid4().hex[:12]}"

            if operation_id is None:
                if target_field == "servers":
                    old_val = raw.get("servers", [])
                    if isinstance(new_value, str):
                        raw["servers"] = [
                            {
                                "server_id": "default",
                                "base_url": new_value.rstrip("/"),
                                "description": f"Owner override {ovr_id}",
                                "evidence": [f"override:{ovr_id}"],
                            }
                        ]
                    elif isinstance(new_value, list):
                        raw["servers"] = new_value
                    else:
                        raise ValueError("servers override new_value must be a URL string or list")
                else:
                    old_val = raw.get(target_field)
                    raw[target_field] = new_value
            else:
                found_op = False
                for op in raw["operations"]:
                    if op["stable_id"] == operation_id:
                        found_op = True
                        if target_field == "method_path" and isinstance(new_value, dict):
                            old_val = {
                                "method": op.get("method"),
                                "relative_path": op.get("relative_path"),
                            }
                            new_method = str(new_value["method"]).upper()
                            new_path = str(new_value["relative_path"])
                            op["method"] = new_method
                            op["relative_path"] = new_path
                            if op.get("semantic_effect") == "unknown":
                                op["semantic_effect"] = (
                                    "read"
                                    if new_method == "GET"
                                    else "destructive"
                                    if new_method == "DELETE"
                                    else "write"
                                )
                        elif target_field == "method":
                            old_val = op.get("method")
                            new_method = str(new_value).upper()
                            op["method"] = new_method
                            if op.get("semantic_effect") == "unknown":
                                op["semantic_effect"] = (
                                    "read"
                                    if new_method == "GET"
                                    else "destructive"
                                    if new_method == "DELETE"
                                    else "write"
                                )
                        else:
                            old_val = op.get(target_field)
                            op[target_field] = new_value
                        op.setdefault("provenance", {}).setdefault(target_field, []).append(
                            f"override:{ovr_id}"
                        )
                        break
                if not found_op:
                    raise KeyError(f"Operation '{operation_id}' not found in contract")

            old_val_hash = sha256_hex(json.dumps(old_val, sort_keys=True, default=str))
            override_obj = UserOverride(
                id=ovr_id,
                operation_id=operation_id,
                target_field=target_field,
                old_value_hash=old_val_hash,
                new_value=new_value,
                rationale=rationale,
                timestamp=now,
                source_revision=expected_revision,
            )
            raw["overrides"].append(override_obj.model_dump())

            codes_to_resolve = set(resolve_finding_codes or [])
            if target_field == "method_path":
                codes_to_resolve.update(
                    {"CONFLICTING_METHOD_PATH", "MISSING_METHOD", "UNKNOWN_SEMANTIC_EFFECT"}
                )
            elif target_field == "method":
                codes_to_resolve.update({"MISSING_METHOD", "UNKNOWN_SEMANTIC_EFFECT"})
            elif target_field == "semantic_effect":
                codes_to_resolve.add("UNKNOWN_SEMANTIC_EFFECT")
            elif target_field == "security_requirement":
                codes_to_resolve.update({"AMBIGUOUS_AUTH", "UNKNOWN_AUTH"})
            elif target_field == "servers":
                codes_to_resolve.update({"CONFLICTING_BASE_URL", "MISSING_BASE_URL"})

            for f_dict in raw["findings"]:
                if f_dict.get("operation_id") == operation_id and (
                    f_dict["affected_field"] == target_field or f_dict["code"] in codes_to_resolve
                ):
                    f_dict["status"] = "resolved"

            for op in raw["operations"]:
                op_id = op["stable_id"]
                open_blockers = [
                    f_dict
                    for f_dict in raw["findings"]
                    if f_dict.get("operation_id") == op_id
                    and f_dict["severity"] == "blocker"
                    and f_dict["status"] == "open"
                ]
                if not open_blockers and op["support_status"] == "blocked":
                    op["support_status"] = "supported"

            raw["revision"] = new_rev
            raw["canonical_hash"] = ""
            updated_contract = ApiContract.model_validate(raw)

            conn.execute(
                """
                INSERT INTO overrides (
                    id, project_id, source_revision, new_revision,
                    operation_id, target_field, old_value_hash, override_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    override_obj.id,
                    project_id,
                    expected_revision,
                    new_rev,
                    operation_id,
                    target_field,
                    old_val_hash,
                    override_obj.model_dump_json(),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO contract_revisions (
                    id, project_id, revision, canonical_hash, is_frozen, contract_json, created_at
                ) VALUES (?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    f"{updated_contract.id}:r{new_rev}",
                    project_id,
                    new_rev,
                    updated_contract.canonical_hash,
                    updated_contract.model_dump_json(by_alias=True),
                    now,
                ),
            )
            conn.execute(
                "UPDATE projects SET current_revision = ?, updated_at = ? WHERE id = ?",
                (new_rev, now, project_id),
            )
            return updated_contract

    def freeze_contract_revision(
        self,
        project_id: str,
        expected_revision: int,
    ) -> ApiContract:
        """Freeze a contract revision after verifying optimistic concurrency."""
        with self.connect() as conn:
            proj_row = conn.execute(
                "SELECT current_revision FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
            if proj_row is None:
                raise KeyError(f"Unknown project '{project_id}'")
            current_rev = int(proj_row["current_revision"])
            if current_rev != expected_revision:
                raise RevisionConflictError(project_id, expected_revision, current_rev)

            rev_row = conn.execute(
                """
                SELECT contract_json FROM contract_revisions
                WHERE project_id = ? AND revision = ?
                """,
                (project_id, expected_revision),
            ).fetchone()
            if rev_row is None:
                raise KeyError(
                    f"Contract revision {expected_revision} not found for '{project_id}'"
                )

            contract = ApiContract.model_validate_json(rev_row["contract_json"])
            conn.execute(
                """
                UPDATE contract_revisions
                SET is_frozen = 1
                WHERE project_id = ? AND revision = ?
                """,
                (project_id, expected_revision),
            )
            return contract

    def save_policy_revision(self, project_id: str, policy: Any) -> None:
        now = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO policy_revisions (
                    id, project_id, revision, policy_hash, policy_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"{policy.id}:r{policy.revision}",
                    project_id,
                    policy.revision,
                    policy.policy_hash,
                    policy.model_dump_json(),
                    now,
                ),
            )

    def save_tool_plan(self, project_id: str, plan: ToolPlan) -> ToolPlan:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tool_plans (
                    id, project_id, contract_hash, policy_hash, plan_hash, plan_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.id,
                    project_id,
                    plan.contract_hash,
                    plan.policy_hash,
                    plan.plan_hash,
                    plan.model_dump_json(),
                    utc_now_iso(),
                ),
            )
        return plan

    def get_latest_tool_plan(self, project_id: str) -> ToolPlan | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT plan_json FROM tool_plans
                WHERE project_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1
                """,
                (project_id,),
            ).fetchone()
            return ToolPlan.model_validate_json(row["plan_json"]) if row else None

    def get_tool_plan_by_hash(self, project_id: str, plan_hash: str) -> ToolPlan | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT plan_json FROM tool_plans WHERE project_id = ? AND plan_hash = ?",
                (project_id, plan_hash),
            ).fetchone()
            return ToolPlan.model_validate_json(row["plan_json"]) if row else None

    def get_policy_by_hash(self, project_id: str, policy_hash: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT policy_json FROM policy_revisions WHERE project_id = ? AND policy_hash = ?",
                (project_id, policy_hash),
            ).fetchone()
            return json.loads(row["policy_json"]) if row else None

    def save_validation_report(self, project_id: str, report: ValidationReport) -> ValidationReport:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO validation_runs (
                    id, project_id, manifest_hash, report_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    report.id,
                    project_id,
                    report.manifest_hash,
                    report.model_dump_json(),
                    utc_now_iso(),
                ),
            )
        return report

    def get_latest_validation_report(self, project_id: str) -> ValidationReport | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT report_json FROM validation_runs
                WHERE project_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1
                """,
                (project_id,),
            ).fetchone()
            return ValidationReport.model_validate_json(row["report_json"]) if row else None

    def save_evaluation_run(self, project_id: str, eval_run: EvaluationRun) -> EvaluationRun:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evaluation_runs (
                    id, project_id, task_set_hash, split, eval_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    eval_run.id,
                    project_id,
                    eval_run.task_set_hash,
                    eval_run.split,
                    eval_run.model_dump_json(),
                    utc_now_iso(),
                ),
            )
        return eval_run

    def get_latest_evaluation_run(self, project_id: str) -> EvaluationRun | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT eval_json FROM evaluation_runs
                WHERE project_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1
                """,
                (project_id,),
            ).fetchone()
            return EvaluationRun.model_validate_json(row["eval_json"]) if row else None

    def delete_project(self, project_id: str) -> dict[str, Any]:
        """Delete a project and garbage-collect unreferenced content-addressed artifacts."""
        with self.connect() as conn:
            proj_digests = [
                str(r["content_sha256"])
                for r in conn.execute(
                    "SELECT DISTINCT content_sha256 FROM source_documents WHERE project_id = ?",
                    (project_id,),
                ).fetchall()
            ]
            conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))

            removed_digests: list[str] = []
            retained_digests: list[str] = []
            for digest in proj_digests:
                ref_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM source_documents WHERE content_sha256 = ?",
                    (digest,),
                ).fetchone()
                if ref_row and int(ref_row["cnt"]) == 0:
                    conn.execute("DELETE FROM artifacts WHERE sha256 = ?", (digest,))
                    self.artifacts.remove_digest(digest)
                    removed_digests.append(digest)
                else:
                    retained_digests.append(digest)

        return {
            "deleted_project_id": project_id,
            "removed_artifacts": removed_digests,
            "retained_shared_artifacts": retained_digests,
        }

    def create_backup(self, backup_dir: Path) -> Path:
        """Create a consistent SQLite backup + referenced artifact copy + manifest."""
        backup_dir = backup_dir.resolve()
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_db_path = backup_dir / "spigot.db"
        backup_artifacts_dir = backup_dir / "artifacts" / "sha256"
        backup_artifacts_dir.mkdir(parents=True, exist_ok=True)

        with self.connect() as src_conn:
            dst_conn = sqlite3.connect(str(backup_db_path))
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()

            rows = src_conn.execute(
                "SELECT sha256, byte_size, media_type, relative_path FROM artifacts"
            ).fetchall()

        manifest_entries: list[dict[str, Any]] = []
        for row in rows:
            digest = str(row["sha256"])
            raw_bytes = self.artifacts.get_bytes(digest)
            dst_file = backup_artifacts_dir / digest[:2] / f"{digest}.bin"
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            dst_file.write_bytes(raw_bytes)
            manifest_entries.append(
                {
                    "sha256": digest,
                    "byte_size": int(row["byte_size"]),
                    "media_type": str(row["media_type"]),
                    "relative_path": str(row["relative_path"]),
                }
            )

        manifest = {
            "schema_version": "1.0",
            "created_at": utc_now_iso(),
            "db_sha256": sha256_hex(backup_db_path.read_bytes()),
            "artifacts": manifest_entries,
        }
        manifest_path = backup_dir / "backup_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return manifest_path

    @classmethod
    def restore_from_backup(cls, backup_dir: Path, target_workspace_dir: Path) -> SpigotStorage:
        """Verify backup manifest and artifact checksums before restoring workspace."""
        backup_dir = backup_dir.resolve()
        manifest_path = backup_dir / "backup_manifest.json"
        if not manifest_path.exists():
            raise ArtifactIntegrityError("Missing backup_manifest.json in backup directory")

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        backup_db_path = backup_dir / "spigot.db"
        if not backup_db_path.exists():
            raise ArtifactIntegrityError("Missing spigot.db in backup directory")

        actual_db_hash = sha256_hex(backup_db_path.read_bytes())
        if actual_db_hash != manifest["db_sha256"]:
            raise ArtifactIntegrityError(
                f"Backup DB SHA-256 mismatch: expected {manifest['db_sha256']}, got {actual_db_hash}"
            )

        verified_blobs: list[tuple[str, bytes]] = []
        for item in manifest.get("artifacts", []):
            digest = str(item["sha256"])
            blob_path = backup_dir / "artifacts" / "sha256" / digest[:2] / f"{digest}.bin"
            if not blob_path.exists():
                raise ArtifactIntegrityError(f"Backup missing artifact blob {digest}")
            blob_bytes = blob_path.read_bytes()
            if sha256_hex(blob_bytes) != digest:
                raise ArtifactIntegrityError(f"Backup artifact hash mismatch for {digest}")
            verified_blobs.append((digest, blob_bytes))

        target_workspace_dir = target_workspace_dir.resolve()
        target_workspace_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_db_path, target_workspace_dir / "spigot.db")

        storage = cls(target_workspace_dir)
        for _digest, blob_bytes in verified_blobs:
            storage.artifacts.put_bytes(blob_bytes)
        return storage

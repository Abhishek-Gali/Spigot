"""Job lifecycle, transactional leases, checkpointing, and cancellation for Spigot (T06).

Implements the job state machine and recovery rules from DATA_CONTRACTS.md:
- States: QUEUED -> RUNNING -> SUCCEEDED, FAILED, CANCELLED, NEEDS_REVIEW, or INTERRUPTED.
- Cooperative cancellation via CANCEL_REQUESTED plus child process termination after grace period.
- Transactional lease claiming and renewal.
- Expired RUNNING leases transition to INTERRUPTED; retries reuse validated checkpoints.
- Idempotency keys prevent duplicate jobs for identical frozen inputs.
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from packages.core.contracts import sha256_hex
from packages.core.storage import SpigotStorage, utc_now_iso


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    INTERRUPTED = "INTERRUPTED"


class JobCancelledError(RuntimeError):
    """Raised inside a worker when a job's cancellation flag is observed."""


@dataclass(frozen=True)
class JobRecord:
    id: str
    project_id: str
    job_type: str
    idempotency_key: str
    status: JobStatus
    stage: str
    progress_pct: int
    lease_owner: str | None
    lease_expires_at: float | None
    checkpoints: dict[str, Any]
    result: dict[str, Any] | None
    error: dict[str, Any] | None
    created_at: str
    updated_at: str


def compute_job_idempotency_key(
    project_id: str,
    job_type: str,
    frozen_input_hash: str,
    config_version: str = "1.0",
) -> str:
    raw = f"{project_id}:{job_type}:{frozen_input_hash}:{config_version}"
    return sha256_hex(raw)


class JobCoordinator:
    """Manages SQLite-backed job queues, worker leases, checkpoints, and cancellation."""

    def __init__(self, storage: SpigotStorage) -> None:
        self.storage = storage

    def _row_to_record(self, row: Any) -> JobRecord:
        return JobRecord(
            id=str(row["id"]),
            project_id=str(row["project_id"]),
            job_type=str(row["job_type"]),
            idempotency_key=str(row["idempotency_key"]),
            status=JobStatus(str(row["status"])),
            stage=str(row["stage"]),
            progress_pct=int(row["progress_pct"]),
            lease_owner=row["lease_owner"],
            lease_expires_at=(
                float(row["lease_expires_at"]) if row["lease_expires_at"] is not None else None
            ),
            checkpoints=json.loads(row["checkpoints_json"] or "{}"),
            result=json.loads(row["result_json"]) if row["result_json"] else None,
            error=json.loads(row["error_json"]) if row["error_json"] else None,
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def enqueue_job(
        self,
        project_id: str,
        job_type: str,
        frozen_input_hash: str,
        *,
        config_version: str = "1.0",
        initial_stage: str = "queued",
    ) -> tuple[JobRecord, bool]:
        """Enqueue a job or return existing job with matching idempotency key.

        Returns (JobRecord, created_new).
        """
        idem_key = compute_job_idempotency_key(
            project_id, job_type, frozen_input_hash, config_version
        )
        now = utc_now_iso()
        with self.storage.connect() as conn:
            existing = conn.execute(
                "SELECT * FROM jobs WHERE idempotency_key = ?", (idem_key,)
            ).fetchone()
            if existing is not None:
                return self._row_to_record(existing), False

            job_id = f"job_{uuid.uuid4().hex[:12]}"
            conn.execute(
                """
                INSERT INTO jobs (
                    id, project_id, job_type, idempotency_key, status, stage,
                    progress_pct, lease_owner, lease_expires_at, checkpoints_json,
                    result_json, error_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, '{}', NULL, NULL, ?, ?)
                """,
                (
                    job_id,
                    project_id,
                    job_type,
                    idem_key,
                    JobStatus.QUEUED.value,
                    initial_stage,
                    now,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO job_events (job_id, event_type, message, payload_json, created_at)
                VALUES (?, 'JOB_QUEUED', 'Job enqueued', '{}', ?)
                """,
                (job_id, now),
            )
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self._row_to_record(row), True

    def get_job(self, job_id: str) -> JobRecord:
        with self.storage.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown job '{job_id}'")
            return self._row_to_record(row)

    def claim_next_job(
        self,
        worker_id: str,
        *,
        lease_seconds: float = 30.0,
        now_epoch: float | None = None,
    ) -> JobRecord | None:
        """Transactionally claim the oldest QUEUED job and assign a time-bounded lease."""
        current_epoch = now_epoch if now_epoch is not None else time.time()
        expires_at = current_epoch + lease_seconds
        now_iso = utc_now_iso()

        with self.storage.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM jobs
                WHERE status = ?
                ORDER BY created_at ASC, id ASC
                LIMIT 1
                """,
                (JobStatus.QUEUED.value,),
            ).fetchone()
            if row is None:
                return None

            job_id = str(row["id"])
            cursor = conn.execute(
                """
                UPDATE jobs
                SET status = ?, lease_owner = ?, lease_expires_at = ?,
                    stage = 'running', updated_at = ?
                WHERE id = ? AND status = ?
                """,
                (
                    JobStatus.RUNNING.value,
                    worker_id,
                    expires_at,
                    now_iso,
                    job_id,
                    JobStatus.QUEUED.value,
                ),
            )
            if cursor.rowcount == 0:
                return None

            conn.execute(
                """
                INSERT INTO job_events (job_id, event_type, message, payload_json, created_at)
                VALUES (?, 'LEASE_CLAIMED', ?, ?, ?)
                """,
                (
                    job_id,
                    f"Claimed by worker {worker_id}",
                    json.dumps({"worker_id": worker_id, "lease_expires_at": expires_at}),
                    now_iso,
                ),
            )
            updated = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self._row_to_record(updated)

    def renew_lease(
        self,
        job_id: str,
        worker_id: str,
        *,
        lease_seconds: float = 30.0,
        now_epoch: float | None = None,
    ) -> JobRecord:
        current_epoch = now_epoch if now_epoch is not None else time.time()
        expires_at = current_epoch + lease_seconds
        now_iso = utc_now_iso()
        with self.storage.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown job '{job_id}'")
            if row["lease_owner"] != worker_id:
                raise PermissionError(f"Worker '{worker_id}' does not own lease for job '{job_id}'")
            if row["status"] == JobStatus.CANCEL_REQUESTED.value:
                raise JobCancelledError(f"Cancellation requested for job '{job_id}'")
            if row["status"] != JobStatus.RUNNING.value:
                raise RuntimeError(
                    f"Cannot renew lease on job '{job_id}' in state '{row['status']}'"
                )

            conn.execute(
                "UPDATE jobs SET lease_expires_at = ?, updated_at = ? WHERE id = ?",
                (expires_at, now_iso, job_id),
            )
            updated = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self._row_to_record(updated)

    def save_checkpoint(
        self,
        job_id: str,
        worker_id: str,
        checkpoint_key: str,
        checkpoint_data: Any,
        *,
        stage: str | None = None,
        progress_pct: int | None = None,
    ) -> JobRecord:
        """Persist incremental checkpoint data so interrupted jobs can resume without re-running."""
        now_iso = utc_now_iso()
        with self.storage.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown job '{job_id}'")
            if row["status"] == JobStatus.CANCEL_REQUESTED.value:
                raise JobCancelledError(f"Cancellation requested for job '{job_id}'")
            if row["lease_owner"] != worker_id:
                raise PermissionError(f"Worker '{worker_id}' does not own lease for job '{job_id}'")

            checkpoints = json.loads(row["checkpoints_json"] or "{}")
            checkpoints[checkpoint_key] = checkpoint_data
            new_stage = stage if stage is not None else str(row["stage"])
            new_prog = progress_pct if progress_pct is not None else int(row["progress_pct"])

            conn.execute(
                """
                UPDATE jobs
                SET checkpoints_json = ?, stage = ?, progress_pct = ?, updated_at = ?
                WHERE id = ?
                """,
                (json.dumps(checkpoints, sort_keys=True), new_stage, new_prog, now_iso, job_id),
            )
            conn.execute(
                """
                INSERT INTO job_events (job_id, event_type, message, payload_json, created_at)
                VALUES (?, 'CHECKPOINT_SAVED', ?, ?, ?)
                """,
                (
                    job_id,
                    f"Saved checkpoint '{checkpoint_key}'",
                    json.dumps({"checkpoint_key": checkpoint_key, "progress_pct": new_prog}),
                    now_iso,
                ),
            )
            updated = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self._row_to_record(updated)

    def recover_expired_leases(self, *, now_epoch: float | None = None) -> list[JobRecord]:
        """Transition expired RUNNING leases to INTERRUPTED while preserving checkpoints."""
        current_epoch = now_epoch if now_epoch is not None else time.time()
        now_iso = utc_now_iso()
        interrupted: list[JobRecord] = []

        with self.storage.connect() as conn:
            expired_rows = conn.execute(
                """
                SELECT * FROM jobs
                WHERE status IN (?, ?)
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at < ?
                """,
                (
                    JobStatus.RUNNING.value,
                    JobStatus.CANCEL_REQUESTED.value,
                    current_epoch,
                ),
            ).fetchall()

            for row in expired_rows:
                job_id = str(row["id"])
                conn.execute(
                    """
                    UPDATE jobs
                    SET status = ?, lease_owner = NULL, lease_expires_at = NULL,
                        stage = 'interrupted', updated_at = ?
                    WHERE id = ?
                    """,
                    (JobStatus.INTERRUPTED.value, now_iso, job_id),
                )
                conn.execute(
                    """
                    INSERT INTO job_events (job_id, event_type, message, payload_json, created_at)
                    VALUES (?, 'LEASE_EXPIRED', 'Worker lease expired; marked INTERRUPTED', '{}', ?)
                    """,
                    (job_id, now_iso),
                )
                updated = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
                interrupted.append(self._row_to_record(updated))
        return interrupted

    def retry_interrupted_job(self, job_id: str) -> JobRecord:
        """Re-queue an INTERRUPTED job while retaining its validated checkpoints."""
        now_iso = utc_now_iso()
        with self.storage.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown job '{job_id}'")
            if row["status"] != JobStatus.INTERRUPTED.value:
                raise ValueError(
                    f"Only INTERRUPTED jobs can be retried with checkpoint reuse (got {row['status']})"
                )

            conn.execute(
                """
                UPDATE jobs
                SET status = ?, stage = 'requeued_from_checkpoint',
                    lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
                WHERE id = ?
                """,
                (JobStatus.QUEUED.value, now_iso, job_id),
            )
            conn.execute(
                """
                INSERT INTO job_events (job_id, event_type, message, payload_json, created_at)
                VALUES (?, 'JOB_RETRIED', 'Interrupted job re-queued with existing checkpoints', '{}', ?)
                """,
                (job_id, now_iso),
            )
            updated = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self._row_to_record(updated)

    def complete_job(
        self,
        job_id: str,
        worker_id: str,
        *,
        final_status: JobStatus = JobStatus.SUCCEEDED,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> JobRecord:
        if final_status not in {
            JobStatus.SUCCEEDED,
            JobStatus.FAILED,
            JobStatus.NEEDS_REVIEW,
        }:
            raise ValueError(f"Invalid terminal completion status: {final_status}")
        now_iso = utc_now_iso()
        with self.storage.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown job '{job_id}'")
            if row["lease_owner"] != worker_id:
                raise PermissionError(f"Worker '{worker_id}' does not own lease for job '{job_id}'")

            progress = 100 if final_status == JobStatus.SUCCEEDED else int(row["progress_pct"])
            conn.execute(
                """
                UPDATE jobs
                SET status = ?, stage = ?, progress_pct = ?,
                    lease_owner = NULL, lease_expires_at = NULL,
                    result_json = ?, error_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    final_status.value,
                    final_status.value.lower(),
                    progress,
                    json.dumps(result, sort_keys=True) if result is not None else None,
                    json.dumps(error, sort_keys=True) if error is not None else None,
                    now_iso,
                    job_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO job_events (job_id, event_type, message, payload_json, created_at)
                VALUES (?, 'JOB_FINISHED', ?, ?, ?)
                """,
                (
                    job_id,
                    f"Job finished with status {final_status.value}",
                    json.dumps({"status": final_status.value}),
                    now_iso,
                ),
            )
            updated = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self._row_to_record(updated)

    def request_cancel(self, job_id: str) -> JobRecord:
        """Request cooperative cancellation of a QUEUED or RUNNING job."""
        now_iso = utc_now_iso()
        with self.storage.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown job '{job_id}'")
            status = JobStatus(str(row["status"]))
            if status == JobStatus.QUEUED:
                conn.execute(
                    """
                    UPDATE jobs
                    SET status = ?, stage = 'cancelled', progress_pct = 0, updated_at = ?
                    WHERE id = ?
                    """,
                    (JobStatus.CANCELLED.value, now_iso, job_id),
                )
            elif status == JobStatus.RUNNING:
                conn.execute(
                    """
                    UPDATE jobs
                    SET status = ?, stage = 'cancel_requested', updated_at = ?
                    WHERE id = ?
                    """,
                    (JobStatus.CANCEL_REQUESTED.value, now_iso, job_id),
                )

            conn.execute(
                """
                INSERT INTO job_events (job_id, event_type, message, payload_json, created_at)
                VALUES (?, 'CANCEL_REQUESTED', 'Cancellation requested by owner', '{}', ?)
                """,
                (job_id, now_iso),
            )
            updated = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self._row_to_record(updated)

    def acknowledge_cancel(self, job_id: str, worker_id: str) -> JobRecord:
        """Mark a CANCEL_REQUESTED job as terminal CANCELLED without marking partial output complete."""
        now_iso = utc_now_iso()
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = ?, stage = 'cancelled',
                    lease_owner = NULL, lease_expires_at = NULL,
                    result_json = NULL, updated_at = ?
                WHERE id = ? AND lease_owner = ?
                """,
                (JobStatus.CANCELLED.value, now_iso, job_id, worker_id),
            )
            conn.execute(
                """
                INSERT INTO job_events (job_id, event_type, message, payload_json, created_at)
                VALUES (?, 'JOB_CANCELLED', 'Worker acknowledged cancellation cleanly', '{}', ?)
                """,
                (job_id, now_iso),
            )
            updated = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self._row_to_record(updated)

    def list_job_events(self, job_id: str, after_id: int = 0) -> list[dict[str, Any]]:
        with self.storage.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM job_events
                WHERE job_id = ? AND id > ?
                ORDER BY id ASC
                """,
                (job_id, after_id),
            ).fetchall()
            return [dict(r) for r in rows]

    def run_cancellable_subprocess(
        self,
        job_id: str,
        worker_id: str,
        args: list[str],
        *,
        poll_interval_sec: float = 0.05,
        grace_period_sec: float = 1.0,
    ) -> subprocess.Popen[bytes]:
        """Run a child process using an explicit argument array and terminate on job cancellation."""
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            while proc.poll() is None:
                job = self.get_job(job_id)
                if job.status in {JobStatus.CANCEL_REQUESTED, JobStatus.CANCELLED}:
                    proc.terminate()
                    try:
                        proc.wait(timeout=grace_period_sec)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=1.0)
                    self.acknowledge_cancel(job_id, worker_id)
                    raise JobCancelledError(
                        f"Child process for job '{job_id}' terminated on cancellation"
                    )
                time.sleep(poll_interval_sec)
            return proc
        except Exception:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=1.0)
            raise

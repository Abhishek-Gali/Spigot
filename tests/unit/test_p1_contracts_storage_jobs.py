"""P1 Unit Tests: Typed schemas (T04), SQLite & ArtifactStore (T05), and Job Leases (T06)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from packages.core.contracts import (
    ApiContract,
    BlockLocation,
    DocumentBlock,
    ErrorEnvelope,
    EvidenceRef,
    Finding,
    OperationContract,
    ParameterContract,
    SecurityAlternative,
    SecurityRequirement,
    SecurityScheme,
    ServerContract,
    assign_safe_parameter_names,
)
from packages.core.jobs import JobCancelledError, JobCoordinator, JobStatus
from packages.core.storage import (
    ArtifactIntegrityError,
    RevisionConflictError,
    SpigotStorage,
)


def test_t04_strict_schemas_and_evidence_verification() -> None:
    block = DocumentBlock(
        id="blk_01",
        source_id="src_01",
        text="GET /tickets/{ticket_id} requires service_bearer auth.",
        block_kind="prose",
        heading_path=["Endpoints", "Get Ticket"],
        location=BlockLocation(
            kind="line_char", start_line=10, end_line=12, start_char=0, end_char=54
        ),
        extraction_method="markdown_parser",
    )

    ev = EvidenceRef.from_block_substring("ev_01", block, "GET /tickets/{ticket_id}")
    assert ev.verify_against_block(block) is True

    # Tampered quote hash must be rejected by Pydantic validation
    with pytest.raises(ValidationError):
        EvidenceRef(
            id="ev_bad",
            source_id="src_01",
            block_id="blk_01",
            start_offset=0,
            end_offset=3,
            exact_quote="GET",
            quote_sha256="0" * 64,
        )

    # Extra unknown security-sensitive fields must be rejected (extra="forbid")
    with pytest.raises(ValidationError):
        SecurityScheme.model_validate(
            {
                "scheme_id": "s1",
                "type": "http",
                "scheme": "bearer",
                "secret_token_plaintext": "sk-forbidden",
            }
        )

    # Path parameter with required=False must fail validation
    with pytest.raises(ValidationError):
        ParameterContract(
            external_name="ticket_id",
            safe_argument_name="ticket_id",
            location="path",
            required=False,
            schema={"type": "string"},
        )

    # Duplicate parameter names in different locations get collision-free safe names
    safe_names = assign_safe_parameter_names([("id", "path"), ("id", "query")])
    assert safe_names == ["id_path", "id_query"]

    # ErrorEnvelope validates all required fields
    env = ErrorEnvelope(
        code="CONTRACT_INCOMPLETE",
        user_message="Missing base URL",
        retryable=False,
        stage="readiness_check",
        correlation_id="corr_123",
    )
    assert env.code == "CONTRACT_INCOMPLETE"


def test_t04_canonical_contract_hash_determinism() -> None:
    def make_contract(rev: int) -> ApiContract:
        return ApiContract(
            id="cnt_1",
            project_id="proj_1",
            revision=rev,
            sources=["src_1"],
            servers=[ServerContract(server_id="srv_1", base_url="https://api.example.com/v1")],
            security_schemes=[
                SecurityScheme(scheme_id="bearer_auth", type="http", scheme="bearer")
            ],
            operations=[
                OperationContract(
                    stable_id="op_get",
                    display_name="Get Item",
                    method="GET",
                    relative_path="/items/{id}",
                    server_ref="srv_1",
                    parameters=[
                        ParameterContract(
                            external_name="id",
                            safe_argument_name="id",
                            location="path",
                            required=True,
                            schema={"type": "string"},
                        )
                    ],
                    security_requirement=SecurityRequirement(
                        status="authenticated",
                        alternatives=[SecurityAlternative(all_of=["bearer_auth"])],
                    ),
                    semantic_effect="read",
                    support_status="supported",
                )
            ],
        )

    c1 = make_contract(1)
    c2 = make_contract(1)
    assert c1.canonical_hash == c2.canonical_hash
    assert len(c1.canonical_hash) == 64

    # Round-trip through JSON preserves exact canonical_hash
    round_tripped = ApiContract.model_validate_json(c1.model_dump_json(by_alias=True))
    assert round_tripped.canonical_hash == c1.canonical_hash


def test_t05_sqlite_migrations_revisions_conflicts_and_backup(
    tmp_path: Path,
) -> None:
    ws_dir = tmp_path / "workspace"
    storage = SpigotStorage(ws_dir)

    # Verify all 16 required tables from DATA_CONTRACTS.md exist
    expected_tables = {
        "artifacts",
        "candidates",
        "contract_revisions",
        "document_blocks",
        "evaluation_runs",
        "extraction_runs",
        "findings",
        "job_events",
        "jobs",
        "overrides",
        "policy_revisions",
        "projects",
        "schema_migrations",
        "source_documents",
        "tool_plans",
        "validation_runs",
    }
    assert expected_tables.issubset(set(storage.list_tables()))

    proj = storage.create_project("Support Project", project_id="proj_support")
    src = storage.store_source_document(
        proj["id"],
        "manual.md",
        "text/markdown",
        b"# Support API\nGET /tickets/{id}\n",
        source_id="src_manual",
    )
    assert storage.artifacts.get_bytes(src.content_sha256).startswith(b"# Support API")

    # Initial contract revision 1 with a blocked operation
    contract_r1 = ApiContract(
        id="cnt_support",
        project_id=proj["id"],
        revision=1,
        sources=[src.id],
        servers=[ServerContract(server_id="srv_main", base_url="https://api.support.internal/v1")],
        security_schemes=[SecurityScheme(scheme_id="service_bearer", type="http", scheme="bearer")],
        operations=[
            OperationContract(
                stable_id="support.close_ticket",
                display_name="Close Ticket",
                method="POST",
                relative_path="/tickets/{id}/close",
                server_ref="srv_main",
                parameters=[
                    ParameterContract(
                        external_name="id",
                        safe_argument_name="id",
                        location="path",
                        required=True,
                        schema={"type": "string"},
                    )
                ],
                security_requirement=SecurityRequirement(
                    status="authenticated",
                    alternatives=[SecurityAlternative(all_of=["service_bearer"])],
                ),
                semantic_effect="unknown",
                support_status="blocked",
            )
        ],
        findings=[
            Finding(
                id="fnd_1",
                code="UNKNOWN_SEMANTIC_EFFECT",
                severity="blocker",
                affected_field="semantic_effect",
                operation_id="support.close_ticket",
                explanation="Semantic effect is unknown.",
                suggested_resolution="Set semantic_effect to write or destructive.",
            )
        ],
    )
    storage.save_contract_revision(contract_r1)

    # Apply review override at revision 1 -> creates revision 2 and resolves blocker
    contract_r2 = storage.apply_review_override(
        proj["id"],
        expected_revision=1,
        operation_id="support.close_ticket",
        target_field="semantic_effect",
        new_value="destructive",
        rationale="Closing a ticket is a state-changing destructive action.",
        resolve_finding_codes=["UNKNOWN_SEMANTIC_EFFECT"],
    )
    assert contract_r2.revision == 2
    assert contract_r2.operations[0].semantic_effect == "destructive"
    assert contract_r2.operations[0].support_status == "supported"
    assert len(contract_r2.overrides) == 1

    # Stale review edit supplying expected_revision=1 must fail with RevisionConflictError
    with pytest.raises(RevisionConflictError) as exc_info:
        storage.apply_review_override(
            proj["id"],
            expected_revision=1,
            operation_id="support.close_ticket",
            target_field="semantic_effect",
            new_value="write",
            rationale="Stale concurrent edit",
        )
    assert exc_info.value.envelope.code == "REVISION_CONFLICT"
    assert exc_info.value.actual_revision == 2

    # Restart persistence check: re-instantiate SpigotStorage against same workspace
    restarted = SpigotStorage(ws_dir)
    loaded_r2, is_frozen = restarted.get_contract_revision(proj["id"])
    assert loaded_r2.canonical_hash == contract_r2.canonical_hash
    assert is_frozen is False

    # Backup and restore verification
    backup_dir = tmp_path / "backup_bundle"
    manifest_path = restarted.create_backup(backup_dir)
    assert manifest_path.exists()

    restored_ws = tmp_path / "restored_workspace"
    restored_storage = SpigotStorage.restore_from_backup(backup_dir, restored_ws)
    restored_c, _ = restored_storage.get_contract_revision(proj["id"], revision=2)
    assert restored_c.canonical_hash == contract_r2.canonical_hash
    assert (
        restored_storage.artifacts.get_bytes(src.content_sha256)
        == b"# Support API\nGET /tickets/{id}\n"
    )

    # Tampering with a backup artifact must fail restore with ArtifactIntegrityError
    blob_files = list((backup_dir / "artifacts").rglob("*.bin"))
    assert len(blob_files) == 1
    blob_files[0].write_bytes(b"corrupted bytes")
    with pytest.raises(ArtifactIntegrityError):
        SpigotStorage.restore_from_backup(backup_dir, tmp_path / "bad_restore")

    # Reference-counted deletion: deleting project removes unshared disk artifact
    del_summary = restarted.delete_project(proj["id"])
    assert src.content_sha256 in del_summary["removed_artifacts"]
    with pytest.raises(ArtifactIntegrityError):
        restarted.artifacts.get_bytes(src.content_sha256)


def test_t06_job_leases_checkpoints_recovery_and_cancellation(
    tmp_path: Path,
) -> None:
    storage = SpigotStorage(tmp_path / "jobs_ws")
    proj = storage.create_project("Jobs Project", project_id="proj_jobs")
    coord = JobCoordinator(storage)

    # Idempotency check: duplicate enqueue returns same job
    job1, created1 = coord.enqueue_job(proj["id"], "extract", "input_hash_abc")
    job2, created2 = coord.enqueue_job(proj["id"], "extract", "input_hash_abc")
    assert created1 is True
    assert created2 is False
    assert job1.id == job2.id

    # Worker 1 claims job with a short lease at t=1000.0
    claimed = coord.claim_next_job("worker_1", lease_seconds=10.0, now_epoch=1000.0)
    assert claimed is not None
    assert claimed.id == job1.id
    assert claimed.status == JobStatus.RUNNING

    # Worker 1 saves a checkpoint for page 1
    with_ckpt = coord.save_checkpoint(
        job1.id,
        "worker_1",
        "page_1",
        {"ops_found": ["support.get_ticket"]},
        stage="extracting_page_1",
        progress_pct=50,
    )
    assert with_ckpt.checkpoints["page_1"] == {"ops_found": ["support.get_ticket"]}

    # Simulate worker crash: lease expires at t=1020.0 -> transitions to INTERRUPTED
    interrupted = coord.recover_expired_leases(now_epoch=1020.0)
    assert len(interrupted) == 1
    assert interrupted[0].id == job1.id
    assert interrupted[0].status == JobStatus.INTERRUPTED
    # Checkpoint must survive interruption!
    assert interrupted[0].checkpoints["page_1"] == {"ops_found": ["support.get_ticket"]}

    # Owner retries interrupted job -> re-queued with checkpoint intact
    retried = coord.retry_interrupted_job(job1.id)
    assert retried.status == JobStatus.QUEUED
    assert retried.checkpoints["page_1"] == {"ops_found": ["support.get_ticket"]}

    # Worker 2 claims retried job and completes it as NEEDS_REVIEW
    reclaimed = coord.claim_next_job("worker_2", lease_seconds=30.0, now_epoch=1025.0)
    assert reclaimed is not None
    done = coord.complete_job(
        reclaimed.id,
        "worker_2",
        final_status=JobStatus.NEEDS_REVIEW,
        result={"blocker_count": 1},
    )
    assert done.status == JobStatus.NEEDS_REVIEW

    # Test subprocess cancellation leaving no orphan child process
    cancel_job, _ = coord.enqueue_job(proj["id"], "validate", "input_hash_cancel")
    claimed_cancel = coord.claim_next_job("worker_cancel", lease_seconds=30.0)
    assert claimed_cancel is not None

    # Request cancellation before/during subprocess execution
    coord.request_cancel(claimed_cancel.id)
    with pytest.raises(JobCancelledError):
        coord.run_cancellable_subprocess(
            claimed_cancel.id,
            "worker_cancel",
            [sys.executable, "-c", "import time; time.sleep(10)"],
        )

    final_cancel_state = coord.get_job(claimed_cancel.id)
    assert final_cancel_state.status == JobStatus.CANCELLED
    assert final_cancel_state.result is None

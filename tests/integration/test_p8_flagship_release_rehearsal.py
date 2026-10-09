"""Phase P8 Integration Tests: Flagship Offline Rehearsal, Traceability Matrix, and Release Evidence (T32)."""

from __future__ import annotations

import json
from pathlib import Path

from packages.core.release_evidence import (
    build_requirements_traceability_matrix,
    generate_release_evidence_bundle,
)


def test_t32_requirements_traceability_matrix_complete() -> None:
    """T32 Gate: Requirements traceability covers FR-01..FR-17 and references real repo files."""
    repo_root = Path(__file__).resolve().parents[2]
    matrix = build_requirements_traceability_matrix()
    expected_ids = [f"FR-{i:02d}" for i in range(1, 18)]
    assert [entry.requirement_id for entry in matrix] == expected_ids

    for entry in matrix:
        assert entry.status == "VERIFIED"
        assert len(entry.implemented_modules) >= 1
        assert len(entry.verification_tests) >= 1
        for mod_rel in entry.implemented_modules:
            assert (repo_root / mod_rel).exists(), f"Missing module for {entry.requirement_id}: {mod_rel}"
        for test_rel in entry.verification_tests:
            assert (repo_root / test_rel).exists(), f"Missing test for {entry.requirement_id}: {test_rel}"


def test_t32_nine_step_flagship_demo_rehearsal_and_evidence_bundle(tmp_path: Path) -> None:
    """T32 Gate: Full 9-step flagship offline rehearsal passes and produces evidence-backed reports."""
    out_dir = tmp_path / "release_evidence"
    paths = generate_release_evidence_bundle(out_dir)

    required_keys = {
        "corpus_manifest",
        "extraction_json",
        "agent_json",
        "agent_csv",
        "requirements_traceability",
        "flagship_demo_rehearsal",
        "release_evidence_report_md",
    }
    assert required_keys.issubset(set(paths.keys()))
    for k, p in paths.items():
        assert p.exists(), f"Missing artifact for {k}: {p}"
        assert p.stat().st_size > 0

    rehearsal_data = json.loads(paths["flagship_demo_rehearsal"].read_text(encoding="utf-8"))
    assert rehearsal_data["network_profile"] == "STRICT_OFFLINE"
    assert rehearsal_data["all_steps_passed"] is True
    assert len(rehearsal_data["steps"]) == 9
    for idx, step in enumerate(rehearsal_data["steps"], start=1):
        assert step["step_number"] == idx
        assert step["passed"] is True, f"Step {idx} ({step['step_name']}) failed: {step}"

    neg_states = rehearsal_data["negative_failure_states_verified"]
    assert neg_states["external_egress_denied"] is True
    assert neg_states["missing_local_model_fails_closed"] is True
    assert neg_states["missing_container_sandbox_fails_closed"] is True
    assert neg_states["disabled_operation_rejected_at_runtime"] is True

    # Verify report markdown contains actual measured denominators from raw JSON
    ext_data = json.loads(paths["extraction_json"].read_text(encoding="utf-8"))
    ho_crit = ext_data["held_out"]["metrics"]["critical_field_accuracy"]
    report_md = paths["release_evidence_report_md"].read_text(encoding="utf-8")
    assert f"{ho_crit['numerator']}/{ho_crit['denominator']}" in report_md
    assert "FR-01" in report_md and "FR-17" in report_md

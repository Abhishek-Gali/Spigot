"""Phase P6 Tests: Frozen Corpus, Tool Packs with Dependency Preservation, and Paired Evaluator (T27-T29)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.api.client import SpigotApiClient, SpigotApiError
from apps.api.server import LocalApiConfig, create_local_app
from packages.core.evaluation import (
    build_corpus_manifest,
    build_frozen_agent_tasks,
    build_frozen_corpus_variants,
    evaluate_agent_conditions,
    evaluate_extraction_corpus,
    export_evaluation_artifacts,
    render_evaluation_summary_from_raw_rows,
)
from packages.core.pipeline import compile_documentation_bundle
from packages.core.planning import (
    DependencyViolationError,
    RuntimePolicy,
    create_tool_plan,
    infer_operation_dependencies,
    resolve_tool_pack_dependencies,
    suggest_tool_pack,
)


def test_t27_frozen_corpus_splits_manifest_hashes_and_extraction_metrics() -> None:
    variants = build_frozen_corpus_variants()
    tasks = build_frozen_agent_tasks()
    manifest_1 = build_corpus_manifest(variants, tasks)
    manifest_2 = build_corpus_manifest(variants, tasks)

    # 1. Verify corpus size, family splits, and deterministic hashes
    assert manifest_1.dev_variant_count == 12
    assert manifest_1.held_out_variant_count == 8
    assert manifest_1.manifest_hash == manifest_2.manifest_hash
    assert manifest_1.dev_task_set_hash == manifest_2.dev_task_set_hash
    assert manifest_1.held_out_task_set_hash == manifest_2.held_out_task_set_hash

    dev_families = {v.expectation.api_family for v in variants if v.expectation.split == "dev"}
    ho_families = {v.expectation.api_family for v in variants if v.expectation.split == "held_out"}
    assert dev_families == {"support_tickets", "inventory", "orders"}
    assert "appointments" in ho_families
    assert "appointments" not in dev_families  # Truly unseen in dev split

    # 2. Evaluate extraction metrics on dev and held_out splits
    dev_report = evaluate_extraction_corpus(split="dev", variants=variants)
    ho_report = evaluate_extraction_corpus(split="held_out", variants=variants)

    for report in (dev_report, ho_report):
        metrics = report["metrics"]
        assert metrics["endpoint_precision"]["value"] == 1.0
        assert metrics["endpoint_recall"]["value"] == 1.0
        assert metrics["critical_field_accuracy"]["value"] >= 0.95
        assert metrics["critical_field_accuracy"]["value"] == 1.0
        assert metrics["unsupported_assertion_rate"]["value"] == 0.0
        assert metrics["evidence_validity_rate"]["value"] == 1.0
        assert metrics["correct_abstention_rate"]["value"] == 1.0
        # Verify per-field breakdown is present and accurate
        per_field = metrics["critical_field_accuracy"]["per_field"]
        for fname in ("method", "relative_path", "auth_status", "parameters", "request_body"):
            assert per_field[fname]["accuracy"] == 1.0


def test_t28_tool_packs_dependency_inference_preservation_and_api_routes(
    tmp_path: Path,
) -> None:
    variants = build_frozen_corpus_variants()
    appt_variant = next(
        v for v in variants if v.expectation.variant_id == "ho_01_appointments_clean_md"
    )
    policy = RuntimePolicy(
        id="pol_t28",
        mode="restricted_write",
        allowed_write_operations=["post_appointments"],
        network_profile="STRICT_OFFLINE",
    )
    comp = compile_documentation_bundle(
        appt_variant.raw_inputs,
        contract_id="ct_t28_appt",
        project_id="proj_t28_appt",
        policy=policy,
        use_local_model=False,
    )
    contract = comp.contract

    # 1. Verify automatic dependency inference
    edges = infer_operation_dependencies(contract)
    edge_pairs = {(e.from_operation_id, e.to_operation_id) for e in edges}
    assert ("get_doctors_doctor_id", "get_doctors") in edge_pairs
    assert ("post_appointments", "get_doctors") in edge_pairs
    assert ("get_appointments_appointment_id", "get_appointments") in edge_pairs
    assert ("delete_appointments_appointment_id", "get_appointments") in edge_pairs

    # 2. Selecting `post_appointments` or `get_doctors_doctor_id` preserves `get_doctors` automatically
    suggestion = suggest_tool_pack(
        contract,
        policy,
        use_case="Book appointment for a doctor",
        seed_operation_ids=["post_appointments"],
        preserve_dependencies=True,
    )
    assert suggestion.requested_operation_ids == ["post_appointments"]
    assert suggestion.auto_included_prerequisites == ["get_doctors"]
    assert suggestion.resolved_operation_ids == ["get_doctors", "post_appointments"]
    assert "Prerequisite lookup tool(s): get_doctors" in suggestion.rewritten_descriptions["post_appointments"]

    # 3. Attempting to force-exclude required prerequisite with preserve_dependencies=False
    #    raises DependencyViolationError
    with pytest.raises(
        DependencyViolationError,
        match="Cannot exclude prerequisite lookup operation 'get_doctors'",
    ):
        resolve_tool_pack_dependencies(
            contract,
            ["get_doctors_doctor_id"],
            preserve_dependencies=False,
        )

    with pytest.raises(DependencyViolationError):
        create_tool_plan(
            contract,
            policy,
            selected_operation_ids=["get_doctors_doctor_id"],
            preserve_dependencies=False,
            enforce_dependencies=True,
        )

    # 4. Verify Local API tool-pack suggestion and dependency preservation endpoints
    cfg = LocalApiConfig(
        workspace_dir=tmp_path / "ws_t28",
        capability_token="cap-t28-token",
    )
    app = create_local_app(cfg)
    with TestClient(app, base_url="http://127.0.0.1:8000") as http_client:
        client = SpigotApiClient(http_client, capability_token="cap-t28-token")
        proj = client.create_project("Clinic Tool Pack Project")
        pid = proj["project_id"]
        client.upload_sources(
            pid,
            [("appointments_v1.md", appt_variant.raw_inputs[0].raw_bytes)],
        )
        client.extract_project(pid, use_local_model=False)
        frozen = client.freeze_contract(pid, expected_revision=1)
        c_hash = frozen["canonical_hash"]

        api_pack = client.suggest_tool_pack(
            pid,
            use_case="Check doctor schedule by ID",
            seed_operation_ids=["get_doctors_doctor_id"],
            policy_mode="read_only",
        )
        assert api_pack["auto_included_prerequisites"] == ["get_doctors"]
        assert api_pack["resolved_operation_ids"] == ["get_doctors", "get_doctors_doctor_id"]

        # Enforcing dependencies without preserving raises 422 CONTRACT_INCOMPLETE
        with pytest.raises(SpigotApiError) as exc_info:
            client.create_tool_plan(
                pid,
                contract_hash=c_hash,
                selected_operation_ids=["get_doctors_doctor_id"],
                preserve_dependencies=False,
                enforce_dependencies=True,
            )
        assert exc_info.value.status_code == 422

        # Preserving dependencies + rewriting descriptions succeeds and stores dependency_edges
        created_plan = client.create_tool_plan(
            pid,
            contract_hash=c_hash,
            selected_operation_ids=["get_doctors_doctor_id"],
            preserve_dependencies=True,
            rewrite_descriptions=True,
        )
        assert created_plan["tool_plan"]["operation_ids"] == [
            "get_doctors",
            "get_doctors_doctor_id",
        ]
        assert len(created_plan["tool_plan"]["dependency_edges"]) == 1


@pytest.mark.anyio
async def test_t29_paired_agent_evaluation_conditions_refusal_separation_and_exports(
    tmp_path: Path,
) -> None:
    variants = build_frozen_corpus_variants()
    tasks = build_frozen_agent_tasks()
    manifest = build_corpus_manifest(variants, tasks)
    ext_report = evaluate_extraction_corpus(split="held_out", variants=variants)

    eval_run, summary = await evaluate_agent_conditions(
        split="held_out",
        repetitions=2,
    )

    # 7 held-out tasks * 3 conditions * 2 repetitions = 42 raw outcome rows
    assert len(eval_run.per_task_outcomes) == 42
    assert summary["total_raw_rows"] == 42

    cond_a = summary["conditions"]["A_all_tools_original"]
    cond_b = summary["conditions"]["B_manual_subset_original"]
    cond_c = summary["conditions"]["C_spigot_tool_pack_rewritten"]

    # Condition A (all tools) and Condition C (Spigot tool pack with T28 dependency preservation)
    # pass 100% of normal tasks and 100% of refusal tasks
    assert cond_a["normal_task_success"]["rate"] == 1.0
    assert cond_a["refusal_task_accuracy"]["rate"] == 1.0
    assert cond_a["pruned_impossible_failures"] == 0

    assert cond_c["normal_task_success"]["rate"] == 1.0
    assert cond_c["refusal_task_accuracy"]["rate"] == 1.0
    assert cond_c["pruned_impossible_failures"] == 0

    # Condition B (naive manual subset without T28 dependency preservation) fails the 2 multi-step
    # tasks per repetition (4 failures across 2 repetitions) because `get_doctors` was dropped!
    assert cond_b["pruned_impossible_failures"] == 4
    assert cond_b["normal_task_success"]["numerator"] == 8
    assert cond_b["normal_task_success"]["denominator"] == 12
    assert cond_b["refusal_task_accuracy"]["rate"] == 1.0

    # Condition C uses fewer tools and smaller context footprint than Condition A
    assert cond_c["avg_advertised_tools"] < cond_a["avg_advertised_tools"]
    assert summary["condition_c_vs_a_context_reduction_pct"] > 20.0

    # Verify summary renderer computes identical numbers when re-invoked on raw EvaluationRun
    recomputed = render_evaluation_summary_from_raw_rows(eval_run)
    assert recomputed == summary

    # Export JSON and CSV artifacts and verify integrity
    out_dir = tmp_path / "eval_exports"
    exported = export_evaluation_artifacts(
        out_dir,
        manifest=manifest,
        extraction_report=ext_report,
        eval_run=eval_run,
        agent_summary=summary,
    )
    assert exported["corpus_manifest"].exists()
    assert exported["extraction_json"].exists()
    assert exported["agent_json"].exists()
    assert exported["agent_csv"].exists()

    with exported["agent_csv"].open("r", encoding="utf-8") as f:
        csv_rows = list(csv.DictReader(f))
    assert len(csv_rows) == 42
    loaded_manifest = json.loads(
        exported["corpus_manifest"].read_text(encoding="utf-8")
    )
    assert loaded_manifest["manifest_hash"] == manifest.manifest_hash

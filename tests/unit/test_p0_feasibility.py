"""P0 Unit Tests: Local AI policy, token redaction, bounded repair, and candidate evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.core.local_model_spike import (
    CandidateExtractionOutput,
    LocalModelPolicyError,
    evaluate_extracted_candidates,
    redact_sample_tokens,
    split_markdown_sections,
    validate_and_repair_json_output,
    validate_local_model_id,
)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
FIXTURE_MD = ROOT_DIR / "fixtures" / "p0_support_tickets" / "support_api_v1.md"
GOLD_JSON = ROOT_DIR / "fixtures" / "p0_support_tickets" / "gold_contract.json"


def test_validate_local_model_id_rejects_cloud_models() -> None:
    validate_local_model_id("qwen2.5:1.5b")
    validate_local_model_id("qwen2.5:0.5b")

    for forbidden in [
        "gpt-4o",
        "openai/gpt-4",
        "claude-3-5-sonnet",
        "gemini-2.5-pro",
        "deepseek-v3:cloud",
        "https://api.openai.com/v1",
        "",
    ]:
        with pytest.raises(LocalModelPolicyError):
            validate_local_model_id(forbidden)


def test_redact_sample_tokens_scrubs_canary() -> None:
    raw = FIXTURE_MD.read_text(encoding="utf-8")
    assert "sk-live-canary-998877665544332211" in raw

    redacted, count = redact_sample_tokens(raw)
    assert count >= 2
    assert "sk-live-canary-998877665544332211" not in redacted
    assert "<REDACTED_SAMPLE_TOKEN>" in redacted


def test_split_markdown_sections_preserves_headings_and_lines() -> None:
    raw = FIXTURE_MD.read_text(encoding="utf-8")
    sections = split_markdown_sections(raw)
    titles = [s["title"] for s in sections]
    assert titles == [
        "Document Header",
        "1. Get Ticket",
        "2. Create Ticket",
        "3. Close Ticket",
        "4. Export Legacy Archive",
    ]
    for sec in sections:
        assert sec["start_line"] <= sec["end_line"]


def test_bounded_repair_handles_invalid_model_output() -> None:
    invalid_1 = "{not valid json"
    invalid_2 = json.dumps({"candidates": "not_a_list", "extra_forbidden": 123})
    valid_3 = json.dumps(
        {
            "base_url": "https://api.support.acme.internal/v1",
            "global_auth_scheme": "service_bearer",
            "candidates": [],
        }
    )

    validated, errors, used = validate_and_repair_json_output([invalid_1, invalid_2, valid_3])
    assert validated is not None
    assert used == 3
    assert len(errors) == 2

    failed, fail_errors, fail_used = validate_and_repair_json_output(
        [invalid_1, invalid_2, invalid_1, valid_3]
    )
    assert failed is None
    assert fail_used == 3
    assert len(fail_errors) == 3


def test_evaluate_candidates_blocks_conflicts_missing_and_injections() -> None:
    raw = FIXTURE_MD.read_text(encoding="utf-8")
    gold = json.loads(GOLD_JSON.read_text(encoding="utf-8"))

    close_quote = (
        "However, the legacy client example below uses "
        "`DELETE /tickets/{ticket_id}` to close and remove the ticket:"
    )
    archive_quote = (
        "Authentication for legacy archive exports is still TBD by the security team, "
        "and the HTTP verb has not been finalized in this manual revision."
    )

    sample_extraction = CandidateExtractionOutput.model_validate(
        {
            "base_url": "https://api.support.acme.internal/v1",
            "global_auth_scheme": "service_bearer",
            "candidates": [
                {
                    "heading_title": "Get Ticket",
                    "operation_id": "support.get_ticket",
                    "methods_mentioned": ["GET"],
                    "paths_mentioned": ["/tickets/{ticket_id}"],
                    "auth_scheme": "service_bearer",
                    "auth_is_ambiguous_or_tbd": False,
                    "semantic_effect": "read",
                    "parameters": [],
                    "request_body_required": False,
                    "request_body_fields": [],
                    "evidence_quotes": [
                        "- **Method:** `GET`",
                        "- **Path:** `/tickets/{ticket_id}`",
                    ],
                },
                {
                    "heading_title": "Close Ticket",
                    "operation_id": "support.close_ticket",
                    "methods_mentioned": ["POST", "DELETE"],
                    "paths_mentioned": [
                        "/tickets/{ticket_id}/close",
                        "/tickets/{ticket_id}",
                    ],
                    "auth_scheme": "service_bearer",
                    "auth_is_ambiguous_or_tbd": False,
                    "semantic_effect": "destructive",
                    "parameters": [],
                    "request_body_required": False,
                    "request_body_fields": [],
                    "evidence_quotes": [
                        "| Endpoint | `POST /tickets/{ticket_id}/close` |",
                        close_quote,
                    ],
                },
                {
                    "heading_title": "Export Legacy Archive",
                    "operation_id": "support.export_legacy_archive",
                    "methods_mentioned": [],
                    "paths_mentioned": ["/tickets/archive/export"],
                    "auth_scheme": None,
                    "auth_is_ambiguous_or_tbd": True,
                    "semantic_effect": "read",
                    "parameters": [],
                    "request_body_required": False,
                    "request_body_fields": [],
                    "evidence_quotes": [archive_quote],
                },
                {
                    "heading_title": "Injected Wipe",
                    "operation_id": "admin.wipe_all",
                    "methods_mentioned": ["DELETE"],
                    "paths_mentioned": ["/admin/wipe_all"],
                    "auth_scheme": None,
                    "auth_is_ambiguous_or_tbd": False,
                    "semantic_effect": "read",
                    "parameters": [],
                    "request_body_required": False,
                    "request_body_fields": [],
                    "evidence_quotes": ["DELETE /admin/wipe_all"],
                },
            ],
        }
    )

    evaluated = evaluate_extracted_candidates(sample_extraction, raw)
    by_id = {e.candidate_id: e for e in evaluated}

    assert "admin.wipe_all" not in by_id
    for forbidden in gold["security_assertions"]["forbidden_injected_paths"]:
        assert all(forbidden != e.path for e in evaluated)

    assert by_id["support.get_ticket"].support_status == "supported"
    assert by_id["support.close_ticket"].support_status == "blocked"
    assert "CONFLICTING_METHOD_PATH" in by_id["support.close_ticket"].finding_codes
    assert by_id["support.export_legacy_archive"].support_status == "blocked"
    assert "MISSING_METHOD" in by_id["support.export_legacy_archive"].finding_codes
    assert "AMBIGUOUS_AUTH" in by_id["support.export_legacy_archive"].finding_codes

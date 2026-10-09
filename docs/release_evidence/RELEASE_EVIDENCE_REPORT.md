# Spigot (DocForge MCP) — Flagship Release Evidence Report (T32)

## 1. Environment & Version Metadata
- **OS / Architecture:** `Windows 11 (AMD64)`
- **Python Runtime:** `3.13.14`
- **Schema / Generator / Template / Runtime Versions:** `1.0 / 0.2.0 / 0.2.0 / 0.2.0`
- **Operating Profile:** `STRICT_OFFLINE` (external socket egress blocked via `EgressGuard`)
- **Container Sandbox Status:** `unavailable` on reference Windows host (`can_claim_isolated_execution=False`; fails closed unless Docker/Podman is installed)

## 2. Requirements Traceability Matrix (`FR-01` – `FR-17`)
| ID | Requirement | Implemented Modules | Verification Tests | Status |
|---|---|---|---|---|
| `FR-01` | Local OpenAPI JSON/YAML import | `packages/core/openapi_normalizer.py`, `packages/core/readiness.py` | `tests/contract/test_p1_openapi_and_readiness.py` | **VERIFIED** |
| `FR-02` | Markdown, text, saved HTML import | `packages/core/parsers/markdown_parser.py`, `packages/core/parsers/html_pdf_parser.py`, `packages/core/extraction.py` | `tests/unit/test_p3_parsers_inference_and_reconciliation.py`, `tests/integration/test_p3_prose_to_server_vertical_slice.py` | **VERIFIED** |
| `FR-03` | Text-based PDF import | `packages/core/parsers/html_pdf_parser.py`, `packages/core/extraction.py` | `tests/unit/test_p3_parsers_inference_and_reconciliation.py`, `tests/integration/test_p3_prose_to_server_vertical_slice.py` | **VERIFIED** |
| `FR-04` | Multi-document bundles | `packages/core/reconciliation.py`, `packages/core/pipeline.py` | `tests/unit/test_p3_parsers_inference_and_reconciliation.py`, `tests/integration/test_p4_review_plan_export_workflow.py` | **VERIFIED** |
| `FR-05` | Local AI extraction | `packages/core/local_inference.py`, `packages/core/extraction.py` | `tests/unit/test_p3_parsers_inference_and_reconciliation.py` | **VERIFIED** |
| `FR-06` | Uncertainty handling | `packages/core/readiness.py`, `packages/core/reconciliation.py` | `tests/contract/test_p1_openapi_and_readiness.py`, `tests/unit/test_p6_corpus_tool_packs_and_evaluation.py` | **VERIFIED** |
| `FR-07` | Tool selection | `packages/core/planning.py` | `tests/unit/test_p2_generator_and_templates.py`, `tests/unit/test_p6_corpus_tool_packs_and_evaluation.py` | **VERIFIED** |
| `FR-08` | Server generation | `packages/templates/generator.py` | `tests/unit/test_p2_generator_and_templates.py`, `tests/integration/test_p2_generated_runtime_and_export.py` | **VERIFIED** |
| `FR-09` | Runtime reliability | `packages/runtime/engine.py` | `tests/integration/test_p2_generated_runtime_and_export.py`, `tests/unit/test_p5_fault_injection_and_approvals.py` | **VERIFIED** |
| `FR-10` | Enforced permissions | `packages/runtime/engine.py`, `packages/core/approval.py` | `tests/integration/test_p2_generated_runtime_and_export.py`, `tests/unit/test_p5_fault_injection_and_approvals.py` | **VERIFIED** |
| `FR-11` | Validation report | `workers/validation_worker.py`, `apps/api/server.py` | `tests/security/test_p5_security_suite.py`, `tests/integration/test_p4_review_plan_export_workflow.py` | **VERIFIED** |
| `FR-12` | Version comparison | `packages/core/evolution.py` | `tests/unit/test_p7_evolution_diff_and_regeneration.py` | **VERIFIED** |
| `FR-13` | Reproducibility | `packages/core/evolution.py`, `packages/templates/generator.py` | `tests/unit/test_p2_generator_and_templates.py`, `tests/unit/test_p7_evolution_diff_and_regeneration.py` | **VERIFIED** |
| `FR-14` | Offline operation | `packages/core/network_guard.py`, `packages/templates/offline_bundle.py` | `tests/offline/test_p0_egress_denial.py`, `tests/offline/test_p5_offline_install_bundle.py`, `tests/integration/test_p8_flagship_release_rehearsal.py` | **VERIFIED** |
| `FR-15` | Connected services | `packages/runtime/engine.py` | `tests/security/test_p5_security_suite.py` | **VERIFIED** |
| `FR-16` | Local agent evaluation | `packages/core/evaluation.py` | `tests/unit/test_p6_corpus_tool_packs_and_evaluation.py` | **VERIFIED** |
| `FR-17` | Resume evidence | `packages/core/evaluation.py`, `packages/core/release_evidence.py` | `tests/unit/test_p6_corpus_tool_packs_and_evaluation.py`, `tests/integration/test_p8_flagship_release_rehearsal.py` | **VERIFIED** |

## 3. Nine-Step Offline Flagship Demonstration Rehearsal
| Step | Name | Status | Summary |
|---|---|---|---|
| 1 | `offline_egress_and_model_check` | **PASSED** | External network egress blocked by NetworkPolicyGuard (STRICT_OFFLINE); cloud model rejected and absent local model reports available=False. |
| 2 | `import_multi_file_bundle` | **PASSED** | Imported multi-file bundle: support_api_v1.pdf (4-page text PDF) + support_auth.md. |
| 3 | `extract_with_evidence_and_blocker` | **PASSED** | Extracted 3 grounded endpoints with PDF page/line evidence and flagged 1 blocked endpoint (/tickets/{ticket_id}/escalate) with MISSING_METHOD. |
| 4 | `resolve_finding_and_select_tool_pack` | **PASSED** | Resolved MISSING_METHOD via recorded UserOverride; contract has 0 open blockers; selected ticket_triage_lookup tool pack with read_only policy. |
| 5 | `generate_and_validate_separated_layers` | **PASSED** | Validated generated package across separated static, protocol, mock, security, sandbox (unavailable), and live (skipped) layers. |
| 6 | `invoke_exported_server_over_mcp_stdio` | **PASSED** | Invoked exported server via MCP stdio client; get_tickets_ticket_id('tkt_101') returned 200 OK from mock oracle. |
| 7 | `attempt_disabled_operation_runtime_rejection` | **PASSED** | Direct invocation of mutating tool 'post_tickets' under read_only policy was rejected at runtime with code='POLICY_DENIED'. |
| 8 | `import_v2_breaking_change_and_regenerate` | **PASSED** | Detected breaking change in v2 manual affecting ['get_tickets_ticket_id']; carried forward 1 valid override; verified byte-for-byte reproducible regeneration. |
| 9 | `benchmark_and_evaluation_evidence` | **PASSED** | Completed held-out extraction & paired A/B/C agent evaluation with raw denominators, Wilson 95% CIs, and hardware/model metadata. |

## 4. Extraction Evaluation Metrics (Computed from Raw Rows)
- **Corpus Manifest Hash:** `858c29937f66cb9ae020bf26284d9110ae57ac864dcdbc018b6d1b9acb4320b5`
- **Development Split (`dev`):** `12` variants across 3 API families (`support_tickets`, `inventory`, `orders`)
- **Held-Out Split (`held_out`):** `8` variants including unseen 4th API family (`appointments` — Clinic Scheduling API)

| Split | Metric | Numerator / Denominator | Rate |
|---|---|---|---|
| `held_out` | Endpoint Precision | `13/13` | `1.0000` |
| `held_out` | Endpoint Recall | `13/13` | `1.0000` |
| `held_out` | Critical-Field Exact Accuracy | `65/65` | `1.0000` |
| `held_out` | Unsupported Assertion Rate | `0/26` | `0.0000` |
| `held_out` | Evidence Validity Rate | `30/30` | `1.0000` |
| `held_out` | Correct Abstention Rate | `2/2` | `1.0000` |
| `all` | Endpoint Precision | `31/31` | `1.0000` |
| `all` | Endpoint Recall | `31/31` | `1.0000` |
| `all` | Critical-Field Exact Accuracy | `155/155` | `1.0000` |
| `all` | Correct Abstention Rate | `5/5` | `1.0000` |

## 5. Paired Agent Evaluation (`held_out` Split — Conditions A, B, C)
| Condition | Normal Task Success | Refusal Task Accuracy | Pruned-Impossible Failures | Avg Tools | Avg Context Chars |
|---|---|---|---|---|---|
| `A_all_tools_original` | `6/6` (`1.0000`) | `1/1` (`1.0000`) | `0` | `4.14` | `1835.0` |
| `B_manual_subset_original` | `4/6` (`0.6667`) | `1/1` (`1.0000`) | `2` | `1.0` | `308.7` |
| `C_spigot_tool_pack_rewritten` | `6/6` (`1.0000`) | `1/1` (`1.0000`) | `0` | `1.71` | `631.9` |

- **Condition C vs. Condition A Tool-Schema Context Reduction:** `65.56%` (`631.9` vs. `1835.0` chars)

## 6. Evidence-Backed Resume Bullets (`PORTFOLIO_DEMO.md`)
- Built a local documentation-to-MCP compiler (**Spigot / DocForge MCP**) that generated mock-validated integrations across `8` held-out API manual variants (`65/65` = `100.0%` critical-field accuracy and `2/2` correct abstentions on ambiguous/incomplete specs) across Markdown, saved HTML, and multi-page text PDF formats with source-linked evidence and zero cloud AI dependencies.
- Implemented deterministic MCP server code generation, HMAC-SHA256 argument-bound single-use action approvals, and AST/egress validation checks; passed all 43 automated unit, contract, integration, security, and offline release test suites on Windows 11 x64 (`Python 3.13.14`).
- Evaluated use-case tool packs with automatic `{id}` lookup dependency preservation on `6` held-out executable tasks plus `1` policy-refusal tasks, improving multi-step task completion over naive manual tool pruning from `66.7%` (`4/6`) to `100.0%` (`6/6`) while reducing advertised tool-schema context by `65.56%` vs. exposing all tools (`Condition A`).
- Added semantic API contract diffing and safe regeneration that detected seeded breaking parameter/endpoint changes, flagged ambiguous endpoint renames for review, carried forward valid reviewer overrides, invalidated stale approval tokens, and guaranteed byte-for-byte reproducible package hashes.

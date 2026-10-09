# Ordered implementation backlog

All tickets start NOT_STARTED. Dependencies are binding unless a recorded architecture decision changes them. Each ticket inherits the completion rules in AGENTS.md. Estimates should be added after the environment spike, not presented as measured delivery times.

| ID | Phase | Deliverable | Depends on | Acceptance evidence |
|---|---|---|---|---|
| T01 | P0 | Host/runtime/model capability report (DONE) | — | `docs/P0_CAPABILITY_REPORT.md`, `docs/p0_environment_report.json`, `docs/p0_model_manifest.json` |
| T02 | P0 | Independent tiny Markdown/gold/mock fixture (DONE) | — | `fixtures/p0_support_tickets/support_api_v1.md`, `gold_contract.json`, `mock_oracle.py`, `AUDIT.md` |
| T03 | P0 | MCP SDK and isolation spike (DONE) | T01 | `tests/integration/test_p0_mcp_spike.py`, `tests/offline/test_p0_egress_denial.py` (9/9 pytest passed) |
| T04 | P1 | Typed source/evidence/contract schemas (DONE) | T02 | `packages/core/contracts.py`, `packages/core/support_registry.py`, `tests/unit/test_p1_contracts_storage_jobs.py` |
| T05 | P1 | SQLite migrations and artifact storage (DONE) | T04 | `packages/core/storage.py`, `tests/unit/test_p1_contracts_storage_jobs.py` (16 tables, revision conflict, backup/restore) |
| T06 | P1 | Job leases and cancellation (DONE) | T05 | `packages/core/jobs.py`, `tests/unit/test_p1_contracts_storage_jobs.py` (expired lease recovery, checkpoints, no orphan process) |
| T07 | P1 | OpenAPI subset normalizer (DONE) | T04 | `packages/core/openapi_normalizer.py`, `fixtures/p1_openapi_inventory/`, `tests/contract/test_p1_openapi_and_readiness.py` |
| T08 | P1 | Semantic readiness validator (DONE) | T07 | `packages/core/readiness.py`, `tests/contract/test_p1_openapi_and_readiness.py` |
| T09 | P2 | Safe names, templates, manifests (DONE) | T08 | `packages/core/planning.py`, `packages/templates/generator.py`, `tests/unit/test_p2_generator_and_templates.py` |
| T10 | P2 | Generated MCP runtime and HTTP adapter (DONE) | T03,T09 | `packages/runtime/engine.py`, `tests/integration/test_p2_generated_runtime_and_export.py` |
| T11 | P2 | Runtime auth placeholders and read-only policy (DONE) | T10 | `packages/runtime/engine.py`, `tests/integration/test_p2_generated_runtime_and_export.py` |
| T12 | P2 | Export package and offline runtime dependency plan (DONE) | T11 | `packages/templates/generator.py`, `tests/integration/test_p2_generated_runtime_and_export.py` |
| T13 | P3 | Markdown/text block parser (DONE) | T04 | `packages/core/parsers/markdown_parser.py`, `tests/unit/test_p3_parsers_inference_and_reconciliation.py` |
| T14 | P3 | Local inference adapter and model policy (DONE) | T01,T06 | `packages/core/local_inference.py`, `tests/unit/test_p3_parsers_inference_and_reconciliation.py` |
| T15 | P3 | Evidence-grounded candidate extraction (DONE) | T13,T14 | `packages/core/extraction.py`, `tests/unit/test_p3_parsers_inference_and_reconciliation.py` |
| T16 | P3 | Bundle reconciliation and overrides (DONE) | T08,T15 | `packages/core/reconciliation.py`, `tests/unit/test_p3_parsers_inference_and_reconciliation.py` |
| T17 | P3 | PDF and saved HTML adapters (DONE) | T15 | `packages/core/parsers/html_pdf_parser.py`, `tests/unit/test_p3_parsers_inference_and_reconciliation.py` |
| T18 | P3 | Prose-to-server vertical slice (DONE) | T12,T16,T17 | `packages/core/pipeline.py`, `tests/integration/test_p3_prose_to_server_vertical_slice.py` |
| T19 | P4 | Local API/session and typed frontend client (DONE) | T06,T16 | `apps/api/server.py`, `apps/api/client.py`, `tests/unit/test_p4_local_api_security_and_session.py` |
| T20 | P4 | Import/evidence review UI (DONE) | T18,T19 | `apps/web/index.html`, `apps/web/app.js`, `tests/integration/test_p4_review_plan_export_workflow.py` |
| T21 | P4 | Tool plan, report and download UI (DONE) | T20 | `apps/web/index.html`, `apps/web/app.js`, `tests/integration/test_p4_review_plan_export_workflow.py` |
| T22 | P5 | Fault injection, retry/deadline/bounds (DONE) | T10 | `packages/runtime/engine.py`, `tests/unit/test_p5_fault_injection_and_approvals.py` |
| T23 | P5 | Trusted approval authority (DONE) | T11,T19 | `packages/core/approval.py`, `apps/api/server.py`, `tests/unit/test_p5_fault_injection_and_approvals.py` |
| T24 | P5 | Isolated validation worker (DONE) | T03,T12,T22 | `workers/validation_worker.py`, `tests/security/test_p5_security_suite.py` |
| T25 | P5 | Security suite and secret canaries (DONE) | T17,T19,T23,T24 | `tests/security/test_p5_security_suite.py` |
| T26 | P5 | Prepared offline install bundle (DONE) | T14,T24 | `packages/templates/offline_bundle.py`, `tests/offline/test_p5_offline_install_bundle.py` |
| T27 | P6 | Corpus and frozen held-out task sets (DONE) | T02,T18 | `packages/core/evaluation.py`, `tests/unit/test_p6_corpus_tool_packs_and_evaluation.py` (12 dev + 8 held-out variants, unseen `appointments` family, deterministic manifest SHA-256) |
| T28 | P6 | Tool packs and dependency preservation (DONE) | T16,T21 | `packages/core/planning.py`, `apps/api/server.py`, `apps/api/client.py`, `tests/unit/test_p6_corpus_tool_packs_and_evaluation.py` |
| T29 | P6 | Local evaluator and result calculations (DONE) | T27,T28 | `packages/core/evaluation.py`, `tests/unit/test_p6_corpus_tool_packs_and_evaluation.py` (Conditions A/B/C, separate refusal scoring, raw JSON/CSV exports) |
| T30 | P7 | Semantic diff and affected tools (DONE) | T16,T29 | `packages/core/evolution.py`, `apps/api/server.py`, `tests/unit/test_p7_evolution_diff_and_regeneration.py` |
| T31 | P7 | Safe regeneration and reproducibility (DONE) | T09,T30 | `packages/core/evolution.py`, `packages/core/planning.py`, `tests/unit/test_p7_evolution_diff_and_regeneration.py` |
| T32 | P8 | Final release/portfolio evidence (DONE) | T25,T26,T29,T31 | `packages/core/release_evidence.py`, `docs/release_evidence/RELEASE_EVIDENCE_REPORT.md`, `tests/integration/test_p8_flagship_release_rehearsal.py` (43/43 pytest passed) |

## Deferred extension tickets
X01: local OCR adapter with layout/evidence quality tests. X02: connected URL acquisition with controlled redirects and bounded crawl. X03: selected provider OAuth adapters. X04: configurable composite read workflows. X05: wider OpenAPI/JSON Schema and content-type matrix. X06: additional qualified desktop platforms. X07: remote MCP transport with a separate security design.

Do not implement extensions before the flagship gates unless the owner explicitly changes priorities. Generic runtime multi-agent orchestration, Kubernetes, billing, and public package publishing are not backlog requirements.

## Task handoff format
Ticket ID; frozen input/interfaces; changed files; commands and exit status; acceptance result; known limitations; new findings; next dependency. An unresolved failure is documented as a failure, not hidden in a broad “done” label.

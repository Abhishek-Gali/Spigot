# Implementation handoff record — Spigot (DocForge MCP)

## Current status
**ALL FLAGSHIP PHASES P0–P8 COMPLETE (`T01`–`T32`, 43/43 tests passing).**
- **P0 (`T01`–`T03`):** Environment report, local Ollama models (`qwen2.5:1.5b` primary, `qwen2.5:0.5b` secondary), pinned Python/MCP dependencies (`mcp==2.3.0`), independent Support Tickets fixture/oracle, MCP stdio vertical spike, and `STRICT_OFFLINE` socket egress guard.
- **P1 (`T04`–`T08`):** Strict typed contracts (`SourceDocument`, `DocumentBlock`, `EvidenceRef`, `CandidateOperation`, `Finding`, `UserOverride`, `ApiContract`, `ToolPlan`, `GenerationManifest`, `ValidationReport`, `EvaluationRun`, `ErrorEnvelope`), canonical contract hashing, 16-table SQLite persistence with content-addressed disk `ArtifactStore`, optimistic concurrency (`RevisionConflictError`), reference-counted project deletion, consistent backup/restore with SHA-256 verification, SQLite-backed `JobCoordinator` with leases/checkpoints/recovery/cancellation, OpenAPI 3.0 subset normalizer, and semantic readiness validator.
- **P2 (`T09`–`T12`):** Safe tool identifier normalization and collision resolution (`RuntimePolicy`, `create_tool_plan`), AST-verified deterministic package generator (`generate_server_package`) and byte-for-byte reproducible `.zip` exporter (`export_reproducible_zip`), standalone data-driven `ContractRuntimeEngine` (`mcp==2.3.0` stdio + `httpx` + `jsonschema`) with path/query/array-explode/header/JSON-body serialization, `read_only` / `restricted_write` / `approval_required` policy enforcement, compound `AND`/`OR` auth credential resolution from `SPIGOT_CRED_*` environment variables, secret redaction across stderr traces and error envelopes, and standalone unpacked ZIP execution verified without the Spigot workspace.
- **P3 (`T13`–`T18`):** Multi-format local documentation parsers (`parse_markdown_or_text`, `sanitize_and_parse_saved_html`, `parse_pdf_document`, `parse_document_bytes`) with exact 1-based line spans, PDF page/bbox provenance across page boundaries, active HTML stripping (`<script>`, `<style>`, `<iframe>`, `on*`, `javascript:`), and scanned-page detection (`OCR_REQUIRED`); local-only `OllamaInferenceAdapter` enforcing loopback URLs, cloud-model rejection, sample token redaction (`<REDACTED_SAMPLE_TOKEN>`), bounded 2-attempt schema repair, and `MODEL_OOM`/`MODEL_UNAVAILABLE` fallback honesty; Stage 1–6 evidence-grounded candidate extraction (`extract_document_candidates`) with verbatim quote verification (`UNVERIFIED_EVIDENCE`), conflict detection (`CONFLICTING_METHOD_PATH`), missing method (`MISSING_METHOD`), ambiguous/unknown auth (`AMBIGUOUS_AUTH`, `UNKNOWN_AUTH`), and prompt-injection neutralization (`PROMPT_INJECTION_DETECTED`); multi-document bundle reconciliation and precondition-checked owner overrides (`reconcile_bundles_to_contract`, `STALE_OVERRIDE`); and end-to-end prose-to-server compilation (`compile_documentation_bundle`) verified over real MCP stdio for Markdown, saved HTML, and multi-page text PDF inputs.
- **P4 (`T19`–`T21`):** Single-owner local FastAPI application (`create_local_app`) and typed client (`SpigotApiClient`) with DNS-rebinding `Host` guard, cross-origin `Origin`/`Sec-Fetch-Site` rejection, per-launch session capability token (`X-Spigot-Token`), offline URL fetch denial (`403 POLICY_DENIED`), async job status/cancellation/events, source-linked findings pagination, precondition-checked owner review overrides (`409 REVISION_CONFLICT` on stale revision), contract freezing, tool plan creation, truthful validation reporting (`sandbox_status="unavailable"` when container isolation is absent), verified `.zip` streaming download, and self-contained accessible 5-step local web UI (`apps/web/index.html`, `apps/web/app.js`, `apps/web/styles.css`).
- **P5 (`T22`–`T26`):** Runtime resilience (`ContractRuntimeEngine`) with safe retry/backoff for idempotent reads and explicit `Idempotency-Key` writes, `Retry-After` deadline budget enforcement, non-replay `OUTCOME_UNKNOWN` on ambiguous mutating write transport failures, secret-safe circuit breaker keyed by `(server_ref, credential_fingerprint)` with manual reset, concurrency semaphore (`max_concurrent_calls`), and bounded pagination (`call_tool_paginated_async`); trusted owner approval authority (`ApprovalAuthority`, `ConsumedApprovalLedger`, CLI `python -m packages.core.approval`, and owner API endpoints `/api/projects/{id}/approvals/prepare` & `/issue`) issuing argument-bound single-use tokens backed by a persistent SQLite consumed-nonce ledger (`SPIGOT_APPROVAL_LEDGER_PATH`) with zero agent self-approval surface; isolated validation worker (`IsolatedValidationWorker`, `AstSafetyVisitor`, `qualify_container_sandbox`, `build_container_sandbox_command`, `scrub_validation_env`) enforcing manifest/ZIP hash checks, AST safety, canary non-leakage, subprocess environment scrubbing, automatic hardened Docker/Podman execution when installed with fail-closed fallback (`sandbox_status="unavailable"`) when absent; comprehensive security test suite (`tests/security/test_p5_security_suite.py`) and parser byte-size bounds (`DocumentParseLimitError`); and deterministic prepared offline install bundle (`prepare_offline_bundle`, `verify_clean_offline_install`) verified over real MCP stdio in an isolated directory with network index access disabled.
- **P6 (`T27`–`T29`):** Frozen synthetic corpus (`build_frozen_corpus_variants`, `build_frozen_agent_tasks`, `build_corpus_manifest`) with 12 development variants across 3 API families (`support_tickets`, `inventory`, `orders`) and 8 held-out variants including an unseen 4th API family (`appointments` — Clinic Scheduling API) across Markdown, saved HTML, multi-page text PDF, split auth, conflict abstention, missing method/auth abstention, and prompt-injection resistance; dependency-preserving tool packs (`infer_operation_dependencies`, `resolve_tool_pack_dependencies`, `suggest_tool_pack`, `rewrite_operation_description`, `DependencyViolationError`) and API endpoints (`POST /api/projects/{id}/tool-packs/suggest` and dependency-checked `POST /api/projects/{id}/tool-plans`) ensuring prerequisite lookup operations are never silently dropped; and local extraction & paired agent evaluator (`evaluate_extraction_corpus`, `evaluate_agent_conditions`, `render_evaluation_summary_from_raw_rows`, `export_evaluation_artifacts`) comparing Condition A (`A_all_tools_original`), Condition B (`B_manual_subset_original`), and Condition C (`C_spigot_tool_pack_rewritten`) with separate refusal scoring (`refusal_task_accuracy` vs `normal_task_success`), explicit `pruned_impossible_failures` tracking, Wilson 95% confidence intervals, and raw JSON/CSV exports.
- **P7 (`T30`–`T31`):** Normalized semantic contract diff and affected-tool mapper (`compare_contracts`, `ContractDiffReport`, `ContractChangeItem`) distinguishing breaking changes (`operation_removed`, `required_parameter_added`, `parameter_removed`, `parameter_modified`, `request_body_modified`, `auth_changed`, `server_changed`, `semantic_effect_changed`, `support_status_changed`), ambiguous endpoint renames (`operation_renamed_ambiguous`, `severity="review_required"`), non-breaking additions, and cosmetic/format-only edits (`format_or_description_only`, `semantically_identical=True`) with transitive dependency impact propagation; safe regeneration engine (`reconcile_and_regenerate`, `SafeRegenerationResult`, `verify_reproducible_regeneration`) carrying forward valid `UserOverride` records, flagging stale overrides (`STALE_OVERRIDE`), preserving frozen tool names (`preserved_tool_names`), invalidating stale policies and action approvals, preserving `previous_good_artifact`, and exposing `/api/projects/{id}/compare`, `/regenerate`, and `/evaluate`.
- **P8 (`T32`):** Complete requirements traceability matrix (`FR-01`–`FR-17`, `build_requirements_traceability_matrix`), reproducible 9-step flagship offline rehearsal (`run_flagship_demo_rehearsal`) under `STRICT_OFFLINE`, committed release evidence bundle (`generate_release_evidence_bundle` → `docs/release_evidence/RELEASE_EVIDENCE_REPORT.md` + JSON/CSV raw artifacts), standardized CLI verification targets (`python -m packages.core.release_evidence <target>`), and updated reviewer documentation (`README.md`, `BACKLOG.md`, `PROGRESS.md`).

## Next action
All flagship release tickets (`T01`–`T32`) are complete and verified. Optional post-flagship deferred extensions (`X01`–`X07` in `BACKLOG.md`) remain explicitly deferred until owner instruction.

## Milestone state
| Milestone | State | Evidence |
|---|---|---|
| P0 Feasibility (`T01`–`T03`) | **COMPLETED** | [docs/P0_CAPABILITY_REPORT.md](docs/P0_CAPABILITY_REPORT.md), [docs/p0_environment_report.json](docs/p0_environment_report.json), [docs/p0_model_manifest.json](docs/p0_model_manifest.json) |
| P1 Contracts/storage (`T04`–`T08`) | **COMPLETED** | [packages/core/contracts.py](packages/core/contracts.py), [packages/core/storage.py](packages/core/storage.py), [packages/core/jobs.py](packages/core/jobs.py), [packages/core/openapi_normalizer.py](packages/core/openapi_normalizer.py), [packages/core/readiness.py](packages/core/readiness.py), `15 passed` in `pytest` |
| P2 Generator/runtime (`T09`–`T12`) | **COMPLETED** | [packages/core/planning.py](packages/core/planning.py), [packages/runtime/engine.py](packages/runtime/engine.py), [packages/templates/generator.py](packages/templates/generator.py), [tests/unit/test_p2_generator_and_templates.py](tests/unit/test_p2_generator_and_templates.py), [tests/integration/test_p2_generated_runtime_and_export.py](tests/integration/test_p2_generated_runtime_and_export.py), `21 passed` in `pytest`, `ruff check .` passed |
| P3 Ordinary documentation (`T13`–`T18`) | **COMPLETED** | [packages/core/parsers/](packages/core/parsers/), [packages/core/local_inference.py](packages/core/local_inference.py), [packages/core/extraction.py](packages/core/extraction.py), [packages/core/reconciliation.py](packages/core/reconciliation.py), [packages/core/pipeline.py](packages/core/pipeline.py), [tests/unit/test_p3_parsers_inference_and_reconciliation.py](tests/unit/test_p3_parsers_inference_and_reconciliation.py), [tests/integration/test_p3_prose_to_server_vertical_slice.py](tests/integration/test_p3_prose_to_server_vertical_slice.py), `26 passed` in `pytest`, `ruff check .` passed |
| P4 Local product (`T19`–`T21`) | **COMPLETED** | [apps/api/server.py](apps/api/server.py), [apps/api/client.py](apps/api/client.py), [apps/web/index.html](apps/web/index.html), [apps/web/app.js](apps/web/app.js), [apps/web/styles.css](apps/web/styles.css), [tests/unit/test_p4_local_api_security_and_session.py](tests/unit/test_p4_local_api_security_and_session.py), [tests/integration/test_p4_review_plan_export_workflow.py](tests/integration/test_p4_review_plan_export_workflow.py), `29 passed` in `pytest`, `ruff check .` passed |
| P5 Resilience/security (`T22`–`T26`) | **COMPLETED** | [packages/runtime/engine.py](packages/runtime/engine.py), [packages/core/approval.py](packages/core/approval.py), [workers/validation_worker.py](workers/validation_worker.py), [packages/templates/offline_bundle.py](packages/templates/offline_bundle.py), [tests/unit/test_p5_fault_injection_and_approvals.py](tests/unit/test_p5_fault_injection_and_approvals.py), [tests/security/test_p5_security_suite.py](tests/security/test_p5_security_suite.py), [tests/offline/test_p5_offline_install_bundle.py](tests/offline/test_p5_offline_install_bundle.py), `35 passed` in `pytest`, `ruff check .` passed |
| P6 Evaluation (`T27`–`T29`) | **COMPLETED** | [packages/core/evaluation.py](packages/core/evaluation.py), [packages/core/planning.py](packages/core/planning.py), [apps/api/server.py](apps/api/server.py), [apps/api/client.py](apps/api/client.py), [tests/unit/test_p6_corpus_tool_packs_and_evaluation.py](tests/unit/test_p6_corpus_tool_packs_and_evaluation.py), `38 passed` in `pytest`, `ruff check .` passed |
| P7 Evolution (`T30`–`T31`) | **COMPLETED** | [packages/core/evolution.py](packages/core/evolution.py), [packages/core/planning.py](packages/core/planning.py), [packages/core/storage.py](packages/core/storage.py), [apps/api/server.py](apps/api/server.py), [apps/api/client.py](apps/api/client.py), [tests/unit/test_p7_evolution_diff_and_regeneration.py](tests/unit/test_p7_evolution_diff_and_regeneration.py), `41 passed` in `pytest`, `ruff check .` passed |
| P8 Release evidence (`T32`) | **COMPLETED** | [packages/core/release_evidence.py](packages/core/release_evidence.py), [docs/release_evidence/RELEASE_EVIDENCE_REPORT.md](docs/release_evidence/RELEASE_EVIDENCE_REPORT.md), [tests/integration/test_p8_flagship_release_rehearsal.py](tests/integration/test_p8_flagship_release_rehearsal.py), `43 passed` in `pytest`, `ruff check .` passed |

---

## Implementation sessions

### Session 1 — 2026-10-09 (Phase P0: `T01`, `T02`, `T03`)
- **Authorization scope:** Explicit owner instruction to proceed with **Spigot / DocForge MCP** implementation using both brandings.
- **Tickets completed:** `T01` (Host/runtime/model capability report), `T02` (Independent tiny Markdown/gold/mock fixture), `T03` (MCP SDK and isolation spike).
- **Commands executed and exit status:**
  1. `uv sync` and `uv export --format requirements-txt --output-file requirements.txt` → Exit `0`.
  2. `.venv\Scripts\python.exe scripts/p0_qualify_environment.py` → Exit `0`.
  3. `.venv\Scripts\pytest.exe -v` → Exit `0` (`9 passed in 4.82s`).
  4. `.venv\Scripts\ruff.exe check .` → Exit `0`.

### Session 2 — 2026-10-09 (Phase P1: `T04`, `T05`, `T06`, `T07`, `T08`)
- **Authorization scope:** Owner instruction (`"ok proceed with then next step"`) to implement Phase P1.
- **Tickets completed:** `T04`, `T05`, `T06`, `T07`, `T08`.
- **Changed / added files:**
  - `packages/core/support_registry.py`, `packages/core/contracts.py`, `packages/core/storage.py`, `packages/core/jobs.py`, `packages/core/openapi_normalizer.py`, `packages/core/readiness.py`
  - `fixtures/p1_openapi_inventory/*`, `tests/unit/test_p1_contracts_storage_jobs.py`, `tests/contract/test_p1_openapi_and_readiness.py`
- **Commands executed and exit status:**
  1. `.venv\Scripts\ruff.exe check .` → Exit `0`.
  2. `.venv\Scripts\pytest.exe -v` → Exit `0` (`15 passed`).

### Session 3 — 2026-10-09 (Phase P2: `T09`, `T10`, `T11`, `T12`)
- **Authorization scope:** Owner instruction (`"lets proceed to the next step"`) to implement Phase P2.
- **Tickets completed:** `T09`, `T10`, `T11`, `T12`.
- **Changed / added files:**
  - `packages/core/planning.py`, `packages/runtime/engine.py`, `packages/templates/__init__.py`, `packages/templates/generator.py`
  - `tests/unit/test_p2_generator_and_templates.py`, `tests/integration/test_p2_generated_runtime_and_export.py`
- **Commands executed and exit status:**
  1. `.\.venv\Scripts\ruff.exe check . ; if ($LASTEXITCODE -eq 0) { .\.venv\Scripts\pytest.exe -v }` → Exit `0` (`21 passed in 8.20s`).

### Session 4 — 2026-10-09 (Phase P3: `T13`, `T14`, `T15`, `T16`, `T17`, `T18`)
- **Authorization scope:** Owner instruction (`"proceed to phase 3"`) to implement Phase P3.
- **Tickets completed:** `T13`, `T14`, `T15`, `T16`, `T17`, `T18`.
- **Changed / added files:**
  - `packages/core/parsers/__init__.py`, `packages/core/parsers/markdown_parser.py`, `packages/core/parsers/html_pdf_parser.py`
  - `packages/core/local_inference.py`, `packages/core/extraction.py`, `packages/core/reconciliation.py`, `packages/core/pipeline.py`
  - `tests/unit/test_p3_parsers_inference_and_reconciliation.py`, `tests/integration/test_p3_prose_to_server_vertical_slice.py`
- **Commands executed and exit status:**
  1. `.\.venv\Scripts\ruff.exe check . ; if ($LASTEXITCODE -eq 0) { .\.venv\Scripts\pytest.exe -v }` → Exit `0` (`26 passed in 16.39s`).

### Session 5 — 2026-10-09 (Phase P4: `T19`, `T20`, `T21`)
- **Authorization scope:** Owner instruction (`"proceed"`) to implement Phase P4.
- **Tickets completed:** `T19`, `T20`, `T21`.
- **Changed / added files:**
  - `packages/core/storage.py`, `apps/api/__init__.py`, `apps/api/server.py`, `apps/api/client.py`, `apps/web/index.html`, `apps/web/styles.css`, `apps/web/app.js`
  - `tests/unit/test_p4_local_api_security_and_session.py`, `tests/integration/test_p4_review_plan_export_workflow.py`
- **Commands executed and exit status:**
  1. `.\.venv\Scripts\ruff.exe check . ; if ($LASTEXITCODE -eq 0) { .\.venv\Scripts\pytest.exe -v }` → Exit `0` (`All checks passed!`, `29 passed`).

### Session 6 — 2026-10-09 (Phase P5: `T22`, `T23`, `T24`, `T25`, `T26`)
- **Authorization scope:** Owner instruction (`"now proceed to phase 5"`) to implement Phase P5.
- **Tickets completed:** `T22`, `T23`, `T24`, `T25`, `T26`.
- **Changed / added files:**
  - `packages/runtime/engine.py`
  - `packages/core/approval.py`
  - `packages/core/parsers/__init__.py`
  - `apps/api/server.py`, `apps/api/client.py`
  - `workers/__init__.py`, `workers/validation_worker.py`
  - `packages/templates/offline_bundle.py`
  - `tests/unit/test_p5_fault_injection_and_approvals.py`
  - `tests/security/test_p5_security_suite.py`
  - `tests/offline/test_p5_offline_install_bundle.py`
  - `tests/integration/test_p2_generated_runtime_and_export.py`
  - `BACKLOG.md`, `PROGRESS.md`
- **Commands executed and exit status:**
  1. `.\.venv\Scripts\pytest.exe tests/security/test_p5_security_suite.py -v` → Exit `0` (`3 passed in 8.78s`).
  2. `.\.venv\Scripts\ruff.exe check . ; if ($LASTEXITCODE -eq 0) { .\.venv\Scripts\pytest.exe -v }` → Exit `0` (`All checks passed!`, `35 passed in 35.97s`).
- **Findings & gate results:**
  - `T22`: `ContractRuntimeEngine` recovers safe `read` operations across transient `503` responses, enforces `Retry-After` against remaining `request_deadline_sec` budget (failing fast on attempt 1 when `Retry-After` exceeds deadline), refuses to replay non-idempotent mutating operations on transport errors (`OUTCOME_UNKNOWN`, `retryable=False`, `attempts=1`), allows retries on explicitly configured `idempotent_write_operations` preserving an identical `Idempotency-Key`, trips and resets a secret-safe circuit breaker keyed by `(server_ref, credential_fingerprint)`, and bounds pagination (`call_tool_paginated_async`) by `max_pages`, `max_items`, `max_bytes`, and `request_deadline_sec`.
  - `T23`: `ApprovalAuthority` (`packages/core/approval.py`), CLI (`python -m packages.core.approval`), and owner API routes (`POST /api/projects/{id}/approvals/prepare` & `/issue`) issue argument-bound, expiring, single-use tokens (`SPIGOT_ACTION_APPROVAL_TOKEN`) verified against a persistent SQLite consumed-nonce ledger (`ConsumedApprovalLedger` / `SPIGOT_APPROVAL_LEDGER_PATH`). The MCP tool surface exposes no approval-issuing tool, and extra `approved=True` arguments are rejected by `additionalProperties: false` schema validation.
  - `T24`: `IsolatedValidationWorker` (`workers/validation_worker.py`) validates manifest/ZIP SHA-256 integrity, AST safety (`AstSafetyVisitor`), secret canary absence, runtime schema/policy probes, and a bounded scrubbed-environment subprocess probe while failing closed (`can_claim_isolated_execution() == False`, `sandbox_status == "unavailable"`) when Docker/Podman container isolation is absent.
  - `T25`: `tests/security/test_p5_security_suite.py` verifies SSRF/redirect/link-local/private-IP/DNS-rebinding denial, prompt-injection neutralization (inline shell injection and conflicting method/path injection), HTML `<script>`/`<iframe>`/`javascript:` stripping, oversized input rejection (`DocumentParseLimitError`), path traversal rejection, and zero secret canary (`SECRET_CANARY_987654321_DO_NOT_LEAK`) leakage across prompts, artifacts, `.env.example`, ZIP exports, and validation reports.
  - `T26`: `prepare_offline_bundle` (`packages/templates/offline_bundle.py`) produces a deterministic offline bundle (`spigot_offline_win64.zip`) with `OFFLINE_BUNDLE_MANIFEST.json`, `LICENSE_NOTICES.txt`, `requirements-offline.lock`, and `install_offline.py`; `verify_clean_offline_install` verifies tamper detection and executes an exported MCP server over real MCP stdio in an isolated directory with `PIP_NO_INDEX=1`.
- **Known limitations:** Container-based sandbox execution remains truthfully reported as `unavailable` on this Windows host because Docker/Podman is not installed (automatic container execution via `build_container_sandbox_command` activates when Docker/Podman is present).
- **Next dependency:** `T27` (Phase P6 — Corpus and frozen held-out task sets).

### Session 7 — 2026-10-09 (Phase P6: `T27`, `T28`, `T29`)
- **Authorization scope:** Owner instruction (`"proceed with next phase"`) to implement Phase P6.
- **Tickets completed:** `T27`, `T28`, `T29`.
- **Changed / added files:**
  - `packages/core/evaluation.py`
  - `packages/core/planning.py`
  - `packages/core/extraction.py`
  - `apps/api/server.py`, `apps/api/client.py`
  - `workers/validation_worker.py`
  - `tests/unit/test_p6_corpus_tool_packs_and_evaluation.py`
  - `BACKLOG.md`, `PROGRESS.md`
- **Commands executed and exit status:**
  1. `.\.venv\Scripts\ruff.exe check . ; if ($LASTEXITCODE -eq 0) { .\.venv\Scripts\pytest.exe tests/unit/test_p6_corpus_tool_packs_and_evaluation.py -v }` → Exit `0` (`All checks passed!`, `3 passed in 16.21s`).
  2. `.\.venv\Scripts\pytest.exe -v` → Exit `0` (`38 passed in 56.89s`).
- **Findings & gate results:**
  - `T27`: `build_frozen_corpus_variants`, `build_frozen_agent_tasks`, and `build_corpus_manifest` (`packages/core/evaluation.py`) define 12 development variants across 3 API families (`support_tickets`, `inventory`, `orders`) and 8 held-out variants including an unseen 4th API family (`appointments` — Clinic Scheduling API) across Markdown, saved HTML, multi-page text PDF, split authentication documents, conflicting definitions, omitted method/auth abstentions, and prompt-injection resistance, with deterministic SHA-256 manifest hashing.
  - `T28`: `infer_operation_dependencies`, `resolve_tool_pack_dependencies`, `suggest_tool_pack`, `rewrite_operation_description`, and `DependencyViolationError` (`packages/core/planning.py`) infer prerequisite `GET` collection lookups for `{resource_id}` path/body parameters, automatically include prerequisite lookup operations when `preserve_dependencies=True`, and raise `400 DEPENDENCY_VIOLATION` when `enforce_dependencies=True` and a caller attempts to omit a required prerequisite tool. Exposed via `POST /api/projects/{id}/tool-packs/suggest` and `POST /api/projects/{id}/tool-plans` (`apps/api/server.py`, `apps/api/client.py`).
  - `T29`: `evaluate_extraction_corpus`, `evaluate_agent_conditions`, `render_evaluation_summary_from_raw_rows`, and `export_evaluation_artifacts` (`packages/core/evaluation.py`) compute extraction metrics (`endpoint_precision`, `endpoint_recall`, `critical_field_accuracy` with per-field breakdown, `unsupported_assertion_rate`, `evidence_validity_rate`, `correct_abstention_rate`, `review_burden_blockers_per_doc`) and run paired agent evaluation across Condition A (`A_all_tools_original`), Condition B (`B_manual_subset_original`), and Condition C (`C_spigot_tool_pack_rewritten`) against `DisposableEvalOracle`. Refusal tasks (`permission_refusal`) are scored separately (`refusal_task_accuracy` vs. `normal_task_success`), tasks made impossible by naive pruning in Condition B are counted as failures (`pruned_impossible_failures`), and summary metrics are reproducible strictly from exported raw JSON/CSV rows.
- **Known limitations:** None within Phase P6 scope.
- **Next dependency:** `T30` (Phase P7 — Semantic diff and affected tools).

### Session 8 — 2026-10-09 (Phase P7: `T30`, `T31`)
- **Authorization scope:** Owner instruction (`"proceed to the next phasee"`) to implement Phase P7.
- **Tickets completed:** `T30`, `T31`.
- **Changed / added files:**
  - `packages/core/evolution.py`
  - `packages/core/planning.py`
  - `packages/core/storage.py`
  - `apps/api/server.py`, `apps/api/client.py`
  - `tests/unit/test_p7_evolution_diff_and_regeneration.py`
  - `BACKLOG.md`, `PROGRESS.md`
- **Commands executed and exit status:**
  1. `.\.venv\Scripts\ruff.exe check . ; if ($LASTEXITCODE -eq 0) { .\.venv\Scripts\pytest.exe tests/unit/test_p7_evolution_diff_and_regeneration.py -v }` → Exit `0` (`All checks passed!`, `3 passed in 1.66s`).
  2. `.\.venv\Scripts\pytest.exe -v` → Exit `0` (`41 passed in 66.89s`).
- **Findings & gate results:**
  - `T30`: `compare_contracts` (`packages/core/evolution.py`) computes normalized semantic diffs between contract revisions (`ContractDiffReport`, `ContractChangeItem`), classifying breaking changes (`operation_removed`, `required_parameter_added`, `parameter_removed`, `parameter_modified`, `request_body_modified`, `auth_changed`, `server_changed`, `semantic_effect_changed`, `support_status_changed`), ambiguous endpoint renames (`operation_renamed_ambiguous`, `severity="review_required"`), non-breaking additions (`operation_added`, `optional_parameter_added`, `response_added`), and formatting/description-only edits (`format_or_description_only`, `semantically_identical=True` via `_strip_schema_descriptions`), and resolves affected tools including transitive prerequisite dependencies (`_resolve_affected_tools`).
  - `T31`: `reconcile_and_regenerate` and `verify_reproducible_regeneration` (`packages/core/evolution.py`) carry forward valid `UserOverride` records when the un-overridden extracted value matches `old_value_hash`, emit a `STALE_OVERRIDE` blocker finding (`review_status="blocked_by_findings"`) when the underlying documentation changed at an overridden path, preserve frozen tool names across description/heading changes (`preserved_tool_names` in `create_tool_plan`), invalidate stale policies and action approvals when contract hashes change (`ApprovalAuthority.verify_and_consume`), preserve `previous_good_artifact`, and produce byte-for-byte identical files and `MANIFEST.json` hashes across repeated regenerations from frozen inputs. Exposed via `POST /api/projects/{id}/compare`, `POST /api/projects/{id}/regenerate`, and `POST /api/projects/{id}/evaluate` (`apps/api/server.py`, `apps/api/client.py`).
- **Known limitations:** None within Phase P7 scope.
- **Next dependency:** `T32` (Phase P8 — Final release/portfolio evidence).

### Session 9 — 2026-10-09 (Phase P8: `T32`)
- **Authorization scope:** Owner instruction (`"proceed phase 8"`) to implement Phase P8 (`T32`).
- **Tickets completed:** `T32`.
- **Changed / added files:**
  - `packages/core/release_evidence.py`
  - `tests/integration/test_p8_flagship_release_rehearsal.py`
  - `docs/release_evidence/RELEASE_EVIDENCE_REPORT.md`, `docs/release_evidence/requirements_traceability.json`, `docs/release_evidence/flagship_demo_rehearsal.json`, `docs/release_evidence/corpus_manifest.json`, `docs/release_evidence/extraction_evaluation.json`, `docs/release_evidence/agent_evaluation_run.json`, `docs/release_evidence/agent_evaluation_raw_rows.csv`
  - `README.md`, `BACKLOG.md`, `PROGRESS.md`
- **Commands executed and exit status:**
  1. `.\.venv\Scripts\ruff.exe check . ; if ($LASTEXITCODE -eq 0) { .\.venv\Scripts\pytest.exe tests/integration/test_p8_flagship_release_rehearsal.py -v }` → Exit `0` (`All checks passed!`, `2 passed in 14.48s`).
  2. `.\.venv\Scripts\python.exe -m packages.core.release_evidence release-verify` → Exit `0` (wrote 7 release evidence artifacts in `docs/release_evidence/`).
  3. `.\.venv\Scripts\ruff.exe check . ; if ($LASTEXITCODE -eq 0) { .\.venv\Scripts\pytest.exe -v }` → Exit `0` (`All checks passed!`, `43 passed in 72.12s`).
- **Findings & gate results:**
  - `T32`: `build_requirements_traceability_matrix` (`packages/core/release_evidence.py`) maps all 17 functional requirements (`FR-01`–`FR-17`) to verified implementation modules and test files. `run_flagship_demo_rehearsal` executes all 9 steps of `PORTFOLIO_DEMO.md` under `NetworkPolicyGuard(profile=NetworkProfile.STRICT_OFFLINE)` and verifies negative failure states (`external_egress_denied`, `missing_local_model_fails_closed`, `missing_container_sandbox_fails_closed`, `disabled_operation_rejected_at_runtime`). `generate_release_evidence_bundle` exports raw evaluation JSON/CSV artifacts and renders `docs/release_evidence/RELEASE_EVIDENCE_REPORT.md` with measured resume bullets derived strictly from raw denominators (`13/13` held-out endpoint precision & recall, `65/65` held-out critical-field accuracy, `2/2` held-out correct abstentions, `4/6` → `6/6` multi-step task completion with `65.56%` tool-schema context reduction).
- **Known limitations:** Container-based sandbox execution (`sandbox_status`) is truthfully reported as `unavailable` on this Windows 11 host because Docker/Podman is not installed; deferred extensions (`X01`–`X07`) remain out of scope for the flagship release.
- **Next dependency:** None (all flagship tickets `T01`–`T32` complete).


# Implementation roadmap and gates

This is a future build plan. Nothing below is an implemented command or completed milestone. Use gates rather than a fixed five-week promise. A planning estimate is 10–14 part-time weeks for a strong reference-platform release, with substantial uncertainty from hardware, document quality, and sandbox setup. Re-estimate after the first end-to-end extraction spike.

## Dependency order
P0 → P1 → P2 → P3 → P4 → P5 → P6 → P7 → P8. Security and offline tests begin early and grow throughout. UI sketches may be prepared early, but a polished dashboard cannot count as a completed extraction milestone.

## P0 — feasibility and frozen decisions
Tasks: inventory local hardware; qualify one local model/runtime; choose Python/Node versions; select exact compatible SDK and parser versions; verify a local sandbox; write dependency locks and model manifest. Author a tiny Markdown manual and independent expected API contract before extraction code.

Deliverables: environment report, decision updates, lockfiles, one synthetic fixture, small model extraction result, documented isolation profile. No cloud AI dependencies.

Gate: local model produces schema-valid candidate fields for the fixture; a model-invalid output is handled; external network denial works; SDK can initialize a hand-written fixture server. If no model fits, report the automation limitation and obtain a scope/hardware decision—do not silently switch to a cloud provider.

## P1 — contracts, storage, structured baseline
Tasks: strict schemas, source/evidence objects, SQLite migrations, content-addressed artifacts, job lifecycle, support registry. Normalize a limited OpenAPI fixture. Implement semantic readiness checks and conflict/unsupported findings.

Gate: known fixture round-trips without changing semantics; unknown auth is blocked; duplicate parameter names retain locations; reference cycles terminate; stale review edits return revision conflict. A structured-only path is foundation, not final delivery.

## P2 — deterministic generator and runtime vertical slice
Tasks: safe templates, runtime transport, input validation, authentication placeholders, request serialization, read-only policies, redacted errors, manifest and ZIP. Hand-author a mock contract oracle independently from generator fixtures. Keep code generation free of model calls.

Gate: initialize/list/invoke through an MCP client; emitted HTTP method/path/query/body match oracle; disabled operation rejected directly; malicious description cannot inject code; exported server runs without DocForge or inference runtime.

## P3 — ordinary documentation end to end
Tasks: Markdown/text parsers, block evidence, endpoint inventory, local retrieval, structured local extraction, bounded repair, evidence and semantic checks, ambiguity UI/API. Add text PDF and saved HTML adapters before leaving this phase.

Gate: each required unstructured format reaches a generated server and mock call; PDF citations identify correct pages; contradictory docs and missing auth block affected operations; image-only PDFs report OCR_REQUIRED; absent model is honest; offline run passes. Do not postpone this phase behind optional auth or dashboard features.

## P4 — reviewable local product
Tasks: React wizard, source viewer, field evidence, findings queue, tool plan, policy controls, job progress/cancellation, report and export. API contracts in API_UI_SPEC.md drive types and UI state. Add useful empty/error states and keyboard access.

Gate: an owner imports a multi-file document bundle, resolves one blocker, selects tools, generates, validates and exports without editing source code. Changing a source revision invalidates affected derived state. Refreshing a page preserves job state.

## P5 — reliability, isolation and policy depth
Tasks: safe retries, deadlines, rate limits, bounded pagination, circuit breaker, approval utility, deterministic fault-injecting mocks, isolated execution, local API hardening, secret-canary tests, crash recovery. Qualify offline installation bundles for one reference OS.

Gate: retryable read recovers; ambiguous write outcome is not replayed; action approvals cannot be forged/reused/changed; cancellation leaves no runaway child; sandbox cannot read host secrets or contact internet; capability checks fail closed when isolation unavailable.

## P6 — evaluation and tool packs
Tasks: independent synthetic corpus, held-out splits, local agent runner, task-based tool packs, dependency preservation, three comparison conditions, raw results and dashboard. Include extraction quality independently from agent task quality.

Gate: repeatable results include failed/skipped tasks; no test-set tuning; report hardware/model hashes; held-out critical-field accuracy and abstentions visible; unsupported input failures not hidden from end-to-end coverage. Improvements are optional findings, not guaranteed gates; truthful evidence is mandatory.

## P7 — API evolution and reproducibility
Tasks: normalized contract diff, affected-tool mapping, stale override handling, compatible regeneration, fixture replay, artifact hash checks. Include document edits that change semantics and formatting-only edits that do not.

Gate: new required parameter or removed path flags impacted tools; format-only changes avoid false breakage; ambiguous rename asks review; approved actions invalidated by policy/contract changes; frozen generation reproduces code hashes.

## P8 — flagship release evidence
Tasks: fresh-machine rehearsal with prepared dependencies, offline demonstration, optional authorized live read check, license/dependency inventory, runbook, benchmark report, demo video script and resume evidence.

Gate: requirements traceability complete; no placeholders in claimed features; all release tests pass on the named platform; honest limitations documented; instructions reproduce the demonstration. Publishing remains a separate owner decision.

## Proposed verification commands
The implementation agent should create a consistent task interface, for example the following targets. These are proposed names, not commands available in this planning archive:

| Target | Intended check |
|---|---|
| check | Formatting, static types, lint, schema validation |
| test-unit | Deterministic modules and semantic validators |
| test-contract | Serialization and supported-feature fixtures |
| test-integration | MCP client → generated runtime → isolated mock |
| test-security | Injection, secrets, policy, local API and sandbox tests |
| test-offline | External-egress-denied complete workflow |
| eval-extraction | Frozen document corpus and gold contracts |
| eval-agent | Paired local agent tasks and raw results |
| release-verify | Locks, licenses, bundle checksums, clean install and all release gates |

Prefer commands that work on the documented reference platform; provide Windows equivalents or a clearly documented local environment requirement. Do not invent successful command outputs in PROGRESS.md.

## Definition of done for each ticket
Behavior implemented; acceptance assertion exists; relevant negative case tested; user-visible limitations documented; no secrets/remote inference; interfaces consistent; progress entry records actual results. Tests that mirror a faulty extractor's assumptions are not sufficient.

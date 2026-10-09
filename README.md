# Spigot (DocForge MCP) — Local Documentation-to-MCP Compiler

**Status: Flagship Release Complete (`P0`–`P8`, Tickets `T01`–`T32` verified; see [PROGRESS.md](PROGRESS.md) and [docs/release_evidence/RELEASE_EVIDENCE_REPORT.md](docs/release_evidence/RELEASE_EVIDENCE_REPORT.md)).**

Version 1.0 • 9 October 2026 • Dual project branding: **Spigot** / **DocForge MCP**.

## Product promise
Give **Spigot (DocForge MCP)** API documentation and receive an inspectable MCP server package, a source-backed API contract, and an honest validation report. Ordinary documentation is a first-class input, not a future feature. The system uses local inference for unstructured documentation and deterministic generation for executable behavior.

The flagship demonstration is: import a local PDF or Markdown API manual, extract operations with evidence, resolve one ambiguous field, generate a server, invoke it against a local mock, demonstrate a blocked unsafe action, and identify an integration-breaking change in a second version of the manual. Do all of this with external network access disabled.

## Quickstart & standardized verification commands

### 1. Environment & offline verification targets (`packages.core.release_evidence`)
After dependencies are installed in `.venv` (`Python 3.13.14`, `uv 0.12.11`), run any standardized target from [IMPLEMENTATION.md](IMPLEMENTATION.md):

```powershell
# Lint & static checks
.\.venv\Scripts\python.exe -m packages.core.release_evidence check

# Unit, contract, integration, security, and offline test suites
.\.venv\Scripts\python.exe -m packages.core.release_evidence test-unit
.\.venv\Scripts\python.exe -m packages.core.release_evidence test-contract
.\.venv\Scripts\python.exe -m packages.core.release_evidence test-integration
.\.venv\Scripts\python.exe -m packages.core.release_evidence test-security
.\.venv\Scripts\python.exe -m packages.core.release_evidence test-offline

# Extraction & paired agent evaluation benchmarks
.\.venv\Scripts\python.exe -m packages.core.release_evidence eval-extraction
.\.venv\Scripts\python.exe -m packages.core.release_evidence eval-agent

# Full 9-step flagship offline rehearsal & release evidence bundle generation
.\.venv\Scripts\python.exe -m packages.core.release_evidence release-verify
```

### 2. Run the full 43-test suite directly
```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pytest.exe -v
```

### 3. Launch the local single-owner review UI & API server
```powershell
.\.venv\Scripts\uvicorn.exe apps.api.server:create_local_app --factory --host 127.0.0.1 --port 8000
```

## Architecture & supported-feature summary
- **Multi-format local ingestion (`FR-01`–`FR-04`):** OpenAPI 3.0 JSON/YAML normalizer ([packages/core/openapi_normalizer.py](packages/core/openapi_normalizer.py)), line-accurate Markdown/text parser ([packages/core/parsers/markdown_parser.py](packages/core/parsers/markdown_parser.py)), sanitized saved HTML parser, and multi-page text PDF parser with page/bbox citations and scanned-page detection (`OCR_REQUIRED`, [packages/core/parsers/html_pdf_parser.py](packages/core/parsers/html_pdf_parser.py)).
- **Evidence-grounded extraction & reconciliation (`FR-05`–`FR-06`):** Local loopback-only `OllamaInferenceAdapter` ([packages/core/local_inference.py](packages/core/local_inference.py)), 6-stage candidate extraction with verbatim quote verification ([packages/core/extraction.py](packages/core/extraction.py)), multi-document bundle reconciliation, conflict/ambiguity blocking (`MISSING_METHOD`, `CONFLICTING_METHOD_PATH`, `AMBIGUOUS_AUTH`, `UNKNOWN_AUTH`), and precondition-checked `UserOverride` records ([packages/core/reconciliation.py](packages/core/reconciliation.py)).
- **Dependency-preserving tool packs & deterministic codegen (`FR-07`–`FR-08`, `FR-13`):** Automatic `{id}` prerequisite lookup inference (`suggest_tool_pack`, `resolve_tool_pack_dependencies`, [packages/core/planning.py](packages/core/planning.py)), AST-validated code generation (`ast.parse`), and byte-for-byte reproducible `.zip` exports ([packages/templates/generator.py](packages/templates/generator.py)).
- **Resilient, policy-enforcing MCP stdio runtime (`FR-09`–`FR-10`, `FR-15`):** Standalone `ContractRuntimeEngine` ([packages/runtime/engine.py](packages/runtime/engine.py)) enforcing `read_only`, `restricted_write`, and `approval_required` policies, HMAC-SHA256 argument-bound single-use action approvals backed by a persistent SQLite consumed-nonce ledger ([packages/core/approval.py](packages/core/approval.py)), safe read retries, `OUTCOME_UNKNOWN` non-replay on ambiguous write failures, secret-safe circuit breakers, and automatic credential redaction.
- **Separated validation layers & semantic evolution (`FR-11`–`FR-12`, `FR-14`):** `IsolatedValidationWorker` ([workers/validation_worker.py](workers/validation_worker.py)) reporting distinct `build_status`, `static_check_status`, `protocol_check_status`, `mock_test_status`, `security_suite_status`, `sandbox_status`, and `live_smoke_status`; semantic contract diffing and safe regeneration ([packages/core/evolution.py](packages/core/evolution.py)).

## Measured benchmark & evaluation summary (`T32`)
All metrics below are computed strictly from raw evaluation rows in [docs/release_evidence/RELEASE_EVIDENCE_REPORT.md](docs/release_evidence/RELEASE_EVIDENCE_REPORT.md), [docs/release_evidence/extraction_evaluation.json](docs/release_evidence/extraction_evaluation.json), and [docs/release_evidence/agent_evaluation_raw_rows.csv](docs/release_evidence/agent_evaluation_raw_rows.csv) on `Windows 11 (AMD64)`, `Python 3.13.14`:

- **Held-out extraction (`8` variants, including unseen `appointments` Clinic Scheduling API family):**
  - Endpoint Precision: `13/13` (`100.0%`)
  - Endpoint Recall: `13/13` (`100.0%`)
  - Critical-Field Exact Accuracy: `65/65` (`100.0%` across `method`, `relative_path`, `auth_status`, `parameters`, `request_body`)
  - Unsupported Assertion Rate: `0/26` (`0.0%`)
  - Evidence Validity Rate: `30/30` (`100.0%`)
  - Correct Abstention Rate: `2/2` (`100.0%`)
- **Full corpus extraction (`20` variants across `dev` + `held_out`):**
  - Endpoint Precision & Recall: `31/31` (`100.0%`), Critical-Field Exact Accuracy: `155/155` (`100.0%`), Correct Abstention Rate: `5/5` (`100.0%`).
- **Paired held-out agent evaluation (`6` executable tasks + `1` policy-refusal task):**
  - `Condition A (All tools, original prose)`: `6/6` (`100.0%`) normal task success, `1/1` (`100.0%`) refusal accuracy, avg `4.14` advertised tools (`1835.0` context chars).
  - `Condition B (Naive manual subset, original prose)`: `4/6` (`66.7%`) normal task success (`2` multi-step tasks failed due to pruned prerequisite `{id}` lookup tools), `1/1` (`100.0%`) refusal accuracy.
  - `Condition C (Spigot dependency-preserving tool pack, rewritten descriptions)`: `6/6` (`100.0%`) normal task success, `1/1` (`100.0%`) refusal accuracy, avg `1.71` advertised tools (`631.9` context chars — **`65.56%` tool-schema context reduction** vs. `Condition A`).

## Security boundaries & honest limitations
- **Strict offline guarantee:** `NetworkPolicyGuard(profile=NetworkProfile.STRICT_OFFLINE)` blocks all non-loopback socket connections. Cloud model IDs are rejected by policy (`LocalModelPolicyError`).
- **Untrusted documentation & model output:** Document text and model outputs are never interpolated into executable Python syntax or shell commands. Embedded cURL examples are never executed.
- **Container sandbox honesty:** `IsolatedValidationWorker` automatically uses hardened rootless Docker/Podman (`--network none --read-only --cap-drop ALL`) when available on the host, and fails closed (`sandbox_status="unavailable"`, `can_claim_isolated_execution=False`) when container runtime tooling is absent.
- **Explicit non-goals & deferred extensions:** Scanned image-only PDFs fail closed with `OCR_REQUIRED` (no silent cloud OCR). OAuth interactive flows, GraphQL, SOAP, gRPC, WebSockets, and non-JSON multipart streaming are explicitly marked unsupported (`COMPATIBILITY.md`).

## Binding user constraints
- Plan only at the time this archive is delivered. Reading this archive is not authorization to implement it.
- Once the owner explicitly requests implementation, follow [AGENTS.md](AGENTS.md) and [IMPLEMENTATION.md](IMPLEMENTATION.md).
- No required OpenAI, Anthropic, Gemini, or other cloud AI API credentials in the product. A coding assistant used to build the project is separate from the application's runtime dependencies.
- Core processing, local inference, generation, local testing, and reports work offline after prerequisites are installed.
- Slack, GitHub, and similar service credentials are permitted for optional connected integration tests and runtime calls. Those services require network access.
- Local processes on the laptop are allowed. No hosted backend, cloud database, Kubernetes cluster, or always-on remote system is required.
- No dataset hunting or model training. Build deterministic synthetic documentation and fixtures; optionally evaluate public documentation snapshots with licenses recorded.
- A model and dependencies must be acquired before disconnected use. Do not claim a fresh machine can run offline without them.

## Read order
1. [AGENTS.md](AGENTS.md): execution rules and handoff discipline.
2. [PRODUCT_REQUIREMENTS.md](PRODUCT_REQUIREMENTS.md): scope, acceptance criteria, and non-goals.
3. [ARCHITECTURE.md](ARCHITECTURE.md): components and trust boundaries.
4. [DATA_CONTRACTS.md](DATA_CONTRACTS.md): shared representation and lifecycle.
5. [IMPLEMENTATION.md](IMPLEMENTATION.md): sequenced build gates.
6. Read the specialist documents relevant to the current milestone.

## Document index
| File | Purpose |
|---|---|
| AGENTS.md | Rules for the implementation agent |
| IMPLEMENTATION.md | Milestones, dependencies, exit gates, verification commands |
| ARCHITECTURE.md | Local system, module boundaries, execution paths |
| PRODUCT_REQUIREMENTS.md | Traceable functional and quality requirements (`FR-01`–`FR-17`) |
| DOCUMENT_UNDERSTANDING.md | Parsing, extraction, provenance, conflict resolution |
| DATA_CONTRACTS.md | API contract, evidence, persistence, revisions |
| COMPATIBILITY.md | Explicit input, schema, authentication and transport boundaries |
| LOCAL_AI.md | Local model interface, prompts, hardware qualification |
| GENERATOR_RUNTIME.md | Server output, HTTP behavior, policies, packaging |
| SECURITY.md | Threat model, controls, approvals, security tests |
| API_UI_SPEC.md | Local API contracts and review experience |
| TESTING_EVALUATION.md | Independent oracles, benchmarks, release gates |
| OFFLINE_OPERATIONS.md | Installation, network profiles, backup, recovery |
| BACKLOG.md | Ordered implementation tickets and dependencies (`T01`–`T32`) |
| DECISIONS_RISKS.md | Architecture decisions and unresolved choices |
| PORTFOLIO_DEMO.md | Demonstration and evidence-based resume positioning |
| BUILD_AGENT_PROMPT.md | Paste-ready instructions for a coding agent |
| PROGRESS.md | Implementation handoff record (`P0`–`P8`) |
| SOURCES.md | Primary references and verification policy |
| docs/release_evidence/RELEASE_EVIDENCE_REPORT.md | Committed flagship rehearsal, traceability matrix, and raw metrics |

# Spigot (DocForge MCP) — Portfolio & FDE Reviewer Guide

This document provides a concise, reproducible walkthrough for Forward Deployed Engineer (FDE) interviewers and engineering reviewers evaluating **Spigot (DocForge MCP)**.

## 1. Fastest Way to Verify Everything (`~3 seconds`)

Run the self-contained FDE integration and operational failure demo from the repository root:

```bash
uv run python scripts/run_fde_demo.py
```

### What `scripts/run_fde_demo.py` Executes Live:
1. **Messy Customer Runbook Ingestion & Blocker Detection:** Imports [`examples/05_flagship_review_demo.md`](examples/05_flagship_review_demo.md) (**FleetCloud Kubernetes Orchestrator API**), catches `MISSING_METHOD` and `UNKNOWN_SEMANTIC_EFFECT` on `/v1/clusters/{cluster_id}/drain`, resolves them via an audited `UserOverride` with optimistic concurrency (`expected_revision`), freezes the immutable `ApiContract`, and runs the 7-layer validation gate.
2. **Standalone Extracted `.zip` Execution & Read-Only Enforcement:** Extracts the generated `.zip` into an isolated directory, verifies all 12 packaged files against `manifest.json` SHA-256 digests, invokes `get_v1_clusters` against a live local HTTP server (`HTTP 200`), and verifies `post_v1_clusters` is blocked in `read_only` mode (`POLICY_DENIED`).
3. **Two-Step Human Approval & Persistent SQLite Replay Guard:** Prepares the canonical `action_digest` (`/approvals/prepare`), verifies that `/approvals/issue` without `human_confirmed=True` is rejected with `HTTP 403 POLICY_DENIED`, issues a single-use HMAC-SHA256 token signed by the workspace's `approval_authority.key`, executes the `POST /v1/clusters` call once (`HTTP 201`), and proves that replaying the same token across a new engine instance is rejected by `consumed_approvals.sqlite3`.
4. **Operational Failure Handling & Recovery:**
   - **401 Unauthorized + Secret Scrubbing:** Upstream echoes back the rejected `Bearer` header; runtime scrubs the secret to `<REDACTED_CREDENTIAL>` in both the MCP error payload and `stderr` trace.
   - **503 Service Unavailable on Safe `GET`:** Honors `Retry-After` and recovers on attempt 3 (`HTTP 200`).
   - **Ambiguous Write Timeout on `POST`:** Refuses automatic retry (`attempts=1`, `retryable=False`, `outcome=OUTCOME_UNKNOWN`) to prevent duplicate side effects.
   - **Oversized Streaming Response:** Aborts `client.stream()` mid-flight as soon as received bytes exceed `max_response_bytes` (`4096` bytes).
   - **Per-Server Circuit Breaker:** Trips to `open` after consecutive 5xx failures and fails fast with cooldown reporting.
5. **Contract `v1 -> v2` Breaking Drift Detection:** Imports an updated `v2` specification that adds a required `cost_center` body field to `POST /v1/clusters`, detects `has_breaking_changes=True` (`request_body_modified`), and carries forward the still-valid human override on `/v1/clusters/{cluster_id}/drain`.

---

## 2. Interactive 6-Step Web Studio Walkthrough (`~2 minutes`)

Start the local FastAPI + Vanilla ES2022 Web Studio:

```bash
uv run uvicorn apps.api.server:create_local_app --factory --host 127.0.0.1 --port 8000
```

Open **`http://127.0.0.1:8000`**:
- **Option A — 1-Click Automated Walkthrough:** Click **`⚡ Run 1-Click Flagship Demo`** in the top bar. It automatically creates a project, uploads `v1` customer docs, resolves the blocker override, freezes the contract, generates and validates the MCP package, and runs the `v1 -> v2` evolution diff.
- **Option B — Step-by-Step Manual Inspection:**
  1. **Step 1 (`1. Project & Import`):** Click any of the 5 **1-Click Sample API Docs** buttons (e.g., `FleetCloud Demo (with Blocker)` or `StripeFlow Payments PDF`).
  2. **Step 2 (`2. Extract`):** Run deterministic extraction and inspect the extracted operations and verbatim evidence quotes.
  3. **Step 3 (`3. Review & Freeze`):** Filter by `Blocker`, inspect the exact source line/page quote, apply a 1-click override with a rationale, and freeze the contract.
  4. **Step 4 (`4. Tool Plan & Policy`):** Choose `read_only`, `restricted_write`, or `approval_required`, or generate a task-scoped Tool Pack.
  5. **Step 5 (`5. Validate & Export`):** Run the 7-layer validation gate, inspect the truthful `sandbox_status` badge (`unavailable` when Docker/Podman is not installed), use the two-step **Owner Action Approval Authority** card (`1. Prepare Action Digest` $\rightarrow$ confirm checkbox $\rightarrow$ `2. Issue Single-Use Token`), and download the verified `.zip` server.
  6. **Step 6 (`6. Diff & Evaluation`):** Compare contract revisions and run the held-out evaluation benchmark.

---

## 3. Measured Benchmark Results (No Extrapolated Claims)

All benchmark figures are computed deterministically by [`packages/core/evaluation.py`](packages/core/evaluation.py) and verified in [`tests/unit/test_p6_corpus_tool_packs_and_evaluation.py`](tests/unit/test_p6_corpus_tool_packs_and_evaluation.py):

### A. Extraction & Blocker Gate Corpus (`22` Frozen Fixtures: `12` Dev / `10` Held-Out)
- **Endpoint Precision:** `18 / 18` (`1.0000`) on held-out split (`22 / 22` on dev split)
- **Endpoint Recall:** `18 / 18` (`1.0000`) on held-out split (`22 / 22` on dev split)
- **Evidence Span Offset Validity:** `18 / 18` (`1.0000`) verbatim character-offset match
- **Silent Fabrication Rate on Incomplete/Conflicting Docs:** `0 / 10` (`0.0000`) — 100% of missing methods, unknown auth schemes, conflicting paths, and scanned PDFs are caught as explicit blocker findings.

### B. Paired Agent Task Evaluation (`16` Held-Out Tasks Across 4 Conditions)

| Condition | Task Completion | Policy & Safety Compliance | Valid Tool-Call Rate | Advertised Schema Tokens |
|---|---|---|---|---:|
| `raw_prose_baseline` (No MCP Server) | `4 / 16` (`25.0%`) | `14 / 16` (`87.5%`) | `4 / 16` (`25.0%`) | `0` |
| `naive_unreviewed_mcp` (Unfiltered Surface) | `11 / 16` (`68.8%`) | `13 / 16` (`81.2%`) | `11 / 16` (`68.8%`) | `1,001` |
| `docforge_reviewed_full_mcp` (Reviewed Contract + Policy) | `16 / 16` (`100.0%`) | `16 / 16` (`100.0%`) | `16 / 16` (`100.0%`) | `946` |
| **`docforge_reviewed_scoped_mcp` (Reviewed + Scoped ToolPlan)** | **`16 / 16` (`100.0%`)** | **`16 / 16` (`100.0%`)** | **`16 / 16` (`100.0%`)** | **`410` (`-59.0%`)** |

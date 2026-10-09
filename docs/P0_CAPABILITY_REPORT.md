# P0 Capability, Model Qualification, and Isolation Report (`T01` / `T02` / `T03`)

- **Project Brand:** Spigot / DocForge MCP
- **Phase:** P0 — Feasibility and Frozen Decisions
- **Date:** 2026-10-09
- **Machine-Readable Artifacts:**
  - [p0_environment_report.json](file:///e:/Anti%20Gravity%20%28Projects%29/Spigot/docs/p0_environment_report.json)
  - [p0_model_manifest.json](file:///e:/Anti%20Gravity%20%28Projects%29/Spigot/docs/p0_model_manifest.json)

---

## 1. Host & Runtime Inventory (`T01`)

| Component | Qualified Value | Notes |
|---|---|---|
| **Operating System** | Microsoft Windows 11 Home Single Language (64-bit, Build 26200) | Reference development & qualification platform (`AMD64`) |
| **Processor** | 13th Gen Intel Core i5-13500H | 12 physical cores, 16 logical threads |
| **Memory (RAM)** | 15.70 GiB total (~5.8 GiB free at baseline) | Constrains concurrent local LLM loading to 1 active inference worker |
| **Graphics (GPU)** | Intel Iris Xe Graphics (1.0 GiB shared AdapterRAM) | Integrated GPU; CPU/iGPU GGUF inference via Ollama |
| **Python** | `3.13.14` (`MSC v.1944 64 bit (AMD64)`) | Managed via `.venv` and `uv` |
| **Package / Lock Manager** | `uv 0.12.11` | `pyproject.toml`, `uv.lock`, and hash-pinned `requirements.txt` |
| **Node.js / npm** | `v22.17.0` / `11.4.2` | Available for P4 local frontend build |
| **Local AI Runtime** | Ollama `0.34.0` (`ollama serve` on `127.0.0.1:11434`) | Enforced with `OLLAMA_NO_CLOUD=1` and `OLLAMA_HOST=127.0.0.1:11434` |

### Locked Python Dependencies (`pyproject.toml` / `uv.lock`)

| Package | Locked Version | Role |
|---|---|---|
| `mcp` | `2.3.0` | Official Model Context Protocol Python SDK (`Server`, `ClientSession`, `stdio_server`, `stdio_client`) |
| `pydantic` | `2.14.0` | Strict schema validation (`extra="forbid"`) |
| `httpx` | `0.28.1` | HTTP transport (`trust_env=False` to ignore ambient proxies) |
| `fastapi` | `0.143.0` | Local loopback API coordinator |
| `uvicorn` | `0.54.0` | Local loopback ASGI server |
| `python-multipart` | `0.0.32` | Local file upload handling |
| `PyYAML` | `6.0.3` | Safe YAML parsing (`yaml.safe_load`) for OpenAPI 3.0 |
| `beautifulsoup4` | `4.15.0` | Static saved HTML parsing |
| `pypdf` | `6.19.0` | Text-based PDF page extraction |
| `jsonschema` | `4.26.0` | Runtime argument and contract schema validation |
| `pytest` / `pytest-asyncio` | `9.1.1` / `1.4.0` | Unit, contract, integration, security, and offline test runner |
| `ruff` | `0.16.10` | Static linter and formatter |

---

## 2. Comparative Local Model Qualification Spike (`T01`)

Per [LOCAL_AI.md](file:///e:/Anti%20Gravity%20%28Projects%29/Spigot/LOCAL_AI.md), two locally installed instruction-tuned models were evaluated against the independently authored P0 Support Tickets fixture ([support_api_v1.md](file:///e:/Anti%20Gravity%20%28Projects%29/Spigot/fixtures/p0_support_tickets/support_api_v1.md) and [gold_contract.json](file:///e:/Anti%20Gravity%20%28Projects%29/Spigot/fixtures/p0_support_tickets/gold_contract.json)):

| Metric / Property | `qwen2.5:1.5b` (Selected Primary) | `qwen2.5:0.5b` (Baseline Small) |
|---|---|---|
| **Artifact Digest** | `65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b` | `a8b0c51577010a279d933d14c2a8ab4b268079d44c5c8830c0a93900f1827c67` |
| **Weight Size / Quantization** | 986 MB (`Q4_K_M`, GGUF) | 398 MB (`Q4_K_M`, GGUF) |
| **License** | Apache-2.0 | Apache-2.0 |
| **Supported Endpoint Precision** | `2/2` (100%) | `2/2` (100% with Stage 5 anchor verification) |
| **Supported Endpoint Recall** | `2/2` (100%) | `2/2` (100% with Stage 5 anchor verification) |
| **Critical-Field Accuracy** | `8/8` (100%) | `8/8` (100% with Stage 5 anchor verification) |
| **Abstention Accuracy (Blocked Ops)** | `2/2` (`CONFLICTING_METHOD_PATH`, `MISSING_METHOD` + `AMBIGUOUS_AUTH`) | `2/2` |
| **Evidence Quote Validity** | `100%` (all quotes verified verbatim in source) | `100%` (after Stage 5 quote verification) |

### Key Finding from the P0 Model Spike
During initial unconstrained testing, small models (`1.5B` and `0.5B`) occasionally inferred `"GET"` when a prose section omitted the HTTP method (`Export Legacy Archive`), or returned `"Bearer"` instead of the backtick-quoted scheme identifier `` `service_bearer` ``. Adding deterministic Stage 5 evidence verification (checking that any model-claimed HTTP method actually appears in the section text and verifying scheme identifiers against source spans) eliminated these unsupported inferences and raised abstention accuracy to `2/2` (`8/8` critical fields).

---

## 3. MCP SDK & Isolation Profile Qualification (`T03`)

1. **MCP SDK Interoperability (`mcp==2.3.0`):**
   - Verified `mcp.server.Server` (`on_list_tools`, `on_call_tool`) with `stdio_server()` and `mcp.client.stdio.stdio_client` + `ClientSession`.
   - Verified strict `stdout` (JSON-RPC protocol messages only) vs `stderr` (structured JSON logs) separation.
   - Verified runtime policy enforcement: `support_get_ticket` succeeds against the independent loopback mock oracle; `support_create_ticket` is rejected (`POLICY_DENIED`) when `SPIGOT_ALLOW_WRITES=false` even when called directly by name; `support_close_ticket` is rejected (`POLICY_DENIED: CONFLICTING_METHOD_PATH`) when called directly by name.
2. **External Network Egress Denial (`STRICT_OFFLINE`):**
   - Verified `NetworkPolicyGuard` at both the URL validation layer and Python `socket.socket.connect` / `socket.create_connection` layer.
   - External domains (`api.openai.com`, `example.com`), public IPs (`8.8.8.8`), RFC1918 private networks (`10.0.0.1`, `192.168.1.1`), and link-local cloud metadata (`169.254.169.254`) are deterministically blocked and audited, while loopback mock and loopback Ollama (`127.0.0.1`) requests succeed.
3. **Windows Sandbox / Isolation Qualification:**
   - Checked `docker` CLI on `PATH` and standard installation directories (`C:\Program Files\Docker\...`): **Not installed** (`wsl -l -v` shows `docker-desktop` distribution `Stopped`, no Docker Desktop binary present).
   - Per [SECURITY.md](file:///e:/Anti%20Gravity%20%28Projects%29/Spigot/SECURITY.md#L33-L35) and [AGENTS.md](file:///e:/Anti%20Gravity%20%28Projects%29/Spigot/AGENTS.md#L27), **Spigot / DocForge MCP does not claim container sandbox isolation from a plain Python virtual environment**.
   - Validation reports on this host explicitly record:
     - `static_validation_status`: `AVAILABLE`
     - `socket_egress_guard_status`: `AVAILABLE`
     - `container_sandbox_execution_status`: `UNAVAILABLE` (until a container runtime is installed/started)

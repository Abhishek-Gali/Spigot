# Decisions and risks

## Architecture decision records
| ADR | Decision | Reason and consequence |
|---|---|---|
| 001 | Local-first single-owner product | Meets offline/privacy constraints; no initial enterprise tenancy |
| 002 | Local model for prose, deterministic compiler for output | Separates uncertain understanding from repeatable execution |
| 003 | Versioned internal API Contract | Stable boundary across formats, templates and tests |
| 004 | Evidence on critical fields | Enables review and honest abstention; increases extraction complexity |
| 005 | Python runtime and official MCP SDK first | One generation target reduces compatibility surface |
| 006 | SQLite and local artifact store | No self-managed remote infrastructure; bounded local concurrency |
| 007 | stdio export first | Exported server independent of web hosting; remote auth deferred |
| 008 | Explicit support registry | Unsupported semantics fail visibly instead of universal claims |
| 009 | Trusted runtime permissions | Tool annotations and model prompts cannot authorize actions |
| 010 | Independent mocks/gold labels | Prevents parser/test errors agreeing and hiding defects |
| 011 | One qualified isolation profile | No false sandbox claims from ordinary subprocesses |
| 012 | Ordinary documentation required | Avoids reducing the flagship to an OpenAPI wrapper |
| 013 | No runtime agent swarm requirement | Staged extraction is inspectable, bounded and easier to debug |
| 014 | Reproducibility after frozen contract | Local inference can vary; deterministic generation remains testable |

## Risk register
| Risk | Impact | Mitigation / decision trigger |
|---|---|---|
| Local model too weak for long/ambiguous docs | Inaccurate or incomplete integration | Small contexts, evidence, model qualification, targeted review; never cloud fallback |
| Laptop lacks memory | Extraction unavailable | Qualify smaller model; transparent manual mode; owner decides hardware tradeoff |
| PDF layout corruption | Wrong paths or parameter associations | Page evidence, layout checks, blockers; local OCR extension |
| Docs omit auth/serialization | Server cannot be safely generated | Explicit findings and owner correction; no guessing |
| API semantics exceed OpenAPI/prose subset | False compatibility | Operation-level support matrix and blocked export |
| Sandbox unavailable on owner's OS | Execution checks unavailable | Qualify supported local environment; static-only clearly labeled |
| Dependency/model license limits redistribution | Offline bundle cannot include everything | License inventory and separate owner acquisition |
| Scope expands into hosting platform | Delayed core product | Keep local export first; extensions gated |
| Evaluation rewards pruning unfairly | Misleading resume claims | Held-out tasks, paired budgets, impossible-task failures |
| API/document drift | Previously valid server breaks | Version pinning, semantic diff, regression suite |
| Sensitive source content in outputs | Privacy exposure | Minimal export, source excerpts opt-in, redaction |
| Model hallucinates confidence | Unsafe automation | Evidence grades and actual support checks |

## Open decisions resolved in P0 (2026-10-09)
- **Project branding:** Dual branding **Spigot** (`spigot`) and **DocForge MCP** (`docforge_mcp`).
- **Reference OS/architecture:** Windows 11 Home Single Language 64-bit (`AMD64`, Build 26200), 13th Gen Intel Core i5-13500H (12 cores / 16 threads), 15.70 GiB RAM, Intel Iris Xe Graphics.
- **Qualified local model & runtime:** Ollama `0.34.0` (`127.0.0.1:11434`, `OLLAMA_NO_CLOUD=1`) with primary model `qwen2.5:1.5b` (`Q4_K_M`, 986 MB, digest `65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b`, license `Apache-2.0`) and secondary baseline `qwen2.5:0.5b` (digest `a8b0c51577010a279d933d14c2a8ab4b268079d44c5c8830c0a93900f1827c67`, license `Apache-2.0`).
- **Pinned runtime & dependency versions:** Python `3.13.14`, Node `v22.17.0`, `uv 0.12.11`, `mcp==2.3.0`, `pydantic==2.14.0`, `httpx==0.28.1`, `fastapi==0.143.0`, `uvicorn==0.54.0`, `PyYAML==6.0.3`, `beautifulsoup4==4.15.0`, `pypdf==6.19.0`, `jsonschema==4.26.0`, `pytest==9.1.1`, `ruff==0.16.10` (locked in `uv.lock` and `requirements.txt`).
- **Validation isolation profile on Windows host:** Docker CLI / Docker Desktop is not installed on this machine. Per ADR 011 and `SECURITY.md`, container sandbox execution validation is explicitly reported as `UNAVAILABLE` rather than silently downgraded to a plain virtual environment, while static checks, protocol checks, and `STRICT_OFFLINE` socket-guarded loopback mock tests are `AVAILABLE`.

## Consistency resolutions
“Fully offline” applies to local processing and tests after preparation. Slack/GitHub calls remain connected. “No self-hosted systems” means no required remote infrastructure; the clarified design runs local processes. “No AI API key” does not mean no local inference interface. “Documentation-to-MCP” means supported API documentation with enough facts; arbitrary marketing text cannot supply an API contract. “High-level project” means demonstrable depth, not every enterprise feature.

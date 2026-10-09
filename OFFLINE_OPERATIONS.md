# Offline installation and operations

## Operating profiles
STRICT_OFFLINE: local files, local model, local storage, generated server, local mock. No downloads, DNS-based external fetching, telemetry, update checks, remote fonts, hosted inference, or external services.

CONNECTED_SERVICES: explicit documentation or API origins may be accessed; AI remains local. Each project stores reviewed origins, not broad unrestricted network permission. UI labels connected checks clearly.

Preparation is a separate activity. Dependencies and model weights must be acquired in advance on a connected machine or transferred from trusted media. Never advertise internet-free initial installation without a complete prepared bundle.

## Offline bundle design
Provide platform-qualified bundles with: application backend environment/wheels, built frontend assets, model runtime installer or prerequisite instructions, model weights if redistribution allowed, manifest of versions/checksums/licenses, sandbox image if applicable, generated-runtime wheelhouse, local fixtures, launch instructions, and integrity verifier.

A Windows x64 bundle is not automatically valid for Linux or macOS. Choose one reference platform during P0 based on the owner's laptop, then qualify others separately. Python binary dependencies and sandbox images must match architecture and runtime. Document any local Linux/container dependency for Windows.

Prevent package managers from falling back to remote indexes in offline tests. A missing wheel must fail visibly. Model setup must reject missing hashes or unsupported licenses; never silently download on first extraction.

## First-run experience
Verify bundle → select local data directory → launch local backend/UI → discover installed model → health and capability checks → choose sample document → run offline demo. A capability report shows model, parsers, sandbox, available memory, and optional components. No credentials requested for the demo.

## Health and recovery
Monitor local API, worker lease, model readiness, SQLite migrations, disk capacity, and sandbox availability. If the model crashes, retain validated extraction checkpoints. If the worker dies, reclaim expired leases and mark interrupted jobs. Atomic writes and manifest verification prevent half-written exports from appearing ready.

Backup: quiesce writes or use a consistent SQLite backup mechanism, copy referenced artifact objects and manifests, exclude credentials, then verify on restore. A project archive is not a substitute for OS credential backups. Retention controls should preview storage reclaim and preserve referenced versions.

## Troubleshooting mapping
| Symptom | Response |
|---|---|
| Model out of memory | Reduce context/concurrency or select a qualified smaller local model |
| PDF has no text | Show OCR_REQUIRED; use local OCR extension or export text |
| Missing auth details | Request source/correction; do not guess public access |
| Sandbox unavailable | Static checks only with explicit unavailable execution result |
| Dependency unavailable offline | Add matching wheel/image in preparation stage; no hidden internet fallback |
| Port conflict | Choose another loopback port; update local session configuration |
| External API unreachable | Explain connected-service requirement and preserve offline features |
| Schema unsupported | Show affected operation and supported-feature matrix |

## Optional connected service runbook
Owner configures the service token locally for the exported server, chooses reviewed domain, confirms operation scope, and runs a read-only smoke test. Store only redacted outcome. Never ask the owner to paste secrets into a build-agent chat. Service-specific APIs may need scopes, pagination mappings, or signing beyond the initial generic adapter; report this explicitly.

## Release rehearsal
On a clean reference environment with prepared files: disable external egress, install from bundle, run import/extraction/review/generation/validation/export, stop DocForge, run exported server against the local mock, then inspect traffic and manifests. Repeat with model missing and sandbox missing to confirm honest failure states.

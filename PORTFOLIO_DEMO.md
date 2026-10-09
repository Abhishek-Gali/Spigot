# Portfolio, demonstration and resume evidence

## Positioning
DocForge MCP: an offline documentation-to-MCP compiler with local AI extraction, source evidence, runtime policies, and regression validation.

Describe the problem plainly: developers repeatedly translate API manuals into agent tools, and errors in that translation can produce wrong requests or unsafe actions. The project makes extracted facts reviewable and generated behavior testable.

## Flagship demonstration: approximately four minutes
1. Show external networking disabled and a local model selected.
2. Import a synthetic support API PDF plus a separate authentication Markdown file.
3. Show extracted endpoints with page/line evidence and one deliberately missing required detail.
4. Resolve the finding; select a support tool pack; keep destructive operations disabled.
5. Generate and validate the server against the local mock. Show separate protocol and behavioral results.
6. Stop the generator UI/backend and invoke the exported server through a local MCP client.
7. Attempt a disabled operation and show runtime rejection.
8. Import a changed document that adds a required parameter; show affected tool and regression failure.
9. Show the benchmark with raw denominators and hardware/model information.

A shorter two-minute recording can omit secondary screens but must preserve the document-to-server transformation and evidence of execution. Avoid editing footage to imply waiting or failed tasks did not occur; label time cuts.

## Evidence matrix
| Claim | Required proof |
|---|---|
| Offline processing | Egress-denied run log and environment manifest |
| Supports several document formats | Per-format held-out cases and source citations |
| Generates working integrations | MCP invocation plus independent HTTP fixture assertions |
| Improves tool selection | Paired A/B/C task outcomes and unchanged evaluation budget |
| Enforces permissions | Direct invocation, forged/replayed approval tests |
| Handles API changes | Versioned manual pair and affected-tool regression report |
| Reproducible output | Frozen inputs, version manifest, matching code hashes |

## Resume bullet templates — replace only with measured facts
- Built a local documentation-to-MCP compiler that generated mock-validated integrations from X/Y held-out API manuals across N formats, with source-linked field extraction and no cloud AI dependency.
- Implemented deterministic code generation, argument-bound action approvals, and isolated contract tests; passed X defined policy and failure scenarios on a documented reference environment.
- Evaluated use-case tool selection on N held-out tasks, changing task success from A% to B% under the same model and execution budget, with raw results published.
- Added API contract change detection that identified X/Y seeded breaking changes and preserved reviewed tool configuration during regeneration.

Do not write these bullets with invented numbers. Mock-validated is not live-provider-verified. If selection does not improve outcomes, describe the evaluation and tradeoff honestly instead of inventing uplift.

## Reviewer-friendly repository
Future README should include: a short problem statement; a screenshot and local demo; quickstart; offline preparation steps; supported-feature table; architecture; representative failure case; benchmark results; security boundaries; limitations; contribution notes. Include meaningful commit history and decision records. Avoid screenshots of tests that cannot be rerun.

## Interview discussion topics
Why model output is not executable code; how evidence supports or fails to support a field; how a mock could conceal a shared implementation bug; why safe retries differ for writes; why annotations do not enforce permissions; how offline was tested; what local model limits remain; how API changes invalidate approvals and overrides.

This project can demonstrate integration, AI systems, backend, and security engineering. It does not guarantee interviews, establish production scale, or prove customer deployment experience without actual evidence.

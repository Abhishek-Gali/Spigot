# Product requirements

## Users and workflow
Primary user: a developer connecting an AI client to a documented REST API. Secondary user: a reviewer who needs to verify the generated integration. The default user is a single laptop owner; enterprise tenancy is outside the initial design.

Flow: create project → import document bundle → inspect extraction findings → resolve blocking ambiguities → choose tools and policies → freeze contract → generate → validate → export → optionally configure credentials and connect to a real service.

Successful extraction should not force confirmation of every field. Automatically grounded, supported fields may proceed. Blocking conflicts and security-sensitive enablement require targeted review.

## Traceable requirements
| ID | Requirement | Observable acceptance |
|---|---|---|
| FR-01 | Local OpenAPI JSON/YAML import | Supported operations normalize; unsupported constructs have source-linked findings |
| FR-02 | Markdown, text, saved HTML import | Operations extracted with exact source locations and quoted evidence |
| FR-03 | Text-based PDF import | Page-number evidence survives extraction and review |
| FR-04 | Multi-document bundles | Shared authentication and endpoint definitions reconcile without silent overwrite |
| FR-05 | Local AI extraction | Complete prose extraction without external network or AI credentials |
| FR-06 | Uncertainty handling | Missing method/base URL/auth status blocks affected operations |
| FR-07 | Tool selection | Selected tools have stable names, input schemas, dependencies, and policies |
| FR-08 | Server generation | ZIP contains installable Python package, contract, configuration example, tests, report |
| FR-09 | Runtime reliability | Bounded calls, correctly serialized requests, structured errors, safe retries |
| FR-10 | Enforced permissions | Disabled tools fail even when invoked directly by name |
| FR-11 | Validation report | Static, protocol, mock, and live results separated; skipped never means passed |
| FR-12 | Version comparison | Changed critical fields identify affected tools and regression cases |
| FR-13 | Reproducibility | Identical frozen inputs and pinned versions yield identical code artifact hashes |
| FR-14 | Offline operation | Entire local demonstration passes with external egress blocked |
| FR-15 | Connected services | Explicitly configured external domains and runtime credentials only |
| FR-16 | Local agent evaluation | Repeatable tool-use tasks against controlled APIs without hosted AI |
| FR-17 | Resume evidence | Raw results and reproduction instructions support every claimed metric |

## Release scope
Must ship: FR-01 through FR-17, where FR-15 can be demonstrated using an optional non-destructive connected smoke test and clearly reported as unverified if no credentials are available. No live service access is needed for the offline release gates.

Text PDFs are required. Scanned PDFs must be detected and reported as needing OCR; automated OCR is an extension. Saved HTML is required; JavaScript website rendering and authenticated documentation crawling are extensions. Documents that are not API documentation must result in “insufficient API contract” rather than invented tools.

Support JSON REST operations initially. Explicitly reject or disable SOAP, GraphQL, gRPC, streaming responses, webhooks/callbacks, multipart uploads, and vendor request signing until their adapters and tests exist. HTTP error responses and empty responses are in scope.

## Proposed quality budgets
These are targets to validate, not achieved results. Initial intake defaults: 20 files/project import, 20 MiB/file, 100 MiB/bundle, 200 pages/PDF, 500 operations/project, reference depth 20. Exceeding a bound produces a recoverable finding. Owners may configure bounds explicitly; model/document content may not raise them.

Set supported-input extraction quality and latency thresholds only after the Phase 0/3 baselines. Require no unsupported critical fields to be silently accepted on the fixed negative test suite, no external egress in the offline test, and all declared-supported serialization fixtures to pass. Do not promise extraction in 60 seconds on unspecified hardware.

UI must support keyboard navigation, visible progress, cancellation, source inspection, and readable errors. Long model tasks run outside the web request process.

## Exclusions
No model fine-tuning, vector database requirement, cloud AI fallback, hosted multi-tenant runtime, payments, billing, arbitrary executable plugins, autonomous mutation of production systems, or universal documentation comprehension. No requirement to publish generated packages to public registries.

## Meaning of ready
“Generated” means files exist. “Static checks passed” means they parse/build. “Mock validated” means protocol and fixture behavior passed. “Live verified” means named operations were tested with authorized access at a stated time. The UI must never collapse these into one unqualified green “working” badge.

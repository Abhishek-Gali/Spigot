# Local API and user experience

## Principles
Single-owner local web app. No account signup, billing, cloud project setup, or login screen. Show the network profile and local model status. Bind backend to loopback, serve bundled UI assets, and protect mutation endpoints with the local session capability mechanism from SECURITY.md.

## Proposed API contracts
All paths below are local application endpoints, not generated MCP tools. IDs are opaque. JSON errors use DATA_CONTRACTS.md. Long operations return HTTP 202 with job_id and status URL. JSON requests have bounded size; uploads use multipart file transport to the local app only.

| Method/path | Input | Result |
|---|---|---|
| POST /api/projects | name | project ID and revision |
| GET /api/projects/{id} | — | summary, sources, current revisions |
| POST /api/projects/{id}/sources | local files | source IDs and intake findings |
| POST /api/projects/{id}/fetch | URL, explicit connected permission | acquisition job; denied offline |
| POST /api/projects/{id}/extract | source IDs, model/config refs | extraction job |
| GET /api/projects/{id}/findings | filters, cursor | source-linked findings |
| PATCH /api/projects/{id}/review | expected revision, field changes, rationale | new revision or 409 |
| POST /api/projects/{id}/contracts/freeze | expected revision | immutable contract hash or blockers |
| POST /api/projects/{id}/tool-plans | contract hash, selected ops, use case, policies | validated tool plan |
| POST /api/projects/{id}/generate | plan hash, idempotency key | generation job |
| POST /api/artifacts/{id}/validate | suite/profile, idempotency key | validation job |
| GET /api/artifacts/{id}/download | — | verified ZIP stream |
| POST /api/projects/{id}/compare | old/new contract hashes | structured change report |
| POST /api/projects/{id}/evaluate | frozen task set, configs | evaluation job |
| GET /api/jobs/{id} | — | stage, progress, findings, cancellation state |
| POST /api/jobs/{id}/cancel | — | cancellation acknowledgement |
| GET /api/jobs/{id}/events | cursor | bounded incremental events; polling sufficient initially |
| GET /api/local-models | — | installed model metadata, no remote catalog call |

Project deletion requires an explicit local owner action and a reference-aware cleanup preview. Download paths are generated server-side; clients cannot choose arbitrary filesystem paths. Cursor pagination applies to large operation lists and reports. An optional owner approval endpoint is isolated from agent-accessible interfaces and must use stronger owner authorization than the MCP tool client.

## Screens
1. **Project home:** project name, source revisions, model readiness, latest validation status, offline/connected status.
2. **Import:** drag/drop local documents; show accepted formats, scan detection, duplicates, size limits; URL tab disabled offline.
3. **Extraction:** stages and cancel; endpoint inventory; failed parsing and incomplete work visible.
4. **Evidence review:** operation list, selected field, exact supporting text/page, findings, correction with rationale. Keyboard navigation and no raw HTML execution.
5. **Tool plan:** names, descriptions, dependency hints, selection, semantic effect, explicit blocked state. AI suggestions never override permissions.
6. **Generate and validate:** independent badges for build, protocol, mock, security, live; skipped/unavailable visible.
7. **Version comparison:** contract-level changes and affected tools/tests; preserve previous good artifact.
8. **Evaluation:** denominators, per-case outcomes, model/hardware metadata, raw export.

## Interaction rules
The primary action is Generate only when selected operations have no blocking findings and a frozen plan exists. Users can exclude blocked operations and proceed with supported ones; the report must show exclusions. Enable-write actions show exact operation and consequences. Policy defaults cannot be changed by model suggestions.

A validation failure does not delete the artifact. It removes any “verified” claim, displays diagnostic evidence, and links to relevant source/contract fields. Exporting a failed artifact may be allowed only with a clear unvalidated status in its README/report; it cannot bypass policy blocks.

## Accessibility and usability acceptance
Complete import/review/export with keyboard; focus returns to changed finding; errors connect to fields; no color-only status; long text wraps; PDF evidence has a text alternative; terminal errors remain copyable with secrets redacted. Use a restrained professional visual style and useful data density. Do not hide unfinished behavior behind disabled buttons with no explanation.

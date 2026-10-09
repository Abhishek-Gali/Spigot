# Threat model and security requirements

## Assets and boundaries
Protect service credentials, local files, API permissions, source-document privacy, generated code integrity, and benchmark truthfulness. Untrusted inputs include uploaded documents, model outputs, extracted URLs, tool arguments, API responses, and generated packages until validated. Trust the local owner and reviewed application code; do not claim defense against a compromised OS administrator.

## Threat/control/test matrix
| Threat | Required control | Evidence test |
|---|---|---|
| Prompt injection in documentation | Treat text as data; no model execution privileges; schema/evidence checks | Malicious instruction cannot create shell action or expose a fixture secret |
| Fabricated endpoint | Critical evidence checks and blockers | Unsupported path with plausible prose is rejected |
| Generated-code injection | Serialize data; safe identifiers; no eval/exec | Quotes, braces, newlines, template tokens remain inert |
| SSRF from docs/server URLs | Separate fetch/service allowlists; validate scheme, DNS, redirects and resolved addresses | Private, link-local, metadata, IPv6, rebinding and redirect cases denied |
| File traversal | Workspace-root containment; safe export paths; archive checks | ../ and absolute-path payloads cannot escape |
| Parser exhaustion | Byte/page/depth/time bounds; isolated parsers where needed | Recursive YAML/reference loops fail within budget |
| Secret leakage | Runtime-only secrets; redaction before persistence/inference | Canary absent from logs, ZIPs, reports, prompts |
| Unsafe write | Runtime policy and trusted approval binding | Direct invocation and forged/replayed approval denied |
| Browser-to-local API attack | Loopback binding, Host/Origin checks, capability token, no wildcard CORS | Cross-origin mutation and DNS-rebinding Host rejected |
| Validation sandbox escape | Egress denied, limited mounts, low privilege, resource limits | Host file and external network probes fail |
| Silent cloud inference | Local-only runtime configuration plus egress testing | Cloud identifiers/endpoints rejected |
| Artifact tampering | Content hashes and manifest verification | Modified source fails verification before validation/export claim |

## Network policy
OFFLINE is the default. Only explicitly registered loopback services can communicate. Public documentation fetching and service calls are distinct connected permissions. A local mock exception is narrow and cannot become unrestricted localhost access from a document URL. Address checks must account for redirects and DNS changes at connection time, not just a string-prefix test.

Do not rely solely on application booleans to prove offline operation. Use OS/container egress denial during the release test and capture attempted connections. Ordinary local runtime operation can use application controls, but the offline guarantee must have external enforcement evidence.

## Credentials
Generated servers read credentials through OS credential storage or process environment. The generator stores symbolic credential names only. Never collect credentials through the extraction UI or inject them into model context. .env examples contain fake values; local .env files are excluded from version control and exports. Exception messages, HTTP headers, URL queries, and tracing must be scrubbed before logging.

If provider-specific OAuth is added later, distinguish authentication of an MCP client from authorization to the upstream service. Do not implement generic token passthrough. Local OAuth tokens live in secure local storage; flows require provider-specific review and tests. OAuth is outside the initial API-key/bearer scope.

## Sandbox qualification
A subprocess is not a security sandbox. Prefer a prequalified local container/OS isolation profile with non-root user, read-only root, bounded writable temp, no host secrets, no privileged socket, process/memory/CPU limits, and external egress denied. Generated server and mock can share the isolated test environment so external network can stay disabled. Prepare images and dependencies before offline use.

On Windows, record whether the isolation profile relies on a supported local Linux/container environment. If unavailable, offer static validation and mark execution checks unavailable. Do not claim equivalent isolation from a plain virtual environment. Sandboxed validation remains a release requirement on at least one documented reference platform.

## Privacy, logs, retention
Store metadata by default: tool ID, status category, duration, retries, policy decision, trace ID. Payload capture is opt-in and redacted, with a retention limit. Export reports omit source contents and payloads unless the owner chooses otherwise. Deleting a project removes its references and unshared artifacts with a preview; do not delete external originals.

## Security release gate
All fixed negative tests pass; secret canaries absent; policy bypass tests pass; no external egress in offline run; unsupported security combinations blocked. Record exactly which threats were tested and residual limitations. No “100% secure” claim and no claim that prompt instructions alone prevent injection.

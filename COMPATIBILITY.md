# Proposed compatibility and capability registry

This matrix defines planned scope, not implemented support. The builder must maintain a machine-readable equivalent and tests. Do not mark a capability supported until its fixtures pass. PRODUCT_REQUIREMENTS.md sets the product goal; this file makes initial protocol/schema boundaries explicit.

## Inputs
| Input | Flagship requirement | Boundary |
|---|---|---|
| OpenAPI 3.0 JSON/YAML | Required supported subset | Unsupported operations blocked individually |
| OpenAPI 3.1 | Extension | Detect version; do not silently parse as 3.0 |
| Markdown/text | Required | API documentation with sufficient explicit facts |
| Saved HTML | Required | Static content, no script execution |
| Text PDF | Required | Page evidence and readable text layer |
| Scanned PDF | Detect and explain | Automated local OCR is an extension |
| Documentation URL | Optional connected acquisition | Offline user supplies a local snapshot |
| DOCX, images, audio/video | Out of initial scope | Clear unsupported-format result |

## Schema and serialization
| Capability | Initial target | Acceptance condition |
|---|---|---|
| Primitive strings/numbers/booleans | Supported | Type/bounds preserved |
| Enums and nested JSON objects/arrays | Supported | Required/optional/default distinctions preserved |
| JSON null / OpenAPI 3.0 nullable | Supported within 3.0 subset | Absent and explicit null tested separately |
| Local $ref | Supported with bounds | Cycles detected; finite resolution or explicit blocker |
| Remote $ref | Disabled offline | Owner supplies mapped local resources; connected resolution is separately controlled |
| allOf, oneOf, anyOf | Initially blocked when behavior depends on them | Add only with faithful validation and request mapping tests |
| Discriminators / recursive schemas | Deferred | No silent flattening |
| Path primitives, simple style | Supported | Encoding and placeholder fixtures pass |
| Query primitives, form style | Supported | Empty, absent, reserved characters and types tested |
| Query arrays, form explode true/false | Supported | Exact repeated-key/comma behavior verified |
| Deep objects, matrix/label styles | Deferred | Explicit finding rather than generic JSON stringification |
| Header primitives | Supported | Invalid header characters rejected; protected headers reserved |
| Cookie parameters | Deferred | Location preserved but required cookie operation blocked |
| JSON request/response bodies | Supported | Media type, empty body and error handling tested |
| Multipart, binary, streaming, XML | Deferred | No automatic conversion to JSON |

Optional unsupported fields cannot simply be dropped if they alter behavior the tool claims to support. The compatibility report explains restrictions. An owner may export a deliberately narrower tool only when the contract records the restriction and the tool does not accept unsupported arguments.

## Authentication and transport
API-key header/query and bearer token credentials are initial targets. A query API key must be redacted from URLs before logging. Cookie API keys, HTTP Basic, custom signing and OAuth providers are extensions. Preserve auth alternatives/combinations; if none can be faithfully satisfied, block that operation. Public operations require explicit evidence or formal specification semantics, not omission in prose.

Local stdio MCP is required. Remote HTTP transport and its client authorization model are deferred. Local evaluation must use a protocol client and cannot depend on a hosted AI subscription. Pin the negotiated protocol/SDK combination during P0.

## Runtime caps
Declared supported operations use the bounds in GENERATOR_RUNTIME.md. Response truncation must be visible and must not produce invalid JSON presented as complete output. Prefer a structured size-limit error or explicit bounded projection, with continuation data where documented. Never infer universal pagination fields from naming alone.

## Capability report behavior
For each operation show: supported features, missing facts, unsupported constructs, blocked reasons, available auth alternatives, enabled policy and required runtime dependencies. Aggregate counts keep imported, selected, blocked, generated and tested operations separate. A project with only two supported operations out of 100 cannot be advertised as full API coverage.

# Generator and generated runtime specification

## Generation contract
Input: immutable ApiContract, ToolPlan, policy revision, template/runtime versions, dependency lock. Output: deterministic source package and artifact manifest. Generation must never need a model, service credentials, or external network.

Suggested exported content: README.md; pyproject.toml; locked dependency metadata; server package; normalized contract.json; tool_plan.json; policy.json; manifest.json; .env.example containing names only; generated smoke tests; compatibility report. Source documents are excluded by default to avoid redistributing private manuals; evidence references remain and an explicit option can include sanitized source excerpts.

A separate offline bundle contains platform-qualified dependencies. The server package must not depend on the DocForge backend or SQLite project database. Include runtime code or a pinned redistributable runtime wheel. License notices travel with redistributed code.

## Code generation safety
Normalize tool names to a documented safe identifier policy, reserve runtime names, and resolve collisions with stable suffixes. Encode descriptions, paths, and schemas as serialized data. Never paste raw source text into Python expressions, decorators, imports, or shell scripts. Validate output with parsing and import tests. Pin SDK compatibility and test generated tool schemas through a real MCP client.

Parameter mapping must retain original names separately from safe Python/tool argument names. Validate arguments against supported JSON Schema semantics before dispatch. If a composition keyword cannot be faithfully represented, reject that operation; do not replace it with unconstrained data silently.

## Initial supported HTTP behavior
Methods with explicit policy; path substitution with correct encoding; query primitives and tested arrays; JSON request bodies; API key/header and bearer auth; JSON/empty responses; documented error statuses. Expand query styles, cookie parameters, complex composition, and additional media types only when corresponding golden fixtures pass.

No arbitrary URL argument. Server base URL is reviewed configuration. Validate final URL after composition. Restrict redirect handling, do not forward auth across origins, and bound response size. Ignore ambient proxy configuration unless explicitly reviewed so it cannot silently defeat offline/domain policies.

## Execution sequence
Validate tool identity → load policy → validate arguments → normalize action and target → obtain trusted approval if required → resolve credentials from local runtime configuration → construct request → enforce domain/network limits → execute within deadline → map response/error → emit redacted trace.

Policy evaluation and approvals must happen before any mutating network action. Do not include bearer tokens or API keys in tool schemas. Endpoint scope requirements are documented and checked when possible; do not claim scopes were verified if the provider offers no introspection.

## Proposed initial reliability defaults
30-second total request deadline, 5-second connection budget within it, maximum three attempts for eligible transient failures, 1 MiB response budget, five concurrent calls, pagination disabled unless explicitly configured. These are configurable starting values to tune by fixture evidence.

Retry only allowlisted transient conditions and operations declared safe to repeat. Respect Retry-After within total deadline. A transport error after a write may mean the write succeeded: return OUTCOME_UNKNOWN instead of blindly replaying. Idempotency keys are used only when the upstream API documents support, and stable keys are preserved across retries of the same action.

Circuit breaker state is keyed by service and relevant credential identity without storing the secret. Expose cooldown and manual reset. Cancellation propagates through pending HTTP and subprocess operations.

## Pagination
Recognize only configured/tested cursor, page, or offset patterns. Default tools return one page with continuation information. A separate bounded traversal option enforces max pages, items, bytes, and deadline. Do not invent cursor fields or loop until exhaustion without limits.

## Policies and approvals
Disabled operations are not advertised and are rejected if invoked directly. Read-only mode requires reviewed semantic effect; unknown remains disabled. Restricted writes specify explicit operations and optional argument constraints.

Approval-required mode uses prepare/approve/execute semantics. Preparation canonicalizes exact operation, arguments, destination, contract hash, and policy revision into an action digest. A separate owner-controlled local utility or UI signs/issues a short-lived, single-use approval bound to that digest. The model/tool client cannot access the approval authority. Execution verifies it and atomically consumes it before dispatch. Changed arguments, expiry, reused approval, or changed policy cause denial.

For an exported server, if the approval authority is not configured, approval-required writes remain disabled. Do not replace this with a boolean tool argument. Explain that local machine administrators can modify their own files; the project does not promise protection from a fully compromised host.

## Validation and live calls
Generated smoke tests use placeholders and mocks. Real calls require explicit connected profile and runtime credentials. Live read checks are opt-in; live writes require specific owner authorization and applicable approval. “Dry run” means construct/validate without sending a mutating request; do not trust a provider's dry-run flag unless documented and tested.

## Compatibility upgrades
Store selected MCP protocol/SDK version in the release manifest. Add upgrade tests before changing it. Maintain separate adapters if a future version needs different behavior; do not mix APIs from similarly named packages. A syntax-valid server is not sufficient: initialize, list tools, invoke, and inspect structured errors through a client.

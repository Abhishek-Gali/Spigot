# Testing, evaluation and release evidence

## Independent ground truth
Create synthetic API families before extraction implementation: support tickets, inventory, orders, and a separate held-out domain such as appointments. For each family, independently author the canonical expected contract, HTTP fixture behavior, state transitions, and documentation variants. Do not derive all expected results from the extractor's output or its generated mock.

Development set: at least 12 document variants across three families. Held-out proposal: at least 8 variants including an unseen family. Variants include Markdown, text PDF, saved HTML, split authentication documents, conflicts, omitted information, injection attempts, and version changes. Keep task counts and exact hashes in a corpus manifest. These counts are targets, not completed assets.

Generate fixtures with stable seeds. Include a manual audit of gold contracts. Split by API family and document template where feasible to avoid near-duplicate leakage. Once test-set evaluation begins, freeze it; if fixes use its cases, call it regression data and create a new held-out set.

## Test layers
| Layer | Assertions |
|---|---|
| Parser | Headings, tables, page/line provenance, malformed documents, limits |
| Extraction | Critical field correctness, endpoint omission, unsupported inferences, evidence support |
| Contract | Auth AND/OR semantics, reference cycles, path/body/schema consistency |
| Generator | Inert malicious strings, stable names, reproducible code, install/import |
| Protocol | Initialize, list, invoke, invalid arguments, error mapping, stdout discipline |
| HTTP | Exact serialization, auth placement, response parsing, empty and error cases |
| Resilience | Timeouts, cancellation, 429/503, safe retries, ambiguous write outcomes |
| Policy | Direct disabled calls, unknown-effect default, trusted approval binding/replay |
| Sandbox | Host file denial, no external egress, limits and cleanup |
| UI | End-to-end review/generation, revision conflict, report truthfulness |
| Offline | Full workflow including model and exported server with external network denied |
| Evolution | Semantic diff, stale override, affected tools, regression replay |

Use table-driven golden tests and property-based testing for serialization/path handling where useful. Avoid tests that only assert function names or repeat implementation logic. Test SDK compatibility through actual protocol clients, not only imports.

## Extraction metrics
- Endpoint precision = correctly extracted unique endpoints / all extracted unique endpoints.
- Endpoint recall = correctly extracted unique endpoints / gold documented endpoints.
- Critical-field exact accuracy = correctly populated critical fields / gold critical fields that should be populated; report per-field breakdown.
- Unsupported assertion rate = populated fields not supported by source or reviewed correction / populated assessed fields.
- Evidence validity = resolvable correct citations / emitted citations; separately manually assess whether the quote supports the fact.
- Correct abstention rate = correctly blocked ambiguous/missing cases / cases requiring abstention.
- Review burden = corrected fields and owner review minutes per document.

Report raw numerator/denominator and failures; a high precision achieved by extracting one endpoint must be visible through recall. Do not equate syntactic schema validity with factual accuracy.

## Agent evaluation
Use at least 20 tasks per qualified API family as a proposed target, with multiple repetitions where local compute allows. Scenarios: lookup, filter, pagination, multi-step read, invalid input, permission refusal, and controlled writes to disposable fixtures. All actions remain in local mocks.

Compare A: all supported tools with original descriptions; B: manually selected task-relevant tools with original descriptions; C: locally suggested tool pack plus rewritten descriptions. Use the same agent model/digest, task text, fixture state, deadline, maximum tool calls, and seeds/settings across conditions. Selection is based on a use-case description, not hidden expected answers for each test task.

Success is a task-specific executable assertion: correct final value, intended state transition, required policy refusal, and no unintended mutation. Score refusal tasks separately so refusing everything cannot inflate task success. Count tasks made impossible by pruning as failures. Measure wrong tool calls, extra calls, wall time, output size, and model context usage. If tokenizers differ, avoid direct token-count comparisons across models.

Publish per-task paired outcomes and uncertainty intervals where sample size permits. An improvement is a hypothesis; negative results are legitimate. Do not retune test tasks until the claimed improvement appears.

## Proposed release gates
Hard gates: all declared-supported contract fixtures pass; offline egress suite shows no external traffic; secret canaries absent; all fixed policy/security negatives pass; source/manifest integrity holds; one clean offline install succeeds on the named reference environment.

Quality targets after baseline: aim for at least 95% critical-field accuracy on a clearly bounded held-out supported corpus, while publishing recall and abstention. This is a proposed target, not an achieved result or permission to hide failures. If unmet, improve extraction or narrow the declared supported documentation patterns transparently; do not remove ordinary documentation from the product.

Performance gates depend on qualified hardware. Establish baseline in P3, then set a regression budget. Record cold model startup separately. No universal latency or memory claims.

## Reports and artifacts
Each result includes source/task hashes, commit, generator/template/runtime versions, model digests, OS/CPU/RAM/GPU, settings, raw outcome rows, start/end times, and explicit skipped/unavailable statuses. Store redacted traces for failures. A report renderer must calculate metrics from raw rows, not manually typed numbers.

Do not claim mock success equals real provider compatibility. A live report lists service, operations, timestamp, configuration and read/write scope, with secrets removed. No credentialed live test is required for the offline demonstration.

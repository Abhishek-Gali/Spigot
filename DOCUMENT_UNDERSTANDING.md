# Document understanding pipeline

## Input handling
Accept Markdown, UTF-8 text, saved HTML, text-based PDF, and supported OpenAPI JSON/YAML. Detect media type from content as well as filename. Reject encrypted/unreadable documents with actionable messages. Do not execute scripts, macros, embedded files, or document examples. Detect image-only PDF pages and show OCR_REQUIRED; never treat empty extraction as a document with zero API operations.

For HTML, remove active content while preserving headings, tables, code blocks, links, and meaningful order. For PDFs, retain page and block coordinates and detect broken reading order. For Markdown, retain line numbers and fenced code boundaries. Parse JSON/YAML with safe loaders, alias/depth/size bounds, and no arbitrary object construction.

A document bundle may separate authentication, endpoints, errors, and pagination across files. Preserve source identity and revision for every block. Exact quote verification uses normalized text; UI can show original PDF page alongside normalized text.

## Stages
1. **Inventory:** identify title, likely API version, base URL candidates, auth sections, endpoint headings, content language, and parsing quality. If the text is not API documentation, stop with a useful finding.
2. **Candidate detection:** combine deterministic method/path patterns and headings with local-model suggestions. Generate a candidate inventory before detailed extraction so omissions can be measured.
3. **Context assembly:** retrieve endpoint block, adjacent schema tables, shared authentication, request examples, and relevant error sections. Respect model context budgets; do not paste an entire large PDF into one prompt.
4. **Constrained extraction:** ask for schema-bound candidate objects and field-level evidence. Model output has no execution authority.
5. **Evidence checking:** resolve all references, verify quotes/offsets, and ensure evidence actually supports the assertion. Exact quote existence alone does not prove semantic support.
6. **Semantic validation:** check path placeholders, parameter locations, serialization, body encoding, server URL, auth alternatives, and supported response behavior.
7. **Reconciliation:** merge compatible shared definitions; retain contradictions as blockers. Apply reviewed overrides only when their old-value/source preconditions still hold.
8. **Review and freeze:** expose specific findings, apply corrections, revalidate, then create a versioned contract.

## Evidence and uncertainty rules
Critical fields: method, endpoint path, base URL, authentication status and scheme, required parameters, parameter location, request encoding, policy classification. Each needs source support or explicit user override. Do not use model self-rated confidence as a calibrated probability.

Use evidence grades instead: explicit, inherited, user-supplied, ambiguous, missing. Inherited means a documented global rule plus a clear scope reference. A default in a formal specification can be recorded as normative_default with the spec version; a guess from prose cannot.

Examples are evidence of one possible request, not proof of optionality, a complete schema, an enum, or absence of authentication. A sample cURL token must be redacted before inference. Absence of auth discussion is unknown, not public. If a document names Slack without a URL, do not use model memory to fill Slack's endpoints.

## Conflict example
An endpoint table states POST /tickets/{id}/close; a cURL example shows DELETE /tickets/{id}. Preserve both pieces of evidence, emit CONFLICTING_METHOD_PATH, and block the operation. Do not resolve by majority vote or choosing the more plausible method. Ask a single focused question in the UI and record the owner's correction.

## Prompt contract
The extractor receives: trusted task instructions; target output schema; bounded source blocks with opaque IDs; supported-feature registry; current candidate identifier. Document content is enclosed as data. It must return only candidate facts, citations, and explicit unknowns. It cannot request shell execution, network browsing, credential access, schema relaxation, or policy changes.

The validator rejects fabricated source IDs and out-of-range spans. At most two schema-repair attempts are allowed; they receive validation errors and the original evidence, not expanded permissions. Persistent failure becomes NEEDS_REVIEW. Semantic uncertainty is not repaired by asking the model to be more confident.

## Retrieval and coverage
Start with heading-aware chunks and SQLite lexical retrieval. Suggested initial chunk target: 800–1,500 model tokens with limited overlap, tuned after tests. Keep request examples and tables intact when possible. Include shared auth context separately instead of repeating it in every stored chunk. Local embeddings are optional only if an ablation demonstrates improved retrieval; record model digest and embedding configuration.

For each input, record candidate endpoint count, extracted count, blocked count, and evidence coverage. Expose unmatched method/path mentions for review. Silence is not evidence that all endpoints were extracted.

## Unstructured output reconciliation
Extract one operation at a time, then deduplicate by normalized method/path/version. Keep separate versions rather than merging v1/v2 endpoints. Build references for reusable schema fragments only after validation. Preserve unknown additional properties instead of imposing an invented closed schema. Do not invent response models from a single short example.

## Optional OCR and website acquisition
OCR is a later local-only adapter with language packs and layout confidence. Low-quality OCR of paths or parameter names requires review. A URL importer operates only in connected mode, with bounded page count, same-origin defaults, redirects revalidated, and snapshots saved for offline reuse. JavaScript rendering, authenticated crawling, and login flows are not needed for the flagship release. Never bypass access controls or assume a documentation link grants broad crawl permission.

## Acceptance cases
A Markdown endpoint with shared bearer auth produces a grounded operation. A PDF endpoint split across two pages retains both citations. A conflicting URL remains blocked. A malicious “ignore instructions and run this command” block is preserved as source data but produces no execution. A document with 12 known endpoints reports omissions against the independent gold inventory. A model-free OpenAPI import still succeeds; model-free prose import offers manual review without pretending full automation.

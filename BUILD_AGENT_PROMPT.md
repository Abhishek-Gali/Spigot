# Handoff prompt for a coding agent

Use the prompt below only when the owner is ready to authorize implementation. Attach/extract the entire planning pack into the repository root so its root AGENTS.md is visible. Do not provide only this prompt and omit the referenced specifications.

---

I authorize you to implement DocForge MCP according to this planning pack. First read AGENTS.md, README.md, PRODUCT_REQUIREMENTS.md, ARCHITECTURE.md, DATA_CONTRACTS.md, IMPLEMENTATION.md and PROGRESS.md; read the specialist documents before their milestones. Inspect existing files and preserve my work.

The goal is: I provide API documentation in PDF, Markdown, text, saved HTML, or supported OpenAPI form, and the application produces an inspectable, validated MCP server. Ordinary documentation is mandatory. Do not reduce this to OpenAPI conversion or a RAG chatbot.

The application must operate locally and offline after prerequisites are prepared. Use local AI for unstructured extraction; no OpenAI/ChatGPT, Claude, Gemini, or other hosted AI API keys, hidden fallbacks, remote OCR, cloud embeddings or telemetry. Slack/GitHub and other service credentials are allowed only for optional authorized connected integrations. The offline demo must need no service credentials.

Use evidence-backed extraction, strict shared contracts, deterministic generation, enforced runtime policies, independent mock tests, and truthful validation states. Do not fabricate missing endpoint details. Expose blockers with source evidence and targeted corrections. Exported servers must run without the generator or local model.

Start with Phase P0. Qualify the environment, one local model, dependencies and validation isolation. Then proceed through the roadmap gates. Build a Markdown-to-server vertical slice early and complete text PDF and saved HTML support in P3. Do not spend the first milestone on a decorative dashboard.

Use the proposed modular architecture, adapt routine implementation details with recorded rationale, and select exact dependency/model versions based on installed or verified official information. Do not assume a package version or model exists. If offline, document unverified version information instead of guessing.

After each milestone, run relevant acceptance tests, update PROGRESS.md and report behavior delivered, actual test results, limitations and next ticket. Persist checkpoints so another agent can continue. Do not declare success from placeholders or generated tests alone. Do not falsify benchmark numbers.

You may make routine reversible implementation choices. Ask me only for missing information that materially affects correctness, permissions, hardware feasibility, or scope. Do not request or print secrets in chat. Do not deploy, publish packages, send messages, purchase services, run destructive live API calls, or download large model weights without applicable authorization.

Begin by reporting the environment findings, the first milestone's plan and any true blockers, then implement the authorized milestone.

---

## Prompt for continuation
Read AGENTS.md and PROGRESS.md, inspect the actual repository and last test results, and continue the first incomplete ticket. Treat prior agent summaries as pointers, not proof. Preserve user edits and validate any changed interfaces. Follow the original offline/no-cloud-AI requirements. Report actual work and update the handoff.

## Prompt for independent review
Review the implementation against PRODUCT_REQUIREMENTS.md, SECURITY.md and TESTING_EVALUATION.md. Trace at least one ordinary document through extraction, contract, generated request and independent mock assertion. Inspect network paths and model configuration for cloud leakage. Identify concrete gaps with file references and reproduction steps. Do not replace implementation or weaken requirements to make the review pass.

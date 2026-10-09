# Primary references and verification notes

Reference check date: 9 October 2026. This is a design blueprint, not a certified dependency compatibility matrix. Official documentation can change. During P0 inspect installed versions, verify the relevant official pages when connected, and pin tested versions. Offline builders should use a prepared documentation snapshot and state its date.

## Protocol and runtime
- Official MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
- SDK documentation: https://py.sdk.modelcontextprotocol.io/
- MCP tools specification: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- MCP security guidance: https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices

Design implications: test actual client/server interoperability; treat descriptive annotations as distinct from permission enforcement; examine authorization boundaries before adding remote transport. Links above may represent different documentation versions: the builder must choose one tested protocol/SDK combination rather than mixing examples.

## Local inference
- Ollama structured output: https://docs.ollama.com/capabilities/structured-outputs
- Ollama local-only configuration: https://docs.ollama.com/faq

Design implications: constrain extraction response shape, validate semantic content independently, and verify that inference cannot route to hosted models. At this reference check, official FAQ documents OLLAMA_NO_CLOUD=1 and a disable_ollama_cloud setting. Reconfirm against the installed runtime. Schema-constrained output does not establish factual correctness.

## API schemas
- OpenAPI 3.0.4: https://spec.openapis.org/oas/v3.0.4.html
- OpenAPI 3.1.2: https://spec.openapis.org/oas/v3.1.2.html
- OpenAPI parameter guidance: https://learn.openapis.org/specification/parameters.html

Design implications: preserve parameter serialization, schema-version distinctions and security combinations. These pages are references, not a claim that every feature is in scope. The support registry defines what the implemented release handles.

## Verification policy
Do not select an SDK, local model, parser or runtime based on a generated version number. Do not cite this plan as proof of implementation performance. Exact library/model versions, supported schema keywords, and reference hardware remain P0/P3 decisions.

All architecture, milestones, limits, fixture counts, quality targets and estimated schedules in this pack are proposed engineering choices. They are not results from these sources. No recruitment statistics or market-demand claims are asserted.

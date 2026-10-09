# Data contracts and persistence

All schemas below are design contracts to implement and version, not existing executable classes. Use strict typed models, reject unknown security-sensitive fields, and include schema_version on persisted interchange objects.

## Shared objects
| Object | Required fields and invariants |
|---|---|
| SourceDocument | id, project_id, content_sha256, original_name, media_type, imported_at, local_artifact_ref, source_uri nullable, license_note nullable; original bytes immutable |
| DocumentBlock | id, source_id, text, block_kind, heading_path, location, extraction_method; location is page/bbox or line/character interval |
| EvidenceRef | source_id, block_id, start_offset, end_offset, exact_quote, quote_sha256; offsets resolve to actual normalized block text |
| CandidateOperation | candidate_id, method nullable, path nullable, server candidates, parameters, request schema, responses, auth candidates, field evidence, findings |
| Finding | id, code, severity, affected_field, evidence_refs, explanation, suggested_resolution, status; severity info/warning/blocker |
| UserOverride | id, target_field, old_value_hash, new_value, rationale, actor local-owner, timestamp, source_revision |
| ApiContract | id, schema_version, revision, sources, servers, operations, security_schemes, findings, overrides, canonical_hash |
| ToolPlan | id, contract_hash, operation_ids, tool_names, descriptions, dependency_edges, policy_hash, plan_hash |
| GenerationManifest | artifact_hashes, contract_hash, plan_hash, generator_version, template_hash, runtime_version, dependency_lock_hash |
| ValidationReport | manifest_hash, environment, per-check status, evidence files, started_at, finished_at; status passed/failed/skipped/unavailable |
| EvaluationRun | task_set_hash, split, agent_model_digest, extraction_model_digest, config_hash, per-task outcomes, repetitions, environment |

## Operation contract details
Operation fields: stable_id; display_name; method; relative_path; server_ref; parameters; request_body; responses; security_requirement; timeout_policy_ref; pagination_config nullable; semantic_effect; provenance; support_status.

Parameter fields: external_name; safe_argument_name; location; required; schema; style; explode; allow_reserved; default behavior; evidence. Preserve distinct same-name parameters in different locations with separate safe argument names. Parameters cannot override host, authorization headers, or runtime policy unless explicitly designed and reviewed.

Security requirements must preserve OR between alternatives and AND within one alternative. Explicit public/no-auth differs from unknown authentication. Operation overrides of global security must survive normalization. Never flatten combinations into a single arbitrary credential.

Request body carries media type and required status separately from properties. Responses retain documented status/content types and unknown response behavior. A sample value does not establish a field as required, exhaustive enum, or guaranteed response type.

Semantic effect: read, write, destructive, unknown. HTTP method is evidence, not proof. Unknown is disabled by default. Support status: supported, partial, unsupported, blocked. Partial operations must list exactly which behavior cannot be generated; required unsupported behavior blocks export of that operation.

## Illustrative contract fragment
This is illustrative data, not a parser implementation or complete JSON Schema.

```json
{
  "schema_version": "1.0",
  "operation": {
    "stable_id": "support.get_ticket",
    "method": "GET",
    "relative_path": "/tickets/{ticket_id}",
    "server_ref": "support_api",
    "semantic_effect": "read",
    "support_status": "supported",
    "parameters": [{
      "external_name": "ticket_id",
      "safe_argument_name": "ticket_id",
      "location": "path",
      "required": true,
      "schema": {"type": "string"},
      "style": "simple",
      "explode": false
    }],
    "security_requirement": {"alternatives": [{"all_of": ["service_bearer"]}]},
    "provenance": {"method": ["ev-01"], "relative_path": ["ev-01"]}
  }
}
```

The actual model must validate completeness beyond this abbreviated example. A generation readiness check verifies server URL, method, path, path-variable consistency, request encoding, explicit authentication status, policy classification, and supported schema semantics. Unknown required information blocks only affected operations when possible.

## Identity and reproducibility
Source identity is content-addressed plus project association. Prefer documented operationId when unique and stable; otherwise derive an identity from normalized method/path with tracked rename mappings. Freeze names after review; do not rename existing tools because descriptions changed.

Canonical contract hashing must specify JSON key sorting, number handling, encoding, and exclusion of volatile timestamps. Generated source reproducibility excludes execution reports and timestamps. For ZIP reproducibility, normalize entry order, timestamps, modes, and newline conventions. Model reruns need not be identical; reproducibility is guaranteed from a frozen reviewed contract onward.

## SQLite model
Tables: projects, source_documents, document_blocks, extraction_runs, candidates, findings, overrides, contract_revisions, tool_plans, policy_revisions, jobs, job_events, artifacts, validation_runs, evaluation_runs, schema_migrations. Store large content-addressed bytes on disk and references in SQLite. Store no service credential values in these tables.

Foreign keys enabled; explicit migrations; transactional revision creation; optimistic revision checking for edits. Deletion must remove only owned artifacts no longer referenced by retained revisions. Backup DB and artifact manifest consistently. Do not use SQLite full-text search results as authoritative evidence unless their source offsets validate.

## Job lifecycle
QUEUED → RUNNING → SUCCEEDED, FAILED, CANCELLED, or NEEDS_REVIEW. NEEDS_REVIEW ends the current job; a new revision/job resumes after corrections. Workers renew leases. Expired RUNNING leases become INTERRUPTED, then an owner-controlled retry reuses valid checkpoints. CANCEL_REQUESTED is cooperative first; terminate child process groups after a grace period. Never mark partial output complete.

Job idempotency keys cover project, frozen input hashes, operation type, model/config version. Duplicate requests return the matching existing job. Retry extraction and generation safely; never automatically replay real external writes.

## Error envelope
Fields: code, user_message, retryable, stage, operation_id nullable, finding_ids, correlation_id, redacted_details. Distinguish DOCUMENT_UNREADABLE, MODEL_UNAVAILABLE, EXTRACTION_INVALID, CONTRACT_INCOMPLETE, FEATURE_UNSUPPORTED, POLICY_DENIED, AUTH_MISSING, UPSTREAM_RATE_LIMITED, UPSTREAM_FAILED, SANDBOX_UNAVAILABLE, CANCELLED, REVISION_CONFLICT. Avoid raw exception dumps in the user interface.

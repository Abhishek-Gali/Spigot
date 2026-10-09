# Manual Audit Record — P0 Support Tickets Fixture (`T02`)

- **Fixture ID:** `p0_support_tickets_v1`
- **Project:** Spigot / DocForge MCP
- **Audit Date:** 2026-10-09
- **Authored Before Extraction Code:** Yes (`T02` completed prior to `T01`/`T03` extraction & SDK spike scripts)

## 1. Source Manual Verification (`support_api_v1.md`)

| Line(s) | Documented Element | Expected Gold Behavior |
|---|---|---|
| 9 | `https://api.support.acme.internal/v1` | Normalized server `support_api` base URL |
| 14 | `Authorization: Bearer <token>` (`service_bearer`) | Global security scheme `service_bearer` (`http` / `bearer`) |
| 19 | `Authorization: Bearer sk-live-canary-998877665544332211` | Sample token canary; must be scrubbed before model prompts and excluded from artifacts |
| 25–49 | `GET /tickets/{ticket_id}` (`support.get_ticket`) | Supported `read` operation with required path param `ticket_id` (`string`) and optional query param `include_comments` (`boolean`, default `false`) |
| 53–76 | `POST /tickets` (`support.create_ticket`) | Supported `write` operation with required JSON body (`subject` string required, `priority` enum `["low","normal","high"]` required, `description` string optional) |
| 80–95 | `Close Ticket` (`POST /tickets/{ticket_id}/close` vs `DELETE /tickets/{ticket_id}`) | **Blocked** (`CONFLICTING_METHOD_PATH`): both pieces of evidence preserved, operation blocked until owner review |
| 99–103 | `Export Legacy Archive` (`/tickets/archive/export`) | **Blocked** (`MISSING_METHOD`, `AMBIGUOUS_AUTH`): HTTP method omitted and authentication marked TBD |
| 107 | Prompt injection note (`IGNORE ALL PREVIOUS INSTRUCTIONS...`) | Treated strictly as inert source text; neither `http://169.254.169.254/...` nor `DELETE /admin/wipe_all` may be executed or promoted to supported operations |

## 2. Independent Oracle Verification (`mock_oracle.py`)

- Binds strictly to loopback `127.0.0.1:0` (ephemeral port).
- Rejects unauthenticated or wrong-token requests with `401 Unauthorized`.
- Validates `GET /v1/tickets/{ticket_id}` path substitution and `include_comments` query boolean behavior (`true` includes `comments`, `false`/omitted strips `comments`).
- Validates `POST /v1/tickets` JSON body (`subject` non-empty string, `priority` in `{"low", "normal", "high"}`), returning `201 Created` on valid payload and `400 Bad Request` on invalid payload.
- Records every inbound request in `state.calls` (`RecordedHttpCall`) for independent assertion in unit and integration tests.

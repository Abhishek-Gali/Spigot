# Spigot (DocForge MCP) — Sample API Documentation Gallery

This directory contains 5 realistic, production-style API documentation files across all 4 formats supported by **Spigot (DocForge MCP)**. You can upload any of these files in **Step 1 (`1. Project & Import`)** of the Web Studio (`http://127.0.0.1:8000`)—or click the **1-Click Sample API Docs** buttons directly inside the UI.

## Included Sample Files

| File | Format | API Described | Extracted Endpoints |
|---|---|---|---|
| [`01_payments_api_manual.pdf`](01_payments_api_manual.pdf) | 3-Page Typeset PDF (`.pdf`) | **StripeFlow Payments & Treasury API (`v2.4`)** (`https://api.stripeflow.dev`) | **7 endpoints:** `GET /v1/customers`, `GET /v1/customers/{customer_id}`, `GET /v1/charges`, `GET /v1/charges/{charge_id}`, `POST /v1/charges`, `POST /v1/charges/{charge_id}/refunds`, `DELETE /v1/customers/{customer_id}` |
| [`02_support_tickets_api.md`](02_support_tickets_api.md) | Markdown Manual (`.md`) | **HelpDesk Cloud — Customer Support & SLA Triage API (`v2.1`)** (`https://api.helpdesk.dev`) | **7 endpoints:** `GET /v1/customers`, `GET /v1/customers/{customer_id}`, `GET /v1/tickets`, `GET /v1/tickets/{ticket_id}`, `POST /v1/tickets`, `POST /v1/tickets/{ticket_id}/comments`, `DELETE /v1/tickets/{ticket_id}` |
| [`03_incident_response_api.html`](03_incident_response_api.html) | Styled Developer Portal HTML (`.html`) | **OpsGuard Cloud — Incident & On-Call API (`v1`)** (`https://api.opsguard.dev`) | **5 endpoints:** `GET /v1/services`, `GET /v1/incidents`, `GET /v1/incidents/{incident_id}`, `POST /v1/incidents`, `DELETE /v1/incidents/{incident_id}` |
| [`04_inventory_openapi_3_0.yaml`](04_inventory_openapi_3_0.yaml) | OpenAPI 3.0.3 Spec (`.yaml`) | **Global Warehouse & Order Fulfillment API (`v2.0.0`)** (`https://api.fulfillment.dev/v1`) | **6 endpoints:** `GET /items`, `POST /items`, `GET /items/{sku}`, `POST /items/{sku}/adjust`, `POST /shipments`, `DELETE /shipments/{shipment_id}` |
| [`05_flagship_review_demo.md`](05_flagship_review_demo.md) | Markdown Manual with 1 Blocker (`.md`) | **FleetCloud Kubernetes & Node Orchestrator API (`v1.4`)** (`https://api.fleetcloud.dev`) | **5 endpoints:** 4 ready (`GET /v1/clusters`, `GET /v1/clusters/{cluster_id}`, `POST /v1/clusters`, `DELETE /v1/clusters/{cluster_id}`) + **1 intentionally ambiguous endpoint (`/v1/clusters/{cluster_id}/drain`)** that triggers a `MISSING_METHOD` blocker in Step 3 so you can test 1-click override resolution! |

---

## Side-by-Side: What Makes a Document Valid vs. Blocked?

Spigot compiles **concrete HTTP REST API documentation** into MCP tools. It fails closed (`NOT_API_DOCUMENTATION`) when given documents that do not describe actual HTTP endpoints.

### ✅ Valid Input (HTTP REST API Reference)
```markdown
# StripeFlow Payments & Treasury REST API (v2.4)
Base URL: `https://api.stripeflow.dev`
Authentication: Send `Authorization: Bearer <token>` on all requests.

## Retrieve Payment Charge
`GET /v1/charges/{charge_id}`
- `charge_id` (path, string, required): Unique payment charge identifier (`ch_...`)

## Create Payment Charge
`POST /v1/charges`

| Field | Location | Type | Required | Description |
|---|---|---|---|---|
| `customer_id` | body | string | yes | Customer identifier to bill |
| `amount_cents` | body | integer | yes | Charge amount in minor currency units |
| `currency` | body | string | yes | Three-letter ISO-4217 currency code |
```

### ❌ Invalid Input (Fails Closed with `NOT_API_DOCUMENTATION`)
1. **Specification Metaschemas / Framework Standards** (e.g., `microprofile-openapi-spec-4.0-RC3.pdf`):
   - Documents how Java annotations like `@Operation(summary = "...")` or `@APIResponse` work in Eclipse MicroProfile, rather than documenting a real HTTP server's endpoints.
2. **Language-Specific Client SDK Manuals** (e.g., `docs-python-telegram-bot.pdf`):
   - Documents Python classes (`await bot.send_message(chat_id, text)`) without HTTP methods (`GET`/`POST`), URL paths, or raw HTTP headers.
3. **Marketing / Overview Pages** (e.g., "What is OpenAPI?"):
   - Discusses API concepts in general without defining a concrete Base URL, authentication scheme, and endpoint catalog.

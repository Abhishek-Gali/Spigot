# Spigot (DocForge MCP) — Sample API Documentation Gallery

This directory contains ready-to-import API documentation files across all 4 formats supported by **Spigot (DocForge MCP)**. You can upload any of these files in **Step 1 (`1. Project & Import`)** of the Web Studio (`http://127.0.0.1:8000`)—or click the **1-Click Sample Loader** buttons directly in the UI.

## Included Sample Files

| File | Format | API Described | Extracted Endpoints |
|---|---|---|---|
| [`01_payments_api_manual.pdf`](01_payments_api_manual.pdf) | Multi-page Text PDF (`.pdf`) | **Acme Payments & Refunds API** (`https://api.payments.internal`) | `GET /v1/charges`, `GET /v1/charges/{charge_id}`, `POST /v1/charges`, `DELETE /v1/charges/{charge_id}` |
| [`02_support_tickets_api.md`](02_support_tickets_api.md) | Markdown Manual (`.md`) | **Customer Support Tickets API** (`https://api.support.internal`) | `GET /v1/tickets`, `GET /v1/tickets/{ticket_id}`, `POST /v1/tickets`, `DELETE /v1/tickets/{ticket_id}` |
| [`03_incident_response_api.html`](03_incident_response_api.html) | Saved Static HTML (`.html`) | **Cloud Incident Response API** (`https://api.incidents.internal`) | `GET /v1/incidents`, `GET /v1/incidents/{incident_id}`, `POST /v1/incidents` |
| [`04_inventory_openapi_3_0.yaml`](04_inventory_openapi_3_0.yaml) | OpenAPI 3.0 Spec (`.yaml`) | **Warehouse Inventory Service API** (`https://api.inventory.internal/v1`) | `GET /items`, `POST /items`, `GET /items/{sku}` |

---

## Side-by-Side: What Makes a Document Valid vs. Blocked?

Spigot compiles **concrete HTTP REST API documentation** into MCP tools. It fails closed (`NOT_API_DOCUMENTATION`) when given documents that do not describe actual HTTP endpoints.

### ✅ Valid Input (HTTP REST API Reference)
```markdown
# Acme Payments API
Base URL: `https://api.payments.internal`
Authentication: Send `Authorization: Bearer <token>` on all requests.

## Create Charge
`POST /v1/charges`

| Field | Location | Type | Required | Description |
|---|---|---|---|---|
| `amount_cents` | body | integer | yes | Charge amount in cents |
| `currency` | body | string | yes | Three-letter ISO currency code |
```

### ❌ Invalid Input (Fails Closed with `NOT_API_DOCUMENTATION`)
1. **Specification Metaschemas / Framework Standards** (e.g., `microprofile-openapi-spec-4.0-RC3.pdf`):
   - Documents how Java annotations like `@Operation(summary = "...")` or `@APIResponse` work in Eclipse MicroProfile, rather than documenting a real HTTP server's endpoints.
2. **Language-Specific Client SDK Manuals** (e.g., `docs-python-telegram-bot.pdf`):
   - Documents Python classes (`await bot.send_message(chat_id, text)`) without HTTP methods (`GET`/`POST`), URL paths, or raw HTTP headers.
3. **Marketing / Overview Pages** (e.g., "What is OpenAPI?"):
   - Discusses API concepts in general without defining a concrete Base URL, authentication scheme, and endpoint catalog.

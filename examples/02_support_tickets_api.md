# HelpDesk Cloud — Customer Support & SLA Triage REST API (v2.1)

Base URL: `https://api.helpdesk.dev`

## Overview & Authentication

The HelpDesk Cloud REST API allows engineering and support operations teams to query customer organizations, inspect support tickets, post triage updates, and purge spam records.

Authentication: Send `X-API-Key: <your-api-key>` on every HTTP request. All request and response bodies are encoded as `application/json`.

---

## Customer Directory Endpoints

### List Customer Accounts

`GET /v1/customers`

Returns a paginated directory of customer accounts and their SLA tier.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `tier` | query | string | no | Filter by SLA tier (`free`, `pro`, `enterprise`) |
| `limit` | query | integer | no | Maximum number of customer records to return (1-100) |

### Get Customer Account

`GET /v1/customers/{customer_id}`

Fetches full organization metadata, SLA policy, and primary contact for a customer ID.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `customer_id` | path | string | yes | Unique customer identifier (`cust_...`) |

---

## Support Ticket Endpoints

### List Support Tickets

`GET /v1/tickets`

Queries customer support tickets with optional filtering by status, priority, or customer.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `status` | query | string | no | Filter tickets by status (`open`, `pending`, `resolved`, `closed`) |
| `priority` | query | string | no | Filter by severity (`low`, `normal`, `high`, `urgent`) |
| `customer_id` | query | string | no | Filter tickets belonging to a specific customer ID |

### Get Support Ticket by ID

`GET /v1/tickets/{ticket_id}`

Retrieves full conversation history, SLA timers, and assignee details for a single ticket.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `ticket_id` | path | string | yes | Unique support ticket identifier (`tkt_...`) |

### Create Support Ticket

`POST /v1/tickets`

Creates a new support ticket linked to an existing customer account.

| Field | Location | Type | Required | Description |
|---|---|---|---|---|
| `customer_id` | body | string | yes | Customer identifier (`cust_...`) opening the ticket |
| `subject` | body | string | yes | Concise summary of the reported issue |
| `priority` | body | string | yes | Initial triage priority (`low`, `normal`, `high`, `urgent`) |
| `description` | body | string | no | Detailed reproduction steps or error logs |

### Post Ticket Triage Comment

`POST /v1/tickets/{ticket_id}/comments`

Appends an internal engineering note or public reply to an existing support ticket.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `ticket_id` | path | string | yes | Target support ticket identifier (`tkt_...`) |
| `body` | body | string | yes | Markdown-formatted comment text |
| `public` | body | boolean | no | Whether the comment is visible to the end customer |

### Delete Support Ticket

`DELETE /v1/tickets/{ticket_id}`

Permanently purges a support ticket and its attachment history (compliance/spam removal only).

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `ticket_id` | path | string | yes | Unique support ticket identifier to permanently delete |

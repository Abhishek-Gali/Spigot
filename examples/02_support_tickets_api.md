# Customer Support Tickets REST API (v1)

Base URL: `https://api.support.internal`

## Authentication

All requests to the Customer Support Tickets API require an API key header:
Send `X-API-Key: <your-api-key>` on every HTTP request.

## Endpoints

### List Support Tickets

`GET /v1/tickets`

Returns a paginated list of customer support tickets.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `status` | query | string | no | Filter tickets by status (`open`, `pending`, `closed`) |
| `limit` | query | integer | no | Maximum number of tickets to return (1-100) |

### Get Ticket by ID

`GET /v1/tickets/{ticket_id}`

Fetches full details for a single support ticket.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `ticket_id` | path | string | yes | Unique support ticket identifier |

### Create Support Ticket

`POST /v1/tickets`

Creates a new customer support ticket.

| Field | Location | Type | Required | Description |
|---|---|---|---|---|
| `subject` | body | string | yes | Short summary of the customer issue |
| `priority` | body | string | no | Ticket priority (`low`, `normal`, `high`, `urgent`) |

### Delete Support Ticket

`DELETE /v1/tickets/{ticket_id}`

Permanently deletes a support ticket record.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `ticket_id` | path | string | yes | Unique support ticket identifier to delete |

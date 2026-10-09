# FleetCloud Kubernetes & Node Orchestrator REST API (v1.4)

Base URL: `https://api.fleetcloud.dev`

## Authentication

All requests require a Bearer token in the `Authorization` header:
Send `Authorization: Bearer <token>` on all requests.

## Cluster Operations

### List Kubernetes Clusters

`GET /v1/clusters`

Returns all managed Kubernetes clusters in the organization.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `region` | query | string | no | Filter clusters by cloud region (`us-east-1`, `eu-west-1`) |

### Get Cluster Details

`GET /v1/clusters/{cluster_id}`

Fetches control-plane version, node pools, and health status for a single cluster.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `cluster_id` | path | string | yes | Unique cluster identifier (`cls_...`) |

### Provision New Cluster

`POST /v1/clusters`

Provisions a new managed Kubernetes cluster in the specified region.

| Field | Location | Type | Required | Description |
|---|---|---|---|---|
| `name` | body | string | yes | Human-readable cluster name |
| `region` | body | string | yes | Target deployment region |
| `node_count` | body | integer | yes | Initial worker node count (1-50) |

### Drain Cluster Nodes (Ambiguous Method Demo)

Endpoint path: `/v1/clusters/{cluster_id}/drain`

Cordons and drains workloads from all worker nodes in the cluster prior to maintenance.
*(Note for Reviewer: This section intentionally omits the HTTP verb `POST` so you can see Spigot flag `MISSING_METHOD` in Step 3 and resolve it in 1 click!)*

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `cluster_id` | path | string | yes | Target cluster identifier (`cls_...`) |
| `grace_period_sec` | body | integer | no | Pod eviction grace period in seconds |

### Decommission Cluster

`DELETE /v1/clusters/{cluster_id}`

Tears down a cluster and releases all attached compute and load-balancer resources.

| Parameter | Location | Type | Required | Description |
|---|---|---|---|---|
| `cluster_id` | path | string | yes | Unique cluster identifier to decommission |

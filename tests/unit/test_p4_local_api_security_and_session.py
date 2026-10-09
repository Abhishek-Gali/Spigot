"""Phase P4 Unit Tests: Local API Security Guards, Session Bootstrap, and Job Lifecycle (T19)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.api import LocalApiConfig, SpigotApiClient, SpigotApiError, create_local_app


def test_t19_ui_assets_session_bootstrap_and_security_guards(tmp_path: Path) -> None:
    config = LocalApiConfig(
        workspace_dir=tmp_path / "ws",
        capability_token="test-secret-cap-token-12345",
    )
    app = create_local_app(config)
    raw_client = TestClient(app)

    # 1. Local UI assets are served with nosniff and DENY frame headers
    idx_res = raw_client.get("/")
    assert idx_res.status_code == 200
    assert "Spigot" in idx_res.text
    assert "DocForge MCP" in idx_res.text
    assert idx_res.headers["X-Content-Type-Options"] == "nosniff"
    assert idx_res.headers["X-Frame-Options"] == "DENY"

    js_res = raw_client.get("/static/app.js")
    assert js_res.status_code == 200
    css_res = raw_client.get("/static/styles.css")
    assert css_res.status_code == 200

    # Path traversal in static asset route is rejected
    trav_res = raw_client.get("/static/..%5Cpyproject.toml")
    assert trav_res.status_code in {400, 404}

    # 2. DNS rebinding Host header is rejected with 403 POLICY_DENIED
    rebind_res = raw_client.get(
        "/api/session",
        headers={"Host": "evil-rebind.attacker.example"},
    )
    assert rebind_res.status_code == 403
    assert rebind_res.json()["code"] == "POLICY_DENIED"

    # 3. Cross-origin Origin header and Sec-Fetch-Site: cross-site are rejected
    cors_res = raw_client.post(
        "/api/projects",
        json={"name": "Cross Origin Attack"},
        headers={
            "Origin": "https://evil.example",
            "X-Spigot-Token": config.capability_token,
        },
    )
    assert cors_res.status_code == 403
    assert cors_res.json()["code"] == "POLICY_DENIED"

    fetch_site_res = raw_client.post(
        "/api/projects",
        json={"name": "Fetch Site Attack"},
        headers={
            "Sec-Fetch-Site": "cross-site",
            "X-Spigot-Token": config.capability_token,
        },
    )
    assert fetch_site_res.status_code == 403
    assert fetch_site_res.json()["code"] == "POLICY_DENIED"

    # 4. Missing or invalid capability token on state-changing endpoint is rejected
    no_tok_res = raw_client.post("/api/projects", json={"name": "No Token"})
    assert no_tok_res.status_code == 403
    assert no_tok_res.json()["code"] == "POLICY_DENIED"

    bad_tok_res = raw_client.post(
        "/api/projects",
        json={"name": "Bad Token"},
        headers={"X-Spigot-Token": "wrong-token"},
    )
    assert bad_tok_res.status_code == 403
    assert bad_tok_res.json()["code"] == "POLICY_DENIED"


def test_t19_typed_client_offline_fetch_denial_jobs_and_project_deletion(
    tmp_path: Path,
) -> None:
    config = LocalApiConfig(workspace_dir=tmp_path / "ws_jobs")
    app = create_local_app(config)
    raw_client = TestClient(app)
    client = SpigotApiClient(raw_client)

    session = client.bootstrap_session()
    assert session["brandings"] == ["Spigot", "DocForge MCP"]
    assert session["default_network_profile"] == "STRICT_OFFLINE"
    assert session["sandbox_available"] is False

    models_info = client.get_local_models()
    assert models_info["remote_catalog_queried"] is False

    proj = client.create_project("Offline Job Test")
    project_id = proj["project_id"]
    assert proj["current_revision"] == 1

    # Remote URL acquisition is strictly denied in STRICT_OFFLINE mode
    with pytest.raises(SpigotApiError) as exc_info:
        client.fetch_remote_url(
            project_id,
            "https://example.com/api-docs.md",
            explicit_connected_permission=True,
        )
    assert exc_info.value.status_code == 403
    assert exc_info.value.envelope.code == "POLICY_DENIED"

    # Upload a local Markdown source and enqueue a deferred extraction job to test cancellation & events
    upload_res = client.upload_sources(
        project_id,
        [
            (
                "guide.md",
                (
                    b"# Inventory\nBase URL: http://127.0.0.1:19999\n"
                    b"### GET /v1/items\nPublic endpoint: no authentication.\n"
                ),
            )
        ],
    )
    assert len(upload_res["source_ids"]) == 1

    deferred_job = client.extract_project(project_id, defer_execution=True)
    job_id = deferred_job["job_id"]
    assert deferred_job["status"] == "QUEUED"

    job_status = client.get_job(job_id)
    assert job_status["job_id"] == job_id
    assert job_status["status"] == "QUEUED"

    cancelled = client.cancel_job(job_id)
    assert cancelled["status"] == "CANCELLED"

    events = client.get_job_events(job_id, cursor=0)
    event_types = [e["event_type"] for e in events["events"]]
    assert "JOB_QUEUED" in event_types
    assert "CANCEL_REQUESTED" in event_types

    # Reference-aware project deletion preview vs confirmed deletion
    preview_del = client.delete_project(project_id, preview=True)
    assert preview_del["preview"] is True
    assert preview_del["source_count"] == 1

    confirm_del = client.delete_project(project_id, confirm=True)
    assert confirm_del["deleted_project_id"] == project_id
    assert len(confirm_del["removed_artifacts"]) == 1

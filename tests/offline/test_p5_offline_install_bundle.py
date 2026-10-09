"""Phase P5 Prepared Offline Install Bundle Verification Tests (T26).

Verifies:
- `prepare_offline_bundle` creates a deterministic, platform-qualified offline bundle
  (`.zip` and directory) containing `OFFLINE_BUNDLE_MANIFEST.json`, `LICENSE_NOTICES.txt`,
  `requirements-offline.lock`, `install_offline.py`, and the standalone `spigot_runtime` package.
- Tampering with any file inside the offline bundle causes `install_offline.py` to fail closed.
- `verify_clean_offline_install` unpacks an exported server `.zip` and the offline bundle `.zip`
  into an isolated temporary directory outside the Spigot repository and executes MCP `initialize`,
  `list_tools`, and a live local mock read call over stdio with `PIP_NO_INDEX=1`.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fixtures.p0_support_tickets.mock_oracle import SupportTicketsMockServer
from packages.core.pipeline import RawDocumentInput, compile_documentation_bundle
from packages.core.planning import RuntimePolicy, create_tool_plan
from packages.templates.generator import (
    export_reproducible_zip,
    generate_server_package,
)
from packages.templates.offline_bundle import (
    prepare_offline_bundle,
    verify_clean_offline_install,
)


@pytest.mark.anyio
async def test_t26_prepared_offline_bundle_determinism_tamper_check_and_clean_stdio_install(
    tmp_path: Path,
) -> None:
    # 1. Build offline bundle twice and verify deterministic manifest hash and ZIP SHA-256
    bundle_out_1 = tmp_path / "bundle_build_1"
    bundle_out_2 = tmp_path / "bundle_build_2"

    b1 = prepare_offline_bundle(bundle_out_1, bundle_id="spigot_offline_win64")
    b2 = prepare_offline_bundle(bundle_out_2, bundle_id="spigot_offline_win64")

    assert b1.manifest.bundle_hash == b2.manifest.bundle_hash
    assert b1.zip_sha256 == b2.zip_sha256
    assert (b1.bundle_dir / "LICENSE_NOTICES.txt").exists()
    assert (b1.bundle_dir / "requirements-offline.lock").exists()
    assert (b1.bundle_dir / "vendor" / "spigot_runtime" / "engine.py").exists()
    assert any(d.name == "mcp" for d in b1.manifest.pinned_distributions)

    # 2. Tampering with a file in the unpacked bundle causes install_offline.py to fail closed
    tampered_dir = tmp_path / "tampered_bundle"
    shutil.copytree(b1.bundle_dir, tampered_dir)
    engine_py = tampered_dir / "vendor" / "spigot_runtime" / "engine.py"
    engine_py.write_bytes(engine_py.read_bytes() + b"\n# corrupted\n")

    proc = subprocess.run(
        [sys.executable, str(tampered_dir / "install_offline.py"), str(tampered_dir)],
        capture_output=True,
        text=True,
        timeout=10.0,
        check=False,
    )
    assert proc.returncode != 0
    assert "Checksum mismatch" in proc.stderr

    # 3. Compile Support Tickets manual and export a standalone MCP server ZIP
    with SupportTicketsMockServer(expected_bearer_token="offline-bundle-token") as oracle:
        md_bytes = (
            f"# Support Tickets API\n\n"
            f"Base URL: `{oracle.base_url}`\n\n"
            "Authentication: Send `Authorization: Bearer <token>` on all requests.\n\n"
            "## Get Ticket\n\n"
            "`GET /tickets/{ticket_id}`\n\n"
            "| Parameter | Location | Type | Required | Description |\n"
            "|---|---|---|---|---|\n"
            "| `ticket_id` | path | string | yes | Ticket ID |\n"
        ).encode()

        policy = RuntimePolicy(
            id="pol_offline_bundle_test",
            mode="read_only",
            network_profile="STRICT_OFFLINE",
        )
        comp = compile_documentation_bundle(
            [
                RawDocumentInput(
                    source_id="src_support",
                    filename="support_api.md",
                    raw_bytes=md_bytes,
                )
            ],
            contract_id="ct_offline_bundle",
            project_id="proj_offline_bundle",
            policy=policy,
            use_local_model=False,
        )
        tool_plan = create_tool_plan(comp.contract, policy)

        pkg_dir = tmp_path / "server_pkg"
        gen_manifest = generate_server_package(
            comp.contract,
            tool_plan,
            policy,
            pkg_dir,
            package_slug="offline_tickets_server",
        )
        server_zip = tmp_path / "offline_tickets_server.zip"
        export_reproducible_zip(pkg_dir, server_zip)

        isolated_dir = tmp_path / "clean_machine_rehearsal"
        result = await verify_clean_offline_install(
            server_zip_path=server_zip,
            offline_bundle_zip_path=b1.zip_path,
            isolated_target_dir=isolated_dir,
            package_slug="offline_tickets_server",
            runtime_env_vars={
                "SPIGOT_CRED_BEARER_AUTH": "offline-bundle-token",
            },
            call_tool_name="get_tickets_ticket_id",
            call_tool_args={"ticket_id": "tkt_101"},
        )

    assert result["bundle_hash"] == b1.manifest.bundle_hash
    assert result["server_manifest_hash"] == gen_manifest.manifest_hash
    assert "get_tickets_ticket_id" in result["tool_names"]
    assert result["call_output"] is not None
    assert result["call_output"]["is_error"] is False
    assert result["call_output"]["payload"]["status_code"] == 200
    assert result["call_output"]["payload"]["data"]["id"] == "tkt_101"

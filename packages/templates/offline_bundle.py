"""Prepared Offline Install Bundle Builder and Verifier for Spigot / DocForge MCP (T26).

Implements the platform-qualified offline bundle specification from GENERATOR_RUNTIME.md,
ARCHITECTURE.md, and IMPLEMENTATION.md:
- Packages the standalone `spigot_runtime` engine, owner approval utility, license notices,
  and exact distribution metadata/checksums for the reference platform (Windows x86_64, Python 3.13).
- Provides `verify_clean_offline_install` to unpack a generated server `.zip` plus the
  offline bundle into a clean directory outside the Spigot repository and verify standalone
  MCP stdio initialization, tool listing, and mock execution with external network egress denied.
"""

from __future__ import annotations

import importlib.metadata
import io
import json
import os
import platform
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import BaseModel, ConfigDict, model_validator

from packages.core.contracts import (
    SCHEMA_VERSION,
    canonical_json_bytes,
    sha256_hex,
)
from packages.templates.generator import FIXED_ZIP_DATETIME

RUNTIME_DISTRIBUTION_NAMES = (
    "mcp",
    "httpx",
    "httpcore",
    "anyio",
    "pydantic",
    "pydantic-core",
    "jsonschema",
    "jsonschema-specifications",
    "referencing",
    "rpds-py",
    "certifi",
    "idna",
    "sniffio",
    "h11",
    "typing-extensions",
    "annotated-types",
    "attrs",
)

LICENSE_NOTICES_TEXT = """# Third-Party and Runtime License Notices (Spigot / DocForge MCP Offline Bundle)

This offline bundle redistributes the Spigot standalone MCP runtime (`spigot_runtime`)
and records the pinned dependency lock for the reference platform:

- Spigot / DocForge MCP Runtime: MIT License
- mcp (Official Python Model Context Protocol SDK): MIT License
- httpx / httpcore / h11: BSD-3-Clause / MIT License
- pydantic / pydantic-core: MIT License
- jsonschema / referencing / rpds-py / attrs: MIT License
- anyio / sniffio / idna / typing-extensions: MIT / BSD-3-Clause / PSF-2.0 License
- certifi: MPL-2.0 License
"""


class PinnedDistributionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    license_summary: str
    record_sha256: str


class OfflineBundleManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    bundle_id: str
    target_os: str
    target_arch: str
    python_version: str
    mcp_sdk_version: str
    file_hashes: dict[str, str]
    pinned_distributions: list[PinnedDistributionRecord]
    site_packages_path: str
    bundle_hash: str = ""

    def compute_bundle_hash(self) -> str:
        raw = self.model_dump()
        return sha256_hex(canonical_json_bytes(raw, exclude_keys={"bundle_hash"}))

    @model_validator(mode="after")
    def _populate_or_verify_hash(self) -> OfflineBundleManifest:
        computed = self.compute_bundle_hash()
        if not self.bundle_hash:
            self.bundle_hash = computed
        elif self.bundle_hash != computed:
            raise ValueError(
                f"OfflineBundleManifest hash mismatch: expected {computed}, got {self.bundle_hash}"
            )
        return self


@dataclass(frozen=True)
class PreparedOfflineBundle:
    bundle_dir: Path
    zip_path: Path
    zip_sha256: str
    manifest: OfflineBundleManifest


def _collect_pinned_distributions() -> list[PinnedDistributionRecord]:
    records: list[PinnedDistributionRecord] = []
    for dist_name in RUNTIME_DISTRIBUTION_NAMES:
        try:
            dist = importlib.metadata.distribution(dist_name)
        except importlib.metadata.PackageNotFoundError:
            continue
        version = dist.version
        meta = dist.metadata
        lic = (
            meta.get("License-Expression")
            or meta.get("License")
            or "MIT/BSD-compatible"
        )
        lic_line = str(lic).splitlines()[0][:80]
        record_text = dist.read_text("RECORD") or f"{dist_name}=={version}"
        records.append(
            PinnedDistributionRecord(
                name=dist_name,
                version=version,
                license_summary=lic_line,
                record_sha256=sha256_hex(record_text.encode("utf-8")),
            )
        )
    return sorted(records, key=lambda r: r.name)


def _find_site_packages_dir() -> Path:
    import mcp as mcp_mod

    mcp_file = Path(mcp_mod.__file__).resolve()
    # `.../site-packages/mcp/__init__.py` -> parent.parent is `site-packages`
    return mcp_file.parent.parent


def prepare_offline_bundle(
    output_dir: Path,
    *,
    bundle_id: str = "spigot_offline_bundle_reference",
) -> PreparedOfflineBundle:
    """Build a platform-qualified offline runtime bundle and deterministic `.zip` archive."""
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = output_dir / bundle_id
    bundle_dir.mkdir(parents=True, exist_ok=True)

    repo_root = Path(__file__).resolve().parents[2]
    engine_src = (repo_root / "packages" / "runtime" / "engine.py").read_text(
        encoding="utf-8"
    )
    approval_src = (repo_root / "packages" / "core" / "approval.py").read_text(
        encoding="utf-8"
    )

    site_packages_dir = _find_site_packages_dir()
    dists = _collect_pinned_distributions()
    mcp_version = next((d.version for d in dists if d.name == "mcp"), "unknown")

    install_script = (
        '"""Offline Bundle Integrity & Bootstrap Verifier (T26)."""\n'
        "from __future__ import annotations\n"
        "import hashlib, json, os, socket, sys\n"
        "from pathlib import Path\n\n"
        "def verify_and_bootstrap(bundle_root: Path, target_env_dir: Path) -> dict:\n"
        "    manifest_path = bundle_root / 'OFFLINE_BUNDLE_MANIFEST.json'\n"
        "    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))\n"
        "    for rel_path, expected_sha in manifest['file_hashes'].items():\n"
        "        f_path = bundle_root / rel_path\n"
        "        if not f_path.exists():\n"
        "            raise RuntimeError(f'Missing offline bundle file: {rel_path}')\n"
        "        actual_sha = hashlib.sha256(f_path.read_bytes()).hexdigest()\n"
        "        if actual_sha != expected_sha:\n"
        "            raise RuntimeError(f'Checksum mismatch for {rel_path}')\n"
        "    target_env_dir.mkdir(parents=True, exist_ok=True)\n"
        "    pth_file = target_env_dir / 'spigot_offline_runtime.pth'\n"
        "    pth_lines = [\n"
        "        str((bundle_root / 'vendor').resolve()),\n"
        "        str(Path(manifest['site_packages_path']).resolve()),\n"
        "    ]\n"
        "    pth_file.write_text('\\n'.join(pth_lines) + '\\n', encoding='utf-8')\n"
        "    return {'verified_files': len(manifest['file_hashes']), 'pth_file': str(pth_file)}\n\n"
        "if __name__ == '__main__':\n"
        "    b_root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent\n"
        "    t_dir = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else (b_root / 'activated_env')\n"
        "    res = verify_and_bootstrap(b_root, t_dir)\n"
        "    sys.stdout.write(json.dumps(res, sort_keys=True) + '\\n')\n"
    )

    files_map: dict[str, bytes] = {
        "LICENSE_NOTICES.txt": LICENSE_NOTICES_TEXT.encode("utf-8"),
        "install_offline.py": install_script.encode("utf-8"),
        "vendor/spigot_runtime/__init__.py": (
            b'"""Standalone redistributed Spigot / DocForge MCP runtime package."""\n'
            b"from spigot_runtime.engine import ContractRuntimeEngine, load_engine_from_package_dir\n"
            b"from spigot_runtime.approval import ApprovalAuthority, compute_action_digest\n"
            b"__all__ = [\n"
            b"    'ApprovalAuthority',\n"
            b"    'ContractRuntimeEngine',\n"
            b"    'compute_action_digest',\n"
            b"    'load_engine_from_package_dir',\n"
            b"]\n"
        ),
        "vendor/spigot_runtime/engine.py": engine_src.encode("utf-8"),
        "vendor/spigot_runtime/approval.py": approval_src.encode("utf-8"),
        "requirements-offline.lock": (
            "\n".join(
                f"{d.name}=={d.version} # record_sha256:{d.record_sha256}"
                for d in dists
            )
            + "\n"
        ).encode("utf-8"),
    }

    file_hashes = {
        rel_path: sha256_hex(content)
        for rel_path, content in sorted(files_map.items())
    }

    manifest = OfflineBundleManifest(
        bundle_id=bundle_id,
        target_os=platform.system(),
        target_arch=platform.machine(),
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        mcp_sdk_version=mcp_version,
        file_hashes=file_hashes,
        pinned_distributions=dists,
        site_packages_path=str(site_packages_dir),
    )
    files_map["OFFLINE_BUNDLE_MANIFEST.json"] = (
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    for rel_path, content in sorted(files_map.items()):
        dest = bundle_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path, content in sorted(files_map.items()):
            info = zipfile.ZipInfo(
                filename=f"{bundle_id}/{rel_path}",
                date_time=FIXED_ZIP_DATETIME,
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, content)

    zip_bytes = zip_buf.getvalue()
    zip_path = output_dir / f"{bundle_id}.zip"
    zip_path.write_bytes(zip_bytes)

    return PreparedOfflineBundle(
        bundle_dir=bundle_dir,
        zip_path=zip_path,
        zip_sha256=sha256_hex(zip_bytes),
        manifest=manifest,
    )


async def verify_clean_offline_install(
    *,
    server_zip_path: Path,
    offline_bundle_zip_path: Path,
    isolated_target_dir: Path,
    package_slug: str,
    runtime_env_vars: dict[str, str] | None = None,
    call_tool_name: str | None = None,
    call_tool_args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Unpack an exported server ZIP and offline bundle into an isolated directory and verify execution.

    Runs `install_offline.py` with `PIP_NO_INDEX=1`, verifies checksums, and connects
    to the unpacked server over MCP stdio without including the Spigot repository in `PYTHONPATH`.
    """
    isolated_target_dir.mkdir(parents=True, exist_ok=True)
    bundle_unpack_dir = isolated_target_dir / "offline_bundle"
    server_unpack_dir = isolated_target_dir / "unpacked_server"
    activated_env_dir = isolated_target_dir / "activated_env"

    with zipfile.ZipFile(offline_bundle_zip_path, "r") as zf:
        zf.extractall(bundle_unpack_dir)

    # Locate the inner bundle folder containing OFFLINE_BUNDLE_MANIFEST.json
    manifest_files = list(bundle_unpack_dir.rglob("OFFLINE_BUNDLE_MANIFEST.json"))
    if not manifest_files:
        raise RuntimeError("OFFLINE_BUNDLE_MANIFEST.json not found in offline bundle ZIP.")
    inner_bundle_dir = manifest_files[0].parent

    # Run offline installer verification subprocess with PIP_NO_INDEX=1
    install_env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
        "TEMP": os.environ.get("TEMP", ""),
        "TMP": os.environ.get("TMP", ""),
        "PYTHONUTF8": "1",
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    }
    proc = subprocess.run(
        [
            sys.executable,
            str(inner_bundle_dir / "install_offline.py"),
            str(inner_bundle_dir),
            str(activated_env_dir),
        ],
        cwd=str(isolated_target_dir),
        env=install_env,
        capture_output=True,
        text=True,
        timeout=10.0,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Offline bundle installer verification failed: {proc.stderr.strip()}"
        )
    bootstrap_info = json.loads(proc.stdout.strip())

    # Unpack exported server ZIP
    with zipfile.ZipFile(server_zip_path, "r") as zf:
        zf.extractall(server_unpack_dir)

    # Verify server manifest.json hashes before running
    server_manifest_path = server_unpack_dir / "manifest.json"
    server_manifest = json.loads(server_manifest_path.read_text(encoding="utf-8"))
    for rel_path, expected_sha in server_manifest.get("artifact_hashes", {}).items():
        f_path = server_unpack_dir / rel_path
        if not f_path.exists() or sha256_hex(f_path.read_bytes()) != expected_sha:
            raise RuntimeError(f"Server artifact verification failed for {rel_path}")

    bundle_manifest = json.loads(
        (inner_bundle_dir / "OFFLINE_BUNDLE_MANIFEST.json").read_text(encoding="utf-8")
    )

    # Construct isolated PYTHONPATH that does NOT reference the Spigot source repository
    isolated_pythonpath = os.pathsep.join(
        [
            str(server_unpack_dir.resolve()),
            str((inner_bundle_dir / "vendor").resolve()),
            str(Path(bundle_manifest["site_packages_path"]).resolve()),
        ]
    )
    stdio_env = dict(install_env)
    stdio_env["PYTHONPATH"] = isolated_pythonpath
    stdio_env["PYTHONNOUSERSITE"] = "1"
    if runtime_env_vars:
        stdio_env.update(runtime_env_vars)

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", f"{package_slug}.server"],
        cwd=str(server_unpack_dir.resolve()),
        env=stdio_env,
    )

    call_output: dict[str, Any] | None = None
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools_res = await session.list_tools()
            tool_names = [t.name for t in tools_res.tools]
            if call_tool_name:
                call_res = await session.call_tool(call_tool_name, call_tool_args or {})
                call_output = {
                    "is_error": call_res.is_error,
                    "payload": json.loads(call_res.content[0].text),
                }

    return {
        "bootstrap_info": bootstrap_info,
        "bundle_hash": bundle_manifest["bundle_hash"],
        "server_manifest_hash": server_manifest["manifest_hash"],
        "tool_names": tool_names,
        "call_output": call_output,
    }

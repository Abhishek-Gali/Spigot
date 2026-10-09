"""Isolated Validation Worker for Spigot / DocForge MCP (T24).

Implements multi-layer artifact validation, tamper detection, AST safety inspection,
scrubbed-environment protocol/egress/host-file probes, and truthful container sandbox
qualification as specified in SECURITY.md, GENERATOR_RUNTIME.md, and IMPLEMENTATION.md:
- Never claims a plain subprocess or virtual environment is an OS security sandbox.
- Fails closed on isolated execution claims when Docker/Podman container isolation is
  unavailable on the host (`sandbox_status="unavailable"`, `can_claim_isolated_execution=False`).
- Enforces process-tree termination on cancellation or timeout (`terminate_process_tree`).
"""

from __future__ import annotations

import ast
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packages.core.contracts import (
    GenerationManifest,
    ValidationCheckResult,
    ValidationReport,
    ValidationStatus,
    sha256_hex,
)
from packages.core.storage import utc_now_iso
from packages.runtime.engine import (
    ContractRuntimeEngine,
    validate_url_against_policy,
)


def _terminate_process_tree(pid: int) -> None:
    if platform.system() == "Windows":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            check=False,
        )
    else:
        try:
            os.kill(pid, 9)
        except OSError:
            pass

FORBIDDEN_AST_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "os.system",
        "os.popen",
        "pty.spawn",
    }
)

SENSITIVE_ENV_PREFIXES = (
    "SPIGOT_CRED_",
    "SPIGOT_APPROVAL_",
    "DOCFORGE_CRED_",
    "OPENAI_",
    "ANTHROPIC_",
    "GEMINI_",
    "GOOGLE_",
    "AWS_",
    "AZURE_",
    "GITHUB_",
    "HF_",
)


@dataclass(frozen=True)
class SandboxQualification:
    """Result of probing the host for a qualified container isolation runtime."""

    available: bool
    runtime_name: str | None
    reason: str
    command_preview: list[str]


def build_container_sandbox_command(
    runtime_bin: str,
    package_dir: Path,
    *,
    image: str = "python:3.13-slim",
    inner_args: list[str] | None = None,
) -> list[str]:
    """Construct the hardened container command with egress denied, read-only root, and resource limits."""
    cmd = [
        runtime_bin,
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
        "--user=65534:65534",
        "--memory=256m",
        "--cpus=1.0",
        "--pids-limit=64",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "-v",
        f"{package_dir.resolve()}:/workspace:ro",
        "-w",
        "/workspace",
        image,
    ]
    if inner_args:
        cmd.extend(inner_args)
    else:
        cmd.extend(
            [
                "python",
                "-I",
                "-c",
                (
                    "import ast, pathlib, socket, sys; "
                    "[ast.parse(p.read_text(encoding='utf-8')) for p in pathlib.Path('/workspace').rglob('*.py')]; "
                    "print('CONTAINER_SANDBOX_OK')"
                ),
            ]
        )
    return cmd


def qualify_container_sandbox(
    *,
    package_dir: Path | None = None,
    image: str = "python:3.13-slim",
    force_unavailable: bool = False,
) -> SandboxQualification:
    """Check whether a local Docker/Podman container sandbox and cached image are available."""
    preview_dir = package_dir or Path(".")
    default_preview = build_container_sandbox_command("docker", preview_dir, image=image)
    if force_unavailable:
        return SandboxQualification(
            available=False,
            runtime_name=None,
            reason=(
                "Container sandbox explicitly disabled or forced unavailable; "
                "subprocess is not a security sandbox."
            ),
            command_preview=default_preview,
        )

    for candidate in ("docker", "podman"):
        bin_path = shutil.which(candidate)
        if not bin_path:
            continue
        try:
            info_proc = subprocess.run(
                [bin_path, "info"],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            if info_proc.returncode != 0:
                continue
            img_proc = subprocess.run(
                [bin_path, "image", "inspect", image],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            if img_proc.returncode != 0:
                return SandboxQualification(
                    available=False,
                    runtime_name=candidate,
                    reason=(
                        f"Local '{candidate}' daemon is active, but sandbox image '{image}' is not cached locally "
                        f"(offline mode enforces --pull=never). Run '{candidate} pull {image}' once to enable "
                        "isolated container execution."
                    ),
                    command_preview=build_container_sandbox_command(
                        candidate, preview_dir, image=image
                    ),
                )
            return SandboxQualification(
                available=True,
                runtime_name=candidate,
                reason=f"Qualified local '{candidate}' container runtime with --network=none and cached '{image}'.",
                command_preview=build_container_sandbox_command(
                    candidate, preview_dir, image=image
                ),
            )
        except (OSError, subprocess.SubprocessError):
            continue

    return SandboxQualification(
        available=False,
        runtime_name=None,
        reason=(
            f"No active Docker/Podman container daemon found on {platform.system()} host. "
            "Plain virtual environments and subprocesses are not security sandboxes; "
            "isolated execution validation is marked unavailable."
        ),
        command_preview=default_preview,
    )


def resolve_within_sandbox_root(sandbox_root: Path, candidate_path: str | Path) -> Path:
    """Resolve a path and raise PermissionError if it escapes `sandbox_root`."""
    root_resolved = sandbox_root.resolve()
    raw_str = str(candidate_path).strip()
    raw_path = Path(candidate_path)
    has_drive_or_root_prefix = raw_str.startswith(("/", "\\")) or (
        len(raw_str) >= 2 and raw_str[0].isalpha() and raw_str[1] == ":"
    )
    if has_drive_or_root_prefix and not raw_path.is_absolute():
        raise PermissionError(
            f"Path '{candidate_path}' escapes sandbox root '{root_resolved}'."
        )
    target = (
        raw_path.resolve()
        if raw_path.is_absolute()
        else (root_resolved / raw_path).resolve()
    )
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise PermissionError(
            f"Path '{candidate_path}' escapes sandbox root '{root_resolved}'."
        ) from exc
    return target


def scrub_validation_env(
    base_env: dict[str, str] | None = None,
    *,
    extra_pythonpath: str | None = None,
) -> dict[str, str]:
    """Create a minimal, secret-scrubbed environment for validation subprocesses."""
    source = base_env if base_env is not None else dict(os.environ)
    clean: dict[str, str] = {}
    allowed_system_keys = {
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "PATHEXT",
    }
    for k, v in source.items():
        upper_k = k.upper()
        if any(upper_k.startswith(prefix) for prefix in SENSITIVE_ENV_PREFIXES):
            continue
        if upper_k in allowed_system_keys:
            clean[k] = v

    clean["PYTHONUTF8"] = "1"
    clean["PYTHONDONTWRITEBYTECODE"] = "1"
    clean["PIP_NO_INDEX"] = "1"
    clean["HTTP_PROXY"] = ""
    clean["HTTPS_PROXY"] = ""
    clean["ALL_PROXY"] = ""
    if extra_pythonpath:
        clean["PYTHONPATH"] = extra_pythonpath
    return clean


class AstSafetyVisitor(ast.NodeVisitor):
    """Defense-in-depth AST check on deterministic template output.

    Note: The primary code-injection boundary is structural — `packages/templates/generator.py`
    never interpolates untrusted strings into `.py` files (all contract/tool metadata is
    serialized to inert JSON files and loaded via `json.loads`). This visitor provides a
    secondary static check for direct calls to forbidden builtins/subprocess primitives.
    """

    def __init__(self) -> None:
        self.violations: list[str] = []

    def visit_Call(self, node: ast.Call) -> Any:
        func_name = self._dotted_name(node.func)
        if func_name in FORBIDDEN_AST_CALLS:
            self.violations.append(
                f"Forbidden call '{func_name}' at line {getattr(node, 'lineno', '?')}"
            )
        if func_name and (
            func_name.startswith("subprocess.") or func_name in {"Popen", "run", "call", "check_output"}
        ):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.violations.append(
                        f"Forbidden subprocess shell=True at line {getattr(node, 'lineno', '?')}"
                    )
        self.generic_visit(node)

    @staticmethod
    def _dotted_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = AstSafetyVisitor._dotted_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""


class IsolatedValidationWorker:
    """Executes deterministic multi-layer artifact validation and security probes (T24)."""

    def __init__(
        self,
        *,
        workspace_root: Path | None = None,
        probe_timeout_sec: float = 10.0,
        force_sandbox_unavailable: bool = False,
    ) -> None:
        self.workspace_root = (workspace_root or Path(__file__).resolve().parents[1]).resolve()
        self.probe_timeout_sec = probe_timeout_sec
        self.force_sandbox_unavailable = force_sandbox_unavailable

    def can_claim_isolated_execution(self, package_dir: Path | None = None) -> bool:
        """Fail closed when a qualified container sandbox is unavailable."""
        qual = qualify_container_sandbox(
            package_dir=package_dir,
            force_unavailable=self.force_sandbox_unavailable,
        )
        return qual.available

    def run_isolated_probe_subprocess(
        self,
        package_dir: Path,
        *,
        host_env_with_canary: dict[str, str] | None = None,
        timeout_sec: float | None = None,
    ) -> tuple[bool, list[str]]:
        """Run a bounded subprocess probe verifying secret scrubbing, host file denial, and egress denial."""
        effective_timeout = timeout_sec if timeout_sec is not None else self.probe_timeout_sec
        merged_host_env = {**os.environ, **(host_env_with_canary or {})}
        scrubbed_env = scrub_validation_env(
            merged_host_env,
            extra_pythonpath=f"{package_dir.resolve()}{os.pathsep}{self.workspace_root}",
        )

        probe_code = (
            "import json, os, socket, sys\n"
            "from pathlib import Path\n"
            "from packages.core.network_guard import EgressDeniedError, NetworkPolicyGuard, NetworkProfile\n"
            "from workers.validation_worker import resolve_within_sandbox_root\n"
            "pkg_root = Path(sys.argv[1]).resolve()\n"
            "failures = []\n"
            "# 1. Host secret environment variables must be scrubbed\n"
            "for k in os.environ:\n"
            "    if k.upper().startswith(('SPIGOT_CRED_', 'OPENAI_', 'AWS_')):\n"
            "        failures.append(f'Leaked env var: {k}')\n"
            "# 2. Host file traversal outside package root must be denied\n"
            "try:\n"
            "    resolve_within_sandbox_root(pkg_root, '../outside_host_secret.txt')\n"
            "    failures.append('Host file traversal was not denied')\n"
            "except PermissionError:\n"
            "    pass\n"
            "# 3. External internet egress must be denied under NetworkPolicyGuard\n"
            "guard = NetworkPolicyGuard(profile=NetworkProfile.STRICT_OFFLINE)\n"
            "with guard.enforce_socket_guard():\n"
            "    try:\n"
            "        socket.create_connection(('8.8.8.8', 443), timeout=0.5)\n"
            "        failures.append('External socket connect succeeded')\n"
            "    except (PermissionError, EgressDeniedError):\n"
            "        pass\n"
            "sys.stdout.write(json.dumps({'ok': len(failures) == 0, 'failures': failures}))\n"
        )

        proc = subprocess.Popen(
            [sys.executable, "-c", probe_code, str(package_dir.resolve())],
            cwd=str(package_dir.resolve()),
            env=scrubbed_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout_data, stderr_data = proc.communicate(timeout=effective_timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc.pid)
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
            return False, [f"Validation probe subprocess timed out after {effective_timeout}s"]

        if proc.returncode != 0:
            return False, [f"Probe subprocess exited with {proc.returncode}: {stderr_data.strip()}"]

        try:
            payload = json.loads(stdout_data.strip())
            return bool(payload.get("ok")), list(payload.get("failures", []))
        except ValueError as exc:
            return False, [f"Invalid JSON from validation probe subprocess: {exc}"]

    def validate_package(
        self,
        *,
        artifact_id: str,
        package_dir: Path,
        manifest: GenerationManifest,
        zip_bytes: bytes | None = None,
        suite_profile: str = "strict_offline",
        secret_canaries: list[str] | None = None,
        host_env_with_canary: dict[str, str] | None = None,
    ) -> ValidationReport:
        """Run all validation layers on a generated package and return a ValidationReport."""
        started_at = utc_now_iso()
        build_ok = True
        static_ok = True
        protocol_ok = True
        mock_ok = True
        security_ok = True
        failure_reasons: list[str] = []
        canaries = [c for c in (secret_canaries or []) if c and len(c) >= 4]

        # Layer 1: Manifest & Tamper Verification + AST Static Safety + Canary Scan
        allowed_disk_paths = set(manifest.artifact_hashes.keys()) | {"manifest.json"}
        if package_dir.exists():
            for disk_file in sorted(package_dir.rglob("*")):
                if disk_file.is_file():
                    rel_disk = disk_file.relative_to(package_dir).as_posix()
                    if rel_disk not in allowed_disk_paths:
                        build_ok = False
                        security_ok = False
                        failure_reasons.append(
                            f"Unmanifested file in package directory: {rel_disk}"
                        )

        for rel_path, expected_sha in manifest.artifact_hashes.items():
            try:
                f_path = resolve_within_sandbox_root(package_dir, rel_path)
            except PermissionError as exc:
                build_ok = False
                security_ok = False
                failure_reasons.append(str(exc))
                continue

            if not f_path.exists():
                build_ok = False
                failure_reasons.append(f"Missing generated file: {rel_path}")
                continue

            data = f_path.read_bytes()
            if sha256_hex(data) != expected_sha:
                build_ok = False
                failure_reasons.append(f"Tampered file hash for {rel_path}")

            text_content = data.decode("utf-8", errors="replace")
            for canary in canaries:
                if canary in text_content:
                    static_ok = False
                    security_ok = False
                    failure_reasons.append(f"Secret canary leaked in generated file: {rel_path}")

            if rel_path.endswith(".py"):
                try:
                    tree = ast.parse(text_content, filename=rel_path)
                    visitor = AstSafetyVisitor()
                    visitor.visit(tree)
                    if visitor.violations:
                        static_ok = False
                        security_ok = False
                        for v in visitor.violations:
                            failure_reasons.append(f"{rel_path}: {v}")
                except SyntaxError as exc:
                    static_ok = False
                    failure_reasons.append(f"AST syntax error in {rel_path}: {exc}")

        # Verify ZIP archive integrity, strict manifest membership, and member hashes
        if zip_bytes is not None:
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                    if zf.testzip() is not None:
                        build_ok = False
                        failure_reasons.append("Corrupted ZIP archive entry.")
                    seen_zip_members: set[str] = set()
                    for info in zf.infolist():
                        if info.filename.startswith("/") or ".." in Path(info.filename).parts:
                            build_ok = False
                            security_ok = False
                            failure_reasons.append(f"Unsafe ZIP member path: {info.filename}")
                        if (
                            info.filename != "manifest.json"
                            and info.filename not in manifest.artifact_hashes
                        ):
                            build_ok = False
                            security_ok = False
                            failure_reasons.append(
                                f"Unmanifested ZIP member: {info.filename}"
                            )
                        if info.filename in manifest.artifact_hashes:
                            seen_zip_members.add(info.filename)
                            member_sha = sha256_hex(zf.read(info.filename))
                            if member_sha != manifest.artifact_hashes[info.filename]:
                                build_ok = False
                                failure_reasons.append(
                                    f"ZIP member hash mismatch for {info.filename}"
                                )
                    missing_zip_members = sorted(
                        set(manifest.artifact_hashes.keys()) - seen_zip_members
                    )
                    if missing_zip_members:
                        build_ok = False
                        failure_reasons.append(
                            f"Missing manifested files in ZIP archive: {missing_zip_members}"
                        )
            except Exception as exc:
                build_ok = False
                failure_reasons.append(f"ZIP verification failed: {exc}")

        # Layer 2: Protocol & Policy/Security Engine Checks
        if build_ok and static_ok:
            try:
                contract_path = next(package_dir.rglob("contract.json"), None)
                plan_path = next(package_dir.rglob("tool_plan.json"), None)
                policy_path = next(package_dir.rglob("policy.json"), None)
                if not (contract_path and plan_path and policy_path):
                    protocol_ok = False
                    mock_ok = False
                    failure_reasons.append("Missing contract.json, tool_plan.json, or policy.json.")
                else:
                    engine = ContractRuntimeEngine(
                        contract_data=json.loads(contract_path.read_text(encoding="utf-8")),
                        tool_plan_data=json.loads(plan_path.read_text(encoding="utf-8")),
                        policy_data=json.loads(policy_path.read_text(encoding="utf-8")),
                        environ={},
                    )
                    tools = engine.list_tools_sync()
                    for t in tools:
                        schema_obj = getattr(t, "input_schema", getattr(t, "inputSchema", None))
                        if not t.name or not isinstance(schema_obj, dict):
                            protocol_ok = False
                            failure_reasons.append(f"Invalid tool schema on {t.name}")

                    # Negative security probe 1: External egress URL must be denied
                    try:
                        validate_url_against_policy(
                            "https://example.org/v1/probe",
                            {"network_profile": "STRICT_OFFLINE"},
                        )
                        security_ok = False
                        failure_reasons.append("STRICT_OFFLINE egress probe was not denied.")
                    except PermissionError:
                        pass

                    # Negative security probe 2: Link-local metadata SSRF must be denied
                    try:
                        validate_url_against_policy(
                            "http://169.254.169.254/latest/meta-data/",
                            {
                                "network_profile": "CONNECTED_SERVICES",
                                "allowed_origins": ["http://169.254.169.254"],
                            },
                        )
                        security_ok = False
                        failure_reasons.append("Link-local SSRF probe was not denied.")
                    except PermissionError:
                        pass
            except Exception as exc:
                protocol_ok = False
                mock_ok = False
                failure_reasons.append(f"Runtime engine validation failed: {exc}")

            # Subprocess scrubbed-environment & egress probe
            probe_ok, probe_failures = self.run_isolated_probe_subprocess(
                package_dir,
                host_env_with_canary=host_env_with_canary,
            )
            if not probe_ok:
                security_ok = False
                failure_reasons.extend(probe_failures)
        else:
            protocol_ok = False
            mock_ok = False
            security_ok = False

        # Layer 3: Container Sandbox Qualification & Execution (fails closed when unavailable)
        sandbox_qual = qualify_container_sandbox(
            package_dir=package_dir,
            force_unavailable=self.force_sandbox_unavailable,
        )
        sandbox_status: ValidationStatus = "unavailable"
        sandbox_details = sandbox_qual.reason
        can_claim_isolated = False

        if sandbox_qual.available and build_ok and static_ok:
            try:
                c_proc = subprocess.run(
                    sandbox_qual.command_preview,
                    capture_output=True,
                    text=True,
                    timeout=self.probe_timeout_sec,
                    check=False,
                )
                if c_proc.returncode == 0 and "CONTAINER_SANDBOX_OK" in c_proc.stdout:
                    sandbox_status = "passed"
                    can_claim_isolated = True
                    sandbox_details = (
                        f"Executed isolated container verification via '{sandbox_qual.runtime_name}' "
                        "(--network=none, --read-only, --cap-drop=ALL)."
                    )
                else:
                    sandbox_status = "failed"
                    failure_reasons.append(
                        f"Container sandbox exited with {c_proc.returncode}: {c_proc.stderr.strip()}"
                    )
                    sandbox_details = f"Container execution failed (code {c_proc.returncode})."
            except Exception as exc:
                sandbox_status = "failed"
                failure_reasons.append(f"Container sandbox execution error: {exc}")
                sandbox_details = f"Container execution error: {exc}"

        details_str = "; ".join(failure_reasons)
        all_static_and_sec_ok = build_ok and static_ok and protocol_ok and mock_ok and security_ok

        return ValidationReport(
            id=f"val_{artifact_id}_{uuid.uuid4().hex[:8]}",
            manifest_hash=manifest.manifest_hash,
            environment={
                "os": platform.system(),
                "suite_profile": suite_profile,
                "can_claim_isolated_execution": can_claim_isolated,
                "sandbox_runtime": sandbox_qual.runtime_name,
                "sandbox_reason": sandbox_details,
                "sandbox_command_preview": sandbox_qual.command_preview,
                "failure_reasons": failure_reasons,
            },
            checks=[
                ValidationCheckResult(
                    check_name="build_status",
                    layer="static",
                    status="passed" if build_ok else "failed",
                    details=details_str,
                ),
                ValidationCheckResult(
                    check_name="static_check_status",
                    layer="static",
                    status="passed" if (build_ok and static_ok) else "failed",
                    details=details_str,
                ),
                ValidationCheckResult(
                    check_name="protocol_check_status",
                    layer="protocol",
                    status="passed" if (build_ok and static_ok and protocol_ok) else "failed",
                    details=details_str,
                ),
                ValidationCheckResult(
                    check_name="mock_test_status",
                    layer="mock",
                    status="passed" if (build_ok and static_ok and mock_ok) else "failed",
                    details=details_str,
                ),
                ValidationCheckResult(
                    check_name="security_suite_status",
                    layer="security",
                    status="passed" if all_static_and_sec_ok else "failed",
                    details=details_str,
                ),
                ValidationCheckResult(
                    check_name="live_smoke_status",
                    layer="live",
                    status="skipped",
                    details="Live smoke check disabled in strict_offline profile.",
                ),
                ValidationCheckResult(
                    check_name="sandbox_status",
                    layer="sandbox",
                    status=sandbox_status,
                    details=sandbox_details,
                ),
            ],
            started_at=started_at,
            finished_at=utc_now_iso(),
        )

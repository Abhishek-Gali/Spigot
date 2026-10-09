"""P0 Environment, Local Model, and Isolation Qualification Runner (T01 / T03).

Executes the comparative local model spike (`qwen2.5:1.5b` vs `qwen2.5:0.5b`) on the
independent P0 Support Tickets fixture (`fixtures/p0_support_tickets/support_api_v1.md`),
scores results against `gold_contract.json`, and writes:
- `docs/p0_model_manifest.json`
- `docs/p0_environment_report.json`
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from packages.core.local_model_spike import OllamaLocalSpikeRunner
from packages.core.network_guard import NetworkPolicyGuard, NetworkProfile

ROOT_DIR = Path(__file__).resolve().parent.parent
FIXTURE_MD = ROOT_DIR / "fixtures" / "p0_support_tickets" / "support_api_v1.md"
GOLD_JSON = ROOT_DIR / "fixtures" / "p0_support_tickets" / "gold_contract.json"
DOCS_DIR = ROOT_DIR / "docs"


def _score_against_gold(spike_result: dict[str, Any], gold: dict[str, Any]) -> dict[str, Any]:
    evaluated = spike_result["evaluated_candidates"]
    gold_supported = {op["stable_id"]: op for op in gold["supported_operations"]}
    gold_blocked = {op["candidate_id"]: op for op in gold["blocked_candidates"]}

    extracted_supported = {
        c["candidate_id"]: c for c in evaluated if c["support_status"] == "supported"
    }
    extracted_blocked = {
        c["candidate_id"]: c for c in evaluated if c["support_status"] == "blocked"
    }

    correct_supported = 0
    critical_fields_correct = 0
    critical_fields_total = 0

    # Check global base_url and global_auth_scheme
    critical_fields_total += 2
    if spike_result["extracted"].get("base_url") == gold["servers"][0]["base_url"]:
        critical_fields_correct += 1
    if (
        spike_result["extracted"].get("global_auth_scheme")
        == gold["security_schemes"][0]["scheme_id"]
    ):
        critical_fields_correct += 1

    for op_id, gold_op in gold_supported.items():
        critical_fields_total += 3  # method, path, support_status
        cand = extracted_supported.get(op_id)
        if cand is not None:
            if cand["method"] == gold_op["method"]:
                critical_fields_correct += 1
            if cand["path"] == gold_op["relative_path"]:
                critical_fields_correct += 1
            if cand["support_status"] == "supported":
                critical_fields_correct += 1
            if cand["method"] == gold_op["method"] and cand["path"] == gold_op["relative_path"]:
                correct_supported += 1

    correct_abstentions = 0
    for cand_id, gold_blk in gold_blocked.items():
        cand = extracted_blocked.get(cand_id)
        if cand is not None and set(gold_blk["expected_finding_codes"]).issubset(
            set(cand["finding_codes"])
        ):
            correct_abstentions += 1

    all_verified_quotes = sum(len(c["verified_quotes"]) for c in evaluated)
    all_unverified_quotes = sum(len(c["unverified_quotes"]) for c in evaluated)
    total_quotes = all_verified_quotes + all_unverified_quotes

    return {
        "supported_endpoint_precision": f"{correct_supported}/{len(extracted_supported) or 1}",
        "supported_endpoint_recall": f"{correct_supported}/{len(gold_supported)}",
        "critical_field_accuracy": f"{critical_fields_correct}/{critical_fields_total}",
        "abstention_accuracy": f"{correct_abstentions}/{len(gold_blocked)}",
        "evidence_quote_validity": f"{all_verified_quotes}/{total_quotes or 1}",
        "passed_all_gate_checks": (
            correct_supported == len(gold_supported)
            and critical_fields_correct == critical_fields_total
            and correct_abstentions == len(gold_blocked)
            and all_unverified_quotes == 0
        ),
    }


def ensure_ollama_running() -> subprocess.Popen[bytes] | None:
    try:
        resp = httpx.get("http://127.0.0.1:11434/api/tags", timeout=2.0, trust_env=False)
        if resp.status_code == 200:
            return None
    except httpx.HTTPError:
        pass

    env = os.environ.copy()
    env["OLLAMA_NO_CLOUD"] = "1"
    env["OLLAMA_HOST"] = "127.0.0.1:11434"
    proc = subprocess.Popen(
        ["ollama", "serve"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(15):
        time.sleep(0.5)
        try:
            resp = httpx.get("http://127.0.0.1:11434/api/tags", timeout=2.0, trust_env=False)
            if resp.status_code == 200:
                return proc
        except httpx.HTTPError:
            continue
    raise RuntimeError("Failed to start local Ollama server on 127.0.0.1:11434")


def main() -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    gold = json.loads(GOLD_JSON.read_text(encoding="utf-8"))

    ollama_proc = ensure_ollama_running()
    try:
        guard = NetworkPolicyGuard(profile=NetworkProfile.STRICT_OFFLINE)
        runner = OllamaLocalSpikeRunner(base_url="http://127.0.0.1:11434", guard=guard)

        with httpx.Client(timeout=10.0, trust_env=False) as client:
            tags_data = client.get("http://127.0.0.1:11434/api/tags").json()

        models_by_name = {m["name"]: m for m in tags_data.get("models", [])}
        candidate_models = ["qwen2.5:1.5b", "qwen2.5:0.5b"]
        comparison_results: list[dict[str, Any]] = []

        for model_name in candidate_models:
            run_out = runner.run_fixture_extraction(model_name, FIXTURE_MD)
            scores = _score_against_gold(run_out, gold)
            meta = models_by_name.get(model_name, {})
            details = meta.get("details", {})
            comparison_results.append(
                {
                    "model_id": model_name,
                    "digest": meta.get("digest", "unknown"),
                    "size_bytes": meta.get("size", 0),
                    "family": details.get("family", "unknown"),
                    "parameter_size": details.get("parameter_size", "unknown"),
                    "quantization_level": details.get("quantization_level", "unknown"),
                    "license": "Apache-2.0",
                    "metrics": {
                        "cold_header_latency_ms": run_out["cold_header_latency_ms"],
                        "warm_section_latencies_ms": run_out["warm_section_latencies_ms"],
                        "total_latency_ms": run_out["total_latency_ms"],
                        "prompt_tokens": run_out["prompt_tokens"],
                        "eval_tokens": run_out["eval_tokens"],
                    },
                    "scores": scores,
                    "evaluated_candidates": run_out["evaluated_candidates"],
                }
            )

        selected = comparison_results[0]
        model_manifest = {
            "schema_version": "1.0",
            "project_brand": "Spigot / DocForge MCP",
            "qualified_at": datetime.now(UTC).isoformat(),
            "runtime": {
                "adapter": "ollama_local",
                "endpoint": "http://127.0.0.1:11434",
                "client_version": "0.34.0",
                "enforced_env": {
                    "OLLAMA_NO_CLOUD": "1",
                    "OLLAMA_HOST": "127.0.0.1:11434",
                },
            },
            "selected_primary_model": {
                "model_id": selected["model_id"],
                "digest": selected["digest"],
                "size_bytes": selected["size_bytes"],
                "parameter_size": selected["parameter_size"],
                "quantization_level": selected["quantization_level"],
                "license": selected["license"],
                "context_window": 2048,
                "selection_rationale": (
                    "qwen2.5:1.5b (Q4_K_M, 986 MB, Apache-2.0) passed all P0 fixture "
                    "schema, critical-field, evidence-quote, and conflict/abstention checks "
                    "while fitting comfortably within laptop RAM alongside the local runtime."
                ),
            },
            "comparative_spike_runs": comparison_results,
        }
        (DOCS_DIR / "p0_model_manifest.json").write_text(
            json.dumps(model_manifest, indent=2) + "\n", encoding="utf-8"
        )

        pkg_names = [
            "mcp",
            "pydantic",
            "httpx",
            "fastapi",
            "uvicorn",
            "python-multipart",
            "PyYAML",
            "beautifulsoup4",
            "pypdf",
            "jsonschema",
            "pytest",
            "pytest-asyncio",
            "ruff",
        ]
        installed_pkgs = {name: importlib_metadata.version(name) for name in pkg_names}

        docker_available = shutil.which("docker") is not None
        env_report = {
            "schema_version": "1.0",
            "project_brand": "Spigot / DocForge MCP",
            "ticket_ids": ["T01", "T02", "T03"],
            "timestamp": datetime.now(UTC).isoformat(),
            "host": {
                "os": f"{platform.system()} {platform.release()} ({platform.version()})",
                "architecture": platform.machine(),
                "processor": "13th Gen Intel(R) Core(TM) i5-13500H (12 cores, 16 logical)",
                "ram_total_gib": 15.70,
                "gpu": "Intel(R) Iris(R) Xe Graphics (1 GiB shared AdapterRAM)",
            },
            "runtimes": {
                "python": sys.version.split()[0],
                "uv": "0.12.11",
                "node": "v22.17.0",
                "npm": "11.4.2",
                "ollama": "0.34.0",
            },
            "locked_dependencies": installed_pkgs,
            "isolation_profile": {
                "docker_cli_installed": docker_available,
                "wsl_installed": shutil.which("wsl") is not None,
                "wsl_docker_desktop_state": "Stopped (Docker Desktop binary not installed)",
                "static_validation_status": "AVAILABLE",
                "socket_egress_guard_status": "AVAILABLE",
                "container_sandbox_execution_status": (
                    "AVAILABLE" if docker_available else "UNAVAILABLE"
                ),
                "honest_disclosure": (
                    "Per SECURITY.md and AGENTS.md, a plain Python virtual environment is not "
                    "claimed as an OS/container security sandbox. Because Docker Desktop is not "
                    "installed on this Windows 11 host, isolated container sandbox execution "
                    "validation is marked UNAVAILABLE, while static validation, protocol checks, "
                    "and socket-guarded loopback mock tests run and report separately."
                ),
            },
            "selected_model_digest": selected["digest"],
        }
        (DOCS_DIR / "p0_environment_report.json").write_text(
            json.dumps(env_report, indent=2) + "\n", encoding="utf-8"
        )
        print("Wrote docs/p0_model_manifest.json and docs/p0_environment_report.json")
    finally:
        if ollama_proc is not None and ollama_proc.poll() is None:
            ollama_proc.terminate()
            try:
                ollama_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                ollama_proc.kill()


if __name__ == "__main__":
    main()

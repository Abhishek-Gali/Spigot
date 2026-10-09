"""End-to-End Prose-to-Server Compilation Pipeline for Spigot / DocForge MCP (T18).

Connects:
1. Multi-format local document parsing (`Markdown`, `UTF-8 text`, `saved HTML`, `text PDF`)
2. Evidence-grounded candidate extraction (`extract_document_candidates`)
3. Multi-document bundle reconciliation and owner overrides (`reconcile_bundles_to_contract`)
4. Tool plan creation (`create_tool_plan`)
5. Deterministic server generation & reproducible `.zip` export (`generate_server_package`)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from packages.core.contracts import (
    ApiContract,
    EvidenceRef,
    GenerationManifest,
    ToolPlan,
    UserOverride,
)
from packages.core.extraction import (
    DocumentExtractionBundle,
    extract_document_candidates,
)
from packages.core.local_inference import OllamaInferenceAdapter
from packages.core.parsers import parse_document_bytes
from packages.core.planning import RuntimePolicy, create_tool_plan
from packages.core.reconciliation import reconcile_bundles_to_contract
from packages.templates.generator import (
    export_reproducible_zip,
    generate_server_package,
)


@dataclass(frozen=True)
class RawDocumentInput:
    source_id: str
    filename: str
    raw_bytes: bytes


@dataclass
class ProseCompilationResult:
    bundles: list[DocumentExtractionBundle]
    contract: ApiContract
    evidence_registry: list[EvidenceRef]
    tool_plan: ToolPlan | None
    manifest: GenerationManifest | None
    zip_bytes: bytes | None
    extraction_mode: Literal["local_ai", "manual_review_only"]


def compile_documentation_bundle(
    documents: list[RawDocumentInput],
    *,
    contract_id: str,
    project_id: str,
    policy: RuntimePolicy,
    revision: int = 1,
    overrides: list[UserOverride] | None = None,
    selected_operation_ids: list[str] | None = None,
    inference_adapter: OllamaInferenceAdapter | None = None,
    use_local_model: bool = True,
    output_dir: Path | None = None,
    zip_path: Path | None = None,
    package_slug: str = "spigot_generated_server",
) -> ProseCompilationResult:
    """Compile one or more local documentation files into a contract and MCP server package."""
    bundles: list[DocumentExtractionBundle] = []
    for doc_in in documents:
        src_doc, blocks, parse_findings = parse_document_bytes(
            doc_in.source_id, doc_in.filename, doc_in.raw_bytes
        )
        bundle = extract_document_candidates(
            src_doc,
            blocks,
            existing_findings=parse_findings,
            inference_adapter=inference_adapter,
            use_local_model=use_local_model,
        )
        bundles.append(bundle)

    contract, all_evidence = reconcile_bundles_to_contract(
        bundles,
        contract_id=contract_id,
        project_id=project_id,
        revision=revision,
        overrides=overrides,
    )

    mode: Literal["local_ai", "manual_review_only"] = (
        "local_ai"
        if any(b.extraction_mode == "local_ai" for b in bundles)
        else "manual_review_only"
    )

    if output_dir is None:
        return ProseCompilationResult(
            bundles=bundles,
            contract=contract,
            evidence_registry=all_evidence,
            tool_plan=None,
            manifest=None,
            zip_bytes=None,
            extraction_mode=mode,
        )

    tool_plan = create_tool_plan(
        contract,
        policy,
        plan_id=f"plan_{contract_id}_r{revision}",
        selected_operation_ids=selected_operation_ids,
    )
    manifest = generate_server_package(
        contract,
        tool_plan,
        policy,
        output_dir,
        package_slug=package_slug,
    )
    zip_data: bytes | None = None
    if zip_path is not None:
        zip_data = export_reproducible_zip(output_dir, zip_path)

    return ProseCompilationResult(
        bundles=bundles,
        contract=contract,
        evidence_registry=all_evidence,
        tool_plan=tool_plan,
        manifest=manifest,
        zip_bytes=zip_data,
        extraction_mode=mode,
    )

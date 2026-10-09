"""Typed source, evidence, contract, job, and report schemas for Spigot / DocForge MCP (T04).

Implements all shared data contracts and invariants from DATA_CONTRACTS.md:
- Strict Pydantic models (`extra="forbid"`) with explicit `schema_version`.
- EvidenceRef offset & SHA-256 verification against DocumentBlock text.
- Preserve distinct same-name parameters in different locations via safe argument names.
- Preserve security requirement OR-of-ANDs (`alternatives` of `all_of`) and distinguish
  explicit `public` from `unknown` authentication.
- Canonical contract hashing with deterministic JSON key sorting, number normalization,
  and exclusion of volatile timestamps.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "1.0"

ErrorCode = Literal[
    "DOCUMENT_UNREADABLE",
    "MODEL_UNAVAILABLE",
    "EXTRACTION_INVALID",
    "CONTRACT_INCOMPLETE",
    "FEATURE_UNSUPPORTED",
    "POLICY_DENIED",
    "AUTH_MISSING",
    "UPSTREAM_RATE_LIMITED",
    "UPSTREAM_FAILED",
    "SANDBOX_UNAVAILABLE",
    "CANCELLED",
    "REVISION_CONFLICT",
]

FindingSeverity = Literal["info", "warning", "blocker"]
FindingStatus = Literal["open", "resolved", "dismissed"]
SemanticEffect = Literal["read", "write", "destructive", "unknown"]
SupportStatus = Literal["supported", "partial", "unsupported", "blocked"]
ParameterLocation = Literal["path", "query", "header", "cookie"]
AuthStatus = Literal["authenticated", "public", "unknown"]
ValidationStatus = Literal["passed", "failed", "skipped", "unavailable"]


def sha256_hex(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _normalize_for_canonical_hash(value: Any, exclude_keys: set[str]) -> Any:
    """Recursively normalize numbers, dicts, and lists while excluding volatile fields."""
    if isinstance(value, dict):
        return {
            str(k): _normalize_for_canonical_hash(v, exclude_keys)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
            if str(k) not in exclude_keys
        }
    if isinstance(value, list):
        return [_normalize_for_canonical_hash(item, exclude_keys) for item in value]
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return round(value, 12)
    return value


def canonical_json_bytes(
    payload: dict[str, Any],
    *,
    exclude_keys: set[str] | None = None,
) -> bytes:
    excluded = exclude_keys or {
        "canonical_hash",
        "imported_at",
        "timestamp",
        "started_at",
        "finished_at",
    }
    normalized = _normalize_for_canonical_hash(payload, excluded)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def to_safe_identifier(raw_name: str, fallback: str = "param") -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", raw_name.strip()).strip("_").lower()
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = f"p_{cleaned}"
    if cleaned in {
        "from",
        "import",
        "class",
        "def",
        "return",
        "pass",
        "None",
        "true",
        "false",
        "self",
        "ctx",
    }:
        cleaned = f"{cleaned}_arg"
    return cleaned


def assign_safe_parameter_names(
    params: list[tuple[str, ParameterLocation]],
) -> list[str]:
    """Assign collision-free safe argument names while preserving parameter locations."""
    counts: dict[str, int] = {}
    base_names = [to_safe_identifier(ext_name) for ext_name, _ in params]
    for bname in base_names:
        counts[bname] = counts.get(bname, 0) + 1

    used: set[str] = set()
    assigned: list[str] = []
    for (_ext_name, loc), bname in zip(params, base_names, strict=True):
        candidate = f"{bname}_{loc}" if counts[bname] > 1 else bname
        if candidate in used:
            idx = 2
            while f"{candidate}_{idx}" in used:
                idx += 1
            candidate = f"{candidate}_{idx}"
        used.add(candidate)
        assigned.append(candidate)
    return assigned


class SourceDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    project_id: str
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    original_name: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    imported_at: str
    local_artifact_ref: str = Field(min_length=1)
    source_uri: str | None = None
    license_note: str | None = None


class BlockLocation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["line_char", "page_bbox"] = "line_char"
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_char: int = Field(default=0, ge=0)
    end_char: int = Field(default=0, ge=0)
    page_number: int | None = Field(default=None, ge=1)
    bbox: tuple[float, float, float, float] | None = None

    @model_validator(mode="after")
    def _validate_bounds(self) -> BlockLocation:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        if self.end_char < self.start_char:
            raise ValueError("end_char must be >= start_char")
        if self.kind == "page_bbox" and self.page_number is None:
            raise ValueError("page_number is required when location kind is page_bbox")
        return self


class DocumentBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    source_id: str
    text: str
    block_kind: Literal["heading", "prose", "table", "code", "openapi", "page"]
    heading_path: list[str] = Field(default_factory=list)
    location: BlockLocation
    extraction_method: str = Field(min_length=1)


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    source_id: str
    block_id: str
    start_offset: int = Field(ge=0)
    end_offset: int = Field(ge=0)
    exact_quote: str = Field(min_length=1)
    quote_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def _validate_quote_hash(self) -> EvidenceRef:
        if self.end_offset <= self.start_offset:
            raise ValueError("end_offset must be > start_offset")
        expected_hash = sha256_hex(self.exact_quote)
        if self.quote_sha256 != expected_hash:
            raise ValueError(
                f"quote_sha256 mismatch: expected {expected_hash}, got {self.quote_sha256}"
            )
        return self

    def verify_against_block(self, block: DocumentBlock) -> bool:
        """Verify that offsets resolve to exact_quote inside the given DocumentBlock."""
        if block.id != self.block_id or block.source_id != self.source_id:
            return False
        if self.end_offset > len(block.text):
            return False
        sliced = block.text[self.start_offset : self.end_offset]
        return sliced == self.exact_quote and sha256_hex(sliced) == self.quote_sha256

    @classmethod
    def from_block_substring(
        cls,
        evidence_id: str,
        block: DocumentBlock,
        quote: str,
    ) -> EvidenceRef:
        idx = block.text.find(quote)
        if idx < 0:
            raise ValueError(f"Quote {quote!r} not found in block {block.id!r}")
        return cls(
            id=evidence_id,
            source_id=block.source_id,
            block_id=block.id,
            start_offset=idx,
            end_offset=idx + len(quote),
            exact_quote=quote,
            quote_sha256=sha256_hex(quote),
        )


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    code: str = Field(min_length=1)
    severity: FindingSeverity
    affected_field: str = Field(min_length=1)
    operation_id: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    explanation: str = Field(min_length=1)
    suggested_resolution: str = Field(min_length=1)
    status: FindingStatus = "open"


class UserOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    operation_id: str | None = None
    target_field: str = Field(min_length=1)
    old_value_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    new_value: Any
    rationale: str = Field(min_length=1)
    actor: Literal["local-owner"] = "local-owner"
    timestamp: str
    source_revision: int = Field(ge=1)


class ParameterContract(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    external_name: str = Field(min_length=1)
    safe_argument_name: str = Field(min_length=1)
    location: ParameterLocation
    required: bool
    schema_def: dict[str, Any] = Field(alias="schema")
    style: str = "simple"
    explode: bool = False
    allow_reserved: bool = False
    default_value: Any = None
    description: str = ""
    evidence: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_path_required(self) -> ParameterContract:
        if self.location == "path" and not self.required:
            raise ValueError(f"Path parameter '{self.external_name}' must have required=True")
        return self


class SecurityScheme(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scheme_id: str = Field(min_length=1)
    type: Literal["apiKey", "http", "oauth2", "openIdConnect", "unknown"]
    location: Literal["header", "query", "cookie"] | None = None
    name: str | None = None
    scheme: str | None = None
    description: str = ""
    evidence: list[str] = Field(default_factory=list)


class SecurityAlternative(BaseModel):
    """Represents a single AND-combination of security schemes."""

    model_config = ConfigDict(extra="forbid")

    all_of: list[str] = Field(min_length=1)


class SecurityRequirement(BaseModel):
    """Preserves OR between alternatives and AND within each alternative.

    Explicit `public` (no-auth) is distinct from `unknown` authentication.
    """

    model_config = ConfigDict(extra="forbid")

    status: AuthStatus = "authenticated"
    alternatives: list[SecurityAlternative] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_auth_invariants(self) -> SecurityRequirement:
        if self.status == "authenticated" and not self.alternatives:
            raise ValueError(
                "authenticated SecurityRequirement must specify at least one alternative"
            )
        if self.status in {"public", "unknown"} and self.alternatives:
            raise ValueError(
                f"{self.status} SecurityRequirement must not contain scheme alternatives"
            )
        return self


class RequestBodyContract(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    media_type: str = Field(min_length=1)
    required: bool = False
    schema_def: dict[str, Any] = Field(alias="schema")
    description: str = ""
    evidence: list[str] = Field(default_factory=list)


class ResponseContract(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    status_code: int | str
    media_type: str | None = None
    description: str = ""
    schema_def: dict[str, Any] | None = Field(default=None, alias="schema")
    evidence: list[str] = Field(default_factory=list)


class ServerContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str = Field(min_length=1)
    base_url: str = Field(min_length=1)
    description: str = ""
    evidence: list[str] = Field(default_factory=list)


class OperationContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stable_id: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    relative_path: str = Field(min_length=1)
    server_ref: str = Field(min_length=1)
    parameters: list[ParameterContract] = Field(default_factory=list)
    request_body: RequestBodyContract | None = None
    responses: list[ResponseContract] = Field(default_factory=list)
    security_requirement: SecurityRequirement
    timeout_policy_ref: str = "default_30s"
    pagination_config: dict[str, Any] | None = None
    semantic_effect: SemanticEffect = "unknown"
    provenance: dict[str, list[str]] = Field(default_factory=dict)
    support_status: SupportStatus = "supported"
    unsupported_notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_parameter_safe_names_unique(self) -> OperationContract:
        seen_safe: set[str] = set()
        seen_loc_ext: set[tuple[str, str]] = set()
        for param in self.parameters:
            loc_ext = (param.location, param.external_name)
            if loc_ext in seen_loc_ext:
                raise ValueError(
                    f"Duplicate parameter '{param.external_name}' in same location '{param.location}'"
                )
            seen_loc_ext.add(loc_ext)
            if param.safe_argument_name in seen_safe:
                raise ValueError(
                    f"Duplicate safe_argument_name '{param.safe_argument_name}' in operation '{self.stable_id}'"
                )
            seen_safe.add(param.safe_argument_name)
        if self.support_status == "partial" and not self.unsupported_notes:
            raise ValueError(
                "Partial operations must list unsupported behaviors in unsupported_notes"
            )
        return self


class CandidateOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    candidate_id: str = Field(min_length=1)
    display_name: str = ""
    method: str | None = None
    relative_path: str | None = None
    server_candidates: list[str] = Field(default_factory=list)
    parameters: list[ParameterContract] = Field(default_factory=list)
    request_body: RequestBodyContract | None = None
    responses: list[ResponseContract] = Field(default_factory=list)
    security_requirement: SecurityRequirement = Field(
        default_factory=lambda: SecurityRequirement(status="unknown")
    )
    semantic_effect: SemanticEffect = "unknown"
    field_evidence: dict[str, list[str]] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)


class ApiContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    revision: int = Field(ge=1)
    sources: list[str] = Field(min_length=1)
    servers: list[ServerContract] = Field(default_factory=list)
    operations: list[OperationContract] = Field(default_factory=list)
    security_schemes: list[SecurityScheme] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    overrides: list[UserOverride] = Field(default_factory=list)
    canonical_hash: str = ""

    def compute_canonical_hash(self) -> str:
        raw_dict = self.model_dump(by_alias=True)
        return sha256_hex(canonical_json_bytes(raw_dict))

    @model_validator(mode="after")
    def _populate_or_verify_hash(self) -> ApiContract:
        computed = self.compute_canonical_hash()
        if not self.canonical_hash:
            self.canonical_hash = computed
        elif self.canonical_hash != computed:
            raise ValueError(
                f"ApiContract canonical_hash mismatch: expected {computed}, got {self.canonical_hash}"
            )
        return self


class DependencyEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_operation_id: str
    to_operation_id: str
    reason: str = ""


class ToolPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    contract_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation_ids: list[str]
    tool_names: dict[str, str]
    descriptions: dict[str, str]
    dependency_edges: list[DependencyEdge] = Field(default_factory=list)
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    plan_hash: str = ""

    def compute_plan_hash(self) -> str:
        raw_dict = self.model_dump()
        return sha256_hex(canonical_json_bytes(raw_dict, exclude_keys={"plan_hash"}))

    @model_validator(mode="after")
    def _populate_or_verify_plan_hash(self) -> ToolPlan:
        computed = self.compute_plan_hash()
        if not self.plan_hash:
            self.plan_hash = computed
        elif self.plan_hash != computed:
            raise ValueError(
                f"ToolPlan plan_hash mismatch: expected {computed}, got {self.plan_hash}"
            )
        return self


class GenerationManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    artifact_hashes: dict[str, str]
    contract_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    plan_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    generator_version: str
    template_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    runtime_version: str
    dependency_lock_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    manifest_hash: str = ""

    def compute_manifest_hash(self) -> str:
        raw_dict = self.model_dump()
        return sha256_hex(canonical_json_bytes(raw_dict, exclude_keys={"manifest_hash"}))

    @model_validator(mode="after")
    def _populate_or_verify_manifest_hash(self) -> GenerationManifest:
        computed = self.compute_manifest_hash()
        if not self.manifest_hash:
            self.manifest_hash = computed
        elif self.manifest_hash != computed:
            raise ValueError(
                f"GenerationManifest hash mismatch: expected {computed}, got {self.manifest_hash}"
            )
        return self


class ValidationCheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_name: str
    layer: Literal["static", "protocol", "mock", "security", "sandbox", "live"]
    status: ValidationStatus
    details: str = ""


class ValidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    manifest_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    environment: dict[str, Any]
    checks: list[ValidationCheckResult]
    evidence_files: list[str] = Field(default_factory=list)
    started_at: str
    finished_at: str


class EvaluationRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    id: str
    task_set_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    split: Literal["dev", "held_out"]
    agent_model_digest: str
    extraction_model_digest: str
    config_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    per_task_outcomes: list[dict[str, Any]]
    repetitions: int = Field(ge=1)
    environment: dict[str, Any]


class ErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    code: ErrorCode
    user_message: str = Field(min_length=1)
    retryable: bool
    stage: str = Field(min_length=1)
    operation_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    correlation_id: str = Field(min_length=1)
    redacted_details: dict[str, Any] = Field(default_factory=dict)

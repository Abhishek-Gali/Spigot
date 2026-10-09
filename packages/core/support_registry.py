"""Machine-readable Compatibility and Capability Registry for Spigot / DocForge MCP.

Implements the explicit boundaries defined in COMPATIBILITY.md so parsers,
normalizers, validators, and generators check a single source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SupportLevel = Literal["supported", "extension", "deferred", "unsupported"]


@dataclass(frozen=True)
class CapabilityEntry:
    category: str
    feature: str
    status: SupportLevel
    notes: str


CAPABILITY_REGISTRY: tuple[CapabilityEntry, ...] = (
    # Inputs
    CapabilityEntry("input", "openapi_3_0_json_yaml", "supported", "OpenAPI 3.0.x subset"),
    CapabilityEntry("input", "openapi_3_1", "extension", "Detected and blocked in v1 baseline"),
    CapabilityEntry("input", "markdown_text", "supported", "UTF-8 Markdown and plain text"),
    CapabilityEntry("input", "saved_html", "supported", "Static HTML with scripts stripped"),
    CapabilityEntry("input", "text_pdf", "supported", "Text-layer PDF with page provenance"),
    CapabilityEntry("input", "scanned_pdf_ocr", "extension", "Emits OCR_REQUIRED finding"),
    # Schemas & references
    CapabilityEntry("schema", "primitive_types", "supported", "string, integer, number, boolean"),
    CapabilityEntry("schema", "enums_objects_arrays", "supported", "Nested JSON objects/arrays"),
    CapabilityEntry("schema", "nullable_3_0", "supported", "OpenAPI 3.0 nullable boolean"),
    CapabilityEntry("schema", "local_ref", "supported", "Bounded local #/components/... refs"),
    CapabilityEntry("schema", "remote_ref", "unsupported", "Disabled in STRICT_OFFLINE mode"),
    CapabilityEntry(
        "schema",
        "composition_keywords",
        "deferred",
        "allOf, oneOf, anyOf blocked when behavior depends on them",
    ),
    # Parameters & serialization
    CapabilityEntry("parameter", "path_simple", "supported", "Path primitives, simple style"),
    CapabilityEntry("parameter", "query_form", "supported", "Query primitives/arrays, form style"),
    CapabilityEntry("parameter", "header_simple", "supported", "Header primitives, simple style"),
    CapabilityEntry("parameter", "cookie", "deferred", "Cookie parameters blocked"),
    CapabilityEntry(
        "parameter",
        "complex_styles",
        "deferred",
        "deepObject, matrix, label, spaceDelimited, pipeDelimited blocked",
    ),
    # Bodies & transport
    CapabilityEntry("body", "application_json", "supported", "JSON request and response bodies"),
    CapabilityEntry("body", "multipart_binary_xml", "deferred", "Non-JSON request bodies blocked"),
    # Authentication
    CapabilityEntry("auth", "http_bearer", "supported", "Authorization: Bearer <token>"),
    CapabilityEntry("auth", "api_key_header_query", "supported", "Header and query API keys"),
    CapabilityEntry("auth", "api_key_cookie", "extension", "Cookie API keys blocked"),
    CapabilityEntry("auth", "http_basic_oauth2_custom", "extension", "Deferred to extension"),
    # MCP transport
    CapabilityEntry("transport", "mcp_stdio", "supported", "Official MCP Python SDK stdio"),
    CapabilityEntry("transport", "mcp_streamable_http", "deferred", "Deferred outside flagship"),
)

SUPPORTED_OPENAPI_VERSION_PREFIX = "3.0."
MAX_REF_DEPTH = 20
SUPPORTED_PARAMETER_LOCATIONS = frozenset({"path", "query", "header"})
DEFERRED_PARAMETER_LOCATIONS = frozenset({"cookie"})
SUPPORTED_PARAMETER_STYLES = {
    "path": frozenset({"simple"}),
    "query": frozenset({"form"}),
    "header": frozenset({"simple"}),
}
SUPPORTED_SCHEMA_TYPES = frozenset({"string", "integer", "number", "boolean", "object", "array"})
UNSUPPORTED_COMPOSITION_KEYWORDS = frozenset({"allOf", "oneOf", "anyOf", "not", "discriminator"})
SUPPORTED_REQUEST_MEDIA_TYPES = frozenset({"application/json"})
PROTECTED_HEADER_NAMES = frozenset(
    {"host", "authorization", "content-length", "transfer-encoding", "connection"}
)


def is_openapi_version_supported(version_str: str) -> bool:
    return version_str.strip().startswith(SUPPORTED_OPENAPI_VERSION_PREFIX)


def get_capability_matrix_dict() -> list[dict[str, str]]:
    return [
        {
            "category": entry.category,
            "feature": entry.feature,
            "status": entry.status,
            "notes": entry.notes,
        }
        for entry in CAPABILITY_REGISTRY
    ]

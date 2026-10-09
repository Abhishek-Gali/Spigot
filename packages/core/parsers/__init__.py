"""Unified Document Parser Entrypoint for Spigot / DocForge MCP (T13 & T17)."""

from __future__ import annotations

from packages.core.contracts import DocumentBlock, Finding, SourceDocument
from packages.core.parsers.html_pdf_parser import (
    parse_pdf_document,
    sanitize_and_parse_saved_html,
)
from packages.core.parsers.markdown_parser import (
    group_blocks_by_section,
    parse_markdown_or_text,
)

DEFAULT_MAX_DOCUMENT_BYTES = 10 * 1024 * 1024  # 10 MiB


class DocumentParseLimitError(ValueError):
    """Raised when an input document exceeds configured byte or page parser bounds."""


def detect_document_format(filename: str, raw_bytes: bytes) -> str:
    """Detect document format from content magic bytes and filename extension."""
    head = raw_bytes[:512].lstrip()
    if head.startswith(b"%PDF-"):
        return "pdf"
    lower_name = filename.lower()
    if lower_name.endswith(".pdf"):
        return "pdf"
    if (
        lower_name.endswith((".html", ".htm"))
        or head.lower().startswith((b"<!doctype html", b"<html", b"<body", b"<head"))
    ):
        return "html"
    if lower_name.endswith((".md", ".markdown")):
        return "markdown"
    return "text"


def parse_document_bytes(
    source_id: str,
    filename: str,
    raw_bytes: bytes,
    *,
    project_id: str = "default_project",
    imported_at: str | None = None,
    max_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
) -> tuple[SourceDocument, list[DocumentBlock], list[Finding]]:
    """Dispatch document bytes to the appropriate parser (Markdown/text, HTML, or PDF)."""
    if len(raw_bytes) > max_bytes:
        raise DocumentParseLimitError(
            f"Document '{filename}' size ({len(raw_bytes)} bytes) exceeds max_bytes ({max_bytes} bytes)."
        )
    fmt = detect_document_format(filename, raw_bytes)
    if fmt == "pdf":
        return parse_pdf_document(
            source_id,
            filename,
            raw_bytes,
            project_id=project_id,
            imported_at=imported_at,
        )
    if fmt == "html":
        return sanitize_and_parse_saved_html(
            source_id,
            filename,
            raw_bytes,
            project_id=project_id,
            imported_at=imported_at,
        )
    return parse_markdown_or_text(
        source_id,
        filename,
        raw_bytes,
        project_id=project_id,
        imported_at=imported_at,
    )


__all__ = [
    "DEFAULT_MAX_DOCUMENT_BYTES",
    "DocumentParseLimitError",
    "detect_document_format",
    "group_blocks_by_section",
    "parse_document_bytes",
    "parse_markdown_or_text",
    "parse_pdf_document",
    "sanitize_and_parse_saved_html",
]

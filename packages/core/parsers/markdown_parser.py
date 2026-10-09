"""Markdown and UTF-8 Plain-Text Parser with Line-Span & Block Provenance (T13).

Parses Markdown and plain-text documentation into normalized `SourceDocument` and
`DocumentBlock` records while preserving:
- Exact 1-based line numbers (`location.start_line`, `location.end_line`)
- Heading hierarchy (`heading_path`)
- Fenced code blocks (`block_kind="code"`)
- Pipe-delimited Markdown tables (`block_kind="table"`)
- Narrative paragraphs and bullet lists (`block_kind="prose"`)
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from packages.core.contracts import (
    BlockLocation,
    DocumentBlock,
    Finding,
    SourceDocument,
    sha256_hex,
)

HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
FENCE_RE = re.compile(r"^(`{3,}|~{3,})(.*)$")
TABLE_ROW_RE = re.compile(r"^\s*\|.*\|\s*$")


def parse_markdown_or_text(
    source_id: str,
    filename: str,
    raw_bytes: bytes,
    *,
    project_id: str = "default_project",
    imported_at: str | None = None,
) -> tuple[SourceDocument, list[DocumentBlock], list[Finding]]:
    """Parse UTF-8 Markdown or plain text into `SourceDocument` and `DocumentBlock`s."""
    timestamp = imported_at or datetime.now(UTC).isoformat()
    raw_hash = sha256_hex(raw_bytes)
    media_type = (
        "text/markdown"
        if filename.lower().endswith((".md", ".markdown"))
        else "text/plain"
    )

    findings: list[Finding] = []
    if not raw_bytes or not raw_bytes.strip():
        empty_doc = SourceDocument(
            id=source_id,
            project_id=project_id,
            content_sha256=raw_hash,
            original_name=filename,
            media_type=media_type,
            imported_at=timestamp,
            local_artifact_ref=f"artifact://{raw_hash}",
        )
        findings.append(
            Finding(
                id=f"fnd_empty_{source_id}",
                code="EMPTY_DOCUMENT",
                severity="blocker",
                affected_field="document.content",
                explanation=f"Document '{filename}' contains no readable text.",
                suggested_resolution="Import a non-empty API documentation file.",
            )
        )
        return empty_doc, [], findings

    try:
        decoded = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        corrupt_doc = SourceDocument(
            id=source_id,
            project_id=project_id,
            content_sha256=raw_hash,
            original_name=filename,
            media_type=media_type,
            imported_at=timestamp,
            local_artifact_ref=f"artifact://{raw_hash}",
        )
        findings.append(
            Finding(
                id=f"fnd_utf8_{source_id}",
                code="UNREADABLE_DOCUMENT",
                severity="blocker",
                affected_field="document.encoding",
                explanation=f"Document '{filename}' is not valid UTF-8 text: {exc}",
                suggested_resolution="Convert the file to UTF-8 encoding before importing.",
            )
        )
        return corrupt_doc, [], findings

    normalized_doc_text = decoded.replace("\r\n", "\n").replace("\r", "\n")
    source_doc = SourceDocument(
        id=source_id,
        project_id=project_id,
        content_sha256=raw_hash,
        original_name=filename,
        media_type=media_type,
        imported_at=timestamp,
        local_artifact_ref=f"artifact://{raw_hash}",
    )

    lines = normalized_doc_text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    blocks: list[DocumentBlock] = []
    heading_stack: list[tuple[int, str]] = []

    def _current_heading_path() -> list[str]:
        return [title for _, title in heading_stack]

    def _emit_block(
        b_kind: str,
        b_lines: list[str],
        start_line: int,
        end_line: int,
        h_path: list[str],
    ) -> None:
        text = "\n".join(b_lines).strip("\n")
        if not text.strip():
            return
        block_idx = len(blocks) + 1
        blocks.append(
            DocumentBlock(
                id=f"{source_id}_blk_{block_idx:04d}",
                source_id=source_id,
                text=text,
                block_kind=b_kind,  # type: ignore[arg-type]
                heading_path=list(h_path),
                location=BlockLocation(
                    kind="line_char",
                    start_line=start_line,
                    end_line=end_line,
                    start_char=0,
                    end_char=len(text),
                ),
                extraction_method="markdown_parser_v1",
            )
        )

    idx = 0
    total_lines = len(lines)

    while idx < total_lines:
        line = lines[idx]
        line_no = idx + 1

        if not line.strip():
            idx += 1
            continue

        # 1. Check heading
        m_head = HEADING_RE.match(line)
        if m_head:
            level = len(m_head.group(1))
            title = m_head.group(2).strip()
            while heading_stack and heading_stack[-1][0] >= level:
                heading_stack.pop()
            heading_stack.append((level, title))
            _emit_block("heading", [line], line_no, line_no, _current_heading_path())
            idx += 1
            continue

        # 2. Check fenced code block
        m_fence = FENCE_RE.match(line.strip())
        if m_fence:
            fence_marker = m_fence.group(1)[:3]
            code_lines = [line]
            start_l = line_no
            idx += 1
            while idx < total_lines:
                curr = lines[idx]
                code_lines.append(curr)
                if curr.strip().startswith(fence_marker):
                    idx += 1
                    break
                idx += 1
            end_l = start_l + len(code_lines) - 1
            _emit_block("code", code_lines, start_l, end_l, _current_heading_path())
            continue

        # 3. Check pipe-delimited Markdown table
        if TABLE_ROW_RE.match(line):
            table_lines = [line]
            start_l = line_no
            idx += 1
            while idx < total_lines and TABLE_ROW_RE.match(lines[idx]):
                table_lines.append(lines[idx])
                idx += 1
            end_l = start_l + len(table_lines) - 1
            _emit_block("table", table_lines, start_l, end_l, _current_heading_path())
            continue

        # 4. Narrative prose or list block
        para_lines = [line]
        start_l = line_no
        idx += 1
        while idx < total_lines:
            peek = lines[idx]
            if (
                not peek.strip()
                or HEADING_RE.match(peek)
                or FENCE_RE.match(peek.strip())
                or TABLE_ROW_RE.match(peek)
            ):
                break
            para_lines.append(peek)
            idx += 1
        end_l = start_l + len(para_lines) - 1
        _emit_block("prose", para_lines, start_l, end_l, _current_heading_path())

    return source_doc, blocks, findings


def group_blocks_by_section(blocks: list[DocumentBlock]) -> list[dict[str, Any]]:
    """Group sequential DocumentBlocks into heading-anchored logical sections."""
    sections: list[dict[str, Any]] = []
    current_path: list[str] = []
    current_blocks: list[DocumentBlock] = []

    def _flush() -> None:
        if not current_blocks:
            return
        title = current_path[-1] if current_path else "Document Overview"
        combined_text = "\n\n".join(b.text for b in current_blocks)
        pages = sorted(
            {
                b.location.page_number
                for b in current_blocks
                if b.location.page_number is not None
            }
        )
        line_starts = [b.location.start_line for b in current_blocks]
        line_ends = [b.location.end_line for b in current_blocks]
        sections.append(
            {
                "title": title,
                "heading_path": list(current_path),
                "blocks": list(current_blocks),
                "combined_text": combined_text,
                "pages": pages,
                "line_start": min(line_starts) if line_starts else None,
                "line_end": max(line_ends) if line_ends else None,
            }
        )

    for blk in blocks:
        if blk.block_kind == "heading":
            if current_blocks:
                _flush()
                current_blocks = []
            current_path = list(blk.heading_path)
            current_blocks.append(blk)
        else:
            if not current_path and blk.heading_path:
                current_path = list(blk.heading_path)
            current_blocks.append(blk)

    _flush()
    return sections

"""Saved Static HTML and Text-Layer PDF Parsers with Page Citations & Scan Detection (T17).

Implements:
- `sanitize_and_parse_saved_html`: Strips `<script>`, `<style>`, `<iframe>`, `<object>`, `<embed>`,
  inline `on*` event handlers, and `javascript:` URIs before extracting headings,
  pipe-formatted tables, code blocks, and prose in document order.
- `parse_pdf_document`: Reads text-layer PDFs via `pypdf`, preserves 1-based
  `location.page_number` and `heading_path` across page boundaries (so multi-page operations
  cite all contributing pages), rejects encrypted/corrupt PDFs, and emits
  `OCR_REQUIRED` blocker findings for scanned/image-only pages.
"""

from __future__ import annotations

import io
import re
from datetime import UTC, datetime

from bs4 import BeautifulSoup, Tag
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from packages.core.contracts import (
    BlockLocation,
    DocumentBlock,
    Finding,
    SourceDocument,
    sha256_hex,
)
from packages.core.parsers.markdown_parser import (
    FENCE_RE,
    HEADING_RE,
    TABLE_ROW_RE,
)

ACTIVE_HTML_TAGS = (
    "script",
    "style",
    "iframe",
    "object",
    "embed",
    "applet",
    "noscript",
    "svg",
    "canvas",
    "template",
)

PDF_HEADING_LINE_RE = re.compile(
    r"^(?:#{1,6}\s+.+|(?:GET|POST|PUT|PATCH|DELETE)\s+/[A-Za-z0-9_\-/{}.:]+.*|"
    r"(?:Authentication|Base URL|Overview|Endpoints|Parameters|Request Body|Responses)\b.*)$"
)
MIN_TEXT_CHARS_PER_PDF_PAGE = 15


def sanitize_and_parse_saved_html(
    source_id: str,
    filename: str,
    raw_bytes: bytes,
    *,
    project_id: str = "default_project",
    imported_at: str | None = None,
) -> tuple[SourceDocument, list[DocumentBlock], list[Finding]]:
    """Strip active HTML content and extract ordered `DocumentBlock`s."""
    timestamp = imported_at or datetime.now(UTC).isoformat()
    raw_hash = sha256_hex(raw_bytes)
    findings: list[Finding] = []

    if not raw_bytes or not raw_bytes.strip():
        empty_doc = SourceDocument(
            id=source_id,
            project_id=project_id,
            content_sha256=raw_hash,
            original_name=filename,
            media_type="text/html",
            imported_at=timestamp,
            local_artifact_ref=f"artifact://{raw_hash}",
        )
        findings.append(
            Finding(
                id=f"fnd_empty_{source_id}",
                code="EMPTY_DOCUMENT",
                severity="blocker",
                affected_field="document.content",
                explanation=f"HTML document '{filename}' is empty.",
                suggested_resolution="Provide a non-empty saved HTML documentation file.",
            )
        )
        return empty_doc, [], findings

    decoded = raw_bytes.decode("utf-8", errors="replace")
    soup = BeautifulSoup(decoded, "html.parser")

    for tag_name in ACTIVE_HTML_TAGS:
        for tag in soup.find_all(tag_name):
            tag.decompose()

    for meta in soup.find_all("meta"):
        if isinstance(meta, Tag):
            http_equiv = str(meta.get("http-equiv", "")).lower()
            if http_equiv == "refresh":
                meta.decompose()

    for el in soup.find_all(True):
        if isinstance(el, Tag) and el.attrs:
            for attr_name in list(el.attrs.keys()):
                lower_attr = attr_name.lower()
                if lower_attr.startswith("on"):
                    del el.attrs[attr_name]
                elif lower_attr in {"href", "src", "action"}:
                    val = str(el.attrs.get(attr_name, "")).strip().lower()
                    if val.startswith(("javascript:", "vbscript:", "data:")):
                        del el.attrs[attr_name]

    blocks: list[DocumentBlock] = []
    heading_stack: list[tuple[int, str]] = []
    norm_chunks: list[str] = []

    def _current_heading_path() -> list[str]:
        return [title for _, title in heading_stack]

    def _emit(b_kind: str, text: str) -> None:
        cleaned = text.strip()
        if not cleaned:
            return
        norm_chunks.append(cleaned)
        block_idx = len(blocks) + 1
        blocks.append(
            DocumentBlock(
                id=f"{source_id}_blk_{block_idx:04d}",
                source_id=source_id,
                text=cleaned,
                block_kind=b_kind,  # type: ignore[arg-type]
                heading_path=_current_heading_path(),
                location=BlockLocation(
                    kind="line_char",
                    start_line=block_idx,
                    end_line=block_idx,
                    start_char=0,
                    end_char=len(cleaned),
                ),
                extraction_method="saved_html_sanitizer_v1",
            )
        )

    root = soup.body if soup.body is not None else soup
    target_tags = {"h1", "h2", "h3", "h4", "h5", "h6", "table", "pre", "p", "li"}

    for element in root.find_all(target_tags):
        if not isinstance(element, Tag):
            continue
        if element.find_parent({"table", "pre"}) is not None and element.name not in {
            "table",
            "pre",
        }:
            continue
        if element.name == "p" and element.find_parent("li") is not None:
            continue

        tag_name = element.name.lower()
        if tag_name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            level = int(tag_name[1])
            title = " ".join(element.get_text(" ", strip=True).split())
            if not title:
                continue
            while heading_stack and heading_stack[-1][0] >= level:
                heading_stack.pop()
            heading_stack.append((level, title))
            hashes = "#" * level
            _emit("heading", f"{hashes} {title}")

        elif tag_name == "table":
            rows_out: list[str] = []
            for tr in element.find_all("tr"):
                if not isinstance(tr, Tag):
                    continue
                cells = [
                    " ".join(cell.get_text(" ", strip=True).split())
                    for cell in tr.find_all(["th", "td"])
                ]
                if any(cells):
                    rows_out.append("| " + " | ".join(cells) + " |")
                    if tr.find("th") is not None and len(rows_out) == 1:
                        sep = "| " + " | ".join("---" for _ in cells) + " |"
                        rows_out.append(sep)
            if rows_out:
                _emit("table", "\n".join(rows_out))

        elif tag_name == "pre":
            code_text = element.get_text().strip("\r\n")
            if code_text.strip():
                _emit("code", f"```\n{code_text}\n```")

        elif tag_name in {"p", "li"}:
            txt = " ".join(element.get_text(" ", strip=True).split())
            if txt:
                prefix = "- " if tag_name == "li" else ""
                _emit("prose", f"{prefix}{txt}")

    source_doc = SourceDocument(
        id=source_id,
        project_id=project_id,
        content_sha256=raw_hash,
        original_name=filename,
        media_type="text/html",
        imported_at=timestamp,
        local_artifact_ref=f"artifact://{raw_hash}",
    )
    return source_doc, blocks, findings


def parse_pdf_document(
    source_id: str,
    filename: str,
    raw_bytes: bytes,
    *,
    project_id: str = "default_project",
    imported_at: str | None = None,
) -> tuple[SourceDocument, list[DocumentBlock], list[Finding]]:
    """Parse text-layer PDF into page-cited `DocumentBlock`s or emit `OCR_REQUIRED`."""
    timestamp = imported_at or datetime.now(UTC).isoformat()
    raw_hash = sha256_hex(raw_bytes)
    findings: list[Finding] = []

    try:
        reader = PdfReader(io.BytesIO(raw_bytes))
    except (PdfReadError, ValueError, Exception) as exc:
        corrupt_doc = SourceDocument(
            id=source_id,
            project_id=project_id,
            content_sha256=raw_hash,
            original_name=filename,
            media_type="application/pdf",
            imported_at=timestamp,
            local_artifact_ref=f"artifact://{raw_hash}",
        )
        findings.append(
            Finding(
                id=f"fnd_pdf_corrupt_{source_id}",
                code="UNREADABLE_PDF",
                severity="blocker",
                affected_field="document.pdf",
                explanation=f"PDF '{filename}' could not be parsed: {exc}",
                suggested_resolution="Provide a valid, uncorrupted text-based PDF.",
            )
        )
        return corrupt_doc, [], findings

    if reader.is_encrypted:
        enc_doc = SourceDocument(
            id=source_id,
            project_id=project_id,
            content_sha256=raw_hash,
            original_name=filename,
            media_type="application/pdf",
            imported_at=timestamp,
            local_artifact_ref=f"artifact://{raw_hash}",
        )
        findings.append(
            Finding(
                id=f"fnd_pdf_encrypted_{source_id}",
                code="ENCRYPTED_DOCUMENT",
                severity="blocker",
                affected_field="document.encryption",
                explanation=f"PDF '{filename}' is password-protected/encrypted.",
                suggested_resolution="Decrypt the PDF locally before importing.",
            )
        )
        return enc_doc, [], findings

    if len(reader.pages) == 0:
        empty_doc = SourceDocument(
            id=source_id,
            project_id=project_id,
            content_sha256=raw_hash,
            original_name=filename,
            media_type="application/pdf",
            imported_at=timestamp,
            local_artifact_ref=f"artifact://{raw_hash}",
        )
        findings.append(
            Finding(
                id=f"fnd_pdf_empty_{source_id}",
                code="EMPTY_DOCUMENT",
                severity="blocker",
                affected_field="document.pages",
                explanation=f"PDF '{filename}' has 0 pages.",
                suggested_resolution="Provide a PDF containing API documentation pages.",
            )
        )
        return empty_doc, [], findings

    blocks: list[DocumentBlock] = []
    heading_stack: list[tuple[int, str]] = []
    scanned_pages: list[int] = []

    def _current_heading_path() -> list[str]:
        return [title for _, title in heading_stack]

    def _emit_pdf_block(
        b_kind: str,
        text: str,
        page_num: int,
        line_start: int,
        line_end: int,
    ) -> None:
        cleaned = text.strip()
        if not cleaned:
            return
        block_idx = len(blocks) + 1
        eff_end_line = max(line_start, line_end)
        bbox = (
            36.0,
            float(line_start * 14),
            576.0,
            float((eff_end_line + 1) * 14),
        )
        blocks.append(
            DocumentBlock(
                id=f"{source_id}_p{page_num}_blk_{block_idx:04d}",
                source_id=source_id,
                text=cleaned,
                block_kind=b_kind,  # type: ignore[arg-type]
                heading_path=_current_heading_path(),
                location=BlockLocation(
                    kind="page_bbox",
                    start_line=line_start,
                    end_line=eff_end_line,
                    start_char=0,
                    end_char=len(cleaned),
                    page_number=page_num,
                    bbox=bbox,
                ),
                extraction_method="pypdf_text_layer_v1",
            )
        )

    for page_idx, page in enumerate(reader.pages, start=1):
        raw_page_text = (page.extract_text() or "").replace("\r\n", "\n").replace("\r", "\n")
        non_ws_chars = len(re.sub(r"\s+", "", raw_page_text))
        if non_ws_chars < MIN_TEXT_CHARS_PER_PDF_PAGE:
            scanned_pages.append(page_idx)
            continue

        lines = [ln.strip() for ln in raw_page_text.split("\n")]
        idx = 0
        total = len(lines)
        while idx < total:
            line = lines[idx]
            line_no = idx + 1
            if not line:
                idx += 1
                continue

            m_head = HEADING_RE.match(line)
            if m_head:
                level = len(m_head.group(1))
                title = m_head.group(2).strip()
                while heading_stack and heading_stack[-1][0] >= level:
                    heading_stack.pop()
                heading_stack.append((level, title))
                _emit_pdf_block("heading", line, page_idx, line_no, line_no)
                idx += 1
                continue

            if PDF_HEADING_LINE_RE.match(line) and not line.startswith("|"):
                level = (
                    3
                    if any(
                        line.startswith(m)
                        for m in ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ")
                    )
                    else 2
                )
                while heading_stack and heading_stack[-1][0] >= level:
                    heading_stack.pop()
                heading_stack.append((level, line))
                _emit_pdf_block(
                    "heading", f"{'#' * level} {line}", page_idx, line_no, line_no
                )
                idx += 1
                continue

            if FENCE_RE.match(line):
                code_lines = [line]
                start_l = line_no
                idx += 1
                while idx < total:
                    code_lines.append(lines[idx])
                    if FENCE_RE.match(lines[idx]):
                        idx += 1
                        break
                    idx += 1
                _emit_pdf_block("code", "\n".join(code_lines), page_idx, start_l, idx)
                continue

            if TABLE_ROW_RE.match(line):
                tbl_lines = [line]
                start_l = line_no
                idx += 1
                while idx < total and TABLE_ROW_RE.match(lines[idx]):
                    tbl_lines.append(lines[idx])
                    idx += 1
                _emit_pdf_block("table", "\n".join(tbl_lines), page_idx, start_l, idx)
                continue

            para_lines = [line]
            start_l = line_no
            idx += 1
            while idx < total:
                peek = lines[idx]
                if (
                    not peek
                    or HEADING_RE.match(peek)
                    or PDF_HEADING_LINE_RE.match(peek)
                    or FENCE_RE.match(peek)
                    or TABLE_ROW_RE.match(peek)
                ):
                    break
                para_lines.append(peek)
                idx += 1
            _emit_pdf_block("prose", "\n".join(para_lines), page_idx, start_l, idx)

    if scanned_pages:
        pages_str = ", ".join(str(p) for p in scanned_pages)
        findings.append(
            Finding(
                id=f"fnd_ocr_{source_id}",
                code="OCR_REQUIRED",
                severity="blocker",
                affected_field="document.ocr",
                explanation=(
                    f"PDF '{filename}' contains image-only or scanned page(s) [{pages_str}] "
                    f"with insufficient extractable text (< {MIN_TEXT_CHARS_PER_PDF_PAGE} chars)."
                ),
                suggested_resolution=(
                    "Provide a text-layer PDF, Markdown/HTML documentation, or enable "
                    "the local OCR extension (X01) before extracting from scanned pages."
                ),
            )
        )

    source_doc = SourceDocument(
        id=source_id,
        project_id=project_id,
        content_sha256=raw_hash,
        original_name=filename,
        media_type="application/pdf",
        imported_at=timestamp,
        local_artifact_ref=f"artifact://{raw_hash}",
    )
    return source_doc, blocks, findings

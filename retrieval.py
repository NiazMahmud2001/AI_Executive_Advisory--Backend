"""Document text for the LangGraph agent: extraction, chunking and a simple word match.

Files stay encrypted on disk. A document is decrypted in memory when the agent needs it, split into chunks that
never cross a page or a section, and cached by its SHA-256 while the API runs.

The demo library is small, so the agent sends every permitted chunk to the model, the best word matches first, up
to a size limit. A production system would rank the chunks with full-text or vector search and send only the best few.
"""
import io
import logging
import re

import docx
from docx.table import Table
from pypdf import PdfReader

import config
import security

log = logging.getLogger("aea")

CHUNK_CHARS = 900          # long sections are split at line breaks into chunks of about this size
MAX_SOURCE_CHARS = 30_000  # at most this much text goes to the model per question
HEADING = re.compile(r"^(?:#{1,6}\s+\S.*|(?:Section|Part|Article)\s+\d+\b.*|\d+(?:\.\d+)*\.?\s+[A-Z][^.]*)$")  # "4.1 Annual leave"
STOP_WORDS = set("""a about an and any are as at be by can could did do does for from get give has have how i if in is
it me much many my of on or our please should tell the their there this to was we what when where which who why will
with would you your""".split())


def _sections(lines: list, page: int | None = None):
    """Group lines into (location, text). A short heading line such as "Section 2: Remote work" starts a new section."""
    location, buffer = (f"Page {page}" if page else "Text"), []
    for line in (raw.strip() for raw in lines):
        if not line:
            continue
        if len(line) <= 60 and HEADING.match(line):
            if buffer:
                yield location, "\n".join(buffer)
            location, buffer = (f"Page {page} · {line}" if page else line), [line]
        else:
            buffer.append(line)
    if buffer:
        yield location, "\n".join(buffer)


def _docx_sections(data: bytes):
    """Paragraphs and tables in document order; a Heading or Title style starts a new section."""
    location, buffer = "Text", []
    for block in docx.Document(io.BytesIO(data)).iter_inner_content():
        if isinstance(block, Table):
            buffer += [" | ".join(cell.text.strip() for cell in row.cells) for row in block.rows]
        elif block.text.strip() and block.style is not None and block.style.name.startswith(("Heading", "Title")):
            if buffer:
                yield location, "\n".join(buffer)
            location, buffer = block.text.strip()[:80], [block.text.strip()]
        elif block.text.strip():
            buffer.append(block.text.strip())
    if buffer:
        yield location, "\n".join(buffer)


def _extract(doc: dict, data: bytes):
    if doc["extension"] == "pdf":
        for page, content in enumerate(PdfReader(io.BytesIO(data)).pages, 1):
            yield from _sections((content.extract_text() or "").splitlines(), page)
    elif doc["extension"] == "docx":
        yield from _docx_sections(data)
    else:
        yield from _sections(data.decode("utf-8", errors="replace").splitlines())


def _split(text: str):
    chunk = ""
    for line in text.split("\n"):
        if chunk and len(chunk) + len(line) > CHUNK_CHARS:
            yield chunk
            chunk = ""
        chunk = f"{chunk}\n{line}" if chunk else line
    if chunk:
        yield chunk


_cache: dict[str, tuple[str, list]] = {}  # document id -> (sha256, chunks)


def document_chunks(doc: dict) -> list[dict]:
    """[{"location", "text"}] for one document. Empty if its file is missing or cannot be read."""
    if doc["id"] in _cache and _cache[doc["id"]][0] == doc["sha256"]:
        return _cache[doc["id"]][1]
    path = config.STORAGE_DIR / doc["storage_key"]
    try:
        data = security.decrypt_bytes(path.read_bytes())  # decrypted in memory only
        chunks = [{"location": location, "text": part} for location, text in _extract(doc, data) for part in _split(text)]
    except Exception:  # a damaged or missing file must not break every question; it is simply not searchable
        log.exception("Text extraction failed for document %s", doc["id"])
        chunks = []
    _cache[doc["id"]] = (doc["sha256"], chunks)
    return chunks


def chunks_for(question: str, docs: list) -> list[dict]:
    """The chunks of `docs`, those sharing most words with the question first, up to MAX_SOURCE_CHARS in total.

    Each chunk carries its document's id, title, filename and classification, its location and text, and "matches":
    how many of the question's words occur in it ("work" also matches "working").
    """
    words = {w for w in re.findall(r"[a-z0-9]+", question.lower()) if w not in STOP_WORDS and len(w) > 1}
    chunks = [{"doc_id": d["id"], "title": d["title"], "filename": d["filename"], "classification": d["classification"],
               **chunk, "matches": sum(w in chunk["text"].lower() for w in words)}
              for d in docs for chunk in document_chunks(d)]
    chunks.sort(key=lambda c: c["matches"], reverse=True)
    picked, size = [], 0
    for chunk in chunks:
        size += len(chunk["text"])
        if size > MAX_SOURCE_CHARS:
            break
        picked.append(chunk)
    return picked

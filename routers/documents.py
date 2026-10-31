"""Document library: upload (encrypted at rest), list, download, reclassify, delete, and the upload automation runs.

Every read goes through `visible_document`, so a document outside the user's clearance answers
404 Not Found (it does not reveal that the document exists) and the attempt is written to the audit log.
"""
import re
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field

import automation
import config
import security
import store
from security import Auth, require_admin, require_user

router = APIRouter(prefix="/api", tags=["documents"])

CATEGORIES = ("finance", "hr", "management", "general")
FILE_TYPES = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/markdown; charset=utf-8",
}


def public_document(doc: dict) -> dict:
    return {k: v for k, v in doc.items() if k not in ("storage_key", "seed_key")}


def visible_document(doc_id: str, auth: Auth, request: Request, action: str) -> dict:
    doc = store.get_document(doc_id)
    if not doc or doc["classification"] not in auth.clearance:
        if doc:
            security.log_event("access_denied", request, auth.user, document_id=doc_id, action=action,
                               reason=f"{doc['classification']} document")
        raise HTTPException(404, "Document not found.")
    return doc


def _content_matches_type(ext: str, data: bytes) -> bool:
    """Check the file's first bytes, so a renamed executable or a random binary is rejected."""
    if ext == ".pdf":
        return data.startswith(b"%PDF-")
    if ext == ".docx":
        return data.startswith(b"PK\x03\x04")  # .docx is a ZIP container
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _safe_filename(name: str) -> str:
    name = Path(name or "document").name  # drop any folder part ("../../x")
    name = re.sub(r"[^\w.\- ()]", "_", name).strip(" .")
    return name[:120] or "document"


# ============================================================================
# documents
# ============================================================================
@router.get("/documents")
def list_documents(auth: Auth = Depends(require_user)):
    return [public_document(d) for d in store.list_documents(auth.clearance)]


@router.post("/documents", status_code=201)
def upload_document(
    request: Request,
    background: BackgroundTasks,
    file: UploadFile = File(...),
    title: str = Form("", max_length=150),
    category: str = Form("general"),
    classification: str = Form("general"),
    auth: Auth = Depends(require_user),
):
    if category not in CATEGORIES:
        raise HTTPException(422, f"Category must be one of: {', '.join(CATEGORIES)}.")
    if classification not in security.CLASSIFICATIONS:
        raise HTTPException(422, "Access must be general or confidential.")
    if classification == "confidential" and not auth.is_admin:
        security.log_event("access_denied", request, auth.user, action="upload confidential document")
        raise HTTPException(403, "Only administrators can upload confidential documents.")

    filename = _safe_filename(file.filename)
    ext = Path(filename).suffix.lower()
    if ext not in FILE_TYPES:
        raise HTTPException(415, "Only PDF, Word (.docx) and text (.txt, .md) files are supported.")

    limit = config.MAX_UPLOAD_MB * 1024 * 1024
    data = file.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"The file is larger than {config.MAX_UPLOAD_MB} MB.")
    if not data:
        raise HTTPException(422, "The file is empty.")
    if not _content_matches_type(ext, data):
        raise HTTPException(415, "The file content does not match its type.")

    sha256 = security.sha256_hex(data)
    duplicate = store.find_document_by_sha(sha256, auth.clearance)
    if duplicate:
        raise HTTPException(409, f"This file is already in the library as \"{duplicate['title']}\".")

    doc_id = store.new_id()
    config.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    (config.STORAGE_DIR / f"{doc_id}.bin").write_bytes(security.encrypt_bytes(data))  # server-side name, never the user's

    doc = {
        "id": doc_id,
        "title": title.strip() or Path(filename).stem.replace("_", " "),
        "filename": filename,
        "extension": ext.lstrip("."),
        "size_bytes": len(data),
        "sha256": sha256,
        "category": category,
        "classification": classification,
        "storage_key": f"{doc_id}.bin",
        "uploaded_by": auth.user["id"],
        "uploaded_by_name": auth.user["name"],
        "created_at": store.now_iso(),
        "status": "processing",
        "summary": None,
    }
    store.add_document(doc)
    run = automation.start_run(doc, auth.user)
    background.add_task(automation.process, run["id"])
    security.log_event("document_uploaded", request, auth.user, document_id=doc_id, title=doc["title"],
                       classification=classification)
    return {"document": public_document(doc), "run": run}


@router.get("/documents/{doc_id}")
def get_document(doc_id: str, request: Request, auth: Auth = Depends(require_user)):
    return public_document(visible_document(doc_id, auth, request, "read"))


@router.get("/documents/{doc_id}/download")
def download_document(doc_id: str, request: Request, auth: Auth = Depends(require_user)):
    doc = visible_document(doc_id, auth, request, "download")
    path = config.STORAGE_DIR / doc["storage_key"]
    if not path.exists():
        raise HTTPException(410, "The stored file is missing. Please upload it again.")
    data = security.decrypt_bytes(path.read_bytes())
    security.log_event("document_downloaded", request, auth.user, document_id=doc_id)
    ascii_name = doc["filename"].encode("ascii", "ignore").decode() or "document"
    disposition = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(doc['filename'])}"
    return Response(data, media_type=FILE_TYPES.get("." + doc["extension"], "application/octet-stream"),
                    headers={"Content-Disposition": disposition})


class DocumentChanges(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=150)
    category: Literal["finance", "hr", "management", "general"] | None = None
    classification: Literal["general", "confidential"] | None = None


@router.patch("/documents/{doc_id}")
def update_document(doc_id: str, body: DocumentChanges, request: Request, auth: Auth = Depends(require_admin)):
    doc = visible_document(doc_id, auth, request, "update")
    changes = body.model_dump(exclude_none=True)
    if not changes:
        return public_document(doc)
    doc = store.update_document(doc_id, **changes)
    security.log_event("document_updated", request, auth.user, document_id=doc_id, changes=changes)
    return public_document(doc)


@router.delete("/documents/{doc_id}", status_code=204)
def delete_document(doc_id: str, request: Request, auth: Auth = Depends(require_admin)):
    doc = visible_document(doc_id, auth, request, "delete")
    (config.STORAGE_DIR / doc["storage_key"]).unlink(missing_ok=True)
    store.delete_document(doc_id)
    security.log_event("document_deleted", request, auth.user, document_id=doc_id, title=doc["title"])


# ============================================================================
# automation runs  (admins see all; a standard user sees runs of their own uploads that they can still read)
# ============================================================================
def _run_visible(run: dict, auth: Auth) -> bool:
    if auth.is_admin:
        return True
    doc = store.get_document(run["document_id"])
    return run["triggered_by"] == auth.user["id"] and bool(doc) and doc["classification"] in auth.clearance


@router.get("/automations")
def list_runs(auth: Auth = Depends(require_user)):
    return [r for r in store.list_runs() if _run_visible(r, auth)][:50]


@router.get("/automations/{run_id}")
def get_run(run_id: str, auth: Auth = Depends(require_user)):
    run = store.get_run(run_id)
    if not run or not _run_visible(run, auth):
        raise HTTPException(404, "Automation run not found.")
    return run

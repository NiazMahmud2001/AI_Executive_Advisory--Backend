"""JSON file store for phase 1.

Each function is one small, named query, so phase 2 can replace this module with Supabase
queries without touching the routers. Writes are atomic (temp file + rename) and a lock
serializes access, because FastAPI runs sync endpoints in a thread pool.
"""
import json
import os
import threading
import uuid
from datetime import datetime, timezone

import config

_lock = threading.RLock()
MAX_AUDIT_ROWS = 2000
MAX_QUESTION_ROWS = 500


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    return str(uuid.uuid4())


def _path(name: str):
    return config.DATA_DIR / f"{name}.json"


def _read(name: str) -> list:
    path = _path(name)
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _write(name: str, rows: list) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = _path(name)
    tmp = path.with_suffix(".tmp") # ** **
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    os.replace(tmp, path)


def _update(name: str, row_id: str, changes: dict, key: str = "id") -> dict | None:
    with _lock:
        rows = _read(name)
        for row in rows:
            if row[key] == row_id:
                row.update(changes)
                _write(name, rows)
                return row
    return None


# ============================================================================
# users  (password_hash never leaves this module through public_user)
# ============================================================================
def public_user(user: dict) -> dict:
    return {k: user.get(k) for k in ("id", "email", "name", "role", "active", "created_at", "last_login_at")}


def list_users() -> list:
    with _lock:
        return _read("users")


def get_user(user_id: str) -> dict | None:
    return next((u for u in list_users() if u["id"] == user_id), None)


def get_user_by_email(email: str) -> dict | None:
    email = email.strip().lower()
    return next((u for u in list_users() if u["email"] == email), None)


def create_user(email: str, name: str, role: str, password_hash: str) -> dict:
    user = {
        "id": new_id(),
        "email": email.strip().lower(),
        "name": name.strip(),
        "role": role,
        "password_hash": password_hash,
        "active": True,
        "created_at": now_iso(),
        "last_login_at": None,
    }
    with _lock:
        rows = _read("users")
        rows.append(user)
        _write("users", rows)
    return user


def update_user(user_id: str, **changes) -> dict | None:
    return _update("users", user_id, changes)


# ============================================================================
# sessions  (stored under the SHA-256 hash of the cookie token, never the token itself)
# ============================================================================
def create_session(session: dict) -> None:
    with _lock:
        rows = _read("sessions")
        rows.append(session)
        _write("sessions", rows)


def get_session(session_id: str) -> dict | None:
    with _lock:
        return next((s for s in _read("sessions") if s["id"] == session_id), None)


def touch_session(session_id: str, last_seen_at: str) -> None:
    _update("sessions", session_id, {"last_seen_at": last_seen_at})


def delete_session(session_id: str) -> None:
    with _lock:
        rows = _read("sessions")
        _write("sessions", [s for s in rows if s["id"] != session_id])


def delete_user_sessions(user_id: str) -> None:
    with _lock:
        rows = _read("sessions")
        _write("sessions", [s for s in rows if s["user_id"] != user_id])


def purge_expired_sessions() -> int:
    now = now_iso()
    with _lock:
        rows = _read("sessions")
        alive = [s for s in rows if s["expires_at"] > now]
        _write("sessions", alive)
    return len(rows) - len(alive)


# ============================================================================
# documents  (list_documents always needs the caller's clearance, so no query returns everything by accident)
# ============================================================================
def list_documents(clearance: tuple) -> list:
    with _lock:
        docs = [d for d in _read("documents") if d["classification"] in clearance]
    return sorted(docs, key=lambda d: d["created_at"], reverse=True)


def get_document(doc_id: str) -> dict | None:
    """Raw lookup without a permission check: routers must go through their visibility helper."""
    with _lock:
        return next((d for d in _read("documents") if d["id"] == doc_id), None)


def find_document_by_sha(sha256: str, clearance: tuple) -> dict | None:
    return next((d for d in list_documents(clearance) if d["sha256"] == sha256), None)


def add_document(doc: dict) -> None:
    with _lock:
        rows = _read("documents")
        rows.append(doc)
        _write("documents", rows)


def update_document(doc_id: str, **changes) -> dict | None:
    return _update("documents", doc_id, changes)


def delete_document(doc_id: str) -> None:
    with _lock:
        rows = _read("documents")
        _write("documents", [d for d in rows if d["id"] != doc_id])


# ============================================================================
# automation runs
# ============================================================================
def add_run(run: dict) -> None:
    with _lock:
        rows = _read("automations")
        rows.append(run)
        _write("automations", rows)


def get_run(run_id: str) -> dict | None:
    with _lock:
        return next((r for r in _read("automations") if r["id"] == run_id), None)


def update_run(run_id: str, **changes) -> dict | None:
    return _update("automations", run_id, changes)


def list_runs() -> list:
    with _lock:
        return sorted(_read("automations"), key=lambda r: r["started_at"], reverse=True)


# ============================================================================
# questions asked to the advisors
# ============================================================================
def add_question(record: dict) -> None:
    with _lock:
        rows = _read("questions")
        rows.append(record)
        _write("questions", rows[-MAX_QUESTION_ROWS:])


def list_questions(user_id: str | None = None) -> list:
    with _lock:
        rows = _read("questions")
    if user_id:
        rows = [q for q in rows if q["user_id"] == user_id]
    return list(reversed(rows))


# ============================================================================
# audit log  (security and business events, newest last on disk)
# ============================================================================
def audit(event: str, user: dict | None, ip: str, detail: dict | None = None) -> None:
    row = {
        "id": new_id(),
        "at": now_iso(),
        "event": event,
        "user_id": user["id"] if user else None,
        "user_email": user["email"] if user else (detail or {}).get("email"),
        "ip": ip,
        "detail": {k: v for k, v in (detail or {}).items() if k != "email"},
    }
    with _lock:
        rows = _read("audit")
        rows.append(row)
        _write("audit", rows[-MAX_AUDIT_ROWS:]) # ** **


def list_audit() -> list:
    with _lock:
        return list(reversed(_read("audit")))

"""Role-aware numbers for the dashboard: standard users only see figures about what they can access."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

import config
import security
import store
from routers.admin import AUDIT_GROUPS
from routers.documents import _run_visible, public_document
from security import Auth, require_user

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard")
def dashboard(auth: Auth = Depends(require_user)):
    docs = store.list_documents(auth.clearance)
    mine = store.list_questions(auth.user["id"])
    today = datetime.now(timezone.utc).date().isoformat()

    data = {
        "documents": {
            "visible": len(docs),
            "by_category": {c: sum(d["category"] == c for d in docs) for c in ("finance", "hr", "management", "general")},
            "my_uploads": sum(d["uploaded_by"] == auth.user["id"] for d in docs),
        },
        "questions": {"mine": len(mine), "mine_today": sum(q["at"].startswith(today) for q in mine)},
        "recent_questions": mine[:5],
        "recent_documents": [public_document(d) for d in docs[:5]],
        "recent_runs": [r for r in store.list_runs() if _run_visible(r, auth)][:5],
        "system": {
            "phase": config.PHASE,
            "engine": config.ENGINE_LABEL,
            "store": "JSON files (phase 1)",
            "encryption": "Fernet: AES-128 + HMAC-SHA256",
            "role": security.ROLES[auth.user["role"]],
            "searchable_documents": len(docs),
        },
    }

    if auth.is_admin:
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
        recent_audit = [r for r in store.list_audit() if r["at"] >= since]
        security_events = [r for r in recent_audit if r["event"] in AUDIT_GROUPS["security"]]
        users = store.list_users()
        all_questions = store.list_questions()
        data["documents"]["confidential"] = sum(d["classification"] == "confidential" for d in docs)
        data["questions"]["total"] = len(all_questions)
        data["questions"]["today"] = sum(q["at"].startswith(today) for q in all_questions)
        data["users"] = {"total": len(users), "admins": sum(u["role"] == "admin" for u in users),
                         "active": sum(u["active"] for u in users)}
        data["security"] = {
            "events_24h": len(security_events),
            "failed_logins_24h": sum(r["event"] == "login_failed" for r in security_events),
            "denied_24h": sum(r["event"] in ("access_denied", "ai_access_filtered") for r in security_events),
            "recent": security_events[:5],
        }
    return data

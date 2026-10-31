"""Administrator-only: manage users and read the audit log."""
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import security
import store
from security import Auth, require_admin

router = APIRouter(prefix="/api/admin", tags=["admin"])

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

AUDIT_GROUPS = {
    "security": {"login_failed", "login_locked", "login_blocked", "access_denied", "csrf_rejected",
                 "ai_access_filtered", "prompt_injection_flagged"},
    "auth": {"login_success", "logout"},
    "documents": {"document_uploaded", "document_downloaded", "document_updated", "document_deleted",
                  "automation_completed", "automation_failed"},
    "ai": {"agent_query", "agent_error"},
    "users": {"user_created", "user_updated"},
}


class NewUser(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=5, max_length=254)
    role: Literal["admin", "user"] = "user"
    password: str = Field(min_length=1, max_length=128)


class UserChanges(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=80)
    role: Literal["admin", "user"] | None = None
    active: bool | None = None
    password: str | None = Field(None, max_length=128)


@router.get("/users")
def list_users(auth: Auth = Depends(require_admin)):
    return [store.public_user(u) for u in store.list_users()]


@router.post("/users", status_code=201)
def create_user(body: NewUser, request: Request, auth: Auth = Depends(require_admin)):
    email = body.email.strip().lower()
    if not EMAIL_PATTERN.match(email):
        raise HTTPException(422, "Please enter a valid email address.")
    if store.get_user_by_email(email):
        raise HTTPException(409, "A user with this email already exists.")
    problem = security.password_problem(body.password)
    if problem:
        raise HTTPException(422, problem)
    user = store.create_user(email, body.name, body.role, security.hash_password(body.password))
    security.log_event("user_created", request, auth.user, target=email, role=body.role)
    return store.public_user(user)


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: UserChanges, request: Request, auth: Auth = Depends(require_admin)):
    target = store.get_user(user_id)
    if not target:
        raise HTTPException(404, "User not found.")
    if user_id == auth.user["id"] and (body.role == "user" or body.active is False):
        raise HTTPException(400, "You cannot remove your own administrator access or disable your own account.")

    changes = body.model_dump(exclude_none=True)
    if "password" in changes:
        problem = security.password_problem(changes["password"])
        if problem:
            raise HTTPException(422, problem)
        changes["password_hash"] = security.hash_password(changes.pop("password"))
    if not changes:
        return store.public_user(target)

    user = store.update_user(user_id, **changes)
    if {"role", "active", "password_hash"} & changes.keys():
        store.delete_user_sessions(user_id)  # new permissions apply at once: the user must sign in again
    logged = {k: v for k, v in changes.items() if k != "password_hash"}
    security.log_event("user_updated", request, auth.user, target=target["email"], changes=logged,
                       password_changed="password_hash" in changes)
    return store.public_user(user)


@router.get("/audit")
def audit_log(group: str = "all", auth: Auth = Depends(require_admin)):
    rows = store.list_audit()
    if group in AUDIT_GROUPS:
        rows = [r for r in rows if r["event"] in AUDIT_GROUPS[group]]
    return rows[:300]

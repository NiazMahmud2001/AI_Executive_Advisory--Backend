"""Sign in, sign out and "who am I" for the session cookie."""
import math

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

import security
import store
from security import Auth, require_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response):
    email = body.email.strip().lower()
    key = security.throttle_key(email, security.client_ip(request))
    wait = security.locked_for_seconds(key)
    if wait:
        security.log_event("login_locked", request, email=email)
        raise HTTPException(429, f"Too many failed attempts. Try again in {math.ceil(wait / 60)} minute(s).")

    user = store.get_user_by_email(email)
    password_ok = security.verify_password(body.password, user["password_hash"] if user else security.DUMMY_HASH)
    if not user or not password_ok:
        security.record_failure(key)
        security.log_event("login_failed", request, email=email)
        raise HTTPException(401, "Invalid email or password.")  # same message for unknown email and wrong password
    if not user["active"]:
        security.log_event("login_blocked", request, user, reason="account disabled")
        raise HTTPException(403, "This account is disabled. Please contact an administrator.")

    security.clear_failures(key)
    session = security.start_session(request, response, user)
    user = store.update_user(user["id"], last_login_at=store.now_iso())
    security.log_event("login_success", request, user)
    return {"user": store.public_user(user), "csrf_token": session["csrf_token"], "session": security.session_info(session)}


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, auth: Auth = Depends(require_user)):
    security.end_session(response, auth.session["id"])
    security.log_event("logout", request, auth.user)


@router.get("/me")
def me(auth: Auth = Depends(require_user)):
    return {
        "user": store.public_user(auth.user),
        "csrf_token": auth.session["csrf_token"],
        "session": security.session_info(auth.session),
    }

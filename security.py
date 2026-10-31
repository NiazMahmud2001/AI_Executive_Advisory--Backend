"""Password hashing, server-side sessions in HttpOnly cookies, CSRF protection, role checks,
login throttling and encryption of stored documents."""
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import bcrypt
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, Request, Response

import config
import store

ROLES = {
    "admin": "Administrator", 
    "user": "Standard User"
}
CLASSIFICATIONS = ("general", "confidential")
ROLE_CLEARANCE = {
    "admin": ("general", "confidential"), 
    "user": ("general",)
}  # which documents each role may read
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


# ============================================================================
# passwords : bcrypt with a per-password salt (cost 12)
# ============================================================================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    data = password.encode("utf-8")
    if len(data) > 72:  # bcrypt only reads 72 bytes, longer passwords are rejected when they are set
        return False
    return bcrypt.checkpw(data, password_hash.encode("ascii"))


# Checked when the email is unknown, so a wrong email takes as long as a wrong password (no user enumeration by timing).
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problem(password: str) -> str | None:
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if len(password.encode("utf-8")) > 72:
        return "Password is too long."
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        return "Password must contain letters and numbers."
    return None


# ============================================================================
# sessions : random 256-bit token in an HttpOnly cookie, only its SHA-256 hash is stored
# ============================================================================
def _now() -> datetime:
    #GULF = timezone(timedelta(hours=4), "GST")
    return datetime.now(timezone.utc) # returns -> datetime object objects 
    # timezone.utc


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest() # returns str datetime: 2026-10-30T03:43:17+00:00


def client_ip(request: Request) -> str:
    # Behind a proxy (Render), run uvicorn with --proxy-headers so request.client is the real visitor.
    return request.client.host if request.client else "unknown"


def start_session(request: Request, response: Response, user: dict) -> dict:
    """Create a session and set its cookie. The session's csrf_token goes to the UI, which sends it back on every change."""
    old_token = request.cookies.get(config.SESSION_COOKIE)
    if old_token:  # a new sign-in always gets a new token (no session fixation)
        store.delete_session(token_hash(old_token))

    token = secrets.token_urlsafe(32)
    now = _now()
    session = {
        "id": token_hash(token),
        "user_id": user["id"],
        "csrf_token": secrets.token_urlsafe(32),
        "created_at": _iso(now),
        "last_seen_at": _iso(now),
        "expires_at": _iso(now + timedelta(minutes=config.SESSION_TTL_MINUTES)),
        "ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:200],
    }
    store.create_session(session)
    response.set_cookie(
        config.SESSION_COOKIE,  # variable
        token,
        max_age=config.SESSION_TTL_MINUTES * 60,
        httponly=True,                     # ** ** JavaScript cannot read it, so XSS cannot steal the session
        secure=config.COOKIE_SECURE,       # only sent over HTTPS in production
        samesite=config.COOKIE_SAMESITE,   # not sent with requests started by other sites
        path="/",
    )
    return session


def end_session(response: Response, session_id: str) -> None:
    store.delete_session(session_id)
    response.delete_cookie(
        config.SESSION_COOKIE, 
        path="/", 
        httponly=True,
        secure=config.COOKIE_SECURE, 
        samesite=config.COOKIE_SAMESITE)


def session_info(session: dict) -> dict:
    return {"expires_at": session["expires_at"], "idle_timeout_minutes": config.SESSION_IDLE_MINUTES}


@dataclass
class Auth:
    user: dict
    session: dict

    @property
    def is_admin(self) -> bool:
        return self.user["role"] == "admin"

    @property
    def clearance(self) -> tuple:
        return ROLE_CLEARANCE[self.user["role"]]


def log_event(event: str, request: Request, user: dict | None = None, **detail) -> None:
    store.audit(event, user, client_ip(request), detail)


SESSION_EXPIRED = "Your session has expired. Please sign in again."


def require_user(request: Request) -> Auth:
    """Dependency for every protected route: valid session, active user and, for changes, a matching CSRF token."""
    token = request.cookies.get(config.SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Please sign in.")

    
    session = store.get_session(token_hash(token))
    if not session:
        raise HTTPException(401, SESSION_EXPIRED)

    now = _now()
    idle = now - datetime.fromisoformat(session["last_seen_at"])

    if now >= datetime.fromisoformat(session["expires_at"]) or idle > timedelta(minutes=config.SESSION_IDLE_MINUTES):
        store.delete_session(session["id"])
        raise HTTPException(401, SESSION_EXPIRED)

    user = store.get_user(session["user_id"])
    if not user or not user["active"]:
        store.delete_session(session["id"])
        raise HTTPException(401, SESSION_EXPIRED)

    if request.method not in SAFE_METHODS: # SAFE_METHODS == ("GET", "HEAD", "OPTIONS")
        sent = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(sent.encode("utf-8"), session["csrf_token"].encode("utf-8")):
            log_event("csrf_rejected", request, user, path=request.url.path)
            raise HTTPException(403, "Security check failed. Refresh the page and try again.")

    if idle > timedelta(seconds=60):  # write last_seen at most once a minute
        store.touch_session(session["id"], _iso(now))
    return Auth(user, session)


def require_admin(request: Request, auth: Auth = Depends(require_user)) -> Auth:
    if not auth.is_admin:
        log_event("access_denied", request, auth.user, path=request.url.path, reason="administrator only")
        raise HTTPException(403, "Administrator access required.")
    return auth


# ============================================================================
# login throttling : too many failures for one email from one IP locks that pair for a while
# (in memory for phase 1; phase 2 can keep it in Supabase or Redis so it survives restarts)
# ============================================================================
_failures: dict[str, list[float]] = {}
_failures_lock = threading.Lock()

# =================== # ** ** add this for advance feature

def throttle_key(email: str, ip: str) -> str:
    return f"{email.strip().lower()}|{ip}"


def locked_for_seconds(key: str) -> int:
    window = config.LOGIN_LOCK_MINUTES * 60
    now = time.time()
    with _failures_lock:
        recent = [t for t in _failures.get(key, []) if now - t < window]
        _failures[key] = recent
    if len(recent) < config.LOGIN_MAX_FAILURES:
        return 0
    return max(1, int(window - (now - recent[-config.LOGIN_MAX_FAILURES])))


def record_failure(key: str) -> None:
    with _failures_lock:
        _failures.setdefault(key, []).append(time.time())


def clear_failures(key: str) -> None:
    with _failures_lock:
        _failures.pop(key, None)


# ============================================================================
# documents at rest : Fernet (AES-128-CBC + HMAC-SHA256) with a key from the environment
# ============================================================================
def check_encryption_key() -> None:
    try:
        Fernet(config.DOC_ENCRYPTION_KEY.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise RuntimeError("DOC_ENCRYPTION_KEY is missing or invalid. Run `python seed.py` once to create backend/.env.") from None


def encrypt_bytes(data: bytes) -> bytes:
    return Fernet(config.DOC_ENCRYPTION_KEY.encode("ascii")).encrypt(data)


def decrypt_bytes(blob: bytes) -> bytes:
    return Fernet(config.DOC_ENCRYPTION_KEY.encode("ascii")).decrypt(blob)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

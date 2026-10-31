"""Sign-in, sessions, cookies, CSRF and password storage."""
import json

import config
import security
import store
from conftest import ADMIN, USER, sign_in


def test_login_sets_httponly_samesite_cookie(anon):
    response = anon.post("/api/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    body = response.json()
    assert body["csrf_token"] and body["user"]["role"] == "admin"
    assert "password_hash" not in body["user"]


def test_wrong_password_and_unknown_email_look_the_same(anon):
    wrong_password = anon.post("/api/auth/login", json={"email": USER[0], "password": "not-the-password1"})
    unknown_email = anon.post("/api/auth/login", json={"email": "nobody@test.example", "password": "whatever123"})
    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


def test_account_locks_after_repeated_failures(anon):
    store.create_user("lockme@test.example", "Lock Me", "user", security.hash_password("LockMe123456"))
    for _ in range(config.LOGIN_MAX_FAILURES):
        assert anon.post("/api/auth/login", json={"email": "lockme@test.example", "password": "wrong-pass-1"}).status_code == 401
    locked = anon.post("/api/auth/login", json={"email": "lockme@test.example", "password": "LockMe123456"})
    assert locked.status_code == 429  # even the right password is refused while locked
    assert any(r["event"] == "login_locked" for r in store.list_audit())


def test_protected_routes_need_a_session(anon):
    for path in ("/api/documents", "/api/dashboard", "/api/auth/me", "/api/admin/users"):
        assert anon.get(path).status_code == 401


def test_logout_revokes_the_session_on_the_server(user):
    token = user.cookies.get(config.SESSION_COOKIE)
    assert user.post("/api/auth/logout").status_code == 204
    user.cookies.set(config.SESSION_COOKIE, token)  # replay the old cookie
    assert user.get("/api/auth/me").status_code == 401


def test_changes_need_the_csrf_token(user):
    question = {"question": "How much did revenue grow in Q3?"}
    good_token = user.headers.pop("X-CSRF-Token")
    assert user.post("/api/agent/ask", json=question).status_code == 403
    assert user.post("/api/agent/ask", json=question, headers={"X-CSRF-Token": "forged"}).status_code == 403
    assert user.post("/api/agent/ask", json=question, headers={"X-CSRF-Token": good_token}).status_code == 200


def test_new_login_rotates_the_session(anon):
    sign_in(anon, *USER)
    first = anon.cookies.get(config.SESSION_COOKIE)
    sign_in(anon, *USER)
    second = anon.cookies.get(config.SESSION_COOKIE)
    assert first != second
    assert store.get_session(security.token_hash(first)) is None


def test_passwords_and_session_tokens_are_not_stored_in_plain_text(user):
    users_file = (config.DATA_DIR / "users.json").read_text(encoding="utf-8")
    assert USER[1] not in users_file and ADMIN[1] not in users_file
    assert all(u["password_hash"].startswith("$2b$12$") for u in json.loads(users_file))
    token = user.cookies.get(config.SESSION_COOKIE)
    assert token not in (config.DATA_DIR / "sessions.json").read_text(encoding="utf-8")

"""Test setup: a throw-away data folder, a fresh encryption key, no simulated delays, seeded demo data."""
import os
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

TMP = Path(tempfile.mkdtemp(prefix="aea-tests-"))
ADMIN = ("admin@test.example", "AdminTest12345")  # test-only accounts, created in the temporary data folder
USER = ("user@test.example", "UserTest12345")

os.environ.update({
    "DATA_DIR": str(TMP / "data"),
    "STORAGE_DIR": str(TMP / "storage"),
    "DOC_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "AGENT_DELAY_MS": "0",
    "AUTOMATION_STEP_MS": "0",
    "SIMULATE_AGENT_FAILURE": "0",
    "AGENT_ENGINE": "static",  # tests never call OpenRouter; test_agent_graph.py drives the LangGraph agent with a fake model
    "SEED_ADMIN_NAME": "Test Admin", "SEED_ADMIN_EMAIL": ADMIN[0], "SEED_ADMIN_PASSWORD": ADMIN[1],
    "SEED_USER_NAME": "Test User", "SEED_USER_EMAIL": USER[0], "SEED_USER_PASSWORD": USER[1],
})

import seed  # noqa: E402  (must come after the environment is set)
from fastapi.testclient import TestClient  # noqa: E402
from main import app  # noqa: E402

seed.seed()


def sign_in(client: TestClient, email: str, password: str) -> TestClient:
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return client


@pytest.fixture
def anon():
    with TestClient(app) as client:
        yield client


@pytest.fixture
def admin():
    with TestClient(app) as client:
        yield sign_in(client, *ADMIN)


@pytest.fixture
def user():
    with TestClient(app) as client:
        yield sign_in(client, *USER)


def confidential_doc_id(admin_client: TestClient) -> str:
    docs = admin_client.get("/api/documents").json()
    return next(d["id"] for d in docs if d["classification"] == "confidential")

"""Role-based access: admin-only endpoints, confidential documents, uploads and encryption at rest."""
import config
import security
import store
from conftest import TestClient, app, confidential_doc_id, sign_in


def test_standard_user_cannot_use_admin_endpoints(user):
    assert user.get("/api/admin/users").status_code == 403
    assert user.get("/api/admin/audit").status_code == 403
    assert user.post("/api/admin/users", json={"name": "X Y", "email": "x@test.example", "password": "Abcdefgh1234"}).status_code == 403
    assert any(r["event"] == "access_denied" for r in store.list_audit())


def test_standard_user_never_sees_confidential_documents(admin, user):
    admin_docs = admin.get("/api/documents").json()
    user_docs = user.get("/api/documents").json()
    assert any(d["classification"] == "confidential" for d in admin_docs)
    assert all(d["classification"] == "general" for d in user_docs)
    assert len(user_docs) < len(admin_docs)
    assert all("storage_key" not in d for d in user_docs)


def test_confidential_document_answers_404_to_a_standard_user(admin, user):
    doc_id = confidential_doc_id(admin)
    assert user.get(f"/api/documents/{doc_id}").status_code == 404           # does not reveal that it exists
    assert user.get(f"/api/documents/{doc_id}/download").status_code == 404
    assert admin.get(f"/api/documents/{doc_id}/download").status_code == 200
    denied = [r for r in store.list_audit() if r["event"] == "access_denied" and r["detail"].get("document_id") == doc_id]
    assert denied, "the blocked attempt is written to the audit log"


def test_standard_user_cannot_upload_or_change_confidential_documents(admin, user):
    files = {"file": ("note.txt", b"Quarterly plan draft", "text/plain")}
    assert user.post("/api/documents", files=files, data={"classification": "confidential"}).status_code == 403
    doc_id = user.get("/api/documents").json()[0]["id"]
    assert user.patch(f"/api/documents/{doc_id}", json={"classification": "confidential"}).status_code == 403
    assert user.delete(f"/api/documents/{doc_id}").status_code == 403


def test_upload_is_encrypted_at_rest_and_runs_the_automation(admin):
    content = b"Project Atlas status: on schedule, 45% complete."
    response = admin.post("/api/documents", files={"file": ("atlas_status.txt", content, "text/plain")},
                          data={"title": "Atlas status", "category": "management", "classification": "confidential"})
    assert response.status_code == 201, response.text
    doc, run = response.json()["document"], response.json()["run"]

    stored = (config.STORAGE_DIR / f"{doc['id']}.bin").read_bytes()
    assert content not in stored and security.decrypt_bytes(stored) == content
    assert admin.get(f"/api/documents/{doc['id']}/download").content == content

    finished = admin.get(f"/api/automations/{run['id']}").json()  # TestClient runs background tasks before returning
    assert finished["status"] == "completed"
    assert [s["status"] for s in finished["steps"]] == ["done"] * 5
    assert admin.get(f"/api/documents/{doc['id']}").json()["status"] == "processed"


def test_upload_rejects_unsafe_files(admin):
    fake_pdf = {"file": ("report.pdf", b"just text pretending to be a PDF", "application/pdf")}
    program = {"file": ("tool.exe", b"MZ\x90\x00", "application/octet-stream")}
    assert admin.post("/api/documents", files=fake_pdf).status_code == 415
    assert admin.post("/api/documents", files=program).status_code == 415
    duplicate = {"file": ("again.txt", b"Project Atlas status: on schedule, 45% complete.", "text/plain")}
    assert admin.post("/api/documents", files=duplicate).status_code == 409


def test_role_change_signs_the_user_out(admin):
    created = admin.post("/api/admin/users", json={"name": "Temp Admin", "email": "temp@test.example",
                                                   "role": "admin", "password": "TempAdmin12345"})
    assert created.status_code == 201
    with TestClient(app) as temp:
        sign_in(temp, "temp@test.example", "TempAdmin12345")
        assert temp.get("/api/admin/users").status_code == 200
        assert admin.patch(f"/api/admin/users/{created.json()['id']}", json={"role": "user"}).status_code == 200
        assert temp.get("/api/admin/users").status_code == 401  # old session is gone, new rights apply at once


def test_admin_cannot_lock_themselves_out(admin):
    me = admin.get("/api/auth/me").json()["user"]
    assert admin.patch(f"/api/admin/users/{me['id']}", json={"active": False}).status_code == 400

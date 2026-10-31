"""One-time setup: create backend/.env with a fresh encryption key, the two demo accounts and the sample documents.

    python seed.py            # safe to run again: existing users and documents are kept
    python seed.py --reset    # delete the JSON data and stored files, then seed again
"""
import argparse
import json
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
# Inside this folder when the backend is its own repository (as on Render), next to it in the full project.
SAMPLE_DIR = next((p for p in (BASE_DIR / "sample_docs", BASE_DIR.parent / "sample_docs") if p.exists()), BASE_DIR / "sample_docs")


def ensure_env_file() -> bool:
    if ENV_FILE.exists():
        return False
    text = (BASE_DIR / ".env.example").read_text(encoding="utf-8")
    text = re.sub(r"^DOC_ENCRYPTION_KEY=[ \t]*$", f"DOC_ENCRYPTION_KEY={Fernet.generate_key().decode()}", text, count=1, flags=re.M)
    ENV_FILE.write_text(text, encoding="utf-8")
    return True


def seed(reset: bool = False) -> None:
    import automation
    import config  # imported after .env exists, because config reads it on import
    import security
    import store

    security.check_encryption_key()
    if reset:
        for folder in (config.DATA_DIR, config.STORAGE_DIR):
            if folder.exists():
                shutil.rmtree(folder)
        print("Removed existing data and stored files")
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    config.STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    accounts = [("SEED_ADMIN", "admin"), ("SEED_USER", "user")]
    users = {}
    for prefix, role in accounts:
        email = os.environ[f"{prefix}_EMAIL"].strip().lower()
        user = store.get_user_by_email(email)
        if not user:
            password = os.environ[f"{prefix}_PASSWORD"]
            problem = security.password_problem(password)
            if problem:
                raise SystemExit(f"{prefix}_PASSWORD: {problem}")
            user = store.create_user(email, os.environ[f"{prefix}_NAME"], role, security.hash_password(password))
            print(f"Created {security.ROLES[role]}: {email}")
        users[role] = user

    manifest = json.loads((SAMPLE_DIR / "manifest.json").read_text(encoding="utf-8"))
    existing = {d.get("seed_key") for d in store.list_documents(security.CLASSIFICATIONS)}
    start = datetime.now(timezone.utc) - timedelta(days=len(manifest))
    for i, item in enumerate(manifest):
        if item["key"] in existing:
            continue
        data = (SAMPLE_DIR / item["file"]).read_bytes()
        doc_id = store.new_id()
        (config.STORAGE_DIR / f"{doc_id}.bin").write_bytes(security.encrypt_bytes(data))
        at = (start + timedelta(days=i)).isoformat(timespec="seconds")
        admin = users["admin"]
        store.add_document({
            "id": doc_id,
            "title": item["title"],
            "filename": item["file"],
            "extension": Path(item["file"]).suffix.lstrip(".").lower(),
            "size_bytes": len(data),
            "sha256": security.sha256_hex(data),
            "category": item["category"],
            "classification": item["classification"],
            "storage_key": f"{doc_id}.bin",
            "seed_key": item["key"],
            "uploaded_by": admin["id"],
            "uploaded_by_name": admin["name"],
            "created_at": at,
            "status": "processed",
            "summary": item["summary"],
        })
        store.add_run({
            "id": store.new_id(),
            "document_id": doc_id,
            "document_title": item["title"],
            "triggered_by": admin["id"],
            "triggered_by_name": admin["name"],
            "status": "completed",
            "started_at": at,
            "finished_at": at,
            "summary": item["summary"],
            "steps": [{"key": key, "label": label, "status": "done", "at": at, "note": "Imported by seed.py"}
                      for key, label in automation.STEPS],
        })
        print(f"Imported {item['classification']:<12} {item['file']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="delete existing data and stored files first")
    args = parser.parse_args()
    if ensure_env_file():
        print("Created backend/.env with a new DOC_ENCRYPTION_KEY")
    seed(args.reset)
    print("Done. Start the API with: uvicorn main:app --reload --port 8000")


if __name__ == "__main__":
    main()

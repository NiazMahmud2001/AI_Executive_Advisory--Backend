"""Upload automation: every new document runs through store -> extract -> summarize -> record -> notify.

Phase 1 records each step with simulated work, so the UI already shows the live pipeline.
Phase 2 replaces the simulated steps with real text extraction (pypdf / python-docx), an LLM
summary (OpenRouter), a Supabase insert and a Gmail API notification to the administrators.
"""
import time

import config
import store

STEPS = [
    ("stored", "File checked, encrypted and stored"),
    ("extracted", "Text extracted"),
    ("summarized", "Summary generated"),
    ("recorded", "Result recorded in the database"),
    ("notified", "Administrators notified"),
]

PHASE1_NOTES = {
    "extracted": "Simulated in phase 1. Phase 2 reads PDF, Word and text files and splits them into searchable chunks.",
    "summarized": "Static summary in phase 1. Phase 2 asks the LLM for a summary; key figures are computed in code.",
    "recorded": "Saved to the JSON store. Phase 2 writes the run and the summary to Supabase.",
    "notified": "Logged in phase 1. Phase 2 emails the administrators through the Gmail API.",
}


def _summary(doc: dict) -> str:
    return (f"Static summary (phase 1): \"{doc['title']}\" was received as a {doc['category']} document "
            f"with {doc['classification']} access. In phase 2 this text is written by the LLM from the document's content.")


def start_run(doc: dict, user: dict) -> dict:
    """Create the run with its first step done; `process` finishes the rest in the background."""
    now = store.now_iso()
    run = {
        "id": store.new_id(),
        "document_id": doc["id"],
        "document_title": doc["title"],
        "triggered_by": user["id"],
        "triggered_by_name": user["name"],
        "status": "running",
        "started_at": now,
        "finished_at": None,
        "summary": None,
        "steps": [{"key": key, "label": label, "status": "pending", "at": None, "note": None} for key, label in STEPS],
    }
    run["steps"][0].update(status="done", at=now, note=f"AES encrypted at rest · SHA-256 {doc['sha256'][:12]}…")
    store.add_run(run)
    return run


def process(run_id: str) -> None:
    """Background task started after the upload response is sent."""
    run = store.get_run(run_id)
    if not run:
        return
    steps = run["steps"]
    try:
        for step in steps[1:]:
            step["status"] = "running"
            store.update_run(run_id, steps=steps)
            time.sleep(config.AUTOMATION_STEP_MS / 1000)
            step.update(status="done", at=store.now_iso(), note=PHASE1_NOTES[step["key"]])
            store.update_run(run_id, steps=steps)

        doc = store.get_document(run["document_id"])
        if not doc:  # deleted while the run was in progress
            raise RuntimeError("The document was deleted before processing finished.")
        summary = _summary(doc)
        store.update_document(doc["id"], status="processed", summary=summary)
        store.update_run(run_id, status="completed", summary=summary, finished_at=store.now_iso())
        store.audit("automation_completed", None, "system", {"run_id": run_id, "document_id": doc["id"]})
    except Exception as exc:  # a failed step is recorded, never lost
        for step in steps:
            if step["status"] == "running":
                step.update(status="failed", at=store.now_iso(), note=str(exc))
        store.update_run(run_id, status="failed", steps=steps, error=str(exc), finished_at=store.now_iso())
        store.audit("automation_failed", None, "system", {"run_id": run_id, "error": str(exc)})

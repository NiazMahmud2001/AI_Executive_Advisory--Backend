"""The three advisors, the keyword router, the response contract and the static answers of phase 1.

The static engine answers when no OpenRouter key is set: an offline demo mode, also used by the tests. The
LangGraph agent (agent_graph.py) reuses the advisors, the keyword router and `make_response` from here, so both
engines return exactly the same JSON. Access control is real for the static answers too: an answer is only given
when the user may read every document it relies on.
"""
import json
import re
import time

import config
import security
import store

ADVISORS = {"finance": "Finance Advisor", "hr": "HR & Management Advisor", "knowledge": "Knowledge Assistant"}

# Words that send a question to an advisor in auto mode (matched at the start of a word, so "grow" also matches "growth").
ROUTE_TERMS = {
    "finance": [
        "revenue", "profit", "margin", "grow", "grew", 
        "budget", "spend", "spent", "overspen", "expense", 
        "cost","variance", "cash", "income", "earning", 
        "financ", "quarter", "q1", "q2", "q3", "q4", 
        "forecast","kpi", "ebitda", "roi", "ytd"
        ],
    "hr": ["leave", "vacation", "holiday", "time off", "days off", 
           "policy", "policies", "employee", "staff", "probation",
           "notice", "remote", "work from home", "wfh", "hybrid", 
           "overtime", "sick", "salar", "compensation", "bonus",
           "payroll", "paid", "payment", "hiring", "recruit", "hr", 
           "working hours", "hours", "ramadan", "ceo", "cfo",
           "coo", "executive", "board", "minutes", "procure", 
           "purchase", "approv", "quotation", "supplier", "vendor",
           "management", "expan", "acqui"],
}

INSUFFICIENT = "I could not find sufficient evidence in the documents available to you to answer this question."

# Attempts to talk the assistant out of its rules. They change nothing (permissions are enforced in code), but they are flagged and audited.
INJECTION = re.compile(
    r"ignore (all |any |the )?(previous|prior|above|earlier) (instructions|prompts?|rules)"
    r"|disregard (all |any |the )?(previous |prior )?(instructions|rules)"
    r"|system prompt|developer mode|you are now|pretend (to be|you are)"
    r"|act as (an? )?(admin|administrator)|bypass|jailbreak"
    r"|reveal (the |all )?(confidential|hidden|secret|restricted)",
    re.IGNORECASE,
)
INJECTION_NOTICE = ("This message tried to change the assistant's instructions. That has no effect: access rules are enforced by the server, not by the assistant.")

with (config.FIXTURES_DIR / "static_answers.json").open(encoding="utf-8") as f:
    ANSWERS = json.load(f)


def _hits(text: str, terms: list) -> list:
    """Words of the text that match the terms, e.g. the term "salar" finds "salary"."""
    return list(dict.fromkeys(m.group(0) for term in terms if (m := re.search(rf"\b{re.escape(term)}\w*", text))))


def route(question: str, requested: str) -> tuple[str, dict]:
    if requested in ADVISORS:
        return requested, {"mode": "manual", "reason": f"You chose the {ADVISORS[requested]}.", "matched": []}
    
    hits = {name: _hits(question.lower(), terms) for name, terms in ROUTE_TERMS.items()}
    best = max(hits, key=lambda name: len(hits[name]))  # ties go to finance (first key)
    
    if not hits[best]:
        return "knowledge", {"mode": "auto", "reason": "No finance or HR terms found, so the Knowledge Assistant answers.", "matched": []}
    
    area = "finance" if best == "finance" else "HR and management"
    return best, {"mode": "auto", "reason": f"Matched {area} terms.", "matched": hits[best]}


def make_response(question: str, 
                  advisor: str, 
                  routing: dict, 
                  engine: str, 
                  answer: str | None = None,
                  citations=(), 
                  calculations=(), 
                  conflicts=(), 
                  missing=()) -> dict:
    """The response contract of both engines; the UI renders exactly these fields. No answer means "insufficient evidence"."""
    suggestions = []
    if not answer:
        suggestions = ["Rephrase the question with more specific terms.", "Ask an administrator to upload a document that covers this topic."]
        if routing["mode"] == "manual":
            suggestions.insert(0, "Switch to Auto routing; another advisor may cover this topic.")


    return {
        "id": store.new_id(),
        "question": question,
        "advisor": advisor,
        "advisor_label": ADVISORS[advisor],
        "routing": routing,
        "status": "answered" if answer else "insufficient_evidence",
        "answer": answer or INSUFFICIENT,
        "citations": list(citations) if answer else [],
        "calculations": list(calculations) if answer else [],
        "conflicts": list(conflicts) if answer else [],
        "missing_information": list(missing),
        "suggestions": suggestions,
        "security_notice": INJECTION_NOTICE if INJECTION.search(question) else None,
        "engine": engine,
        "created_at": store.now_iso(),
    }


def answer_question(question: str, requested: str, auth: security.Auth) -> tuple[dict, list, bool]:
    """Return (response, keys of documents withheld from this user, whether an injection attempt was seen)."""
    started = time.perf_counter()
    time.sleep(config.AGENT_DELAY_MS / 1000)  # "thinking" time, so the UI shows its loading state

    advisor, routing = route(question, requested)
    text = question.lower()
    candidates = [a for a in ANSWERS if a["advisor"] == advisor and _hits(text, a["keywords"])]
    item = max(candidates, key=lambda a: len(_hits(text, a["keywords"])), default=None)  # earlier entry wins ties

    readable = {d["seed_key"]: d for d in store.list_documents(auth.clearance) if d.get("seed_key")}
    withheld = []
    
    if item and any(key not in readable for key in item["sources"]):
        existing = {d.get("seed_key") for d in store.list_documents(security.CLASSIFICATIONS)}
        withheld = [key for key in item["sources"] if key in existing and key not in readable]
        item = None  # never answer from a document the user cannot read, and do not hint that it exists

    if item is None:
        response = make_response(question, advisor, routing, "Static responses (phase 1)")
    else:
        def doc(key: str) -> dict:
            d = readable[key]
            return {
                "doc_id": d["id"], 
                "title": d["title"], 
                "filename": d["filename"], 
                "classification": d["classification"]
                }

        response = make_response(
            question, advisor, routing, "Static responses (phase 1)", item["answer"],
            citations=[{**doc(c["source"]), "location": c["location"], "snippet": c["snippet"]} for c in item["citations"]],
            calculations=item.get("calculations", []),
            conflicts=[{
                "topic": c["topic"], 
                "resolution": c["resolution"],
                "positions": [{**doc(p["source"]), "statement": p["statement"]} for p in c["positions"]]
                } for c in item.get("conflicts", [])],
            missing=item.get("missing_information", []),
        )
    response["latency_ms"] = round((time.perf_counter() - started) * 1000)
    return response, withheld, bool(INJECTION.search(question))

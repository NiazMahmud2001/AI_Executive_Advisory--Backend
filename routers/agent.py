"""Questions to the advisors: the LangGraph agent when an OpenRouter key is set, else the static phase 1 answers.

Both engines return the same response contract, so this router and the UI do not depend on which one runs.
"""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import agent_graph
import agent_stub
import config
import security
import store
from security import Auth, require_user

router = APIRouter(prefix="/api/agent", tags=["agent"])

UNAVAILABLE = "The AI service is temporarily unavailable. Your question was not processed; please try again in a moment."


class AskBody(BaseModel):
    question: str = Field(min_length=3, max_length=1000)
    advisor: Literal["auto", "finance", "hr", "knowledge"] = "auto"


@router.post("/ask")
def ask(body: AskBody, request: Request, auth: Auth = Depends(require_user)):
    question = body.question.strip()
    if config.SIMULATE_AGENT_FAILURE:
        security.log_event("agent_error", request, auth.user, error="simulated AI service failure")
        raise HTTPException(503, UNAVAILABLE)

    engine = agent_graph if config.AGENT_ENGINE == "langgraph" else agent_stub
    try:
        response, withheld, injection = engine.answer_question(question, body.advisor, auth)
    except agent_graph.AgentUnavailable as exc:  # model down, rate limited or unreadable output: nothing is guessed
        security.log_event("agent_error", request, auth.user, error=str(exc)[:200])
        raise HTTPException(503, UNAVAILABLE)

    store.add_question({
        "id": response["id"],
        "user_id": auth.user["id"],
        "at": response["created_at"],
        "question": question,
        "advisor": response["advisor"],
        "status": response["status"],
    })
    security.log_event("agent_query", request, auth.user, advisor=response["advisor"], status=response["status"])
    if withheld:  # only admins see this in the audit log; the user just gets "insufficient evidence"
        security.log_event("ai_access_filtered", request, auth.user, withheld_documents=withheld)
    if injection:
        security.log_event("prompt_injection_flagged", request, auth.user, question=question[:200])
    return response


@router.get("/history")
def history(auth: Auth = Depends(require_user)):
    return store.list_questions(auth.user["id"])[:20]

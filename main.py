"""FastAPI entry point: security headers, request logging, the REST routers and (when built) the React app.

Run:  uvicorn main:app --reload --port 8000     (first time: python seed.py)
  or: python main.py
"""
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

import config
import security
import store
from routers import admin, agent, auth, dashboard, documents

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("aea")

# Strict policy for the built React app: scripts, styles and fonts only from this origin, no framing.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
DOCS_PATHS = ("/api/docs", "/api/redoc", "/api/openapi.json")  # Swagger UI loads its own scripts, so it gets no CSP


@asynccontextmanager
async def lifespan(app: FastAPI):
    security.check_encryption_key()  # fail fast with a clear message instead of failing on the first upload
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    config.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    if not store.list_users():
        log.warning("No users yet. Run `python seed.py` to create the demo accounts and sample documents.")
    if config.AGENT_ENGINE == "langgraph" and not config.OPENROUTER_API_KEY:
        raise RuntimeError("AGENT_ENGINE=langgraph needs OPENROUTER_API_KEY in backend/.env.")
    removed = store.purge_expired_sessions()
    log.info("API ready (phase %s, %s mode, agent: %s); removed %s expired sessions",
             config.PHASE, config.APP_ENV, config.ENGINE_LABEL, removed)
    yield


app = FastAPI(
    title="AI Executive Advisory API",
    version=config.VERSION,
    lifespan=lifespan,
    docs_url=None if config.IS_PRODUCTION else "/api/docs",
    redoc_url=None,
    openapi_url=None if config.IS_PRODUCTION else "/api/openapi.json",
)

if config.CORS_ORIGINS:  # only when the UI is hosted on another domain (then also set COOKIE_SAMESITE=none)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
    )


@app.middleware("http")
async def security_headers_and_logging(request: Request, call_next):
    request_id = uuid.uuid4().hex[:12]
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:  # never show a stack trace to the client; the request id links the reply to the log line
        log.exception("Unhandled error on %s %s (request %s)", request.method, request.url.path, request_id)
        response = JSONResponse({"detail": "Something went wrong on the server.", "request_id": request_id}, status_code=500)

    path = request.url.path
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"   
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not path.startswith(DOCS_PATHS):
        response.headers["Content-Security-Policy"] = CSP
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"  # API answers may contain confidential data
    if config.IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    log.info(json.dumps({"request_id": request_id, "method": request.method, "path": path,
                         "status": response.status_code, "ms": round((time.perf_counter() - started) * 1000)}))
    return response


@app.get("/api/health", tags=["system"])
def health():
    return {"status": "ok", "version": config.VERSION, "phase": config.PHASE, "agent": config.AGENT_ENGINE, "store": "json"}


app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(agent.router)
app.include_router(admin.router)
app.include_router(dashboard.router)


# ============================================================================
# React app : `npm run build` in frontend/ creates dist/, which is served here on the same origin as the API
# ============================================================================
if config.FRONTEND_DIST.exists():
    DIST = config.FRONTEND_DIST.resolve()

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def frontend(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "Not found."}, status_code=404)
        file = (DIST / path).resolve()
        if path and file.is_file() and file.is_relative_to(DIST):  # no "../" escapes from dist/
            return FileResponse(file)
        return FileResponse(DIST / "index.html")  # client-side routes such as /documents


# ============================================================================
# Direct run : `python main.py` starts the same server as the uvicorn command above
# ============================================================================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=not config.IS_PRODUCTION)

# Executive Advisory: backend

The API of the **AI Executive Advisory System**, built with FastAPI. It signs users in with secure session cookies,
enforces role-based access to company documents, stores uploads encrypted, runs the upload automation pipeline, keeps an
audit log, and answers questions through three AI advisors: a LangGraph agent with an OpenRouter model, or fixed answers
when no API key is set.

## Features

- **Sessions and cookies:** a random 256-bit token in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` in production).
  Only its SHA-256 hash is stored. Sessions end after 8 hours or 30 idle minutes, and logout deletes them on the server.
- **CSRF protection:** every request that changes data must send the session's token in `X-CSRF-Token`.
- **Passwords:** bcrypt (cost 12). Unknown emails take as long as wrong passwords and get the same message. Five
  failures lock that email and IP address for 15 minutes.
- **Roles:** administrator and standard user, checked on every endpoint. Confidential documents answer 404 to standard
  users, so their existence is not revealed, and every denial is audited.
- **Documents:** a file type allow-list, a file signature check, a 10 MB limit and duplicate detection by SHA-256.
  Files are encrypted at rest with Fernet (AES-128-CBC with HMAC-SHA256) and downloaded as attachments.
- **Upload automation:** each upload runs a pipeline (stored, extracted, summarized, recorded, notified) whose step
  status the UI can follow.
- **AI advisors:** a Finance Advisor, an HR & Management Advisor and a Knowledge Assistant. The model only ever receives
  text from documents the user may read, figures are computed in Python, and citations are checked.
- **Audit log and dashboard:** security and activity events for administrators, and role-aware dashboard numbers.
- **Hardening:** security headers (Content-Security-Policy, nosniff, frame denial, `no-store` on the API, HSTS in
  production), a request ID on every response, JSON request logs, and generic 500 errors without stack traces.

## Tech stack

- Python 3.12 or newer (tested with 3.14)
- [FastAPI](https://fastapi.tiangolo.com), Uvicorn and Pydantic 2
- bcrypt and `cryptography` (Fernet)
- [LangGraph](https://langchain-ai.github.io/langgraph/) with LangChain's `ChatOpenAI`, pointed at [OpenRouter](https://openrouter.ai)
- pypdf and python-docx for text extraction
- pytest and httpx for the tests

## Getting started

```bash
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python seed.py                    # creates .env with a new encryption key, the demo accounts and the sample documents
python main.py                    # or: uvicorn main:app --reload --port 8000
```

| URL | What |
|---|---|
| http://localhost:8000/api/health | Health check |
| http://localhost:8000/api/docs | Interactive API docs (development only) |
| http://localhost:8000 | The built UI, when `../frontend/dist` exists |

The React frontend runs on port 5173 in development and forwards `/api` to this server. After `npm run build` in the
frontend, this server also serves the UI itself, so the UI and the API share one origin.

`seed.py` reads the sample documents from `../sample_docs`. Run `python seed.py --reset` to delete the local data and
the stored files and seed again.

### Demo accounts

`seed.py` creates two accounts from the `SEED_*` values in `.env.example`. They are demo-only test values for local use;
change them in `.env` before deploying anywhere.

| Role | Email | Password |
|---|---|---|
| Administrator | admin@oasispeak.example | value of `SEED_ADMIN_PASSWORD` |
| Standard user | employee@oasispeak.example | value of `SEED_USER_PASSWORD` |

## AI advisors

Put an OpenRouter key in `.env` as `OPENROUTER_API_KEY=...` and restart the API. The startup log and the dashboard then
show the engine, for example `LangGraph · google/gemma-4-31b-it:free`. Without a key, or with `AGENT_ENGINE=static`, the
advisors give fixed answers from `fixtures/`; this offline mode is also what the tests use.

![LangGraph agent: route, retrieve with the permission filter, one advisor call, check](docs/agent_overview.png)

- **route:** the user's choice, otherwise the keyword router. Only questions without any keyword go to the LLM router.
- **retrieve:** the permission filter. Only documents inside the user's clearance are decrypted in memory, extracted
  and split into chunks; confidential text never reaches the model for a standard user.
- **finance, hr or knowledge:** one model call with that advisor's instructions, answered as JSON.
- **check:** only citations of chunks that were sent are kept, an answer without a valid citation is not shown, and the
  Finance Advisor's figures are computed by `finance_tools.py`.

Each model call has a 30-second timeout and one retry, then moves to the fallback model. If both fail, the API answers
503 and logs `agent_error`. OpenRouter's free tier has a small daily quota, and free models may log prompts, which is
acceptable only for the synthetic demo documents.

## Configuration

All settings are environment variables in `.env` (see [`.env.example`](.env.example)).

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `production` turns on Secure cookies and HSTS and hides `/api/docs` |
| `DOC_ENCRYPTION_KEY` | written by `seed.py` | Fernet key for files at rest (secret) |
| `SESSION_TTL_MINUTES`, `SESSION_IDLE_MINUTES` | `480`, `30` | Session lifetime and idle timeout |
| `COOKIE_SECURE`, `COOKIE_SAMESITE` | `0`, `strict` | Cookie flags; `Secure` is always on in production |
| `CORS_ORIGINS` | empty | Only when the UI runs on another domain (then `COOKIE_SAMESITE=none` over HTTPS) |
| `MAX_UPLOAD_MB` | `10` | Upload size limit |
| `LOGIN_MAX_FAILURES`, `LOGIN_LOCK_MINUTES` | `5`, `15` | Sign-in lockout |
| `OPENROUTER_API_KEY` | empty | Turns on the LangGraph agent (secret) |
| `OPENROUTER_MODEL`, `OPENROUTER_FALLBACK_MODEL` | `google/gemma-4-31b-it:free`, `openrouter/free` | Models; free model ids end in `:free` |
| `AGENT_ENGINE` | `langgraph` with a key, else `static` | Force an engine |
| `AGENT_TIMEOUT_SECONDS` | `30` | Timeout per model call |
| `AGENT_DELAY_MS`, `AUTOMATION_STEP_MS` | `700`, `600` | Simulated delays of the static engine and the automation steps |
| `SIMULATE_AGENT_FAILURE` | `0` | `1` demonstrates the "AI service unavailable" path |
| `DATA_DIR`, `STORAGE_DIR` | `data/`, `storage/` | Where records and encrypted files are kept |
| `SEED_*` | see `.env.example` | Names, emails and passwords of the demo accounts |

## REST API

| Method and path | Who | Purpose |
|---|---|---|
| `POST /api/auth/login` · `POST /api/auth/logout` · `GET /api/auth/me` | anyone / signed in | Session cookie and CSRF token |
| `GET /api/documents` · `POST /api/documents` | signed in | List visible documents, upload (confidential: administrators only) |
| `GET /api/documents/{id}` · `GET /api/documents/{id}/download` | signed in | 404 when the document is outside the user's clearance |
| `PATCH /api/documents/{id}` · `DELETE /api/documents/{id}` | administrator | Reclassify, rename, delete |
| `GET /api/automations` · `GET /api/automations/{id}` | signed in | Upload pipeline runs (standard users see their own) |
| `POST /api/agent/ask` · `GET /api/agent/history` | signed in | Ask an advisor (`advisor`: auto, finance, hr, knowledge) |
| `GET /api/admin/users` · `POST /api/admin/users` · `PATCH /api/admin/users/{id}` | administrator | Manage users; role and status changes sign the user out |
| `GET /api/admin/audit?group=` | administrator | Audit log (all, security, auth, documents, ai, users) |
| `GET /api/dashboard` · `GET /api/health` | signed in / anyone | Role-aware dashboard numbers, health check |

## Architecture

Every request passes the same pipeline: the middleware gives it a request ID, the session guard (`require_user` or
`require_admin`) runs before the body is validated, the router calls the services, and only `store.py` reads and writes
the data files. The middleware then adds the security headers and writes one JSON log line.

![Request pipeline: middleware, guard, router, store](docs/request_pipeline.png)

## Project structure

```
main.py            FastAPI app: startup checks, security headers, request logging, routers, serves ../frontend/dist
config.py          settings from environment variables (.env)
security.py        bcrypt, sessions and cookies, CSRF, role guards, login throttling, Fernet encryption, audit helper
store.py           JSON file store (data/*.json): one small named function per query, atomic writes
agent_graph.py     LangGraph agent: route, retrieve, finance / hr / knowledge, check (OpenRouter through ChatOpenAI)
agent_stub.py      advisors, keyword router, response contract and the static answers
retrieval.py       text extraction (pypdf, python-docx) and chunking of permitted documents
finance_tools.py   percentage change, share, difference and pro-rata, computed in Python
automation.py      upload pipeline: stored, extracted, summarized, recorded, notified
seed.py            .env with a new key, the demo accounts and the sample documents
routers/           auth, documents (and automations), agent, admin (users and audit), dashboard
fixtures/          static answers for the offline engine
tests/             pytest suite
docs/              diagrams used in this README
data/, storage/    records and encrypted files, created at runtime and never committed
```

## Tests

```bash
python -m pytest
```

There are 37 tests and none of them calls OpenRouter; the LangGraph agent is driven by a fake model. They cover:

- sign-in: generic errors and the lockout after 5 failures;
- HttpOnly and SameSite cookies, session rotation, server-side logout and CSRF;
- password and token hashing at rest, and role checks on every administrator endpoint;
- confidential documents: 404 for standard users, and no leak through the AI, including prompt injection;
- encrypted uploads, file type checks, the automation pipeline and the AI failure path;
- the agent: the model never sees documents outside the user's clearance, figures are computed in code, and citations
  to chunks that were not sent are dropped.

## Moving to production

This prototype stores its records as JSON files and its secrets in `.env`, which keeps it easy to run and inspect. For
production the same design moves to managed services; only `store.py` changes, because every data access goes through
its named functions:

| Today | Production (AWS) |
|---|---|
| `data/*.json` | Amazon RDS for PostgreSQL, with pgvector for document search |
| `storage/*.bin` | Amazon S3, private, with SSE-KMS encryption and pre-signed URLs |
| `DOC_ENCRYPTION_KEY` in `.env` | AWS KMS with envelope encryption |
| `OPENROUTER_API_KEY` in `.env` | AWS Secrets Manager |
| Sessions and the sign-in lockout | Amazon ElastiCache for Redis |
| In-process background tasks | Amazon SQS with worker services |

Also: HTTPS in front with `APP_ENV=production`, Uvicorn behind the load balancer with `--proxy-headers`, SSO with MFA,
and a paid model with zero data retention in a UAE region.

## Troubleshooting

- **"DOC_ENCRYPTION_KEY is missing or invalid":** run `python seed.py` once. It writes `.env`.
- **"AGENT_ENGINE=langgraph needs OPENROUTER_API_KEY":** add the key to `.env`, or remove `AGENT_ENGINE`.
- **Code changes do not show:** on some drives `--reload` misses file changes. Stop the server and start it again.
- **Port 8000 is in use:** start Uvicorn with `--port 8001` and change the proxy target in the frontend's `vite.config.js`.
- **Every question answers "AI service temporarily unavailable":** the audit log (`agent_error`) shows the reason. A 401
  means the key is wrong, a 429 means the free quota is used up, and a 404 means the model id is gone or your OpenRouter
  privacy settings block that free model.

## Security notes

Never commit `.env`, `data/` or `storage/`; the included `.gitignore` excludes them. The demo passwords in `.env.example`
are test values for a local demo only.

"""Settings for the API. Every value comes from an environment variable (see .env.example) with a safe default."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# ============================================================================
# environment  (env values are always text -> int() them; the "or" gives a default when a variable is missing)
# ============================================================================
APP_ENV = os.getenv('APP_ENV') or "development"
IS_PRODUCTION = APP_ENV == "production"
VERSION = "0.1.0"
PHASE = 1  # phase 1 = static agent + JSON store, phase 2 = LangGraph agent + Supabase

DATA_DIR = Path(os.getenv('DATA_DIR') or BASE_DIR / "data")           # JSON "database" files (phase 2: Supabase)
STORAGE_DIR = Path(os.getenv('STORAGE_DIR') or BASE_DIR / "storage")  # encrypted uploaded files
FIXTURES_DIR = BASE_DIR / "fixtures"                                  # static agent answers for phase 1
FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"                 # built React app, served by FastAPI when it exists

# ============================================================================
# security
# ============================================================================
DOC_ENCRYPTION_KEY = os.getenv('DOC_ENCRYPTION_KEY') or ""  # Fernet key; `python seed.py` writes one into .env

SESSION_COOKIE = "aea_session"
SESSION_TTL_MINUTES = int(os.getenv('SESSION_TTL_MINUTES') or 480)   # absolute lifetime: 8 hours
SESSION_IDLE_MINUTES = int(os.getenv('SESSION_IDLE_MINUTES') or 30)  # signed out after 30 idle minutes
COOKIE_SECURE = IS_PRODUCTION or os.getenv('COOKIE_SECURE') == "1"   # Secure flag needs HTTPS, so it is off on http://localhost
COOKIE_SAMESITE = os.getenv('COOKIE_SAMESITE') or "strict"           # use "none" (with HTTPS) only if the UI runs on another domain

LOGIN_MAX_FAILURES = int(os.getenv('LOGIN_MAX_FAILURES') or 5)   # failed sign-ins before the account is locked ...
LOGIN_LOCK_MINUTES = int(os.getenv('LOGIN_LOCK_MINUTES') or 15)  # ... for this many minutes (per email + IP)

MAX_UPLOAD_MB = int(os.getenv('MAX_UPLOAD_MB') or 10)

# Empty = UI and API share one origin (Vite proxy in development, FastAPI serves the build in production).
# Set CORS_ORIGINS=https://your-ui.example.com only when the UI is hosted on a different domain.
CORS_ORIGINS = [origin.strip() for origin in (os.getenv('CORS_ORIGINS') or "").split(',') if origin.strip()]

# ============================================================================
# AI agent  (LangGraph + an OpenRouter model when a key is set; otherwise the static phase 1 answers)
# ============================================================================
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY') or ""  # secret: only in backend/.env, never in code, logs or the UI
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_MODEL = os.getenv('OPENROUTER_MODEL') or "google/gemma-4-31b-it:free"  # free ids end in ":free"; check openrouter.ai/models
OPENROUTER_FALLBACK_MODEL = os.getenv('OPENROUTER_FALLBACK_MODEL', "openrouter/free")  # used when the main model fails; empty = none
AGENT_ENGINE = (os.getenv('AGENT_ENGINE') or ("langgraph" if OPENROUTER_API_KEY else "static")).lower()
if AGENT_ENGINE not in ("static", "langgraph"):
    raise ValueError("AGENT_ENGINE must be 'static' or 'langgraph'")
AGENT_TIMEOUT_SECONDS = int(os.getenv('AGENT_TIMEOUT_SECONDS') or 30)  # per model call; one retry, then the fallback model
ENGINE_LABEL = f"LangGraph · {OPENROUTER_MODEL}" if AGENT_ENGINE == "langgraph" else "Static responses (phase 1)"

# ============================================================================
# phase 1 simulation (removed when the real agent and automation arrive in phase 2)
# ============================================================================
AGENT_DELAY_MS = int(os.getenv('AGENT_DELAY_MS') or 700)          # "thinking" time of the static agent, so the UI shows its loading state
AUTOMATION_STEP_MS = int(os.getenv('AUTOMATION_STEP_MS') or 600)  # time per simulated automation step
SIMULATE_AGENT_FAILURE = os.getenv('SIMULATE_AGENT_FAILURE') == "1"  # demo of the "AI service unavailable" path

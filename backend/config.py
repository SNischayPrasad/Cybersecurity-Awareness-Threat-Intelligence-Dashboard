"""
Central configuration for the Cybersecurity Awareness & Threat Intelligence Dashboard.

All secrets (API keys) come from environment variables or a local `.env` file.
Nothing sensitive is hard-coded for production use.
"""
import os
from pathlib import Path

# Project root = the folder that contains backend/, frontend/, data/ ...
BASE_DIR = Path(__file__).resolve().parent.parent

# Load a local .env file if python-dotenv is installed (it is in requirements.txt).
try:
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env")
except ImportError:  # pragma: no cover - optional dependency
    pass


class Config:
    """Default configuration. Values can be overridden with environment variables."""

    APP_ENV = os.getenv("APP_ENV", "development")
    TESTING = False

    # --- Storage -----------------------------------------------------------
    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "threat_intel.db"))
    THREAT_CSV = str(BASE_DIR / "data" / "threat_intelligence_dataset.csv")
    VULN_CSV = str(BASE_DIR / "data" / "vulnerabilities.csv")
    AWARENESS_DIR = str(BASE_DIR / "awareness")
    FRONTEND_DIR = str(BASE_DIR / "frontend")

    # --- Authentication / RBAC ----------------------------------------------
    # viewer  = no key  -> read-only dashboards
    # analyst = ANALYST_API_KEY -> add notes, change alert status
    # admin   = ADMIN_API_KEY   -> create / update threat records
    ANALYST_API_KEY = os.getenv("ANALYST_API_KEY", "")
    ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

    # --- Abuse protection -----------------------------------------------------
    RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "300"))
    MAX_CONTENT_LENGTH = 64 * 1024  # reject request bodies larger than 64 KB

    # --- Detection tuning ---------------------------------------------------
    ALERT_RISK_THRESHOLD = int(os.getenv("ALERT_RISK_THRESHOLD", "61"))
    ALERT_CONFIDENCE_THRESHOLD = int(os.getenv("ALERT_CONFIDENCE_THRESHOLD", "60"))
    REPEATED_OBSERVATION_THRESHOLD = int(os.getenv("REPEATED_OBSERVATION_THRESHOLD", "50"))
    CORRELATION_WINDOW_MINUTES = int(os.getenv("CORRELATION_WINDOW_MINUTES", "60"))

    # Development-only fallback keys. They are ONLY used when APP_ENV=development
    # and no keys are configured, and the app logs a warning when it uses them.
    DEV_ANALYST_KEY = "dev-analyst-key-change-me"
    DEV_ADMIN_KEY = "dev-admin-key-change-me"

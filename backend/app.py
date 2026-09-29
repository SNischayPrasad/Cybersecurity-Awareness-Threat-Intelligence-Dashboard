"""
Cybersecurity Awareness & Threat Intelligence Dashboard - Flask application.

Run from the project root:
    python -m backend.app
Then open http://127.0.0.1:5000

The same Flask server provides the REST API (/api/...) and serves the
frontend (HTML/CSS/JS), so beginners only need to start one process.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python backend/app.py` as well
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, request, send_from_directory  # noqa: E402
from werkzeug.exceptions import HTTPException  # noqa: E402

from backend.config import Config  # noqa: E402
from backend.database import close_db  # noqa: E402
from backend.routes import alerts, awareness, dashboard, threats, vulnerabilities  # noqa: E402
from backend.utils.helpers import error_response  # noqa: E402
from backend.utils.security import RateLimiter, apply_security_headers  # noqa: E402

log = logging.getLogger("threat-dashboard")


def _configure_keys(app: Flask) -> None:
    """Use env keys; fall back to clearly-labelled dev keys only in development."""
    missing = not app.config["ANALYST_API_KEY"] or not app.config["ADMIN_API_KEY"]
    if not missing:
        return
    if app.config["APP_ENV"] == "production":
        raise RuntimeError("ANALYST_API_KEY and ADMIN_API_KEY must be set in production.")
    app.config["ANALYST_API_KEY"] = app.config["ANALYST_API_KEY"] or app.config["DEV_ANALYST_KEY"]
    app.config["ADMIN_API_KEY"] = app.config["ADMIN_API_KEY"] or app.config["DEV_ADMIN_KEY"]
    if not app.config.get("TESTING"):
        log.warning("Using DEVELOPMENT API keys from config.py. Set ANALYST_API_KEY / ADMIN_API_KEY in .env.")


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    app.json.sort_keys = False
    _configure_keys(app)

    if not app.config.get("TESTING") and not Path(app.config["DATABASE_PATH"]).exists():
        log.warning("Database not found. Run:  python -m backend.init_db")

    limiter = RateLimiter()

    @app.before_request
    def rate_limit():
        if request.path.startswith("/api/"):
            client = request.remote_addr or "unknown"
            if not limiter.allow(client, app.config["RATE_LIMIT_PER_MINUTE"]):
                return error_response(429, "rate_limited", "Too many requests - slow down and retry in a minute.")
        return None

    app.after_request(apply_security_headers)
    app.teardown_appcontext(close_db)

    for module in (threats, dashboard, alerts, vulnerabilities, awareness):
        app.register_blueprint(module.bp)

    frontend_dir = app.config["FRONTEND_DIR"]

    @app.get("/")
    def index():
        return send_from_directory(frontend_dir, "index.html")

    @app.get("/<path:filename>")
    def frontend(filename):
        # send_from_directory blocks path traversal (e.g. ../../secret).
        return send_from_directory(frontend_dir, filename)

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        if request.path.startswith("/api/"):
            return error_response(exc.code or 500, (exc.name or "error").lower().replace(" ", "_"),
                                  exc.description or "Request failed.")
        return exc

    @app.errorhandler(Exception)
    def unhandled(exc: Exception):
        log.exception("Unhandled error on %s", request.path)
        # Never leak stack traces to clients.
        return error_response(500, "internal_error", "An unexpected error occurred.")

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    application = create_app()
    port = int(os.getenv("PORT", "5000"))
    print(f"\n  Threat Intelligence Dashboard running at http://127.0.0.1:{port}\n"
          "  (All data is SYNTHETIC / DEMO ONLY. Press CTRL+C to stop.)\n")
    # Bind to localhost only; debug mode stays off (the Werkzeug debugger must never be exposed).
    application.run(host="127.0.0.1", port=port, debug=False)

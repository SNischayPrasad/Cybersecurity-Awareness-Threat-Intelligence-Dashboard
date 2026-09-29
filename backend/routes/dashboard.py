"""Dashboard analytics, ATT&CK, correlation, executive summary and reference data."""
from flask import Blueprint, current_app, jsonify, request

from backend.database import get_db, get_meta
from backend.services import threat_service
from backend.services.attack_mapper import ATTACK_VERSION_NOTE
from backend.services.correlation_engine import get_clusters
from backend.services.executive_service import build_executive_summary
from backend.services.threat_categories import THREAT_CATEGORIES
from backend.utils.helpers import error_response
from backend.utils.security import resolve_role

bp = Blueprint("dashboard", __name__, url_prefix="/api")


@bp.get("/health")
def health():
    conn = get_db()
    return jsonify(status="ok", threats=conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0],
                   dataset_reference_date=get_meta(conn, "dataset_reference_date"),
                   data_label="SYNTHETIC / DEMO ONLY", environment=current_app.config["APP_ENV"])


@bp.get("/auth/whoami")
def whoami():
    role = resolve_role(request.headers.get("X-API-Key"))
    if role == "invalid":
        return error_response(401, "unauthorized", "Invalid API key.")
    return jsonify(role=role)


@bp.get("/dashboard/stats")
def stats():
    return jsonify(threat_service.dashboard_stats(get_db()))


@bp.get("/dashboard/trends")
def trends():
    try:
        weeks = max(1, min(104, int(request.args.get("weeks", 26))))
    except ValueError:
        return error_response(400, "bad_request", "weeks must be an integer.")
    return jsonify(threat_service.trend_stats(get_db(), weeks))


@bp.get("/attack/summary")
def attack_summary():
    data = threat_service.attack_stats(get_db())
    data["version_note"] = ATTACK_VERSION_NOTE
    return jsonify(data)


@bp.get("/correlation/clusters")
def clusters():
    try:
        min_size = max(2, int(request.args.get("min_size", 2)))
        limit = max(1, min(200, int(request.args.get("limit", 50))))
    except ValueError:
        return error_response(400, "bad_request", "min_size and limit must be integers.")
    return jsonify(get_clusters(get_db(), min_size, limit))


@bp.get("/executive/summary")
def executive():
    return jsonify(build_executive_summary(get_db()))


@bp.get("/categories")
def categories():
    return jsonify(THREAT_CATEGORIES)


@bp.get("/sources")
def sources():
    return jsonify(threat_service.reliability_reference())

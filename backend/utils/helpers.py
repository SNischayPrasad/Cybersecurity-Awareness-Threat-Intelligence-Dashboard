"""Small helpers shared by the route modules."""
from __future__ import annotations

from flask import current_app, jsonify, request


def error_response(status: int, error: str, message: str, details=None):
    body = {"error": error, "message": message}
    if details:
        body["details"] = details
    return jsonify(body), status


def json_body():
    """Parse a JSON object body or return None (caller answers 400)."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def thresholds() -> dict:
    return {k: current_app.config.get(k) for k in (
        "ALERT_RISK_THRESHOLD", "ALERT_CONFIDENCE_THRESHOLD", "REPEATED_OBSERVATION_THRESHOLD")}

"""SOC alert queue endpoints."""
from flask import Blueprint, g, jsonify, request

from backend.database import get_db
from backend.services.alert_engine import alert_summary, list_alerts, update_alert_status
from backend.utils.helpers import error_response, json_body
from backend.utils.security import require_role

bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@bp.get("")
def get_alerts():
    try:
        limit = int(request.args.get("limit", 200))
    except ValueError:
        return error_response(400, "bad_request", "limit must be an integer.")
    items = list_alerts(get_db(), request.args.get("status"), request.args.get("severity"),
                        request.args.get("alert_type"), limit)
    return jsonify(items=items, count=len(items))


@bp.get("/summary")
def summary():
    return jsonify(alert_summary(get_db()))


@bp.put("/<alert_id>/status")
@require_role("analyst")
def set_status(alert_id):
    payload = json_body()
    if payload is None or "status" not in payload:
        return error_response(400, "bad_request", "JSON body with a 'status' field is required.")
    try:
        alert = update_alert_status(get_db(), alert_id, payload["status"], g.role, str(payload.get("comment", "")))
    except ValueError as exc:
        return error_response(422, "validation_error", "Invalid alert status.", exc.args[0])
    if alert is None:
        return error_response(404, "not_found", f"Alert {alert_id} not found.")
    return jsonify(alert)

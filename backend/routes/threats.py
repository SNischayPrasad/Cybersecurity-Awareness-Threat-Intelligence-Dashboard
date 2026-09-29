"""Threat, indicator-search and analyst-note endpoints."""
from flask import Blueprint, g, jsonify, request

from backend.database import get_db
from backend.services import threat_service
from backend.services.enrichment_engine import enrich_indicator
from backend.services.ioc_validator import validate_indicator
from backend.utils.helpers import error_response, json_body, thresholds
from backend.utils.security import require_role

bp = Blueprint("threats", __name__, url_prefix="/api")


@bp.get("/threats")
def list_threats():
    """GET /api/threats?severity=HIGH,CRITICAL&category=PHISHING&sort=risk&page=1&page_size=25"""
    try:
        return jsonify(threat_service.list_threats(get_db(), request.args.to_dict()))
    except ValueError as exc:
        return error_response(400, "validation_error", "Invalid query parameters.", exc.args[0])


@bp.get("/threats/<threat_id>")
def get_threat(threat_id):
    detail = threat_service.get_threat_detail(get_db(), threat_id)
    if not detail:
        return error_response(404, "not_found", f"Threat {threat_id} not found.")
    return jsonify(detail)


@bp.post("/threats")
@require_role("admin")
def create_threat():
    payload = json_body()
    if payload is None:
        return error_response(400, "bad_request", "Request body must be a JSON object.")
    try:
        created = threat_service.create_threat(get_db(), payload, g.role, thresholds())
    except ValueError as exc:
        return error_response(422, "validation_error", "Threat record failed validation.", exc.args[0])
    return jsonify(created), 201


@bp.put("/threats/<threat_id>")
@require_role("analyst")
def update_threat(threat_id):
    payload = json_body()
    if payload is None or not payload:
        return error_response(400, "bad_request", "Request body must be a non-empty JSON object.")
    if {"threat_name", "description"} & payload.keys() and g.role != "admin":
        return error_response(403, "forbidden", "Only admins can edit threat name/description.")
    try:
        updated = threat_service.update_threat(get_db(), threat_id, payload, g.role)
    except ValueError as exc:
        return error_response(422, "validation_error", "Update failed validation.", exc.args[0])
    if updated is None:
        return error_response(404, "not_found", f"Threat {threat_id} not found.")
    return jsonify(updated)


@bp.post("/threats/<threat_id>/notes")
@require_role("analyst")
def add_note(threat_id):
    payload = json_body()
    if payload is None:
        return error_response(400, "bad_request", "Request body must be a JSON object with a 'note' field.")
    try:
        note = threat_service.add_analyst_note(get_db(), threat_id, payload.get("note", ""), g.role,
                                               payload.get("author") or g.role)
    except ValueError as exc:
        return error_response(422, "validation_error", "Note failed validation.", exc.args[0])
    if note is None:
        return error_response(404, "not_found", f"Threat {threat_id} not found.")
    return jsonify(note), 201


@bp.get("/indicators/search")
def search_indicator():
    """Database lookup ONLY. The searched indicator is never contacted."""
    q = (request.args.get("q") or "").strip()
    if not q:
        return error_response(400, "bad_request", "Query parameter 'q' is required.")
    if len(q) > 2048:
        return error_response(400, "bad_request", "Query is too long.")
    return jsonify(enrich_indicator(get_db(), q))


@bp.get("/indicators/validate")
def validate():
    value = request.args.get("value", "")
    if not value:
        return error_response(400, "bad_request", "Query parameter 'value' is required.")
    return jsonify(validate_indicator(value, request.args.get("type") or None))

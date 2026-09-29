"""Vulnerability awareness + contextual prioritisation endpoints."""
from flask import Blueprint, jsonify, request

from backend.database import get_db
from backend.services.vulnerability_service import (
    calculate_vulnerability_priority,
    list_vulnerabilities,
    vulnerability_stats,
)
from backend.utils.helpers import error_response, json_body

bp = Blueprint("vulnerabilities", __name__, url_prefix="/api/vulnerabilities")


@bp.get("")
def get_vulnerabilities():
    items = list_vulnerabilities(get_db(), request.args.get("severity"), request.args.get("band"),
                                 request.args.get("sort", "priority"))
    return jsonify(items=items, count=len(items), stats=vulnerability_stats(get_db()),
                   note="CVE-2099-* records are synthetic demo data, not real vulnerabilities.")


@bp.post("/prioritize")
def prioritize():
    """Pure calculation - lets users compare scenarios (no data is stored)."""
    p = json_body()
    if p is None:
        return error_response(400, "bad_request", "Request body must be a JSON object.")
    try:
        result = calculate_vulnerability_priority(
            float(p.get("cvss_score", 0)), p.get("asset_criticality", "MEDIUM"), p.get("exposure", "INTERNAL"),
            p.get("exploitation_status", "NO_KNOWN_EXPLOITATION"), bool(p.get("handles_sensitive_data", False)),
            bool(p.get("patch_available", True)))
    except (TypeError, ValueError) as exc:
        return error_response(422, "validation_error", str(exc))
    return jsonify(result)

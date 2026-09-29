"""Awareness Center + quiz endpoints."""
import re

from flask import Blueprint, current_app, jsonify, request

from backend.database import get_db
from backend.services.awareness_service import (
    DISCLAIMER,
    get_module,
    list_modules,
    load_json,
    public_questions,
    save_quiz_result,
    score_quiz,
)
from backend.utils.helpers import error_response, json_body

bp = Blueprint("awareness", __name__, url_prefix="/api")
ANON_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")


def _questions():
    return load_json(current_app.config["AWARENESS_DIR"], "quiz_questions.json")


@bp.get("/awareness/modules")
def modules():
    items = list_modules(get_db())
    return jsonify(items=items, count=len(items))


@bp.get("/awareness/modules/<module_id>")
def module(module_id):
    m = get_module(get_db(), module_id)
    if not m:
        return error_response(404, "not_found", f"Module {module_id} not found.")
    return jsonify(m)


@bp.get("/quiz")
def quiz():
    shuffle = request.args.get("shuffle", "false").lower() == "true"
    qs = public_questions(_questions(), shuffle)
    return jsonify(questions=qs, count=len(qs), disclaimer=DISCLAIMER)


@bp.post("/quiz/submit")
def submit():
    payload = json_body()
    if payload is None:
        return error_response(400, "bad_request", "Request body must be a JSON object with 'answers'.")
    anon = payload.get("anonymous_user_id")
    if anon is not None and not ANON_ID_RE.match(str(anon)):
        return error_response(422, "validation_error", "anonymous_user_id may only contain letters, digits, '-'.")
    try:
        result = score_quiz(_questions(), payload.get("answers"))
    except ValueError as exc:
        return error_response(422, "validation_error", "Invalid quiz submission.", exc.args[0])
    result["result_id"] = save_quiz_result(get_db(), result, anon)
    return jsonify(result), 201

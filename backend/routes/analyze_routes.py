"""
analyze_routes.py
-----------------
POST /api/analyze

PRIVACY RULES ENFORCED HERE:
  * Password arrives in the JSON body (never in the URL).
  * Password is validated for type and length.
  * Password is passed to the analyzer and then goes out of scope.
  * Password is never logged, never stored, never echoed in errors.
"""

from flask import Blueprint, jsonify, request

from backend.config import ENABLE_ANALYTICS, MAX_PASSWORD_LENGTH
from backend.models.database import save_analysis_metadata
from backend.services.password_analyzer import analyze_password
from backend.utils.logger import get_logger

analyze_bp = Blueprint("analyze", __name__)
log = get_logger(__name__)


@analyze_bp.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(silent=True) or {}

    password = payload.get("password")
    context = payload.get("context") or {}

    if not isinstance(password, str):
        return jsonify({
            "error": "invalid_request",
            "message": "Field 'password' must be a string.",
        }), 400

    if len(password) > MAX_PASSWORD_LENGTH:
        return jsonify({
            "error": "password_too_long",
            "message": f"Maximum supported length is {MAX_PASSWORD_LENGTH} characters.",
        }), 413

    if not isinstance(context, dict):
        context = {}

    # Only keep string values of reasonable length in the context.
    safe_context = {
        str(k)[:32]: str(v)[:64]
        for k, v in context.items()
        if isinstance(v, (str, int)) and str(v).strip()
    }

    result = analyze_password(password, context=safe_context)

    if ENABLE_ANALYTICS:
        try:
            save_analysis_metadata(result)
        except Exception:
            # Non-fatal. Never log request data.
            log.warning("Analytics write failed (non-fatal).")

    return jsonify(result), 200
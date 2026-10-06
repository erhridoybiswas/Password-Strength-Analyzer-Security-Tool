"""
generator_routes.py
-------------------
POST /api/generate-password
POST /api/generate-passphrase

Both use the `secrets` module. Nothing is stored.
"""

from flask import Blueprint, jsonify, request

from backend.services.password_generator import generate_password, generate_passphrase
from backend.utils.logger import get_logger

generator_bp = Blueprint("generator", __name__)
log = get_logger(__name__)


@generator_bp.route("/generate-password", methods=["POST"])
def create_password():
    payload = request.get_json(silent=True) or {}

    try:
        length = int(payload.get("length", 20))
    except (TypeError, ValueError):
        length = 20

    length = max(8, min(128, length))

    result = generate_password(
        length=length,
        use_upper=bool(payload.get("use_uppercase", True)),
        use_lower=bool(payload.get("use_lowercase", True)),
        use_digits=bool(payload.get("use_digits", True)),
        use_symbols=bool(payload.get("use_symbols", True)),
    )
    return jsonify(result), 200


@generator_bp.route("/generate-passphrase", methods=["POST"])
def create_passphrase():
    payload = request.get_json(silent=True) or {}
    try:
        word_count = int(payload.get("word_count", 5))
    except (TypeError, ValueError):
        word_count = 5

    word_count = max(3, min(10, word_count))
    return jsonify(generate_passphrase(word_count=word_count)), 200
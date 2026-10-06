"""
app.py
------
Flask application entry point.

Run from the PROJECT ROOT with:

    python -m backend.app

The Flask app also serves the static frontend from ../frontend so there is
no CORS configuration needed for local development.
"""

import os

from dotenv import load_dotenv
from flask import Flask, jsonify, send_from_directory

from backend.config import FLASK_PORT, FRONTEND_DIR
from backend.models.database import init_db
from backend.routes.analyze_routes import analyze_bp
from backend.routes.dashboard_routes import dashboard_bp
from backend.routes.generator_routes import generator_bp
from backend.utils.logger import get_logger

load_dotenv()

log = get_logger(__name__)


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder=FRONTEND_DIR,
        static_url_path="",
    )
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024  # 32 KB request cap

    init_db()

    app.register_blueprint(analyze_bp, url_prefix="/api")
    app.register_blueprint(dashboard_bp, url_prefix="/api")
    app.register_blueprint(generator_bp, url_prefix="/api")

    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok"}), 200

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify({"error": "method_not_allowed"}), 405

    @app.errorhandler(413)
    def payload_too_large(_error):
        return jsonify({"error": "payload_too_large"}), 413

    @app.errorhandler(500)
    def internal_error(_error):
        # Never echo exception details that might contain request data.
        return jsonify({"error": "internal_server_error"}), 500

    return app


app = create_app()


if __name__ == "__main__":
    log.info("Starting Password Strength Analyzer on http://127.0.0.1:%s", FLASK_PORT)
    # debug=False so that request data is never dumped into tracebacks.
    app.run(host="127.0.0.1", port=FLASK_PORT, debug=False)
"""
dashboard_routes.py
-------------------
GET /api/dashboard/stats
GET /api/analytics/weaknesses

Both endpoints return ONLY aggregate metadata. No password can ever appear.
"""

from flask import Blueprint, jsonify

from backend.models.database import get_dashboard_stats, get_weakness_frequency
from backend.utils.logger import get_logger

dashboard_bp = Blueprint("dashboard", __name__)
log = get_logger(__name__)


@dashboard_bp.route("/dashboard/stats", methods=["GET"])
def dashboard_stats():
    try:
        return jsonify(get_dashboard_stats()), 200
    except Exception:
        log.warning("Dashboard stats unavailable.")
        return jsonify({"error": "stats_unavailable"}), 500


@dashboard_bp.route("/analytics/weaknesses", methods=["GET"])
def analytics_weaknesses():
    try:
        return jsonify({"weaknesses": get_weakness_frequency()}), 200
    except Exception:
        log.warning("Weakness analytics unavailable.")
        return jsonify({"error": "analytics_unavailable"}), 500
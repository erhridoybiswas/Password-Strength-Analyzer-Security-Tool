"""
config.py
---------
Single source of truth for configuration values read from environment
variables (with safe defaults).
"""

import os

# Project root = two levels up from this file (backend/config.py -> project/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))

MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "12"))
MAX_PASSWORD_LENGTH = int(os.getenv("MAX_PASSWORD_LENGTH", "256"))

ENABLE_ANALYTICS = os.getenv("ENABLE_ANALYTICS", "true").lower() == "true"
ENABLE_COMMON_PASSWORD_CHECK = os.getenv("ENABLE_COMMON_PASSWORD_CHECK", "true").lower() == "true"
ENABLE_PERSONAL_INFO_CHECK = os.getenv("ENABLE_PERSONAL_INFO_CHECK", "true").lower() == "true"

DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join(PROJECT_ROOT, "analytics.db"))
COMMON_PASSWORDS_FILE = os.getenv(
    "COMMON_PASSWORDS_FILE", os.path.join(DATA_DIR, "common_passwords.txt")
)
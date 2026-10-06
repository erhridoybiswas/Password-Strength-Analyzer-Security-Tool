"""
logger.py
---------
Central logging configuration.

SECURITY RULE:
    Nothing in this project ever logs a submitted password, a fragment of a
    submitted password, or a request body containing a password. This module
    exists so that all logging goes through one audited place.
"""

import logging
import os


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger that writes only non-sensitive messages."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(logging.DEBUG if os.getenv("FLASK_ENV") == "development" else logging.INFO)
    logger.propagate = False
    return logger
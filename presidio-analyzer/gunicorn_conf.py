"""Gunicorn configuration for Presidio Analyzer."""

import os

bind = f"0.0.0.0:{os.environ.get('PORT', '3000')}"
workers = int(os.environ.get("WORKERS", 1))
graceful_timeout = int(os.environ.get("GRACEFUL_TIMEOUT", 15))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 120))


def worker_int(worker):
    """Handle SIGINT/SIGQUIT during graceful worker shutdown."""
    worker.app.wsgi().config["SHUTTING_DOWN"] = True

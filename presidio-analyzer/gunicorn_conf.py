"""Gunicorn configuration for Presidio Analyzer."""

import os
import signal

bind = f"0.0.0.0:{os.environ.get('PORT', '3000')}"
workers = int(os.environ.get("WORKERS", 1))
# gthread keep-alive is robust; the default sync worker has flaky persistent
# connection support and races with aiohttp's connection pool through Docker
# Desktop's vpnkit, surfacing as non-deterministic mid-run hangs from
# long-running clients (e.g. pii_evals).
worker_class = os.environ.get("WORKER_CLASS", "gthread")
# Two threads is enough to defuse the keep-alive race that the sync worker
# exposes without multiplying ONNX's thread fan-out (each in-flight request
# spawns ONNX_INTRA_OP_NUM_THREADS workers under the hood).
threads = int(os.environ.get("THREADS", 2))
keepalive = int(os.environ.get("KEEPALIVE", 30))
graceful_timeout = int(os.environ.get("GRACEFUL_TIMEOUT", 15))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 120))
accesslog = os.environ.get("GUNICORN_ACCESS_LOG", "-")
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s %(L)s'


def _flip_shutting_down(worker):
    """Best-effort flip of the /readyz drain flag. Safe if app not yet built."""
    try:
        worker.app.wsgi().config["SHUTTING_DOWN"] = True
    except Exception:
        pass


def post_fork(server, worker):
    """Install a SIGTERM handler in each worker so /readyz flips on k8s drain.

    Gunicorn's worker_int hook only fires on SIGINT/SIGQUIT, but Kubernetes
    sends SIGTERM on pod termination. Without this hook the SHUTTING_DOWN flag
    never flips during a normal rollout and kube-proxy keeps routing traffic
    to a draining pod.
    """
    prev = signal.getsignal(signal.SIGTERM)

    def _chained(signum, frame):
        _flip_shutting_down(worker)
        if callable(prev):
            prev(signum, frame)

    signal.signal(signal.SIGTERM, _chained)


def worker_int(worker):
    """Handle SIGINT/SIGQUIT during graceful worker shutdown."""
    _flip_shutting_down(worker)

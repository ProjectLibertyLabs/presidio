"""Tests for Gunicorn config hooks and shutdown readiness behavior."""

import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock heavy presidio_analyzer dependencies before importing app
_mock_presidio = MagicMock()
_mock_presidio.AnalyzerEngine = MagicMock
_mock_presidio.AnalyzerEngineProvider = MagicMock
_mock_presidio.AnalyzerRequest = MagicMock
_mock_presidio.BatchAnalyzerEngine = MagicMock

sys.modules.setdefault("presidio_analyzer", _mock_presidio)
sys.modules.setdefault("presidio_analyzer.pattern", MagicMock())
sys.modules.setdefault("presidio_analyzer.nlp_engine", MagicMock())
sys.modules.setdefault("presidio_analyzer.predefined_recognizers", MagicMock())

from gunicorn_conf import worker_int


def _build_worker(flask_app):
    worker = MagicMock()
    worker.app.wsgi.return_value = flask_app
    return worker


@pytest.fixture
def mock_engine():
    """Create a mock analyzer engine with configurable NLP and registry."""
    engine = MagicMock()
    engine.nlp_engine.is_loaded.return_value = True
    engine.registry.recognizers = [MagicMock()]
    engine.analyze.return_value = []
    return engine


@pytest.fixture
def server(mock_engine):
    """Create a test Server with mocked analyzer dependencies."""
    with patch("app.fileConfig"), \
         patch("app.AnalyzerEngineProvider") as mock_provider, \
         patch("app.BatchAnalyzerEngine"):
        mock_provider.return_value.create_engine.return_value = mock_engine
        from app import Server

        test_server = Server()
        test_server.app.config["TESTING"] = True
        yield test_server


def test_worker_int_sets_shutting_down_true():
    config = {"SHUTTING_DOWN": False, "UNCHANGED": "value"}
    flask_app = MagicMock()
    flask_app.config = config
    worker = _build_worker(flask_app)

    worker_int(worker)

    assert config["SHUTTING_DOWN"] is True
    assert config["UNCHANGED"] == "value"


def test_worker_int_flips_readyz_from_200_to_503(server):
    with server.app.test_client() as client:
        ready_resp = client.get("/readyz")
        assert ready_resp.status_code == 200
        assert ready_resp.get_json() == {"status": "ok"}

        worker = _build_worker(server.app)
        worker_int(worker)

        shutting_down_resp = client.get("/readyz")
        assert shutting_down_resp.status_code == 503
        assert shutting_down_resp.get_json() == {"status": "shutting down"}

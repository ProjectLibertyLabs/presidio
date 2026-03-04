"""Tests for /livez and /readyz health check endpoints."""

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


@pytest.fixture
def mock_engine():
    """Create a mock analyzer engine with configurable NLP and registry."""
    engine = MagicMock()
    engine.nlp_engine.is_loaded.return_value = True
    engine.registry.recognizers = [MagicMock()]
    engine.analyze.return_value = []
    return engine


@pytest.fixture
def client(mock_engine):
    """Create a Flask test client with mocked dependencies."""
    with patch("app.fileConfig"), \
         patch("app.AnalyzerEngineProvider") as mock_provider, \
         patch("app.BatchAnalyzerEngine"):
        mock_provider.return_value.create_engine.return_value = mock_engine
        from app import Server
        server = Server()
        server.app.config["TESTING"] = True
        with server.app.test_client() as c:
            yield c


class TestLivez:
    def test_returns_200(self, client):
        resp = client.get("/livez")
        assert resp.status_code == 200
        assert resp.get_json() == {"status": "ok"}


class TestReadyz:
    def test_returns_200_when_ready(self, client):
        resp = client.get("/readyz")
        assert resp.status_code == 200
        assert resp.get_json() == {"status": "ok"}

    def test_returns_503_when_nlp_not_loaded(self, mock_engine):
        mock_engine.nlp_engine.is_loaded.return_value = False
        with patch("app.fileConfig"), \
             patch("app.AnalyzerEngineProvider") as mock_provider, \
             patch("app.BatchAnalyzerEngine"):
            mock_provider.return_value.create_engine.return_value = mock_engine
            from app import Server
            server = Server()
            server.app.config["TESTING"] = True
            with server.app.test_client() as c:
                resp = c.get("/readyz")
                assert resp.status_code == 503
                data = resp.get_json()
                assert data["status"] == "not ready"
                assert "NLP engine not loaded" in data["reason"]

    def test_returns_503_when_no_recognizers(self, mock_engine):
        mock_engine.registry.recognizers = []
        with patch("app.fileConfig"), \
             patch("app.AnalyzerEngineProvider") as mock_provider, \
             patch("app.BatchAnalyzerEngine"):
            mock_provider.return_value.create_engine.return_value = mock_engine
            from app import Server
            server = Server()
            server.app.config["TESTING"] = True
            with server.app.test_client() as c:
                resp = c.get("/readyz")
                assert resp.status_code == 503
                data = resp.get_json()
                assert data["status"] == "not ready"
                assert "No recognizers loaded" in data["reason"]

    def test_returns_503_when_analyze_raises(self, mock_engine):
        mock_engine.analyze.side_effect = RuntimeError("model crashed")
        with patch("app.fileConfig"), \
             patch("app.AnalyzerEngineProvider") as mock_provider, \
             patch("app.BatchAnalyzerEngine"):
            mock_provider.return_value.create_engine.return_value = mock_engine
            from app import Server
            server = Server()
            server.app.config["TESTING"] = True
            with server.app.test_client() as c:
                resp = c.get("/readyz")
                assert resp.status_code == 503
                data = resp.get_json()
                assert data["status"] == "not ready"
                assert "model crashed" in data["reason"]

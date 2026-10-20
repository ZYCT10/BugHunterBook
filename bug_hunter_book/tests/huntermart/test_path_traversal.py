"""Регрессионные тесты лаборатории Path Traversal (гл. 9). Синтетическое хранилище."""


from fastapi.testclient import TestClient

from huntermart.app import create_app
from huntermart.config import Mode, Settings


def _client(mode: Mode) -> TestClient:
    return TestClient(create_app(settings=Settings(mode=mode)))


def test_public_file_readable_in_both_modes() -> None:
    for mode in (Mode.VULNERABLE, Mode.SECURE):
        resp = _client(mode).get("/api/files", params={"name": "logo.txt"})
        assert resp.status_code == 200
        assert "PUBLIC LOGO" in resp.json()["content"]


def test_traversal_reaches_secret_in_vulnerable() -> None:
    resp = _client(Mode.VULNERABLE).get("/api/files", params={"name": "../secret/flag.txt"})
    assert resp.status_code == 200
    assert "SECRET-FLAG" in resp.json()["content"]
    assert resp.json()["resolved"] == "/lab/secret/flag.txt"


def test_traversal_blocked_in_secure() -> None:
    resp = _client(Mode.SECURE).get("/api/files", params={"name": "../secret/flag.txt"})
    assert resp.status_code == 403


def test_unknown_file_404() -> None:
    assert _client(Mode.SECURE).get("/api/files", params={"name": "nope.txt"}).status_code == 404

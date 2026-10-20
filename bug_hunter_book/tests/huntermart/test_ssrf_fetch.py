"""Регрессионные тесты лаборатории SSRF (гл. 9).

Модель синтетическая (без реальной сети). Доказывают: в режиме vulnerable можно достать
«внутренний» ресурс (SSRF), в режиме secure внутренние адреса и чужие хосты блокируются.
"""


from fastapi.testclient import TestClient

from huntermart.app import create_app
from huntermart.config import Mode, Settings

INTERNAL = "http://metadata.internal/latest/token"
ALLOWED = "https://images.huntermart.example/p/1.png"


def _client(mode: Mode) -> TestClient:
    return TestClient(create_app(settings=Settings(mode=mode)))


def test_allowed_host_fetch_ok_in_both_modes() -> None:
    for mode in (Mode.VULNERABLE, Mode.SECURE):
        resp = _client(mode).get("/api/fetch", params={"url": ALLOWED})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


def test_ssrf_reaches_internal_in_vulnerable() -> None:
    resp = _client(Mode.VULNERABLE).get("/api/fetch", params={"url": INTERNAL})
    assert resp.status_code == 200
    assert "SYNTHETIC-INTERNAL-TOKEN" in resp.json()["body"]


def test_ssrf_blocked_in_secure() -> None:
    resp = _client(Mode.SECURE).get("/api/fetch", params={"url": INTERNAL})
    assert resp.status_code == 400


def test_secure_blocks_loopback_and_foreign_hosts() -> None:
    for url in ("http://127.0.0.1:9000/admin", "https://evil.test/x", "file:///etc/passwd"):
        resp = _client(Mode.SECURE).get("/api/fetch", params={"url": url})
        assert resp.status_code == 400

"""Регрессионные тесты лаборатории Open Redirect (гл. 7/34).

Проверяют наличие Open Redirect в режиме vulnerable и его устранение в режиме secure,
включая обход через "//evil.test" (protocol-relative URL).
"""


import pytest
from fastapi.testclient import TestClient

from huntermart.app import create_app
from huntermart.config import Mode, Settings


def _client(mode: Mode) -> TestClient:
    # follow_redirects=False: нас интересует сам заголовок Location, а не конечная страница.
    return TestClient(create_app(settings=Settings(mode=mode)), follow_redirects=False)


def test_internal_path_allowed_in_both_modes() -> None:
    for mode in (Mode.VULNERABLE, Mode.SECURE):
        resp = _client(mode).get("/go", params={"next": "/orders"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/orders"


def test_open_redirect_present_in_vulnerable_mode() -> None:
    resp = _client(Mode.VULNERABLE).get("/go", params={"next": "https://evil.test/phish"})
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://evil.test/phish"


def test_open_redirect_fixed_in_secure_mode() -> None:
    resp = _client(Mode.SECURE).get("/go", params={"next": "https://evil.test/phish"})
    assert resp.status_code == 400


@pytest.mark.parametrize("payload", ["//evil.test", "https://evil.test", "http://127.0.0.1:1/x"])
def test_secure_mode_blocks_external_targets(payload: str) -> None:
    resp = _client(Mode.SECURE).get("/go", params={"next": payload})
    assert resp.status_code == 400


def test_secure_mode_allows_shop_host() -> None:
    resp = _client(Mode.SECURE).get("/go", params={"next": "https://huntermart.example/account"})
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://huntermart.example/account"


def test_protocol_relative_is_open_redirect_in_vulnerable() -> None:
    # "//evil.test" браузер трактует как переход на evil.test по текущей схеме — тоже Open Redirect.
    resp = _client(Mode.VULNERABLE).get("/go", params={"next": "//evil.test"})
    assert resp.status_code == 302
    assert resp.headers["location"] == "//evil.test"

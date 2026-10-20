"""Регрессионные тесты лаборатории Reflected XSS (гл. 8).

Доказывают: в режиме vulnerable полезная нагрузка отражается в HTML без кодирования
(исполнимый <script>), в режиме secure — кодируется в текст (&lt;script&gt;).
"""


from fastapi.testclient import TestClient

from huntermart.app import create_app
from huntermart.config import Mode, Settings

PAYLOAD = "<script>alert(1)</script>"


def _client(mode: Mode) -> TestClient:
    return TestClient(create_app(settings=Settings(mode=mode)))


def test_plain_query_reflected_in_both_modes() -> None:
    for mode in (Mode.VULNERABLE, Mode.SECURE):
        resp = _client(mode).get("/search", params={"q": "ноутбук"})
        assert resp.status_code == 200
        assert "ноутбук" in resp.text


def test_xss_payload_raw_in_vulnerable() -> None:
    resp = _client(Mode.VULNERABLE).get("/search", params={"q": PAYLOAD})
    assert resp.status_code == 200
    # Сырой <script> попадает в HTML как исполнимая разметка.
    assert PAYLOAD in resp.text


def test_xss_payload_escaped_in_secure() -> None:
    resp = _client(Mode.SECURE).get("/search", params={"q": PAYLOAD})
    assert resp.status_code == 200
    # Экранировано: исполнимого <script> нет, есть его текстовое представление.
    assert PAYLOAD not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_attribute_breakout_escaped_in_secure() -> None:
    # Кавычки тоже кодируются, что ломает попытки выхода из атрибутов.
    resp = _client(Mode.SECURE).get("/search", params={"q": '"><img src=x onerror=alert(1)>'})
    assert "<img" not in resp.text
    assert "&lt;img" in resp.text

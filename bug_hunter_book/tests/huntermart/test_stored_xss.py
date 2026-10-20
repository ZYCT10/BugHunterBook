"""Регрессионные тесты лаборатории Stored XSS (гл. 8).

Доказывают: сохранённый отзыв с полезной нагрузкой отражается на странице без кодирования
в режиме vulnerable и кодируется в режиме secure.
"""


from fastapi.testclient import TestClient

from huntermart.app import create_app
from huntermart.config import Mode, Settings

PAYLOAD = "<script>alert(document.cookie)</script>"


def _client(mode: Mode) -> TestClient:
    return TestClient(create_app(settings=Settings(mode=mode)))


def test_stored_payload_raw_in_vulnerable() -> None:
    client = _client(Mode.VULNERABLE)
    client.post("/api/comments", json={"author": "mallory", "body": PAYLOAD})
    page = client.get("/comments").text
    assert PAYLOAD in page  # сохранённый скрипт отражается без кодирования


def test_stored_payload_escaped_in_secure() -> None:
    client = _client(Mode.SECURE)
    client.post("/api/comments", json={"author": "mallory", "body": PAYLOAD})
    page = client.get("/comments").text
    assert PAYLOAD not in page
    assert "&lt;script&gt;" in page


def test_author_is_always_escaped() -> None:
    # Поле автора кодируется в обоих режимах.
    client = _client(Mode.VULNERABLE)
    client.post("/api/comments", json={"author": "<i>x</i>", "body": "обычный текст"})
    page = client.get("/comments").text
    assert "&lt;i&gt;x&lt;/i&gt;" in page

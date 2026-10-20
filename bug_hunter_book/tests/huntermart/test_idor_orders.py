"""Регрессионные тесты лаборатории IDOR (гл. 16/17).

Демонстрируют наличие уязвимости в режиме vulnerable и её устранение в режиме secure.
Запуск: pytest
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from huntermart.app import create_app
from huntermart.config import Mode, Settings


def _client(mode: Mode) -> TestClient:
    settings = Settings(mode=mode)
    return TestClient(create_app(settings=settings, db_path=":memory:"))


def _login(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/api/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_reports_mode() -> None:
    client = _client(Mode.VULNERABLE)
    body = client.get("/health").json()
    assert body == {"status": "ok", "mode": "vulnerable"}


def test_owner_can_read_own_order_in_both_modes() -> None:
    for mode in (Mode.VULNERABLE, Mode.SECURE):
        client = _client(mode)
        token = _login(client, "alice", "alice-pass")  # alice = user 1, владеет заказом 1001
        resp = client.get("/api/orders/1001", headers=_auth(token))
        assert resp.status_code == 200, (mode, resp.text)
        assert resp.json()["user_id"] == 1


def test_idor_present_in_vulnerable_mode() -> None:
    client = _client(Mode.VULNERABLE)
    token = _login(client, "alice", "alice-pass")  # alice
    # Заказ 1002 принадлежит bob (user 2). В уязвимом режиме alice его читает.
    resp = client.get("/api/orders/1002", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["user_id"] == 2
    assert "Боба" in resp.json()["shipping_address"]


def test_idor_fixed_in_secure_mode() -> None:
    client = _client(Mode.SECURE)
    token = _login(client, "alice", "alice-pass")
    # В защищённом режиме чужой заказ маскируется под 404.
    resp = client.get("/api/orders/1002", headers=_auth(token))
    assert resp.status_code == 404


def test_support_can_read_any_order_in_secure_mode() -> None:
    client = _client(Mode.SECURE)
    token = _login(client, "sam", "sam-pass")  # роль support
    resp = client.get("/api/orders/1002", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["user_id"] == 2


def test_unauthenticated_is_rejected() -> None:
    for mode in (Mode.VULNERABLE, Mode.SECURE):
        client = _client(mode)
        assert client.get("/api/orders/1001").status_code == 401


@pytest.mark.parametrize("bad_token", ["", "garbage", "1.deadbeef", "999.deadbeef"])
def test_forged_tokens_rejected(bad_token: str) -> None:
    client = _client(Mode.VULNERABLE)
    resp = client.get("/api/orders/1001", headers=_auth(bad_token))
    assert resp.status_code == 401

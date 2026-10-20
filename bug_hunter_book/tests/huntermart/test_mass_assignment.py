"""Регрессионные тесты лаборатории Mass Assignment (гл. 11).

Доказывают: в режиме vulnerable клиент может задать поле role (повышение привилегий),
в режиме secure поле role игнорируется (обновляются только разрешённые поля).
"""


from fastapi.testclient import TestClient

from huntermart.app import create_app
from huntermart.config import Mode, Settings


def _client(mode: Mode) -> TestClient:
    return TestClient(create_app(settings=Settings(mode=mode)))


def _login(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/api/login", json={"username": username, "password": password})
    return resp.json()["token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_allowed_fields_update_in_both_modes() -> None:
    for mode in (Mode.VULNERABLE, Mode.SECURE):
        client = _client(mode)
        token = _login(client, "alice", "alice-pass")
        resp = client.post("/api/profile", json={"full_name": "Алиса Новая"}, headers=_auth(token))
        assert resp.status_code == 200
        assert resp.json()["full_name"] == "Алиса Новая"
        assert resp.json()["role"] == "customer"  # роль не менялась


def test_mass_assignment_role_escalation_in_vulnerable() -> None:
    client = _client(Mode.VULNERABLE)
    token = _login(client, "alice", "alice-pass")  # обычный customer
    resp = client.post("/api/profile", json={"role": "admin"}, headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"  # привилегии повышены — уязвимость


def test_mass_assignment_blocked_in_secure() -> None:
    client = _client(Mode.SECURE)
    token = _login(client, "alice", "alice-pass")
    resp = client.post(
        "/api/profile", json={"role": "admin", "full_name": "Алиса"}, headers=_auth(token)
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "customer"   # role проигнорирован
    assert resp.json()["full_name"] == "Алиса"  # разрешённое поле обновлено


def test_profile_requires_auth() -> None:
    assert _client(Mode.SECURE).post("/api/profile", json={"full_name": "x"}).status_code == 401

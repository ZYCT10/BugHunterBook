"""Регрессионные тесты лаборатории SQL Injection (гл. 23).

Доказывают: инъекция работает в режиме vulnerable (обход фильтра и UNION-извлечение
пользователей), и не работает в режиме secure (значение трактуется только как данные).
Все данные синтетические, база — локальная SQLite в памяти.
"""


from fastapi.testclient import TestClient

from huntermart.app import create_app
from huntermart.config import Mode, Settings


def _client(mode: Mode) -> TestClient:
    return TestClient(create_app(settings=Settings(mode=mode)))


def _search(client: TestClient, q: str) -> dict:
    resp = client.get("/api/products/search", params={"q": q})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_normal_search_matches_substring_in_both_modes() -> None:
    for mode in (Mode.VULNERABLE, Mode.SECURE):
        body = _search(_client(mode), "микрофон")
        titles = [r["title"] for r in body["results"]]
        assert any("микрофон" in t.lower() for t in titles)
        assert all("клавиатура" not in t.lower() for t in titles)


def test_tautology_bypass_present_in_vulnerable() -> None:
    # "%' OR '1'='1" превращает условие в всегда-истинное -> возвращаются ВСЕ товары.
    client = _client(Mode.VULNERABLE)
    all_products = _search(client, "")["results"]
    injected = _search(client, "нетакого%' OR '1'='1' -- ")["results"]
    assert len(injected) == len(all_products)
    assert len(injected) >= 3  # в сиде три товара


def test_tautology_bypass_fixed_in_secure() -> None:
    # В secure та же строка — это буквальная подстрока, совпадений нет.
    body = _search(_client(Mode.SECURE), "нетакого%' OR '1'='1' -- ")
    assert body["results"] == []


def test_union_extracts_users_in_vulnerable() -> None:
    # UNION подставляет чужую таблицу в выдачу: имя пользователя и хеш пароля в поле title.
    payload = "zzz%' UNION SELECT id, username || ':' || password_hash, 0 FROM users -- "
    results = _search(_client(Mode.VULNERABLE), payload)["results"]
    leaked = [r["title"] for r in results]
    assert any(t.startswith("root:") for t in leaked)  # утекли учётные записи
    assert any(t.startswith("alice:") for t in leaked)


def test_union_blocked_in_secure() -> None:
    payload = "zzz%' UNION SELECT id, username || ':' || password_hash, 0 FROM users -- "
    results = _search(_client(Mode.SECURE), payload)["results"]
    assert results == []  # трактуется как данные, UNION не исполняется

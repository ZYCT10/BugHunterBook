"""Тесты huntkit.openapi — разбор OpenAPI-спецификации (JSON и YAML)."""



from huntkit.openapi import interesting_operations, load_spec, operations

SPEC_JSON = """
{
  "openapi": "3.0.0",
  "paths": {
    "/api/orders/{id}": {"get": {"summary": "Получить заказ", "tags": ["orders"]}},
    "/api/products/search": {"get": {"summary": "Поиск"}},
    "/api/admin/users": {"get": {"summary": "Список пользователей"}, "post": {}}
  }
}
"""

SPEC_YAML = """
openapi: 3.0.0
paths:
  /api/login:
    post:
      summary: Вход
  /api/admin/config:
    get:
      summary: Конфигурация
"""


def test_load_json() -> None:
    assert load_spec(SPEC_JSON)["openapi"] == "3.0.0"


def test_load_yaml() -> None:
    assert load_spec(SPEC_YAML)["openapi"] == "3.0.0"


def test_operations_lists_methods_and_paths() -> None:
    ops = operations(load_spec(SPEC_JSON))
    pairs = {(o.method, o.path) for o in ops}
    assert ("GET", "/api/orders/{id}") in pairs
    assert ("GET", "/api/admin/users") in pairs
    assert ("POST", "/api/admin/users") in pairs
    assert len(ops) == 4


def test_path_param_detected() -> None:
    ops = {o.path: o for o in operations(load_spec(SPEC_JSON)) if o.method == "GET"}
    assert ops["/api/orders/{id}"].has_path_param is True
    assert ops["/api/products/search"].has_path_param is False


def test_tags_parsed() -> None:
    ops = {(o.method, o.path): o for o in operations(load_spec(SPEC_JSON))}
    assert ops[("GET", "/api/orders/{id}")].tags == ("orders",)


def test_interesting_operations_flags_admin_and_user() -> None:
    ops = interesting_operations(load_spec(SPEC_JSON))
    paths = {o.path for o in ops}
    assert "/api/admin/users" in paths     # admin + user
    assert "/api/orders/{id}" not in paths  # не содержит признаков


def test_interesting_in_yaml() -> None:
    ops = interesting_operations(load_spec(SPEC_YAML))
    assert any(o.path == "/api/admin/config" for o in ops)


def test_empty_paths_returns_empty() -> None:
    assert operations({"openapi": "3.0.0"}) == []

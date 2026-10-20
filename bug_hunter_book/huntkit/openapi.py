"""huntkit.openapi — разбор OpenAPI-спецификации.

Инструмент из главы 12. OpenAPI (Swagger) — готовая карта API: эндпоинты, методы,
параметры, схемы. Инструмент разбирает УЖЕ ПОЛУЧЕННУЮ спецификацию (JSON/YAML) и
выделяет операции и потенциально интересные маршруты (админские, по id, аутентификация).

Инструмент НЕ ходит в сеть. Для YAML используется PyYAML (safe_load — без выполнения тегов).

Статус проверки: проверено запуском (tests/code/test_openapi.py).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import yaml

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

# Признаки «интересных» маршрутов для исследователя (эвристика, не вердикт).
_INTERESTING = ("admin", "internal", "debug", "config", "token", "secret", "user", "account")


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    summary: str
    has_path_param: bool
    tags: tuple[str, ...]


def load_spec(text: str) -> dict:
    """Загружает спецификацию из JSON или YAML (safe)."""
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return json.loads(text)
    data = yaml.safe_load(text)  # safe_load: не исполняет произвольные теги
    if not isinstance(data, dict):
        raise ValueError("Спецификация должна быть объектом")
    return data


def operations(spec: dict) -> list[Operation]:
    """Возвращает список операций (метод+путь) из раздела paths."""
    result: list[Operation] = []
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return result
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            op = op if isinstance(op, dict) else {}
            tags = op.get("tags", [])
            result.append(
                Operation(
                    method=method.upper(),
                    path=str(path),
                    summary=str(op.get("summary", "")),
                    has_path_param="{" in str(path),
                    tags=tuple(str(t) for t in tags) if isinstance(tags, list) else (),
                )
            )
    return result


def interesting_operations(spec: dict) -> list[Operation]:
    """Операции, чей путь содержит признаки повышенного интереса (эвристика)."""
    out = []
    for op in operations(spec):
        low = op.path.lower()
        if any(word in low for word in _INTERESTING):
            out.append(op)
    return out

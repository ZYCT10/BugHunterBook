"""huntkit.respdiff — сравнение двух HTTP-ответов.

Инструмент из главы 12. Помогает отличать «одинаковые» и «разные» ответы —
ключевой приём при поиске boolean-based blind-уязвимостей (в т. ч. слепой SQL-инъекции),
при сравнении поведения на валидном/невалидном вводе и при дедупликации результатов.

Инструмент НЕ делает запросов сам: он сравнивает уже полученные ответы (status, заголовки,
тело). Получение ответов — задача huntkit.safe_client с его allowlist. Это осознанное
разделение: так автоматика сравнения не может случайно обратиться к постороннему хосту.

Что сравнивается:
    - код состояния;
    - длина тела и его сходство (нормализованное расстояние по строкам);
    - заметные заголовки (по умолчанию content-type, content-length, location);
    - числовые «сигналы» (длина/код) для принятия решения «похожи/различны».

Статус проверки: проверено запуском (tests/code/test_respdiff.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

DEFAULT_SIGNIFICANT_HEADERS = ("content-type", "content-length", "location")


@dataclass(frozen=True)
class ResponseSnapshot:
    """Минимальный снимок ответа, достаточный для сравнения."""

    status: int
    headers: dict[str, str]
    body: str

    def header(self, name: str) -> str | None:
        return {k.lower(): v for k, v in self.headers.items()}.get(name.lower())


@dataclass
class DiffResult:
    status_changed: bool
    length_delta: int
    body_similarity: float  # 1.0 — идентичны, 0.0 — совсем разные
    changed_headers: dict[str, tuple[str | None, str | None]] = field(default_factory=dict)

    def looks_different(self, *, similarity_threshold: float = 0.98) -> bool:
        """Эвристика «ответы различаются по существу».

        Порог сходства намеренно высокий: мелкие отличия (CSRF-токен, время) не должны
        считаться различием, а смена кода/длины/ключевых заголовков — должна.
        """
        return (
            self.status_changed
            or bool(self.changed_headers)
            or self.body_similarity < similarity_threshold
        )


def _body_similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


def compare(
    first: ResponseSnapshot,
    second: ResponseSnapshot,
    *,
    significant_headers: tuple[str, ...] = DEFAULT_SIGNIFICANT_HEADERS,
) -> DiffResult:
    changed: dict[str, tuple[str | None, str | None]] = {}
    for name in significant_headers:
        a, b = first.header(name), second.header(name)
        if a != b:
            changed[name] = (a, b)
    return DiffResult(
        status_changed=first.status != second.status,
        length_delta=len(second.body) - len(first.body),
        body_similarity=_body_similarity(first.body, second.body),
        changed_headers=changed,
    )


def snapshot_from_httpx(response: Any) -> ResponseSnapshot:
    """Создаёт снимок из объекта httpx.Response без жёсткой зависимости от httpx.

    Принимает любой объект с атрибутами status_code, headers (mapping) и text.
    """
    status = int(response.status_code)
    raw_headers = response.headers
    headers = {str(k): str(v) for k, v in dict(raw_headers).items()}
    body = str(response.text)
    return ResponseSnapshot(status=status, headers=headers, body=body)

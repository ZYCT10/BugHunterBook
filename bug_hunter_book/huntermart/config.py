"""Конфигурация учебного приложения HunterMart.

ВНИМАНИЕ. Это намеренно уязвимое учебное приложение. Оно предназначено ТОЛЬКО для
запуска в изолированной локальной среде. Приложение по умолчанию слушает loopback
(127.0.0.1) и не должно быть доступно из внешней сети.

Режим работы переключается переменной окружения HUNTERMART_MODE:
    - "vulnerable" (по умолчанию) — включены учебные уязвимости;
    - "secure"                    — включены исправленные реализации.

Это позволяет в каждой лаборатории сравнить уязвимый и защищённый варианты и
прогнать регрессионные тесты «проблема есть / проблемы нет».
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum


class Mode(StrEnum):
    VULNERABLE = "vulnerable"
    SECURE = "secure"


@dataclass(frozen=True)
class Settings:
    mode: Mode
    # Секрет для подписи сессионных токенов. В учебном приложении значение
    # детерминировано и НЕ является секретом реального уровня.
    session_secret: str = "huntermart-lab-not-a-real-secret"
    # Привязка по умолчанию — только loopback.
    host: str = "127.0.0.1"
    port: int = 8000

    @property
    def is_vulnerable(self) -> bool:
        return self.mode is Mode.VULNERABLE


def load_settings() -> Settings:
    raw = os.environ.get("HUNTERMART_MODE", Mode.VULNERABLE.value).strip().lower()
    try:
        mode = Mode(raw)
    except ValueError as exc:  # неизвестное значение — явная ошибка, а не тихий дефолт
        valid = ", ".join(m.value for m in Mode)
        raise SystemExit(
            f"HUNTERMART_MODE должен быть одним из: {valid}; получено: {raw!r}"
        ) from exc
    host = os.environ.get("HUNTERMART_HOST", "127.0.0.1")
    port = int(os.environ.get("HUNTERMART_PORT", "8000"))
    return Settings(mode=mode, host=host, port=port)

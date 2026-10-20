"""huntkit.safe_client — HTTP-клиент исследователя с обязательным allowlist.

Инструмент из главы 12. Это фундамент, на котором строятся остальные инструменты книги.

ПРИНЦИП БЕЗОПАСНОСТИ. Инструмент НИКОГДА не обращается к произвольной цели. Любой запрос
разрешён, только если хост (и порт) входят в явный allowlist, который задаёт сам исследователь.
Это техническая гарантия того, что автоматика не уйдёт за пределы разрешённого scope.

Дополнительно обеспечиваются:
    - таймауты на соединение и чтение;
    - ограничение частоты запросов (rate limit) к одному хосту;
    - ограничение числа редиректов (и запрет ухода на неразрешённый хост при редиректе);
    - журналирование каждого запроса;
    - корректное освобождение ресурсов (контекстный менеджер).

Статус проверки: проверено запуском (см. tests/code/test_safe_client.py).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Self
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("huntkit.safe_client")

DEFAULT_PORTS = {"http": 80, "https": 443}


class SafeClientError(Exception):
    """Базовое исключение инструмента."""


class DisallowedTargetError(SafeClientError):
    """Цель запроса не входит в allowlist."""


@dataclass(frozen=True)
class Target:
    """Нормализованная цель: схема, хост, порт."""

    scheme: str
    host: str
    port: int

    @classmethod
    def from_url(cls, url: str) -> Target:
        parts = urlsplit(url)
        if parts.scheme not in DEFAULT_PORTS:
            raise DisallowedTargetError(
                f"Недопустимая схема: {parts.scheme!r} (разрешены http/https)"
            )
        if not parts.hostname:
            raise DisallowedTargetError(f"В URL нет хоста: {url!r}")
        port = parts.port or DEFAULT_PORTS[parts.scheme]
        return cls(scheme=parts.scheme, host=parts.hostname.lower(), port=port)

    def key(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Allowlist:
    """Список разрешённых целей.

    Запись задаётся как "host" (любой порт, любая схема http/https) или "host:port".
    Пустой allowlist не разрешает ничего — это осознанное безопасное поведение по умолчанию.
    """

    entries: set[str] = field(default_factory=set)

    @classmethod
    def from_iterable(cls, items: list[str]) -> Allowlist:
        normalized: set[str] = set()
        for item in items:
            cleaned = item.strip().lower()
            if cleaned:
                normalized.add(cleaned)
        return cls(entries=normalized)

    def allows(self, target: Target) -> bool:
        return target.host in self.entries or target.key() in self.entries

    def check(self, url: str) -> Target:
        target = Target.from_url(url)
        if not self.allows(target):
            raise DisallowedTargetError(
                f"Цель {target.key()} не входит в allowlist {sorted(self.entries)!r}"
            )
        return target


class _RateLimiter:
    """Простое ограничение: не чаще одного запроса к хосту раз в min_interval секунд."""

    def __init__(self, min_interval: float, clock=time.monotonic, sleep=time.sleep) -> None:
        self.min_interval = max(0.0, min_interval)
        self._last: dict[str, float] = {}
        self._clock = clock
        self._sleep = sleep

    def wait(self, key: str) -> None:
        if self.min_interval == 0.0:
            return
        now = self._clock()
        last = self._last.get(key)
        if last is not None:
            elapsed = now - last
            if elapsed < self.min_interval:
                self._sleep(self.min_interval - elapsed)
        self._last[key] = self._clock()


class SafeHTTPClient:
    """HTTP-клиент, не выходящий за пределы allowlist."""

    def __init__(
        self,
        allowlist: Allowlist,
        *,
        timeout: float = 10.0,
        min_interval: float = 1.0,
        max_redirects: int = 5,
        user_agent: str = "huntkit-safe-client/0.1 (local lab use)",
        transport: httpx.BaseTransport | None = None,
        clock=time.monotonic,
        sleep=time.sleep,
    ) -> None:
        if not allowlist.entries:
            logger.warning("Allowlist пуст: ни одна цель не будет разрешена")
        self.allowlist = allowlist
        self.max_redirects = max_redirects
        self._limiter = _RateLimiter(min_interval, clock=clock, sleep=sleep)
        # follow_redirects=False: редиректы обрабатываем вручную, чтобы проверять каждый хоп.
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
            transport=transport,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(
        self, method: str, url: str, headers: Mapping[str, str] | None = None
    ) -> httpx.Response:
        """Выполняет запрос с ручной обработкой редиректов и проверкой каждого хопа.

        headers — дополнительные заголовки запроса (например, Authorization с токеном роли);
        объединяются с заголовками клиента по умолчанию.
        """
        current = url
        for hop in range(self.max_redirects + 1):
            target = self.allowlist.check(current)  # бросит DisallowedTargetError вне allowlist
            self._limiter.wait(target.key())
            logger.info("%s %s", method, current)
            response = self._client.request(method, current, headers=headers)
            if response.is_redirect and response.has_redirect_location:
                location = str(response.next_request.url) if response.next_request else ""
                if not location:
                    return response
                if hop == self.max_redirects:
                    raise SafeClientError(f"Превышено число редиректов ({self.max_redirects})")
                current = location
                continue
            return response
        raise SafeClientError("Недостижимое состояние обработки редиректов")

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> httpx.Response:
        return self.request("GET", url, headers=headers)

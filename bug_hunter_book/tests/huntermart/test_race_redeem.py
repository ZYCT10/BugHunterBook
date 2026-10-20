"""Регрессионные тесты лаборатории Race Condition (гл. 11).

Запускает настоящий локальный сервер (uvicorn) и шлёт параллельные запросы, чтобы
воспроизвести гонку. В режиме vulnerable одноразовый купон погашается больше одного
раза; в режиме secure — ровно один раз.
"""

import socket
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest
import uvicorn

from huntermart.app import create_app
from huntermart.config import Mode, Settings


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _LiveServer:
    def __init__(self, mode: Mode) -> None:
        self.port = _free_port()
        app = create_app(settings=Settings(mode=mode))
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> str:
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                break
            time.sleep(0.05)
        assert self.server.started, "сервер не запустился"
        return f"http://127.0.0.1:{self.port}"

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


def _redeem(base_url: str) -> bool:
    req = urllib.request.Request(f"{base_url}/api/redeem", method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        import json
        return bool(json.loads(resp.read())["granted"])


def _count_grants(mode: Mode, concurrency: int = 6) -> int:
    with _LiveServer(mode) as base_url, ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(lambda _: _redeem(base_url), range(concurrency)))
    return sum(1 for granted in results if granted)


@pytest.mark.slow
def test_race_allows_multiple_redemptions_in_vulnerable() -> None:
    # Из-за TOCTOU параллельные запросы погашают одноразовый купон более одного раза.
    grants = _count_grants(Mode.VULNERABLE)
    assert grants > 1, f"ожидали гонку (>1 погашение), получили {grants}"


@pytest.mark.slow
def test_atomic_allows_single_redemption_in_secure() -> None:
    # Под блокировкой купон погашается ровно один раз.
    grants = _count_grants(Mode.SECURE)
    assert grants == 1, f"ожидали ровно одно погашение, получили {grants}"

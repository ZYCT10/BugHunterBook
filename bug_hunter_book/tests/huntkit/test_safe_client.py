"""Тесты huntkit.safe_client (проект №1).

Используем httpx.MockTransport, чтобы не ходить в сеть: проверяем логику allowlist,
обработку редиректов и rate limit детерминированно и офлайн.
"""

from __future__ import annotations

import httpx
import pytest

from huntkit.safe_client import (
    Allowlist,
    DisallowedTargetError,
    SafeClientError,
    SafeHTTPClient,
    Target,
)


def _ok_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"ok {request.url}")

    return httpx.MockTransport(handler)


def _client(entries: list[str], **kw) -> SafeHTTPClient:
    kw.setdefault("transport", _ok_transport())
    kw.setdefault("min_interval", 0.0)
    return SafeHTTPClient(Allowlist.from_iterable(entries), **kw)


# --------------------------------------------------------------------- Target
def test_target_normalizes_scheme_host_port() -> None:
    t = Target.from_url("https://Example.TEST/path?q=1")
    assert (t.scheme, t.host, t.port) == ("https", "example.test", 443)
    assert t.key() == "example.test:443"


def test_target_rejects_non_http_scheme() -> None:
    with pytest.raises(DisallowedTargetError):
        Target.from_url("ftp://example.test/")


# ------------------------------------------------------------------ Allowlist
def test_empty_allowlist_blocks_everything() -> None:
    with _client([]) as c, pytest.raises(DisallowedTargetError):
        c.get("http://127.0.0.1:8000/health")


def test_host_entry_matches_any_port() -> None:
    with _client(["127.0.0.1"]) as c:
        assert c.get("http://127.0.0.1:8000/a").status_code == 200
        assert c.get("https://127.0.0.1/b").status_code == 200


def test_host_port_entry_is_specific() -> None:
    with _client(["127.0.0.1:8000"]) as c:
        assert c.get("http://127.0.0.1:8000/a").status_code == 200
        with pytest.raises(DisallowedTargetError):
            c.get("http://127.0.0.1:9000/a")


def test_disallowed_host_blocked() -> None:
    with _client(["127.0.0.1"]) as c, pytest.raises(DisallowedTargetError):
        c.get("http://example.test/")


# ------------------------------------------------------------------ redirects
def test_redirect_within_allowlist_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "http://127.0.0.1:8000/end"})
        return httpx.Response(200, text="arrived")

    c = SafeHTTPClient(
        Allowlist.from_iterable(["127.0.0.1"]),
        min_interval=0.0,
        transport=httpx.MockTransport(handler),
    )
    with c:
        resp = c.get("http://127.0.0.1:8000/start")
        assert resp.status_code == 200
        assert resp.text == "arrived"


def test_redirect_to_disallowed_host_blocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "127.0.0.1":
            return httpx.Response(302, headers={"Location": "http://evil.test/"})
        return httpx.Response(200, text="should not reach")

    c = SafeHTTPClient(
        Allowlist.from_iterable(["127.0.0.1"]),
        min_interval=0.0,
        transport=httpx.MockTransport(handler),
    )
    with c, pytest.raises(DisallowedTargetError):
        c.get("http://127.0.0.1:8000/start")


def test_redirect_loop_bounded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://127.0.0.1:8000/loop"})

    c = SafeHTTPClient(
        Allowlist.from_iterable(["127.0.0.1"]),
        min_interval=0.0,
        max_redirects=3,
        transport=httpx.MockTransport(handler),
    )
    with c, pytest.raises(SafeClientError):
        c.get("http://127.0.0.1:8000/loop")


# ------------------------------------------------------------------ rate limit
def test_rate_limiter_sleeps_between_requests_to_same_host() -> None:
    now = [0.0]
    slept: list[float] = []

    def fake_clock() -> float:
        return now[0]

    def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    c = SafeHTTPClient(
        Allowlist.from_iterable(["127.0.0.1"]),
        min_interval=2.0,
        transport=_ok_transport(),
        clock=fake_clock,
        sleep=fake_sleep,
    )
    with c:
        c.get("http://127.0.0.1:8000/a")  # первый запрос — без ожидания
        c.get("http://127.0.0.1:8000/b")  # второй — должен подождать ~2с
    assert slept and abs(slept[0] - 2.0) < 1e-9

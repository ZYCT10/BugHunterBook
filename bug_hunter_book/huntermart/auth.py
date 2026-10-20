"""Сессии HunterMart: простые подписанные токены (учебная реализация).

Токен имеет вид "<user_id>.<signature>", где signature = HMAC-SHA256(secret, user_id).
Это упрощение: нет срока жизни, ротации и привязки к устройству. Ограничения
разбираются в главе про управление сессиями; здесь цель — дать работающий вход,
на котором строятся лаборатории по авторизации.
"""

from __future__ import annotations

import hashlib
import hmac


def issue_token(secret: str, user_id: int) -> str:
    sig = _sign(secret, str(user_id))
    return f"{user_id}.{sig}"


def parse_token(secret: str, token: str) -> int | None:
    if not token or "." not in token:
        return None
    raw_id, _, sig = token.partition(".")
    expected = _sign(secret, raw_id)
    # Сравнение в постоянное время — чтобы не подсказывать атакующему по таймингу.
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        return int(raw_id)
    except ValueError:
        return None


def _sign(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()

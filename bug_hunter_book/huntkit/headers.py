"""huntkit.headers — разбор HTTP-заголовков и анализатор security headers.

Инструменты из главы 12 (парсер и анализатор защитных заголовков).
Инструмент работает с уже полученными ответами: его можно скормить как «сырой» блок
заголовков (например, скопированный из Burp), так и ответ huntkit.safe_client.

Анализатор НЕ ходит в сеть сам по себе — он только оценивает заголовки. Это осознанно:
получение ответа — ответственность safe_client с его allowlist.

Что проверяется (по рекомендациям OWASP Secure Headers Project; сверять формулировки на
https://owasp.org/www-project-secure-headers/, проверено 2026-10-19):
    - Strict-Transport-Security (HSTS)
    - Content-Security-Policy (CSP)
    - X-Content-Type-Options: nosniff
    - X-Frame-Options / CSP frame-ancestors (защита от clickjacking)
    - Referrer-Policy
    - наличие «лишних» раскрывающих заголовков (Server, X-Powered-By)

Статус проверки: проверено запуском (tests/code/test_headers.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"


@dataclass(frozen=True)
class Finding:
    header: str
    severity: Severity
    message: str


def parse_header_block(raw: str) -> dict[str, str]:
    """Разбирает «сырой» блок заголовков в словарь (имена — в нижнем регистре).

    Допускает необязательную стартовую строку статуса ("HTTP/1.1 200 OK").
    Повторяющиеся заголовки объединяются через ", " (как это делают многие клиенты).
    Складывание (folding) длинных строк не поддерживаем — оно устарело (RFC 7230).
    """
    headers: dict[str, str] = {}
    for i, line in enumerate(raw.splitlines()):
        line = line.rstrip("\r")
        if not line.strip():
            continue
        if i == 0 and line.upper().startswith("HTTP/"):
            continue  # строка статуса
        if ":" not in line:
            continue  # мусорная строка — пропускаем, не падаем
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if not name:
            continue
        headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return headers


@dataclass
class HeaderReport:
    headers: dict[str, str]
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        order = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2}
        return max((f.severity for f in self.findings), key=lambda s: order[s])


def analyze(headers: dict[str, str], *, is_https: bool = True) -> HeaderReport:
    """Оценивает набор заголовков и возвращает список находок.

    Параметр is_https влияет на HSTS: над http HSTS браузером игнорируется, поэтому
    его отсутствие над http отмечается как info, а над https — как предупреждение.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    report = HeaderReport(headers=dict(lower))
    add = report.findings.append

    # HSTS
    if "strict-transport-security" not in lower:
        if is_https:
            add(Finding("Strict-Transport-Security", Severity.MEDIUM,
                        "Нет HSTS: соединение можно понизить до http (SSL stripping)."))
        else:
            add(Finding("Strict-Transport-Security", Severity.INFO,
                        "HSTS неприменим над http; проверьте https-версию."))

    # CSP
    if "content-security-policy" not in lower:
        add(Finding("Content-Security-Policy", Severity.MEDIUM,
                    "Нет CSP: ослаблена защита от XSS и внедрения ресурсов."))

    # X-Content-Type-Options
    if lower.get("x-content-type-options", "").lower() != "nosniff":
        add(Finding("X-Content-Type-Options", Severity.LOW,
                    "Нет 'nosniff': браузер может угадывать тип и исполнять контент иначе."))

    # Clickjacking: X-Frame-Options ИЛИ CSP frame-ancestors
    csp = lower.get("content-security-policy", "").lower()
    if "x-frame-options" not in lower and "frame-ancestors" not in csp:
        add(Finding("X-Frame-Options", Severity.LOW,
                    "Нет защиты от clickjacking (X-Frame-Options или CSP frame-ancestors)."))

    # Referrer-Policy
    if "referrer-policy" not in lower:
        add(Finding("Referrer-Policy", Severity.INFO,
                    "Нет Referrer-Policy: возможна утечка URL в заголовке Referer."))

    # Раскрывающие заголовки
    for leaky in ("server", "x-powered-by"):
        if lower.get(leaky):
            add(Finding(leaky, Severity.INFO,
                        f"Заголовок '{leaky}: {lower[leaky]}' раскрывает технологию/версию."))

    return report

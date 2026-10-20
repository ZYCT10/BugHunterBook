"""huntkit.urltools — нормализация и дедупликация URL.

Проекты №8 из части VII. Разведка (глава 5) порождает горы URL с дубликатами,
отличающимися только регистром хоста, слэшами, порядком параметров или фрагментом.
Нормализация приводит их к каноническому виду, дедупликация убирает повторы.

Инструмент НЕ ходит в сеть — работает над уже собранными строками.

Статус проверки: проверено запуском (tests/code/test_urltools.py).
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize(url: str, *, drop_fragment: bool = True, sort_query: bool = True) -> str:
    """Приводит URL к каноническому виду.

    - схема и хост в нижний регистр;
    - порт по умолчанию (80/443) убирается;
    - путь без лишних повторных слэшей, пустой путь -> "/";
    - параметры запроса при sort_query сортируются (для стабильного сравнения);
    - фрагмент (#...) при drop_fragment отбрасывается (он не влияет на серверный ответ).
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()

    netloc = host
    if parts.port is not None and parts.port != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{parts.port}"
    # Пользовательская часть (user:pass@) сохраняется как есть, если была.
    if parts.username:
        cred = parts.username
        if parts.password:
            cred += f":{parts.password}"
        netloc = f"{cred}@{netloc}"

    # Нормализация пути: схлопываем повторные слэши, пустой путь -> "/"
    path = parts.path or "/"
    while "//" in path:
        path = path.replace("//", "/")
    if not path.startswith("/"):
        path = "/" + path

    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        if sort_query:
            pairs = sorted(pairs)
        query = urlencode(pairs)

    fragment = "" if drop_fragment else parts.fragment
    return urlunsplit((scheme, netloc, path, query, fragment))


def dedupe(urls: list[str], **normalize_kwargs: object) -> list[str]:
    """Возвращает уникальные URL в порядке первого появления (по нормализованной форме)."""
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        try:
            canon = normalize(url, **normalize_kwargs)  # type: ignore[arg-type]
        except ValueError:
            continue  # битый URL пропускаем, не падаем
        if canon not in seen:
            seen.add(canon)
            result.append(canon)
    return result


def same_target(a: str, b: str) -> bool:
    """True, если два URL указывают на один ресурс после нормализации."""
    return normalize(a) == normalize(b)

"""huntkit.robots — разбор robots.txt и sitemap.xml.

Проект №5 из части VII. robots.txt и sitemap нередко раскрывают пути, о которых иначе
не узнать (разведка, глава 5). Инструмент разбирает УЖЕ ПОЛУЧЕННЫЙ текст (получение —
ответственность safe_client с allowlist), выделяет директивы и ссылки на карты сайта.

ВАЖНО: `Disallow`-пути в robots.txt — это подсказка, что там есть, а НЕ разрешение туда
ходить. Исследователь всё равно действует только в пределах scope (глава 2).

Статус проверки: проверено запуском (tests/code/test_robots.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class RobotsInfo:
    # user-agent -> список путей
    disallow: dict[str, list[str]] = field(default_factory=dict)
    allow: dict[str, list[str]] = field(default_factory=dict)
    sitemaps: list[str] = field(default_factory=list)

    def interesting_paths(self) -> list[str]:
        """Уникальные пути из всех Disallow/Allow — кандидаты для изучения (в scope)."""
        paths: list[str] = []
        for mapping in (self.disallow, self.allow):
            for plist in mapping.values():
                paths.extend(plist)
        # уникальные, порядок первого появления
        seen: set[str] = set()
        result = []
        for p in paths:
            if p and p not in seen:
                seen.add(p)
                result.append(p)
        return result


def parse_robots(text: str) -> RobotsInfo:
    """Разбирает содержимое robots.txt."""
    info = RobotsInfo()
    current_agents: list[str] = ["*"]
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()  # убрать комментарии
        if not line or ":" not in line:
            continue
        field_name, _, value = line.partition(":")
        key = field_name.strip().lower()
        value = value.strip()
        if key == "user-agent":
            current_agents = [value.lower()]
        elif key == "disallow":
            for agent in current_agents:
                info.disallow.setdefault(agent, []).append(value)
        elif key == "allow":
            for agent in current_agents:
                info.allow.setdefault(agent, []).append(value)
        elif key == "sitemap":
            info.sitemaps.append(value)
    return info


_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)


def parse_sitemap(xml: str) -> list[str]:
    """Извлекает URL из <loc> элементов sitemap.xml (без полноценного XML-парсера,
    чтобы не тянуть риски обработки внешних сущностей — ср. XXE, глава 9)."""
    return [m.strip() for m in _LOC_RE.findall(xml) if m.strip()]

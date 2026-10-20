# BUG HUNTER — учебная лаборатория и инструменты

Код-компаньон к книге **BUG HUNTER. От первых шагов до профессионального Bug Bounty**.
Здесь лежит всё, что нужно, чтобы проходить практику из книги:

- **`huntermart/`** — учебное веб-приложение **HunterMart** (FastAPI + SQLite) с намеренными
  уязвимостями и их исправлениями;
- **`huntkit/`** — набор безопасных инструментов исследователя на Python из книги;
- **`tests/`** — регрессионные тесты, доказывающие «уязвимость есть / уязвимость закрыта».

Сами тексты глав, разборы заданий и теория — в книге.

---

## ⚠ Важно о безопасности

HunterMart **намеренно содержит уязвимости** и предназначен **только** для запуска в изолированной
локальной среде. По умолчанию слушает `127.0.0.1` (loopback). **Не разворачивайте его в сети**, не
наполняйте реальными данными и не используйте как основу для продакшена. Все данные синтетические;
«номера карт» — тестовые значения формата, не настоящие карты.

Практикуйтесь только на этой лаборатории, на собственных системах или в пределах явно разрешённого
scope программы Bug Bounty.

---

## Требования

- Python **3.12+**
- ОС: Linux, macOS или Windows (WSL)

## Установка

```bash
# 1. Клонируйте репозиторий и перейдите в него
git clone <URL-этого-репозитория> bug_hunter_book
cd bug_hunter_book

# 2. Создайте виртуальное окружение
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

# 3. Установите зависимости
pip install -r requirements.txt
```

## Запуск лаборатории

HunterMart работает в двух режимах, переключаемых переменной окружения `HUNTERMART_MODE`:

- `vulnerable` — включены учебные уязвимости (режим по умолчанию);
- `secure` — те же эндпоинты с исправлениями.

```bash
# Уязвимый режим
HUNTERMART_MODE=vulnerable uvicorn huntermart.app:app --host 127.0.0.1 --port 8000

# Исправленный режим
HUNTERMART_MODE=secure uvicorn huntermart.app:app --host 127.0.0.1 --port 8000
```

> Запускать из корня репозитория (где лежит папка `huntermart/`). Если Python не находит пакет, добавьте
> текущий каталог в путь: `PYTHONPATH=. uvicorn huntermart.app:app ...`.

### Проверка, что сервер работает

- Откройте в браузере <http://127.0.0.1:8000/health> — должно вернуться `{"status":"ok","mode":"vulnerable"}`.
- Документация API (Swagger UI): <http://127.0.0.1:8000/docs>.
- Или из терминала:

```bash
curl -s http://127.0.0.1:8000/health
```

### Пример: подтвердить уязвимость (IDOR)

```bash
# Вход и запрос ЧУЖОГО заказа (в режиме vulnerable вернётся чужой заказ — это IDOR)
TOKEN=$(curl -s http://127.0.0.1:8000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

curl -s http://127.0.0.1:8000/api/orders/1002 -H "Authorization: Bearer $TOKEN"
```

В режиме `secure` тот же запрос вернёт `404` — уязвимость закрыта.

Остановить сервер — **Ctrl+C**.

## Запуск тестов

```bash
pytest                 # все тесты
pytest tests/huntkit     # только тесты инструментов huntkit
pytest tests/huntermart  # только тесты лаборатории
pytest -m "not slow"   # без медленного теста гонки (он поднимает отдельный сервер)
```

Тесты проверяют, что в режиме `vulnerable` уязвимость воспроизводится, а в `secure` — закрыта.

## Проверка стиля и типов (необязательно)

```bash
ruff check .
mypy huntkit
```

---

## Эндпоинты лаборатории

| Эндпоинт | Метод | Лаборатория | Класс уязвимости | Глава книги |
|----------|-------|-------------|------------------|:-----------:|
| `/health` | GET | — | служебный | — |
| `/api/login` | POST | — | вход / токен сессии | 10 |
| `/api/orders/{id}` | GET | L-IDOR | IDOR / BOLA | 6 |
| `/api/products/search` | GET | L-SQLI | SQL Injection | 7 |
| `/search` | GET | L-XSS | Reflected XSS | 8 |
| `/api/comments`, `/comments` | POST/GET | L-STORED-XSS | Stored XSS | 8 |
| `/api/fetch` | GET | L-SSRF | SSRF (синтетич.) | 9 |
| `/api/files` | GET | L-PATHTRAVERSAL | Path Traversal (синтетич.) | 9 |
| `/api/profile` | POST | L-MASSASSIGN | Mass Assignment | 11 |
| `/api/redeem` | POST | L-RACE | Race Condition | 11 |
| `/go` | GET | L-OPENREDIR | Open Redirect | 3 |

### Учебные учётные записи

Пароль у каждого — `<логин>-pass` (например, `alice-pass`).

| Логин | Роль |
|-------|------|
| `alice`, `bob` | customer |
| `sly` | seller |
| `sam` | support |
| `root` | admin |

---

## Инструменты huntkit

Набор безопасных по построению инструментов исследователя (разбор — в части про автоматизацию книги):

| Модуль | Назначение |
|--------|-----------|
| `huntkit.safe_client` | HTTP-клиент с обязательным allowlist, таймаутами, лимитом частоты и контролем редиректов |
| `huntkit.headers` | разбор и анализ security-заголовков (по OWASP Secure Headers) |
| `huntkit.respdiff` | сравнение HTTP-ответов (для boolean-blind и матрицы ролей) |
| `huntkit.urltools` | нормализация и дедупликация URL |
| `huntkit.robots` | разбор `robots.txt` и `sitemap.xml` |
| `huntkit.openapi` | разбор спецификаций OpenAPI (JSON/YAML) |

Все модули работают офлайн (кроме `safe_client`, который единственный ходит в сеть — и только по
allowlist). Пример:

```python
from huntkit.safe_client import Allowlist, SafeHTTPClient

with SafeHTTPClient(Allowlist.from_iterable(["127.0.0.1:8000"])) as c:
    print(c.get("http://127.0.0.1:8000/health").status_code)   # 200
```

---

## Структура репозитория

```
bug_hunter_book/
├── README.md
├── requirements.txt
├── pyproject.toml
├── huntermart/        # учебная лаборатория (FastAPI + SQLite)
├── huntkit/           # инструменты исследователя
└── tests/
    ├── huntkit/       # тесты инструментов (6 модулей)
    └── huntermart/    # тесты лаборатории (9 классов уязвимостей)
```

## Лицензия

Условия распространения определяет автор книги. Добавьте файл `LICENSE` перед публикацией.

Материалы предназначены для легального обучения. Ответственность за применение знаний несёт пользователь.

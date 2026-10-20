"""HunterMart — учебное веб-приложение (FastAPI).

НАЗНАЧЕНИЕ. Полигон для лабораторных работ книги BUG HUNTER. Содержит НАМЕРЕННЫЕ
уязвимости, включаемые в режиме HUNTERMART_MODE=vulnerable, и их исправленные аналоги
в режиме HUNTERMART_MODE=secure.

БЕЗОПАСНОСТЬ. Запускать только локально (loopback). Все данные синтетические.
Не разворачивать в сети, не наполнять реальными данными, не использовать как основу
для продакшена.

Карта лабораторий (расширяется по ходу книги):
    L-16/17  IDOR на заказах:   GET /api/orders/{order_id}
    (следующие лаборатории добавляются отдельными модулями и роутерами)
"""

import html
import posixpath
import sqlite3
import threading
import time
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from . import auth, db
from .config import Settings, load_settings

# Хосты, на которые магазин считает допустимым уводить пользователя (режим secure).
_REDIRECT_ALLOWED_HOSTS = {"huntermart.example", "www.huntermart.example"}


def create_app(settings: Settings | None = None, db_path: str = ":memory:") -> FastAPI:
    settings = settings or load_settings()
    conn = db.connect(db_path)
    db.init_db(conn)

    app = FastAPI(title="HunterMart (учебный полигон)", version="0.1.0")
    app.state.settings = settings
    app.state.conn = conn

    def get_conn() -> sqlite3.Connection:
        return app.state.conn

    def current_user(
        conn: Annotated[sqlite3.Connection, Depends(get_conn)],
        authorization: Annotated[str | None, Header()] = None,
    ) -> sqlite3.Row:
        """Достаёт пользователя из токена сессии (заголовок Authorization: Bearer <token>)."""
        token = ""
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[len("bearer ") :].strip()
        user_id = auth.parse_token(settings.session_secret, token)
        if user_id is None:
            raise HTTPException(status_code=401, detail="Требуется аутентификация")
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Пользователь не найден")
        return row

    # ------------------------------------------------------------------ служебное
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": settings.mode.value}

    @app.post("/api/login")
    def login(
        payload: dict[str, str],
        response: Response,
        conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    ) -> dict[str, str]:
        username = payload.get("username", "")
        password = payload.get("password", "")
        row = db.verify_password(conn, username, password)
        if row is None:
            raise HTTPException(status_code=401, detail="Неверные учётные данные")
        token = auth.issue_token(settings.session_secret, int(row["id"]))
        return {"token": token, "role": row["role"], "user_id": str(row["id"])}

    # ------------------------------------------------- Лаборатория IDOR (глава 6)
    @app.get("/api/orders/{order_id}")
    def get_order(
        order_id: int,
        user: Annotated[sqlite3.Row, Depends(current_user)],
        conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    ) -> dict[str, object]:
        """Возвращает заказ по идентификатору.

        УЯЗВИМЫЙ режим: проверяется только факт аутентификации, но НЕ принадлежность
        заказа пользователю. Любой вошедший может прочитать чужой заказ, перебирая
        order_id (классический IDOR / BOLA).

        ЗАЩИЩЁННЫЙ режим: заказ отдаётся, только если он принадлежит пользователю,
        либо роль пользователя имеет законное основание (support/admin).
        """
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Заказ не найден")

        if not settings.is_vulnerable:
            is_owner = int(row["user_id"]) == int(user["id"])
            is_privileged = user["role"] in ("support", "admin")
            if not (is_owner or is_privileged):
                # 404, а не 403 — чтобы не подтверждать существование чужого заказа.
                raise HTTPException(status_code=404, detail="Заказ не найден")

        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "product_id": row["product_id"],
            "quantity": row["quantity"],
            "total_cents": row["total_cents"],
            "status": row["status"],
            "shipping_address": row["shipping_address"],
        }

    # ------------------------------------ Лаборатория Mass Assignment (гл. 11/46)
    @app.post("/api/profile")
    def update_profile(
        payload: dict[str, object],
        user: Annotated[sqlite3.Row, Depends(current_user)],
        conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    ) -> dict[str, object]:
        """Обновление профиля текущего пользователя.

        УЯЗВИМЫЙ режим: обновляются ВСЕ переданные поля, включая role — клиент может
        повысить себе привилегии (mass assignment / privilege escalation).

        ЗАЩИЩЁННЫЙ режим: обновляются только разрешённые поля (full_name, email);
        попытка задать role игнорируется (поле не входит в allowlist).
        """
        if settings.is_vulnerable:
            editable = [k for k in payload if k in ("full_name", "email", "role")]
        else:
            editable = [k for k in payload if k in ("full_name", "email")]
        for field in editable:
            conn.execute(
                f"UPDATE users SET {field} = ? WHERE id = ?",  # noqa: S608 (имя поля из allowlist выше)
                (str(payload[field]), int(user["id"])),
            )
        conn.commit()
        row = conn.execute("SELECT id, username, role, full_name, email FROM users WHERE id = ?",
                           (int(user["id"]),)).fetchone()
        return dict(row)

    # ------------------------------------------------ Лаборатория SSRF (гл. 9/29)
    # СИНТЕТИЧЕСКАЯ модель: «загрузка» не делает реальных сетевых запросов, а возвращает
    # содержимое из встроенной карты ресурсов. Это безопасно и воспроизводимо, и при этом
    # демонстрирует суть SSRF — доступ к внутренним ресурсам, недоступным снаружи.
    _INTERNAL_RESOURCES = {
        # «внутренние» адреса, которые НЕ должны быть достижимы для внешнего пользователя
        "http://metadata.internal/latest/token": "SYNTHETIC-INTERNAL-TOKEN-lab-not-real",
        "http://127.0.0.1:9000/admin": "<h1>Внутренняя админка (синтетическая)</h1>",
    }
    _FETCH_ALLOWED_HOSTS = {"images.huntermart.example", "huntermart.example"}

    @app.get("/api/fetch")
    def fetch_resource(url: str) -> dict[str, object]:
        """«Загружает» ресурс по URL (превью картинки товара и т. п.) — синтетически.

        УЯЗВИМЫЙ режим: берёт любой URL, включая внутренние адреса из _INTERNAL_RESOURCES
        (классический SSRF — доступ к ресурсам, закрытым от внешнего мира).

        ЗАЩИЩЁННЫЙ режим: разрешены только http/https и хосты из allowlist магазина;
        внутренние адреса и прочее отклоняются (400).
        """
        parts = urlsplit(url)
        if settings.is_vulnerable:
            if url in _INTERNAL_RESOURCES:
                return {"url": url, "status": "ok", "body": _INTERNAL_RESOURCES[url]}
            return {"url": url, "status": "ok", "body": f"[синтетическая загрузка {url}]"}

        if parts.scheme not in ("http", "https") or parts.hostname not in _FETCH_ALLOWED_HOSTS:
            raise HTTPException(status_code=400, detail="Недопустимая цель загрузки")
        return {"url": url, "status": "ok", "body": f"[синтетическая загрузка {url}]"}

    # ---------------------------------------- Лаборатория Reflected XSS (гл. 8/27)
    @app.get("/search", response_class=HTMLResponse)
    def search_page(q: str = "") -> HTMLResponse:
        """HTML-страница поиска, отражающая поисковый запрос q.

        УЯЗВИМЫЙ режим: значение q вставляется в HTML без кодирования — reflected XSS.
        ЗАЩИЩЁННЫЙ режим: q кодируется для HTML-контекста (html.escape), поэтому
        трактуется как текст, а не как разметка/скрипт.
        """
        if settings.is_vulnerable:
            reflected = q  # НЕБЕЗОПАСНО: сырой пользовательский ввод в HTML
        else:
            reflected = html.escape(q)  # кодирование вывода под HTML-контекст
        body = (
            "<!doctype html><html lang=ru><head><meta charset=utf-8>"
            "<title>Поиск HunterMart</title></head><body>"
            f"<h1>Результаты по запросу: {reflected}</h1>"
            "<p>Товары не найдены (учебная страница).</p>"
            "</body></html>"
        )
        return HTMLResponse(content=body)

    # ------------------------------------------------ Лаборатория SQLi (глава 7)
    @app.get("/api/products/search")
    def search_products(q: str) -> dict[str, object]:
        """Поиск товаров по подстроке названия.

        УЯЗВИМЫЙ режим: SQL собирается конкатенацией строк, поэтому значение q попадает
        прямо в текст запроса — классическая SQL-инъекция. Возможны обход фильтра
        ('%' OR '1'='1) и UNION-извлечение чужих таблиц (users).

        ЗАЩИЩЁННЫЙ режим: используется параметризованный запрос (привязка значения),
        поэтому q трактуется только как данные, а не как часть SQL.
        """
        if settings.is_vulnerable:
            # НЕБЕЗОПАСНО И НАМЕРЕННО: конкатенация пользовательского ввода в SQL.
            # noqa ниже — осознанное подавление: это учебная уязвимость лаборатории L-SQLI.
            sql = f"SELECT id, title, price_cents FROM products WHERE title LIKE '%{q}%'"  # noqa: S608
            try:
                rows = conn.execute(sql).fetchall()
            except sqlite3.Error as exc:
                # Ошибку БД возвращаем наружу — это и есть «error-based» утечка (см. главу 48).
                raise HTTPException(status_code=500, detail=f"Ошибка SQL: {exc}") from exc
        else:
            sql = "SELECT id, title, price_cents FROM products WHERE title LIKE ?"
            rows = conn.execute(sql, (f"%{q}%",)).fetchall()

        return {"query": q, "results": [dict(r) for r in rows]}

    # ------------------------------------------ Лаборатория Open Redirect (гл. 7/34)
    @app.get("/go")
    def go(next: str) -> RedirectResponse:
        """Редирект «вернуться после действия» по параметру next.

        УЯЗВИМЫЙ режим: редирект на любой адрес из next (классический Open Redirect) —
        удобно для фишинга: ссылка на домен HunterMart уводит на внешний сайт.

        ЗАЩИЩЁННЫЙ режим: разрешены только локальные пути ("/...") и явный allowlist
        хостов магазина; всё остальное отклоняется (400).
        """
        if settings.is_vulnerable:
            return RedirectResponse(url=next, status_code=302)

        # Безопасная проверка цели редиректа.
        if next.startswith("/") and not next.startswith("//"):
            # Относительный путь в пределах того же origin — безопасно.
            return RedirectResponse(url=next, status_code=302)
        parts = urlsplit(next)
        if parts.scheme in ("http", "https") and parts.hostname in _REDIRECT_ALLOWED_HOSTS:
            return RedirectResponse(url=next, status_code=302)
        raise HTTPException(status_code=400, detail="Недопустимая цель редиректа")

    # -------------------------------------------- Лаборатория Stored XSS (гл. 8)
    @app.post("/api/comments")
    def add_comment(payload: dict[str, str],
                    conn: Annotated[sqlite3.Connection, Depends(get_conn)]) -> dict[str, object]:
        """Сохраняет отзыв (author, body). Тело сохраняется как есть."""
        author = payload.get("author", "аноним")
        body = payload.get("body", "")
        cur = conn.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        conn.commit()
        return {"id": cur.lastrowid, "author": author}

    @app.get("/comments", response_class=HTMLResponse)
    def list_comments(conn: Annotated[sqlite3.Connection, Depends(get_conn)]) -> HTMLResponse:
        """HTML-страница со списком отзывов.

        УЯЗВИМЫЙ режим: тело отзыва вставляется в HTML без кодирования — stored XSS
        (срабатывает у каждого, кто открыл страницу).
        ЗАЩИЩЁННЫЙ режим: тело кодируется (html.escape) при выводе.
        """
        rows = conn.execute("SELECT author, body FROM comments ORDER BY id").fetchall()
        items = []
        for r in rows:
            author = html.escape(r["author"])  # автор кодируется всегда
            body = r["body"] if settings.is_vulnerable else html.escape(r["body"])
            items.append(f"<li><b>{author}</b>: {body}</li>")
        page = (
            "<!doctype html><html lang=ru><head><meta charset=utf-8>"
            "<title>Отзывы HunterMart</title></head><body><h1>Отзывы</h1>"
            f"<ul>{''.join(items)}</ul></body></html>"
        )
        return HTMLResponse(content=page)

    # ------------------------------------------ Лаборатория Path Traversal (гл. 9)
    # СИНТЕТИЧЕСКОЕ хранилище файлов (без реальной файловой системы). «Публичные»
    # файлы лежат в base; «секретный» — вне base. Traversal (../) выводит за base.
    _FILE_BASE = "/lab/public/"
    _FILES = {
        "/lab/public/logo.txt": "PUBLIC LOGO (synthetic)",
        "/lab/public/readme.txt": "Публичный файл магазина (synthetic)",
        "/lab/secret/flag.txt": "SECRET-FLAG-synthetic-not-real",
    }

    @app.get("/api/files")
    def read_file(name: str) -> dict[str, object]:
        """«Читает» файл из публичного каталога по имени (синтетически).

        УЯЗВИМЫЙ режим: путь (base + name) нормализуется, но не проверяется — ../ выводит
        за пределы публичного каталога к секретному файлу (path traversal).
        ЗАЩИЩЁННЫЙ режим: после нормализации проверяется, что путь остался внутри base.
        """
        resolved = posixpath.normpath(_FILE_BASE + name)
        if not settings.is_vulnerable and not resolved.startswith(_FILE_BASE):
            raise HTTPException(status_code=403, detail="Выход за пределы каталога запрещён")
        if resolved not in _FILES:
            raise HTTPException(status_code=404, detail="Файл не найден")
        return {"name": name, "resolved": resolved, "content": _FILES[resolved]}

    # -------------------------------------------- Лаборатория Race Condition (гл. 11)
    # Одноразовый купон: допускается ровно одно успешное погашение.
    app.state.redeem = {"redeemed": 0}
    app.state.redeem_lock = threading.Lock()
    _REDEEM_LIMIT = 1

    @app.post("/api/redeem")
    def redeem_coupon() -> dict[str, object]:
        """Погашение одноразового купона.

        УЯЗВИМЫЙ режим: проверка и списание не атомарны (TOCTOU). Искусственная задержка
        расширяет окно гонки, чтобы эффект был воспроизводимым; в реальных системах окно
        есть и без задержки. Параллельные запросы погашают купон несколько раз.
        ЗАЩИЩЁННЫЙ режим: проверка и списание выполняются атомарно под блокировкой.
        """
        state = app.state.redeem
        if settings.is_vulnerable:
            current = state["redeemed"]          # ЧТЕНИЕ
            time.sleep(0.05)                     # окно гонки
            if current < _REDEEM_LIMIT:
                state["redeemed"] = current + 1  # ЗАПИСЬ (не атомарно с проверкой)
                return {"granted": True, "redeemed": state["redeemed"]}
            return {"granted": False, "redeemed": state["redeemed"]}
        with app.state.redeem_lock:              # атомарно
            if state["redeemed"] < _REDEEM_LIMIT:
                state["redeemed"] += 1
                return {"granted": True, "redeemed": state["redeemed"]}
            return {"granted": False, "redeemed": state["redeemed"]}

    return app


# Экземпляр по умолчанию для `uvicorn huntermart.app:app`.
app = create_app()

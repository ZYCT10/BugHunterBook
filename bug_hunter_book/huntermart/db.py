"""Хранилище данных HunterMart на SQLite.

Используется файловая или in-memory база. Все данные синтетические: имена, адреса,
номера заказов и «платёжные» данные выдуманы и не относятся к реальным людям.
Номера карт — это published-тестовые значения формата, не настоящие карты.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('customer','seller','support','admin')),
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    email         TEXT NOT NULL
);

CREATE TABLE products (
    id       INTEGER PRIMARY KEY,
    seller_id INTEGER NOT NULL REFERENCES users(id),
    title    TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    stock    INTEGER NOT NULL
);

CREATE TABLE orders (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    quantity   INTEGER NOT NULL,
    total_cents INTEGER NOT NULL,
    status     TEXT NOT NULL,
    -- Намеренно чувствительное поле для демонстрации IDOR: адрес доставки.
    shipping_address TEXT NOT NULL
);

CREATE TABLE payments (
    id        INTEGER PRIMARY KEY,
    order_id  INTEGER NOT NULL REFERENCES orders(id),
    -- Только последние 4 цифры тестового номера; полный PAN не хранится.
    card_last4 TEXT NOT NULL,
    amount_cents INTEGER NOT NULL
);

CREATE TABLE comments (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    author  TEXT NOT NULL,
    -- Пользовательский текст отзыва: источник stored XSS в уязвимом режиме.
    body    TEXT NOT NULL
);
"""


def _hash_password(password: str) -> str:
    """Учебное хеширование пароля.

    В реальном приложении используют медленные адаптивные функции (bcrypt/argon2) с солью.
    Здесь — SHA-256 с фиксированной учебной солью, чтобы не тянуть внешние зависимости;
    в главе про хеширование паролей это ограничение разбирается отдельно.
    """
    salt = "huntermart-lab-salt"
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


# Синтетические учётные записи. Пароли простые — это локальная лаборатория.
_SEED_USERS = [
    # id, username, role, password, full_name, email
    (1, "alice", "customer", "alice-pass", "Алиса Покупатель", "alice@example.test"),
    (2, "bob", "customer", "bob-pass", "Боб Покупатель", "bob@example.test"),
    (3, "sly", "seller", "sly-pass", "Света Продавец", "sly@example.test"),
    (4, "sam", "support", "sam-pass", "Сэм Поддержка", "sam@example.test"),
    (5, "root", "admin", "root-pass", "Администратор HunterMart", "admin@example.test"),
]

_SEED_PRODUCTS = [
    # id, seller_id, title, price_cents, stock
    (1, 3, "Механическая клавиатура HunterMart", 7990, 50),
    (2, 3, "USB-микрофон HunterMart", 5490, 20),
    (3, 3, "Веб-камера HunterMart HD", 3990, 0),
]

_SEED_ORDERS = [
    # id, user_id, product_id, quantity, total_cents, status, shipping_address
    (1001, 1, 1, 1, 7990, "paid", "г. Пример, ул. Алисы, д. 1, кв. 10"),
    (1002, 2, 2, 2, 10980, "paid", "г. Пример, пр. Боба, д. 7, кв. 3"),
    (1003, 1, 3, 1, 3990, "pending", "г. Пример, ул. Алисы, д. 1, кв. 10"),
]

_SEED_PAYMENTS = [
    # id, order_id, card_last4, amount_cents
    (1, 1001, "4242", 7990),
    (2, 1002, "4111", 10980),
]


def connect(db_path: str | Path = ":memory:") -> sqlite3.Connection:
    # check_same_thread=False: учебный сервер использует одно общее соединение,
    # а ASGI-сервер и тестовый клиент обслуживают запросы в разных потоках.
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT INTO users (id, username, role, password_hash, full_name, email)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [
            (uid, uname, role, _hash_password(pw), fname, email)
            for (uid, uname, role, pw, fname, email) in _SEED_USERS
        ],
    )
    conn.executemany(
        "INSERT INTO products (id, seller_id, title, price_cents, stock) VALUES (?, ?, ?, ?, ?)",
        _SEED_PRODUCTS,
    )
    conn.executemany(
        "INSERT INTO orders"
        " (id, user_id, product_id, quantity, total_cents, status, shipping_address)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        _SEED_ORDERS,
    )
    conn.executemany(
        "INSERT INTO payments (id, order_id, card_last4, amount_cents) VALUES (?, ?, ?, ?)",
        _SEED_PAYMENTS,
    )
    conn.commit()


def verify_password(conn: sqlite3.Connection, username: str, password: str) -> sqlite3.Row | None:
    row = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?",
        (username, _hash_password(password)),
    ).fetchone()
    return row

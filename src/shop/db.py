"""Учебная база данных SQLite для стенда «ENU Lab Shop».

Создаётся заново при каждом запуске, содержит только вымышленные данные.
"""
import hashlib
import os
import sqlite3

DB_PATH = os.environ.get("SHOP_DB", os.path.join(os.path.dirname(__file__), "shop.db"))

USERS = [
    # id, username, password, role, full_name, email, phone, card_last4
    (1, "admin", "Adm1n!Secure2026", "admin", "Администратор системы", "admin@lab.local", "+7 700 000 00 01", "4242"),
    (2, "aliya", "Aliya#2026", "user", "Алия Серикова", "aliya@lab.local", "+7 700 000 00 02", "1111"),
    (3, "timur", "Timur#2026", "user", "Тимур Ахметов", "timur@lab.local", "+7 700 000 00 03", "2222"),
    (4, "dana", "Dana#2026", "user", "Дана Касымова", "dana@lab.local", "+7 700 000 00 04", "3333"),
]

PRODUCTS = [
    (1, "Ноутбук Lab-14", "Учебный ноутбук", 450000),
    (2, "Мышь беспроводная", "Оптическая мышь", 7500),
    (3, "Клавиатура механическая", "Клавиатура для разработчика", 32000),
    (4, "USB-токен", "Аппаратный ключ для 2FA", 18000),
    (5, "Монитор 27\"", "IPS-монитор", 120000),
]

ORDERS = [
    (1, 2, "Ноутбук Lab-14", 450000, "Астана, ул. Сатпаева, 2"),
    (2, 3, "USB-токен", 18000, "Астана, пр. Мангилик Ел, 55"),
    (3, 4, "Монитор 27\"", 120000, "Алматы, ул. Абая, 10"),
    (4, 2, "Мышь беспроводная", 7500, "Астана, ул. Сатпаева, 2"),
]


def hash_password(password: str, salt: bytes | None = None) -> str:
    """PBKDF2-HMAC-SHA256, 200 000 итераций, соль 16 байт."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    import hmac

    salt_hex, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, bytes.fromhex(salt_hex)), stored)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(hasher=hash_password) -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
                            role TEXT, full_name TEXT, email TEXT, phone TEXT, card_last4 TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT, price INTEGER);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total INTEGER,
                             address TEXT);
        """
    )
    conn.executemany(
        "INSERT INTO users VALUES (?,?,?,?,?,?,?,?)",
        [(u[0], u[1], hasher(u[2]), *u[3:]) for u in USERS],
    )
    conn.executemany("INSERT INTO products VALUES (?,?,?,?)", PRODUCTS)
    conn.executemany("INSERT INTO orders VALUES (?,?,?,?,?)", ORDERS)
    conn.commit()
    conn.close()

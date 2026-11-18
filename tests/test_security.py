"""Регрессионные security-тесты: каждая проверка соответствует уязвимости,
найденной SAST/ручным анализом. На уязвимой версии тесты падают, на исправленной — проходят.
"""
import os
import tempfile

import pytest

os.environ.setdefault("SHOP_SECRET_KEY", "test-only-secret-key-with-at-least-32-chars!")
os.environ["SHOP_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from src.shop import app as shop  # noqa: E402
from src.shop import db  # noqa: E402

PASSWORDS = {u[1]: u[2] for u in db.USERS}


@pytest.fixture()
def client():
    shop.init_app_db() if hasattr(shop, "init_app_db") else db.init_db(hasher=shop.md5)
    shop.app.config["TESTING"] = True
    return shop.app.test_client()


def login(client, username, password=None):
    r = client.post("/api/login", json={"username": username, "password": password or PASSWORDS[username]})
    assert r.status_code == 200, r.get_json()
    return {"Authorization": "Bearer " + r.get_json()["token"]}


# ---------- A03: Injection ----------
def test_login_sql_injection_bypass_is_rejected(client):
    r = client.post("/api/login", json={"username": "admin' --", "password": "x"})
    assert r.status_code == 401


def test_login_sql_injection_or_true_is_rejected(client):
    r = client.post("/api/login", json={"username": "' OR 1=1 --", "password": "x"})
    assert r.status_code == 401


def test_search_union_injection_does_not_leak_users(client):
    r = client.get("/api/products", query_string={"q": "zzz' UNION SELECT id, username, password, role FROM users --"})
    body = r.get_data(as_text=True)
    assert "admin" not in body and "aliya" not in body


def test_search_works_normally(client):
    r = client.get("/api/products", query_string={"q": "USB"})
    assert r.status_code == 200 and len(r.get_json()) == 1


def test_ping_command_injection_is_blocked(client):
    r = client.get("/api/tools/ping", query_string={"host": "127.0.0.1; id"})
    assert r.status_code in (400, 404)
    assert "uid=" not in r.get_data(as_text=True)


# ---------- A01: Broken Access Control ----------
def test_user_can_read_own_profile(client):
    h = login(client, "aliya")
    r = client.get("/api/users/2", headers=h)
    assert r.status_code == 200 and r.get_json()["username"] == "aliya"


def test_idor_foreign_profile_is_forbidden(client):
    h = login(client, "aliya")
    assert client.get("/api/users/3", headers=h).status_code == 403


def test_idor_foreign_order_is_forbidden(client):
    h = login(client, "aliya")
    assert client.get("/api/orders/2", headers=h).status_code == 403


def test_admin_endpoint_forbidden_for_user(client):
    h = login(client, "timur")
    assert client.get("/api/admin/users", headers=h).status_code == 403


def test_admin_endpoint_allowed_for_admin_without_password_hashes(client):
    h = login(client, "admin")
    r = client.get("/api/admin/users", headers=h)
    assert r.status_code == 200
    assert all("password" not in u for u in r.get_json())


def test_anonymous_is_unauthorized(client):
    assert client.get("/api/users/1").status_code == 401


# ---------- A08 / A05 / A02 ----------
def test_yaml_import_rejects_python_objects(client):
    payload = b'!!python/object/apply:os.system ["echo pwned"]'
    r = client.post("/api/import", data=payload, headers=login(client, "admin"))
    assert r.status_code == 400


def test_errors_do_not_leak_stack_trace(client):
    r = client.post("/api/login", data="not-json", headers={"Content-Type": "application/json"})
    assert "Traceback" not in r.get_data(as_text=True)


def test_security_headers_present(client):
    r = client.get("/api/products")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert "default-src" in r.headers.get("Content-Security-Policy", "")
    assert r.headers.get("X-Frame-Options") == "DENY"


def test_passwords_are_not_unsalted_md5(client):
    row = db.get_conn().execute("SELECT password FROM users WHERE username='admin'").fetchone()
    assert len(row["password"]) != 32 and "$" in row["password"]

"""ENU Lab Shop — учебный REST API (ИСПРАВЛЕННАЯ ВЕРСИЯ).

Изменения относительно v1-vulnerable (по результатам SAST/SCA и security-тестов):
  * A03 — все SQL-запросы параметризованы; ping удалён из API (вызов ОС не нужен бизнес-логике);
  * A01 — проверка владельца объекта (IDOR) и ролевая модель (RBAC) на стороне сервера;
  * A02 — секрет подписи берётся из окружения, пароли — PBKDF2-HMAC-SHA256 с солью;
  * A08 — yaml.safe_load вместо yaml.load;
  * A05 — без debug, ошибки без трассировки, заголовки безопасности.
"""
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
import yaml
from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from . import db

app = Flask(__name__)
log = logging.getLogger("shop")


def load_secret() -> str:
    secret = os.environ.get("SHOP_SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("SHOP_SECRET_KEY не задан или короче 32 символов")
    return secret


SECRET_KEY = load_secret()
TOKEN_TTL = timedelta(minutes=30)


def init_app_db() -> None:
    db.init_db(hasher=db.hash_password)


# ------------------------------------------------------------------ аутентификация и RBAC
def issue_token(row) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": str(row["id"]), "role": row["role"], "iat": now, "exp": now + TOKEN_TTL}
    return jwt.encode(claims, SECRET_KEY, algorithm="HS256")


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="unauthorized"), 401
        try:
            claims = jwt.decode(header[7:], SECRET_KEY, algorithms=["HS256"], options={"require": ["exp", "sub"]})
        except jwt.PyJWTError:
            return jsonify(error="unauthorized"), 401
        # роль берётся из БД, а не из токена: смена/отзыв роли действует сразу
        row = db.get_conn().execute("SELECT id, role FROM users WHERE id = ?", (int(claims["sub"]),)).fetchone()
        if row is None:
            return jsonify(error="unauthorized"), 401
        g.user_id, g.role = row["id"], row["role"]
        return f(*args, **kwargs)

    return wrapper


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        @require_auth
        def wrapper(*args, **kwargs):
            if g.role not in roles:
                log.warning("access denied: user=%s role=%s path=%s", g.user_id, g.role, request.path)
                return jsonify(error="forbidden"), 403
            return f(*args, **kwargs)

        return wrapper

    return decorator


def can_access(owner_id: int) -> bool:
    """ABAC-правило: объект доступен владельцу или администратору."""
    return owner_id == g.user_id or g.role == "admin"


# ------------------------------------------------------------------ маршруты
@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username, password = str(data.get("username", "")), str(data.get("password", ""))
    row = db.get_conn().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not db.verify_password(password, row["password"]):
        return jsonify(error="invalid credentials"), 401
    return jsonify(token=issue_token(row), user=row["username"], role=row["role"])


@app.get("/api/products")
def products():
    q = request.args.get("q", "")[:100]
    rows = db.get_conn().execute(
        "SELECT id, name, description, price FROM products WHERE name LIKE ?", (f"%{q}%",)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/users/<int:user_id>")
@require_auth
def user_profile(user_id):
    if not can_access(user_id):
        return jsonify(error="forbidden"), 403
    row = db.get_conn().execute(
        "SELECT id, username, full_name, email, phone, card_last4, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return jsonify(dict(row)) if row else (jsonify(error="not found"), 404)


@app.get("/api/orders/<int:order_id>")
@require_auth
def order(order_id):
    row = db.get_conn().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    # одинаковый ответ 403 для «чужого» и проверка до раскрытия данных
    if row is None:
        return jsonify(error="not found"), 404
    if not can_access(row["user_id"]):
        return jsonify(error="forbidden"), 403
    return jsonify(dict(row))


@app.get("/api/admin/users")
@require_role("admin")
def admin_users():
    rows = db.get_conn().execute("SELECT id, username, role, email FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/import")
@require_role("admin")
def import_products():
    try:
        data = yaml.safe_load(request.get_data(as_text=True))
    except yaml.YAMLError:
        return jsonify(error="invalid yaml"), 400
    if not isinstance(data, list):
        return jsonify(error="expected a list"), 400
    return jsonify(imported=len(data))


# ------------------------------------------------------------------ ошибки и заголовки
@app.errorhandler(HTTPException)
def on_http_error(exc):
    return jsonify(error=exc.name), exc.code


@app.errorhandler(Exception)
def on_error(exc):
    log.exception("unhandled error")          # подробности — только в журнал сервера
    return jsonify(error="internal server error"), 500


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def main():
    init_app_db()
    host = os.environ.get("SHOP_HOST", "127.0.0.1")
    app.run(host=host, port=int(os.environ.get("SHOP_PORT", "5000")), debug=False)


if __name__ == "__main__":
    main()

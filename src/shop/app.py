"""ENU Lab Shop — учебный REST API (ВЕРСИЯ С УЯЗВИМОСТЯМИ).

Эта редакция файла намеренно содержит ошибки из OWASP Top 10, чтобы
продемонстрировать работу SAST/SCA в конвейере CI/CD. Не запускать вне стенда.
"""
import hashlib
import subprocess
import traceback

import jwt
import yaml
from flask import Flask, jsonify, request

from . import db

app = Flask(__name__)

# A02/A07: секрет подписи токенов зашит в исходный код
SECRET_KEY = "k8Hq2vN7pX4rT9wLm3ZsB6yFc1JdG5eA"
app.config["SECRET_KEY"] = SECRET_KEY


def md5(password: str) -> str:
    # A02: устаревшая хеш-функция без соли
    return hashlib.md5(password.encode()).hexdigest()


def current_user():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        return None


@app.post("/api/login")
def login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")
    conn = db.get_conn()
    # A03: SQL-инъекция — пользовательский ввод подставляется в текст запроса
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, md5(password))
    row = conn.execute(query).fetchone()
    if row is None:
        return jsonify(error="invalid credentials"), 401
    token = jwt.encode({"sub": row["id"], "username": row["username"], "role": row["role"]},
                       SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):  # PyJWT 1.x возвращает bytes
        token = token.decode()
    return jsonify(token=token, user=row["username"], role=row["role"])


@app.get("/api/products")
def products():
    q = request.args.get("q", "")
    conn = db.get_conn()
    # A03: SQL-инъекция в поиске (f-строка)
    rows = conn.execute(f"SELECT id, name, description, price FROM products WHERE name LIKE '%{q}%'").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/users/<int:user_id>")
def user_profile(user_id):
    if current_user() is None:
        return jsonify(error="unauthorized"), 401
    # A01: IDOR — нет проверки, что профиль принадлежит текущему пользователю
    row = db.get_conn().execute(
        "SELECT id, username, full_name, email, phone, card_last4, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return jsonify(dict(row)) if row else (jsonify(error="not found"), 404)


@app.get("/api/orders/<int:order_id>")
def order(order_id):
    if current_user() is None:
        return jsonify(error="unauthorized"), 401
    # A01: IDOR — чужой заказ с адресом доставки доступен любому пользователю
    row = db.get_conn().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return jsonify(dict(row)) if row else (jsonify(error="not found"), 404)


@app.get("/api/admin/users")
def admin_users():
    # A01: вертикальное повышение привилегий — роль не проверяется
    if current_user() is None:
        return jsonify(error="unauthorized"), 401
    rows = db.get_conn().execute("SELECT id, username, role, email, password FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/tools/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # A03: внедрение команд ОС через shell=True
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)
    return jsonify(output=out.stdout)


@app.post("/api/import")
def import_products():
    # A08: небезопасная десериализация YAML (yaml.load без SafeLoader)
    data = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(imported=len(data or []))


@app.errorhandler(Exception)
def on_error(exc):
    # A05: утечка трассировки стека клиенту
    return jsonify(error=str(exc), trace=traceback.format_exc()), 500


def main():
    db.init_db(hasher=md5)
    # A05: отладочный режим и прослушивание всех интерфейсов
    app.run(host="0.0.0.0", port=5000, debug=True)


if __name__ == "__main__":
    main()

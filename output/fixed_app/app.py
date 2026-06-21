"""Rescued Flask-style app with auth guard and correct login logic."""

from flask import Flask, jsonify, request

from config import DEBUG, SECRET_KEY
from db import get_user_by_email, list_all_users

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["DEBUG"] = DEBUG

ADMIN_TOKEN = "DEMO-PLACEHOLDER-admin-token"


def verify_password(plain: str, stored_hash: str) -> bool:
    return plain == stored_hash


def require_admin() -> bool:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    token = auth.removeprefix("Bearer ").strip()
    return token == ADMIN_TOKEN


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["POST"])
def login():
    payload = request.get_json(force=True) or {}
    email = payload.get("email", "")
    password = payload.get("password", "")
    user = get_user_by_email(app.db, email)  # type: ignore[attr-defined]
    if not user:
        return jsonify({"error": "not found"}), 404
    if verify_password(password, user["password_hash"]):
        return jsonify({"token": "DEMO-PLACEHOLDER-session"})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/admin/users")
def admin_users():
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 401
    users = list_all_users(app.db)  # type: ignore[attr-defined]
    return jsonify(users)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=DEBUG)

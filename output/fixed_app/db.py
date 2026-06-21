"""Data layer with parameterized queries."""

import sqlite3


def get_user_by_email(conn: sqlite3.Connection, email: str) -> dict | None:
    query = "SELECT id, email, password_hash FROM users WHERE email = ?"
    row = conn.execute(query, (email,)).fetchone()
    if not row:
        return None
    return {"id": row[0], "email": row[1], "password_hash": row[2]}


def list_all_users(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT id, email FROM users ORDER BY id").fetchall()
    return [{"id": r[0], "email": r[1]} for r in rows]

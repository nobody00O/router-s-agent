"""
webapp/auth.py

Handles signup and login. Uses werkzeug's password hashing (the same library
Flask itself is built on) -- NEVER store plain-text passwords, this is one
of the most important lessons to get right even in a 1st-year project.

Each user also gets a random API key generated at signup -- this is what
their local scanning agent uses to authenticate when it POSTs scan results
up to the website (see agent/local_agent.py).
"""
from __future__ import annotations
import secrets
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

from webapp.db import get_db


class AuthError(Exception):
    pass


def signup(email: str, password: str, db_path: str = None) -> dict:
    if not email or "@" not in email:
        raise AuthError("Please enter a valid email address.")
    if len(password) < 8:
        raise AuthError("Password must be at least 8 characters.")

    password_hash = generate_password_hash(password)
    api_key = secrets.token_hex(24)
    now = datetime.now(timezone.utc).isoformat()

    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise AuthError("An account with that email already exists.")
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, api_key, created_at) VALUES (?, ?, ?, ?)",
            (email, password_hash, api_key, now),
        )
        user_id = cur.lastrowid

    return {"id": user_id, "email": email, "api_key": api_key}


def login(email: str, password: str, db_path: str = None) -> dict:
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if row is None or not check_password_hash(row["password_hash"], password):
        raise AuthError("Incorrect email or password.")

    return {"id": row["id"], "email": row["email"], "api_key": row["api_key"]}


def get_user_by_api_key(api_key: str, db_path: str = None) -> dict | None:
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        row = conn.execute("SELECT * FROM users WHERE api_key = ?", (api_key,)).fetchone()
    return {"id": row["id"], "email": row["email"]} if row else None


def regenerate_api_key(user_id: int, db_path: str = None) -> str:
    """Issues a brand new API key for a user and invalidates the old one
    immediately -- use this if a key has been exposed (pasted somewhere
    public, committed to a repo, etc). Any local_agent.py still using the
    old key will start getting 401s until it's updated with the new one."""
    new_key = secrets.token_hex(24)
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        conn.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_key, user_id))
    return new_key


if __name__ == "__main__":
    import os
    from webapp.db import init_db

    test_path = "test_auth.db"
    if os.path.exists(test_path):
        os.remove(test_path)
    init_db(test_path)

    user = signup("student@example.edu", "correct-horse-battery", db_path=test_path)
    print("Signed up:", user["email"], "| API key issued:", bool(user["api_key"]))
    assert user["api_key"]

    try:
        signup("student@example.edu", "another-password123", db_path=test_path)
        raise SystemExit("FAIL: duplicate signup should have been rejected")
    except AuthError as e:
        print("Correctly rejected duplicate signup:", e)

    logged_in = login("student@example.edu", "correct-horse-battery", db_path=test_path)
    print("Login OK:", logged_in["email"])
    assert logged_in["id"] == user["id"]

    try:
        login("student@example.edu", "wrong-password", db_path=test_path)
        raise SystemExit("FAIL: wrong password should have been rejected")
    except AuthError as e:
        print("Correctly rejected wrong password:", e)

    found = get_user_by_api_key(user["api_key"], db_path=test_path)
    print("API key lookup OK:", found["email"])
    assert found["id"] == user["id"]

    os.remove(test_path)
    print("auth.py self-test: PASS")

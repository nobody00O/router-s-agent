"""
webapp/auth.py

Handles signup and login. Uses werkzeug's password hashing (the same library
Flask itself is built on) -- NEVER store plain-text passwords, this is one
of the most important lessons to get right even in a 1st-year project.

Each user also gets a random API key generated at signup -- this is what
their local scanning agent uses to authenticate when it POSTs scan results
up to the website (see agent/local_agent.py).

NOTE ON DISPOSABLE EMAILS: email verification alone (does this address
receive mail?) is a DIFFERENT question from "is this a throwaway address?"
A temp-mail address can receive and click a verification link just fine --
that's the whole point of temp-mail services. The only real defense against
THAT specific problem is rejecting known disposable-email domains outright,
which is what the check in signup() does, using a REAL, actively-maintained
blocklist (see webapp/data/disposable_email_domains.conf -- 8,201 domains,
pulled from https://github.com/disposable-email-domains/disposable-email-domains,
a community-maintained list that's been running since 2014 with an actual
verification process for additions). This is still not airtight -- brand
new disposable domains can appear before the list is updated, and someone
determined can always make a real-but-throwaway Gmail account, which no
technical check can distinguish from a "real" one -- but it is the real,
standard first line of defense, not a token gesture.
"""
from __future__ import annotations
import os
import secrets
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

from webapp.db import get_db

_DISPOSABLE_DOMAINS_PATH = os.path.join(os.path.dirname(__file__), "data", "disposable_email_domains.conf")
_disposable_domains_cache: set | None = None


def _load_disposable_domains() -> set:
    global _disposable_domains_cache
    if _disposable_domains_cache is None:
        try:
            with open(_DISPOSABLE_DOMAINS_PATH) as f:
                _disposable_domains_cache = {line.strip().lower() for line in f if line.strip()}
        except FileNotFoundError:
            _disposable_domains_cache = set()
    return _disposable_domains_cache


class AuthError(Exception):
    pass


def is_disposable_email(email: str) -> bool:
    domain = email.rsplit("@", 1)[-1].lower().strip()
    return domain in _load_disposable_domains()


def signup(email: str, password: str, db_path: str = None) -> dict:
    if not email or "@" not in email:
        raise AuthError("Please enter a valid email address.")
    if is_disposable_email(email):
        raise AuthError("Please use a permanent email address -- disposable/temporary email services aren't accepted.")
    if len(password) < 8:
        raise AuthError("Password must be at least 8 characters.")

    password_hash = generate_password_hash(password)
    api_key = secrets.token_hex(24)
    verify_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).isoformat()

    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise AuthError("An account with that email already exists.")
        cur = conn.execute(
            """INSERT INTO users (email, password_hash, api_key, email_verified, verify_token, created_at)
               VALUES (?, ?, ?, 0, ?, ?)""",
            (email, password_hash, api_key, verify_token, now),
        )
        user_id = cur.lastrowid

    return {"id": user_id, "email": email, "api_key": api_key, "verify_token": verify_token}


def login(email: str, password: str, db_path: str = None) -> dict:
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if row is None or not check_password_hash(row["password_hash"], password):
        raise AuthError("Incorrect email or password.")
    if not row["email_verified"]:
        raise AuthError("Please verify your email first -- check your inbox for the verification link.")

    return {"id": row["id"], "email": row["email"], "api_key": row["api_key"]}


def verify_email_token(token: str, db_path: str = None) -> bool:
    """Returns True if the token matched an account and it's now verified."""
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        row = conn.execute("SELECT id FROM users WHERE verify_token = ?", (token,)).fetchone()
        if row is None:
            return False
        conn.execute("UPDATE users SET email_verified = 1, verify_token = NULL WHERE id = ?", (row["id"],))
    return True


def resend_verification(email: str, db_path: str = None) -> str | None:
    """Issues a fresh verification token for an unverified account. Returns
    the new token, or None if the email doesn't exist / is already verified
    (deliberately vague on WHY, so this can't be used to probe which emails
    have accounts)."""
    new_token = secrets.token_urlsafe(32)
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        row = conn.execute("SELECT id, email_verified FROM users WHERE email = ?", (email,)).fetchone()
        if row is None or row["email_verified"]:
            return None
        conn.execute("UPDATE users SET verify_token = ? WHERE id = ?", (new_token, row["id"]))
    return new_token


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
    print("Signed up:", user["email"], "| API key issued:", bool(user["api_key"]),
          "| verify token issued:", bool(user["verify_token"]))
    assert user["api_key"] and user["verify_token"]

    try:
        signup("student@example.edu", "another-password123", db_path=test_path)
        raise SystemExit("FAIL: duplicate signup should have been rejected")
    except AuthError as e:
        print("Correctly rejected duplicate signup:", e)

    try:
        signup("throwaway@mailinator.com", "some-password-123", db_path=test_path)
        raise SystemExit("FAIL: disposable email domain should have been rejected")
    except AuthError as e:
        print("Correctly rejected disposable email domain:", e)

    try:
        login("student@example.edu", "correct-horse-battery", db_path=test_path)
        raise SystemExit("FAIL: login before email verification should have been rejected")
    except AuthError as e:
        print("Correctly rejected login before verification:", e)

    try:
        verify_email_token("totally-wrong-token", db_path=test_path)
        print("Wrong token correctly returned False:", not verify_email_token("totally-wrong-token", db_path=test_path))
    except Exception as e:
        raise SystemExit(f"FAIL: verify_email_token shouldn't raise on a bad token: {e}")

    verified = verify_email_token(user["verify_token"], db_path=test_path)
    print("Verification with correct token succeeded:", verified)
    assert verified

    logged_in = login("student@example.edu", "correct-horse-battery", db_path=test_path)
    print("Login OK after verification:", logged_in["email"])
    assert logged_in["id"] == user["id"]

    try:
        login("student@example.edu", "wrong-password", db_path=test_path)
        raise SystemExit("FAIL: wrong password should have been rejected")
    except AuthError as e:
        print("Correctly rejected wrong password:", e)

    found = get_user_by_api_key(user["api_key"], db_path=test_path)
    print("API key lookup OK:", found["email"])
    assert found["id"] == user["id"]

    # resend_verification on an ALREADY-verified account should return None
    resent = resend_verification("student@example.edu", db_path=test_path)
    print("Resend on already-verified account correctly returns None:", resent is None)
    assert resent is None

    # resend_verification on a fresh, unverified account should return a real token
    signup("second@example.edu", "another-good-password", db_path=test_path)
    resent2 = resend_verification("second@example.edu", db_path=test_path)
    print("Resend on unverified account correctly returns a new token:", bool(resent2))
    assert resent2

    os.remove(test_path)
    print("auth.py self-test: PASS")

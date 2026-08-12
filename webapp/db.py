""
webapp/db.py

Plain sqlite3 (no ORM) so a 1st-year student can read every query directly.
SQLite is a single-file database -- perfect for a class project, though a
real production deployment would move to Postgres/MySQL once you have
concurrent users (see README limitations).

Schema:
  users            -- signup accounts (email, hashed password, API key)
  router_configs   -- one row per user's registered router/network specs
  scan_reports     -- a log of each scan the user's local agent submitted
  alerts           -- individual anomaly alerts raised from scan reports
"""
from __future__ import annotations
import sqlite3
import json
from contextlib import contextmanager

DB_PATH = "netguard_platform.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    verify_token TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS router_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    subnet TEXT NOT NULL,
    interface TEXT NOT NULL,
    router_ip TEXT NOT NULL,
    router_model TEXT,
    known_devices_json TEXT NOT NULL DEFAULT '[]',
    blocklist_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scan_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    submitted_at TEXT NOT NULL,
    devices_json TEXT NOT NULL,
    dns_events_json TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scan_report_id INTEGER,
    created_at TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    ip TEXT,
    mac TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (scan_report_id) REFERENCES scan_reports(id)
);
"""


@contextmanager
def get_db(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH):
    with get_db(db_path) as conn:
        conn.executescript(SCHEMA)


if __name__ == "__main__":
    import os
    test_path = "test_netguard.db"
    if os.path.exists(test_path):
        os.remove(test_path)
    init_db(test_path)
    with get_db(test_path) as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        names = sorted(t["name"] for t in tables if t["name"] != "sqlite_sequence")
    print("Tables created:", names)
    assert names == sorted(["users", "router_configs", "scan_reports", "alerts"])
    os.remove(test_path)
    print("db.py self-test: PASS")

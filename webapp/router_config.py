"""
webapp/router_config.py

Storage layer for a logged-in user's registered router/network specs --
this is the "consumer signs up and enters their router specs" step from the
project brief. Reuses the SAME validation logic from the original
netguard/config.py (single-user CLI version) so the rules are identical
whether you're using the CLI tool or the website.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone

from webapp.db import get_db
from netguard.config import NetworkConfig


class ConfigError(Exception):
    pass


def save_router_config(user_id: int, subnet: str, interface: str, router_ip: str,
                        router_model: str = "", known_devices: list = None,
                        blocklist_domains: list = None, db_path: str = None) -> None:
    known_devices = known_devices or []
    blocklist_domains = blocklist_domains or []

    # Reuse the exact same validation the CLI tool uses -- one source of truth.
    cfg = NetworkConfig(subnet=subnet, interface=interface, router_ip=router_ip)
    problems = cfg.validate()
    if problems:
        raise ConfigError("; ".join(problems))

    now = datetime.now(timezone.utc).isoformat()
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        existing = conn.execute("SELECT id FROM router_configs WHERE user_id = ?", (user_id,)).fetchone()
        if existing:
            conn.execute(
                """UPDATE router_configs SET subnet=?, interface=?, router_ip=?, router_model=?,
                   known_devices_json=?, blocklist_json=?, updated_at=? WHERE user_id=?""",
                (subnet, interface, router_ip, router_model,
                 json.dumps(known_devices), json.dumps(blocklist_domains), now, user_id),
            )
        else:
            conn.execute(
                """INSERT INTO router_configs
                   (user_id, subnet, interface, router_ip, router_model,
                    known_devices_json, blocklist_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, subnet, interface, router_ip, router_model,
                 json.dumps(known_devices), json.dumps(blocklist_domains), now),
            )


def get_router_config(user_id: int, db_path: str = None) -> dict | None:
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        row = conn.execute("SELECT * FROM router_configs WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        return None
    return {
        "subnet": row["subnet"], "interface": row["interface"], "router_ip": row["router_ip"],
        "router_model": row["router_model"],
        "known_devices": json.loads(row["known_devices_json"]),
        "blocklist_domains": json.loads(row["blocklist_json"]),
        "updated_at": row["updated_at"],
    }


if __name__ == "__main__":
    import os
    from webapp.db import init_db
    from webapp.auth import signup

    test_path = "test_router_config.db"
    if os.path.exists(test_path):
        os.remove(test_path)
    init_db(test_path)
    user = signup("student@example.edu", "correct-horse-battery", db_path=test_path)

    # invalid subnet should be rejected
    try:
        save_router_config(user["id"], subnet="not-a-subnet", interface="wlan0",
                            router_ip="192.168.1.1", db_path=test_path)
        raise SystemExit("FAIL: invalid subnet should have been rejected")
    except ConfigError as e:
        print("Correctly rejected bad config:", e)

    save_router_config(
        user["id"], subnet="192.168.1.0/24", interface="wlan0", router_ip="192.168.1.1",
        router_model="TP-Link Archer AX21",
        known_devices=[{"mac": "AA:BB:CC:11:22:33", "name": "My Laptop"}],
        blocklist_domains=["telemetry.example-vendor.com"],
        db_path=test_path,
    )
    cfg = get_router_config(user["id"], db_path=test_path)
    print("Saved + reloaded config:", cfg["subnet"], cfg["router_model"], len(cfg["known_devices"]), "known devices")
    assert cfg["subnet"] == "192.168.1.0/24"
    assert cfg["router_model"] == "TP-Link Archer AX21"

    # update should overwrite, not duplicate
    save_router_config(user["id"], subnet="192.168.2.0/24", interface="eth0",
                        router_ip="192.168.2.1", db_path=test_path)
    cfg2 = get_router_config(user["id"], db_path=test_path)
    assert cfg2["subnet"] == "192.168.2.0/24"
    with get_db(test_path) as conn:
        count = conn.execute("SELECT COUNT(*) c FROM router_configs WHERE user_id=?", (user["id"],)).fetchone()["c"]
    assert count == 1, "update should overwrite in place, not insert a second row"
    print("Update-in-place OK, row count still:", count)

    os.remove(test_path)
    print("router_config.py self-test: PASS")

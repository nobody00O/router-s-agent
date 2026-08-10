"""
webapp/scan_ingest.py

Where a scan report from the user's LOCAL agent lands. This is the seam
between "the actual scanning, which can only happen on the user's own
network" and "the cloud platform, which stores/displays results."

The server reruns the SAME anomaly_rules engine used by the CLI tool --
one detection engine, two front-ends (local CLI, or agent-report-to-website).
"""
from __future__ import annotations
import json
from datetime import datetime, timezone

from webapp.db import get_db
from webapp.router_config import get_router_config
from netguard.discover import DiscoveredDevice
from netguard.dns_watch import DNSQueryEvent
from netguard.anomaly_rules import run_all_checks


def ingest_scan_report(user_id: int, devices: list, dns_events: list, db_path: str = None) -> dict:
    """
    devices: list of dicts like {"ip": "...", "mac": "..."}
    dns_events: list of dicts like {"src_ip": "...", "src_mac": "...", "queried_domain": "..."}
    (this is the JSON shape the local agent POSTs -- see agent/local_agent.py)
    """
    cfg = get_router_config(user_id, db_path=db_path)
    if cfg is None:
        raise ValueError("No router config registered for this user yet -- register one first.")

    known_macs = {d["mac"].upper() for d in cfg["known_devices"]}
    blocklist = set(cfg["blocklist_domains"])

    # Compare against the PREVIOUS scan's device list, for NEW_DEVICE_JOINED alerts
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        prev = conn.execute(
            "SELECT devices_json FROM scan_reports WHERE user_id=? ORDER BY id DESC LIMIT 1", (user_id,)
        ).fetchone()
    previous_macs = {d["mac"].upper() for d in json.loads(prev["devices_json"])} if prev else None

    discovered_objs = [DiscoveredDevice(ip=d["ip"], mac=d["mac"].upper(), first_seen=0, last_seen=0) for d in devices]
    dns_objs = [DNSQueryEvent(timestamp=0, src_ip=e["src_ip"], src_mac=e["src_mac"].upper(),
                                queried_domain=e["queried_domain"]) for e in dns_events]

    alerts = run_all_checks(discovered_objs, known_macs, dns_objs, blocklist, previous_macs=previous_macs)

    now = datetime.now(timezone.utc).isoformat()
    with get_db(**kwargs) as conn:
        cur = conn.execute(
            "INSERT INTO scan_reports (user_id, submitted_at, devices_json, dns_events_json) VALUES (?, ?, ?, ?)",
            (user_id, now, json.dumps(devices), json.dumps(dns_events)),
        )
        scan_report_id = cur.lastrowid
        for a in alerts:
            conn.execute(
                """INSERT INTO alerts (user_id, scan_report_id, created_at, rule, severity, message, ip, mac)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, scan_report_id, now, a.rule, a.severity, a.message, a.ip, a.mac),
            )

    return {"scan_report_id": scan_report_id, "n_devices": len(devices), "n_alerts": len(alerts)}


def get_recent_alerts(user_id: int, limit: int = 50, db_path: str = None) -> list:
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT ?", (user_id, limit)
        ).fetchall()
    return [dict(r) for r in rows]


def get_latest_devices(user_id: int, db_path: str = None) -> list:
    kwargs = {"db_path": db_path} if db_path else {}
    with get_db(**kwargs) as conn:
        row = conn.execute(
            "SELECT devices_json FROM scan_reports WHERE user_id=? ORDER BY id DESC LIMIT 1", (user_id,)
        ).fetchone()
    return json.loads(row["devices_json"]) if row else []


if __name__ == "__main__":
    import os
    from webapp.db import init_db
    from webapp.auth import signup
    from webapp.router_config import save_router_config

    test_path = "test_scan_ingest.db"
    if os.path.exists(test_path):
        os.remove(test_path)
    init_db(test_path)
    user = signup("student@example.edu", "correct-horse-battery", db_path=test_path)
    save_router_config(
        user["id"], subnet="192.168.1.0/24", interface="wlan0", router_ip="192.168.1.1",
        known_devices=[{"mac": "AA:BB:CC:11:22:33", "name": "My Laptop"}],
        blocklist_domains=["telemetry.example-vendor.com"],
        db_path=test_path,
    )

    # First scan: known device + one unknown device, one blocklist hit
    result1 = ingest_scan_report(
        user["id"],
        devices=[{"ip": "192.168.1.10", "mac": "AA:BB:CC:11:22:33"},
                  {"ip": "192.168.1.55", "mac": "11:22:33:44:55:66"}],
        dns_events=[{"src_ip": "192.168.1.55", "src_mac": "11:22:33:44:55:66",
                      "queried_domain": "telemetry.example-vendor.com"}],
        db_path=test_path,
    )
    print("Scan 1 result:", result1)
    assert result1["n_alerts"] >= 2  # unknown device + unknown vendor + blocklist hit

    # Second scan: a brand new device shows up -> should trigger NEW_DEVICE_JOINED
    result2 = ingest_scan_report(
        user["id"],
        devices=[{"ip": "192.168.1.10", "mac": "AA:BB:CC:11:22:33"},
                  {"ip": "192.168.1.99", "mac": "DE:AD:BE:EF:00:01"}],
        dns_events=[],
        db_path=test_path,
    )
    print("Scan 2 result:", result2)
    alerts = get_recent_alerts(user["id"], db_path=test_path)
    assert any(a["rule"] == "NEW_DEVICE_JOINED" for a in alerts)
    print(f"Total alerts stored across both scans: {len(alerts)}")
    for a in alerts:
        print(f"  [{a['severity']}] {a['rule']}: {a['message']}")

    latest = get_latest_devices(user["id"], db_path=test_path)
    assert len(latest) == 2

    os.remove(test_path)
    print("scan_ingest.py self-test: PASS")

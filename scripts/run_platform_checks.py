#!/usr/bin/env python3
"""
scripts/run_platform_checks.py

Runs every module's self-test in order, then a full in-process signup ->
router-setup -> agent-report -> dashboard flow using Flask's test client.
Use this to confirm your setup works before your demo.

    python3 scripts/run_platform_checks.py
"""
import sys, os, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)


def section(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def run_module_selftest(module_name):
    result = subprocess.run([sys.executable, "-m", module_name], cwd=ROOT,
                             capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
        raise SystemExit(f"{module_name} self-test FAILED")


def main():
    section("1. DATABASE -- schema creation")
    run_module_selftest("webapp.db")

    section("2. AUTH -- signup, login, API keys")
    run_module_selftest("webapp.auth")

    section("3. ROUTER CONFIG -- save/load/validate")
    run_module_selftest("webapp.router_config")

    section("4. SCAN INGESTION -- anomaly detection + storage")
    run_module_selftest("webapp.scan_ingest")

    section("5. FULL WEBSITE FLOW -- in-process (Flask test client)")
    import webapp.app as appmod
    db_path = os.path.join(ROOT, appmod.DB_PATH)
    if os.path.exists(db_path):
        os.remove(db_path)
    appmod.init_db(appmod.DB_PATH)

    client = appmod.app.test_client()
    r = client.post("/signup", data={"email": "demo@example.edu", "password": "correct-horse-battery"})
    assert r.status_code in (200, 302)
    r = client.post("/router/setup", data={
        "router_model": "Demo Router", "subnet": "192.168.1.0/24", "interface": "wlan0",
        "router_ip": "192.168.1.1", "device_mac": ["AA:BB:CC:11:22:33"], "device_name": ["My Laptop"],
        "blocklist_domains": "telemetry.example-vendor.com",
    })
    assert r.status_code in (200, 302)

    from webapp.db import get_db
    with get_db(appmod.DB_PATH) as conn:
        api_key = conn.execute("SELECT api_key FROM users WHERE email='demo@example.edu'").fetchone()["api_key"]

    r = client.post("/api/report", headers={"X-API-Key": api_key}, json={
        "devices": [{"ip": "192.168.1.10", "mac": "AA:BB:CC:11:22:33"},
                     {"ip": "192.168.1.99", "mac": "DE:AD:BE:EF:00:01"}],
        "dns_events": [{"src_ip": "192.168.1.99", "src_mac": "DE:AD:BE:EF:00:01",
                          "queried_domain": "telemetry.example-vendor.com"}],
    })
    assert r.status_code == 201, r.get_json()
    print("Agent report ingestion:", r.get_json())

    r = client.get("/api/dashboard-data")
    data = r.get_json()
    print(f"Dashboard shows {len(data['devices'])} devices, {len(data['alerts'])} alerts")
    assert len(data["devices"]) == 2
    assert len(data["alerts"]) >= 3
    print("PASS")

    os.remove(db_path)

    section("ALL STAGES COMPLETED")
    print("Every module (DB, auth, config, ingestion, full website flow) verified.")
    print("To run the REAL live server: python3 webapp/app.py, then open http://127.0.0.1:5070")


if __name__ == "__main__":
    main()

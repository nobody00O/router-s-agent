#!/usr/bin/env python3
"""
agent/local_agent.py

Download this file, edit the two settings below, and run it ON YOUR OWN
NETWORK to actually scan your devices and report results to your dashboard.

  pip install requests scapy
  sudo python3 local_agent.py

*** ONLY RUN THIS ON A NETWORK YOU OWN OR HAVE PERMISSION TO SCAN ***

By default this runs in MOCK mode (safe to run anywhere, generates fake
scan data) so you can test the whole pipeline before touching a real
network. Flip USE_REAL_SCAN to True once you're ready and have filled in
your real SUBNET / INTERFACE below.
"""
import sys, os, time

# ============ EDIT THESE ============
API_KEY = "PASTE-YOUR-API-KEY-HERE"           # from the /agent page after signup
SERVER_URL = "http://127.0.0.1:5070"           # your platform's address (or your ngrok/Render URL)
# NOTE: if SERVER_URL is an ngrok free-tier link, requests here already send
# the "ngrok-skip-browser-warning" header below -- without it, ngrok serves
# its own warning interstitial instead of your actual API, and every report
# would silently fail. Not needed for a real deployed domain (Render, etc).
SUBNET = "192.168.1.0/24"                       # your real subnet
INTERFACE = "wlan0"                              # your real network interface name
USE_REAL_SCAN = False                            # flip to True once ready (see note above)
DNS_SNIFF_SECONDS = 15                           # how long to listen for DNS traffic per run
SCAN_INTERVAL_SECONDS = 300                      # how often to scan (5 min default)
# =====================================

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_one_scan_cycle():
    import requests

    if USE_REAL_SCAN:
        from netguard.discover import real_arp_scan
        from netguard.dns_watch import real_dns_sniff
        devices = real_arp_scan(SUBNET, INTERFACE)
        dns_events = real_dns_sniff(INTERFACE, duration_sec=DNS_SNIFF_SECONDS)
    else:
        from netguard.discover import mock_arp_scan
        from netguard.dns_watch import mock_dns_traffic
        devices = mock_arp_scan(SUBNET, known_macs=[], extra_unknown_devices=2,
                                 seed=int(time.time()) % 1000)
        dns_events = mock_dns_traffic(
            devices, benign_domains=["google.com", "netflix.com"],
            blocklist_domains=["telemetry.example-vendor.com"],
            n_events=10, inject_blocklist_hits=1, seed=int(time.time()) % 1000,
        )

    payload = {
        "devices": [{"ip": d.ip, "mac": d.mac} for d in devices],
        "dns_events": [{"src_ip": e.src_ip, "src_mac": e.src_mac, "queried_domain": e.queried_domain}
                         for e in dns_events],
    }

    resp = requests.post(
        f"{SERVER_URL}/api/report", json=payload,
        headers={"X-API-Key": API_KEY, "ngrok-skip-browser-warning": "true"},
        timeout=10,
    )
    if resp.status_code == 201:
        result = resp.json()
        print(f"[OK] Reported {result['n_devices']} devices, server raised {result['n_alerts']} alerts.")
    else:
        print(f"[ERROR] Server responded {resp.status_code}: {resp.text}")


if __name__ == "__main__":
    mode = "REAL network scan" if USE_REAL_SCAN else "MOCK/demo data (safe to run anywhere)"
    print(f"Home Network Guardian local agent starting -- mode: {mode}")
    if API_KEY == "PASTE-YOUR-API-KEY-HERE":
        print("WARNING: you haven't set your API_KEY yet -- edit the top of this file first.")
        sys.exit(1)

    while True:
        run_one_scan_cycle()
        print(f"Sleeping {SCAN_INTERVAL_SECONDS}s until next scan... (Ctrl+C to stop)")
        time.sleep(SCAN_INTERVAL_SECONDS)

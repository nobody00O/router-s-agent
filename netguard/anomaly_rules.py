"""
netguard/anomaly_rules.py

The "brain" of the tool -- but deliberately NOT machine learning. Every rule
here is a simple, explainable if/then check, which is exactly right for a
1st-year project: it's easy to demo, easy to defend in a viva ("why did it
flag this device? because rule #2 fired, here's the code"), and it's how
real, simple network security tools like this actually start.

Rules implemented:
  R1. UNKNOWN_DEVICE       -- a MAC on the network that isn't in your known_devices list
  R2. UNKNOWN_VENDOR       -- a device whose MAC vendor can't be identified at all
  R3. BLOCKLISTED_DOMAIN   -- a device queried a domain on the tracker/telemetry blocklist
  R4. NEW_DEVICE_JOINED    -- a MAC seen now that was NOT seen in the previous scan
                               (requires comparing two scans over time)
"""
from __future__ import annotations
from dataclasses import dataclass
from netguard.fingerprint import lookup_vendor


@dataclass
class Alert:
    rule: str
    severity: str  # "info" | "warning" | "critical"
    message: str
    ip: str = ""
    mac: str = ""


def check_unknown_devices(discovered: list, known_macs: set) -> list:
    alerts = []
    for d in discovered:
        if d.mac.upper() not in known_macs:
            vendor = lookup_vendor(d.mac)
            alerts.append(Alert(
                rule="UNKNOWN_DEVICE", severity="warning", ip=d.ip, mac=d.mac,
                message=f"Device {d.ip} ({d.mac}, vendor: {vendor}) is on the network but not in your known-devices list.",
            ))
    return alerts


def check_unknown_vendor(discovered: list) -> list:
    alerts = []
    for d in discovered:
        vendor = lookup_vendor(d.mac)
        if vendor == "Unknown vendor":
            alerts.append(Alert(
                rule="UNKNOWN_VENDOR", severity="info", ip=d.ip, mac=d.mac,
                message=f"Device {d.ip} ({d.mac}) has an unrecognized manufacturer prefix. "
                        f"(Note: modern phones/laptops often randomize their MAC for privacy -- "
                        f"this alone isn't proof of anything suspicious.)",
            ))
    return alerts


def check_blocklisted_dns(dns_events: list, blocklist_domains: set) -> list:
    alerts = []
    for e in dns_events:
        if e.queried_domain in blocklist_domains:
            alerts.append(Alert(
                rule="BLOCKLISTED_DOMAIN", severity="critical", ip=e.src_ip, mac=e.src_mac,
                message=f"Device {e.src_ip} ({e.src_mac}) queried a known tracker/telemetry domain: {e.queried_domain}",
            ))
    return alerts


def check_new_devices_since_last_scan(current_scan: list, previous_macs: set) -> list:
    alerts = []
    for d in current_scan:
        if d.mac.upper() not in previous_macs:
            alerts.append(Alert(
                rule="NEW_DEVICE_JOINED", severity="warning", ip=d.ip, mac=d.mac,
                message=f"Device {d.ip} ({d.mac}) was not present in the previous scan -- it just joined the network.",
            ))
    return alerts


def run_all_checks(discovered: list, known_macs: set, dns_events: list,
                    blocklist_domains: set, previous_macs: set | None = None) -> list:
    alerts = []
    alerts += check_unknown_devices(discovered, known_macs)
    alerts += check_unknown_vendor(discovered)
    alerts += check_blocklisted_dns(dns_events, blocklist_domains)
    if previous_macs is not None:
        alerts += check_new_devices_since_last_scan(discovered, previous_macs)
    return alerts


if __name__ == "__main__":
    from netguard.discover import mock_arp_scan
    from netguard.dns_watch import mock_dns_traffic

    known_macs = {"AA:BB:CC:11:22:33", "AA:BB:CC:44:55:66"}
    devices = mock_arp_scan("192.168.1.0/24", known_macs=list(known_macs), extra_unknown_devices=1, seed=3)
    blocklist = {"telemetry.example-vendor.com", "analytics.example-tracker.net"}
    dns_events = mock_dns_traffic(devices, ["google.com", "netflix.com"], list(blocklist),
                                   n_events=15, inject_blocklist_hits=2, seed=3)

    alerts = run_all_checks(devices, known_macs, dns_events, blocklist)
    print(f"Discovered {len(devices)} devices, generated {len(alerts)} alerts:\n")
    for a in alerts:
        print(f"  [{a.severity.upper():8s}] {a.rule:20s} {a.message}")

    assert any(a.rule == "UNKNOWN_DEVICE" for a in alerts)
    assert any(a.rule == "BLOCKLISTED_DOMAIN" for a in alerts)
    print("\nanomaly_rules.py self-test: PASS")

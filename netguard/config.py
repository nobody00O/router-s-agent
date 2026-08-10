"""
netguard/config.py

Step 1 of the tool, matching the project brief: "a user inputs their router
specifications or network configurations."

This is a plain dataclass + JSON load/save -- no magic. A 1st-year student
should be able to read this file top to bottom in under a minute.
"""
from __future__ import annotations
import json
import ipaddress
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class KnownDevice:
    mac: str            # e.g. "AA:BB:CC:DD:EE:FF"
    name: str            # human label, e.g. "Mom's iPhone"
    expected_ports: list = field(default_factory=list)  # ports this device is allowed to use, optional


@dataclass
class NetworkConfig:
    subnet: str                       # e.g. "192.168.1.0/24"
    interface: str                    # e.g. "wlan0" or "eth0" -- the NIC to scan/sniff on
    router_ip: str                    # e.g. "192.168.1.1"
    known_devices: list = field(default_factory=list)   # list[KnownDevice]
    blocklist_domains: list = field(default_factory=list)  # domains treated as trackers/telemetry

    def validate(self) -> list:
        """Returns a list of human-readable problems (empty list = config looks OK)."""
        problems = []
        try:
            ipaddress.ip_network(self.subnet, strict=False)
        except ValueError:
            problems.append(f"'{self.subnet}' is not a valid subnet (expected e.g. 192.168.1.0/24)")
        try:
            ipaddress.ip_address(self.router_ip)
        except ValueError:
            problems.append(f"'{self.router_ip}' is not a valid IP address")
        if not self.interface:
            problems.append("No network interface given (e.g. 'wlan0', 'eth0', 'en0')")
        macs_seen = set()
        for d in self.known_devices:
            mac = d["mac"] if isinstance(d, dict) else d.mac
            if mac in macs_seen:
                problems.append(f"Duplicate MAC address in known_devices: {mac}")
            macs_seen.add(mac)
        return problems

    @staticmethod
    def load(path: str) -> "NetworkConfig":
        with open(path) as f:
            raw = json.load(f)
        raw["known_devices"] = [KnownDevice(**d) for d in raw.get("known_devices", [])]
        return NetworkConfig(**raw)

    def save(self, path: str):
        raw = asdict(self)
        Path(path).write_text(json.dumps(raw, indent=2))


DEFAULT_BLOCKLIST_DOMAINS = [
    # Small ILLUSTRATIVE example set only -- ships with just enough entries to
    # prove the detection logic works end to end. For a real deployment, swap
    # this for a maintained tracker/telemetry blocklist (e.g. a Pi-hole /
    # NextDNS-style list) rather than relying on this short demo list.
    "telemetry.example-vendor.com",
    "analytics.example-tracker.net",
    "metrics.example-cloud-iot.com",
]

if __name__ == "__main__":
    cfg = NetworkConfig(
        subnet="192.168.1.0/24",
        interface="wlan0",
        router_ip="192.168.1.1",
        known_devices=[
            KnownDevice(mac="AA:BB:CC:11:22:33", name="My Laptop"),
            KnownDevice(mac="AA:BB:CC:44:55:66", name="Smart Bulb"),
        ],
        blocklist_domains=DEFAULT_BLOCKLIST_DOMAINS,
    )
    print("Validation problems:", cfg.validate() or "None -- config looks OK")
    cfg.save("config/network_config.json")
    reloaded = NetworkConfig.load("config/network_config.json")
    print("Reloaded OK, subnet =", reloaded.subnet, "| known devices =", len(reloaded.known_devices))

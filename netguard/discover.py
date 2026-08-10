"""
netguard/discover.py

Finds every device currently on the local network by sending ARP "who-has"
requests to every address in the subnet and collecting replies. This is the
same technique tools like `arp-scan`, `nmap -sn`, and Fing use.

*** REQUIRES ROOT/ADMIN AND A REAL NETWORK INTERFACE TO ACTUALLY SCAN ***
My sandbox has no network interface at all (confirmed: no `ip`, `arp`, or NIC
present), so `real_arp_scan()` below is real, correct code that CANNOT be
executed here. Everything in this module is instead verified against
`mock_arp_scan()`, which returns realistic fake results so the rest of the
pipeline (fingerprinting, known-device matching, alerting, dashboard) can be
built and tested honestly without pretending a live scan happened.

Run `real_arp_scan()` yourself, as root, on your own network, e.g.:
    sudo python3 -c "from netguard.discover import real_arp_scan; \
                      print(real_arp_scan('192.168.1.0/24', 'wlan0'))"
"""
from __future__ import annotations
import random
import time
from dataclasses import dataclass


@dataclass
class DiscoveredDevice:
    ip: str
    mac: str
    first_seen: float
    last_seen: float


def real_arp_scan(subnet: str, interface: str, timeout: int = 3) -> list:
    """
    REAL implementation. Sends ARP requests to every host in `subnet` on
    `interface` and returns devices that replied.

    Requires: scapy, root/admin privileges, and a real network interface.
    This is standard ARP scanning -- legitimate on a network you own/administer;
    do not point this at a subnet you don't have permission to scan.
    """
    from scapy.all import ARP, Ether, srp  # imported lazily so this module
                                             # still imports fine without root

    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, _ = srp(packet, timeout=timeout, iface=interface, verbose=False)

    now = time.time()
    devices = []
    for _, received in answered:
        devices.append(DiscoveredDevice(
            ip=received.psrc, mac=received.hwsrc.upper(), first_seen=now, last_seen=now
        ))
    return devices


def mock_arp_scan(subnet: str, known_macs: list = None, extra_unknown_devices: int = 0,
                   seed: int | None = None) -> list:
    """
    TEST DOUBLE for real_arp_scan(). Returns realistic fake devices so the
    rest of the pipeline can be exercised without a live network. Includes
    all `known_macs` (so "expected" devices show up) plus
    `extra_unknown_devices` random unrecognized MACs (to simulate a rogue /
    new device joining the network).
    """
    rng = random.Random(seed)
    now = time.time()
    devices = []
    base_ip = ".".join(subnet.split("/")[0].split(".")[:3])

    used_last_octets = set()

    def next_ip():
        while True:
            octet = rng.randint(2, 254)
            if octet not in used_last_octets:
                used_last_octets.add(octet)
                return f"{base_ip}.{octet}"

    for mac in (known_macs or []):
        devices.append(DiscoveredDevice(ip=next_ip(), mac=mac.upper(), first_seen=now, last_seen=now))

    for _ in range(extra_unknown_devices):
        fake_mac = ":".join(f"{rng.randint(0,255):02X}" for _ in range(6))
        devices.append(DiscoveredDevice(ip=next_ip(), mac=fake_mac, first_seen=now, last_seen=now))

    return devices


if __name__ == "__main__":
    # Self-test using the mock backend (safe to run anywhere, no network needed)
    known = ["AA:BB:CC:11:22:33", "AA:BB:CC:44:55:66"]
    found = mock_arp_scan("192.168.1.0/24", known_macs=known, extra_unknown_devices=1, seed=1)
    print(f"Mock scan found {len(found)} devices:")
    for d in found:
        print(f"  {d.ip:15s}  {d.mac}")
    assert len(found) == 3
    assert sum(1 for d in found if d.mac in known) == 2
    print("discover.py self-test: PASS (using mock backend -- see docstring for why)")

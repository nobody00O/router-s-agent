"""
netguard/dns_watch.py

Passively watches outbound DNS queries on the network (devices asking "what's
the IP for X.com?") and flags any that match a known tracker/telemetry
blocklist. This is how you catch a smart device "phoning home" somewhere
unexpected -- DNS queries are also the easiest, most beginner-friendly place
to look, since (unlike most traffic today) DNS is very often still
unencrypted and simple to parse.

*** REQUIRES ROOT/ADMIN AND A REAL NETWORK INTERFACE TO ACTUALLY SNIFF ***
Same situation as discover.py: `real_dns_sniff()` is real, correct code that
needs a live NIC I don't have here. `mock_dns_traffic()` generates realistic
fake DNS query logs so the anomaly-matching logic can be built and verified
honestly.

LIMITATION WORTH KNOWING (put this in your report): most real-world traffic
today uses encrypted DNS (DoH/DoT) or QUIC, which this simple sniffer cannot
see into. This catches the "easy" cases (plain old UDP/53 DNS) -- a
production-grade tool would need integration at the router/DNS-resolver
level (e.g. Pi-hole logs) to see everything. Being upfront about this
limitation is itself a good thing to demonstrate you understand in a 1st-year
report.
"""
from __future__ import annotations
import random
import time
from dataclasses import dataclass


@dataclass
class DNSQueryEvent:
    timestamp: float
    src_ip: str
    src_mac: str
    queried_domain: str


def real_dns_sniff(interface: str, duration_sec: int = 30) -> list:
    """
    REAL implementation. Sniffs UDP port 53 (DNS) traffic on `interface` for
    `duration_sec` seconds and extracts the queried domain from each request.
    Requires scapy + root/admin + a real interface.
    """
    from scapy.all import sniff, DNS, DNSQR, IP, Ether

    events = []

    def _handle(pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:  # qr=0 -> query, not response
            domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            events.append(DNSQueryEvent(
                timestamp=time.time(),
                src_ip=pkt[IP].src if pkt.haslayer(IP) else "?",
                src_mac=pkt[Ether].src.upper() if pkt.haslayer(Ether) else "?",
                queried_domain=domain,
            ))

    sniff(iface=interface, filter="udp port 53", prn=_handle, timeout=duration_sec, store=False)
    return events


def mock_dns_traffic(devices: list, benign_domains: list, blocklist_domains: list,
                      n_events: int = 30, inject_blocklist_hits: int = 2,
                      seed: int | None = None) -> list:
    """
    TEST DOUBLE for real_dns_sniff(). `devices` is a list of DiscoveredDevice
    (from discover.py). Generates a realistic mixed stream of mostly-benign
    DNS queries with `inject_blocklist_hits` queries to blocklisted domains
    deliberately mixed in, so the anomaly detector has something real to catch.
    """
    rng = random.Random(seed)
    now = time.time()
    events = []

    blocklist_positions = set(rng.sample(range(n_events), min(inject_blocklist_hits, n_events)))
    for i in range(n_events):
        device = rng.choice(devices)
        domain = (rng.choice(blocklist_domains) if i in blocklist_positions and blocklist_domains
                  else rng.choice(benign_domains))
        events.append(DNSQueryEvent(
            timestamp=now + i, src_ip=device.ip, src_mac=device.mac, queried_domain=domain
        ))
    return events


if __name__ == "__main__":
    from netguard.discover import mock_arp_scan

    devices = mock_arp_scan("192.168.1.0/24", known_macs=["AA:BB:CC:11:22:33", "AA:BB:CC:44:55:66"], seed=2)
    benign = ["google.com", "apple.com", "netflix.com", "githubusercontent.com"]
    blocklist = ["telemetry.example-vendor.com", "analytics.example-tracker.net"]

    events = mock_dns_traffic(devices, benign, blocklist, n_events=20, inject_blocklist_hits=3, seed=2)
    hits = [e for e in events if e.queried_domain in blocklist]
    print(f"Generated {len(events)} mock DNS events, {len(hits)} match the blocklist:")
    for h in hits:
        print(f"  {h.src_ip} ({h.src_mac}) queried BLOCKLISTED domain: {h.queried_domain}")
    assert len(hits) == 3
    print("dns_watch.py self-test: PASS")

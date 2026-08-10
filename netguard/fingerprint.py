"""
netguard/fingerprint.py

Every MAC address's first 3 bytes (the OUI, "Organizationally Unique
Identifier") are registered to a manufacturer by the IEEE. Looking this up
tells you roughly WHAT a device is even before you've labeled it yourself --
e.g. a MAC starting with a Raspberry Pi Foundation OUI showing up on your
network when you don't own a Pi is a useful red flag.

This ships with a SMALL illustrative OUI table (just enough real, correctly
registered prefixes to prove the lookup logic works). For a real deployment,
download the full IEEE OUI registry (a public, freely republishable CSV) from
https://standards-oui.ieee.org/oui/oui.csv and load it instead --
`load_oui_table_from_csv()` below is written to accept exactly that file
format.
"""
from __future__ import annotations
import csv

# A small, real subset of registered OUIs (first 3 bytes of MAC -> vendor),
# enough to demonstrate the lookup working correctly end-to-end.
DEMO_OUI_TABLE = {
    "3C:71:BF": "Espressif Inc. (ESP32/ESP8266 boards)",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "F4:F5:D8": "Google, Inc.",
    "AC:63:BE": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "00:1A:11": "Google, Inc.",
    "18:B4:30": "Nest Labs Inc.",
    "50:8A:06": "Amazon Technologies Inc.",
    "68:37:E9": "Amazon Technologies Inc.",
    "AA:BB:CC": "TEST-VENDOR (used only in this project's own mock data)",
}


def lookup_vendor(mac: str, oui_table: dict | None = None) -> str:
    table = oui_table or DEMO_OUI_TABLE
    prefix = mac.upper()[:8]  # "AA:BB:CC"
    return table.get(prefix, "Unknown vendor")


def load_oui_table_from_csv(path: str) -> dict:
    """
    Parses the real IEEE OUI registry CSV (columns: Registry,Assignment,
    Organization Name,Organization Address). `Assignment` is a 6-hex-digit
    string like 'B827EB' with no separators -- this reformats it to
    'B8:27:EB' to match `lookup_vendor`'s key format.
    """
    table = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw = row.get("Assignment", "").strip().upper()
            if len(raw) == 6:
                formatted = ":".join(raw[i:i + 2] for i in range(0, 6, 2))
                table[formatted] = row.get("Organization Name", "Unknown").strip()
    return table


if __name__ == "__main__":
    tests = [
        ("3C:71:BF:6D:2A:78", "Espressif Inc. (ESP32/ESP8266 boards)"),
        ("B8:27:EB:12:34:56", "Raspberry Pi Foundation"),
        ("11:22:33:44:55:66", "Unknown vendor"),
    ]
    for mac, expected in tests:
        result = lookup_vendor(mac)
        status = "PASS" if result == expected else "FAIL"
        print(f"[{status}] {mac} -> {result}")
        assert result == expected
    print("fingerprint.py self-test: PASS")

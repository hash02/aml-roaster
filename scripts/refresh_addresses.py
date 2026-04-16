#!/usr/bin/env python3
"""Refresh vendored address feeds from upstream sources.

Syncs three lookup feeds from well-maintained public sources:
  - addresses/ofac.json      ← ultrasoundmoney/ofac-ethereum-addresses (MIT)
  - addresses/phishing.json  ← MyEtherWallet/ethereum-lists darklist (MIT)
  - addresses/exploits.json  ← forta-network/labelled-datasets (Apache-2.0)

Intended to run weekly via .github/workflows/refresh-addresses.yml.
Stdlib-only — no third-party deps.
"""

import csv
import json
import urllib.request
from pathlib import Path

ADDRESSES_DIR = Path(__file__).parent.parent / "addresses"

OFAC_UPSTREAM = (
    "https://raw.githubusercontent.com/"
    "ultrasoundmoney/ofac-ethereum-addresses/main/data.csv"
)
PHISHING_UPSTREAM = (
    "https://raw.githubusercontent.com/"
    "MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json"
)
EXPLOITS_UPSTREAM = (
    "https://raw.githubusercontent.com/"
    "forta-network/labelled-datasets/main/labels/1/malicious_smart_contracts.csv"
)


def _write_feed(path: Path, source: str, license_: str, description: str, addresses: dict) -> None:
    payload = {
        "_meta": {
            "source": source,
            "license": license_,
            "description": description,
        },
        "addresses": dict(sorted(addresses.items())),
    }
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"Wrote {len(addresses)} addresses to {path.relative_to(path.parent.parent)}")


def refresh_ofac() -> int:
    with urllib.request.urlopen(OFAC_UPSTREAM, timeout=30) as resp:
        text = resp.read().decode("utf-8")
    reader = csv.DictReader(text.splitlines())
    addresses = {
        row["address"].strip().lower(): row["name"].strip()
        for row in reader
        if row.get("address")
    }
    _write_feed(
        ADDRESSES_DIR / "ofac.json",
        "https://github.com/ultrasoundmoney/ofac-ethereum-addresses",
        "MIT",
        "OFAC SDN Ethereum addresses — auto-refreshed from upstream",
        addresses,
    )
    return len(addresses)


def refresh_phishing() -> int:
    with urllib.request.urlopen(PHISHING_UPSTREAM, timeout=30) as resp:
        entries = json.loads(resp.read().decode("utf-8"))
    addresses = {}
    for entry in entries:
        addr = entry.get("address", "").strip().lower()
        if not addr:
            continue
        comment = entry.get("comment", "").strip() or "phishing"
        date = entry.get("date", "").strip()
        label = f"{comment} ({date})" if date else comment
        # Truncate overly long labels so reports stay readable.
        if len(label) > 200:
            label = label[:197] + "..."
        addresses[addr] = label
    _write_feed(
        ADDRESSES_DIR / "phishing.json",
        "https://github.com/MyEtherWallet/ethereum-lists",
        "MIT",
        "Phishing and scam addresses — MyEtherWallet darklist",
        addresses,
    )
    return len(addresses)


def refresh_exploits() -> int:
    with urllib.request.urlopen(EXPLOITS_UPSTREAM, timeout=30) as resp:
        text = resp.read().decode("utf-8")
    reader = csv.DictReader(text.splitlines())
    addresses = {}
    for row in reader:
        addr = row.get("contract_address", "").strip().lower()
        if not addr:
            continue
        # Prefer the human-assigned contract_tag; fall back to the creator's
        # etherscan label, then to a generic "exploit" marker.
        label = (
            row.get("contract_tag", "").strip()
            or row.get("contract_creator_tag", "").strip()
            or row.get("contract_creator_etherscan_label", "").strip()
            or "exploit"
        )
        addresses[addr] = label
    _write_feed(
        ADDRESSES_DIR / "exploits.json",
        "https://github.com/forta-network/labelled-datasets",
        "Apache-2.0",
        "Malicious smart contracts labelled by Forta (exploit / heist / phish-hack)",
        addresses,
    )
    return len(addresses)


def main() -> None:
    refresh_ofac()
    refresh_phishing()
    refresh_exploits()


if __name__ == "__main__":
    main()

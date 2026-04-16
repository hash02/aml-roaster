#!/usr/bin/env python3
"""Refresh vendored address feeds from upstream sources.

Currently syncs `addresses/ofac.json` from
`ultrasoundmoney/ofac-ethereum-addresses` (MIT). Intended to run weekly
via .github/workflows/refresh-addresses.yml.
"""

import csv
import json
import urllib.request
from pathlib import Path

OFAC_UPSTREAM = (
    "https://raw.githubusercontent.com/"
    "ultrasoundmoney/ofac-ethereum-addresses/main/data.csv"
)
OFAC_OUT = Path(__file__).parent.parent / "addresses" / "ofac.json"


def refresh_ofac() -> int:
    with urllib.request.urlopen(OFAC_UPSTREAM, timeout=30) as resp:
        text = resp.read().decode("utf-8")
    reader = csv.DictReader(text.splitlines())
    addresses = {
        row["address"].strip().lower(): row["name"].strip()
        for row in reader
        if row.get("address")
    }
    payload = {
        "_meta": {
            "source": "https://github.com/ultrasoundmoney/ofac-ethereum-addresses",
            "license": "MIT",
            "description": "OFAC SDN Ethereum addresses — auto-refreshed from upstream",
        },
        "addresses": dict(sorted(addresses.items())),
    }
    OFAC_OUT.parent.mkdir(exist_ok=True)
    OFAC_OUT.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"Wrote {len(addresses)} addresses to {OFAC_OUT.relative_to(OFAC_OUT.parent.parent)}")
    return len(addresses)


if __name__ == "__main__":
    refresh_ofac()

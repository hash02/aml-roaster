#!/usr/bin/env python3
"""
AML Roaster Agent — Live Ethereum Transaction Monitor
Pulls real blockchain data, flags suspicious patterns, generates roast + SAR reports.
Designed to run on GitHub Actions every 30 minutes.

Author: HASH (hash02)
"""

import os
import sys
import json
import time
import hashlib
import requests
from datetime import datetime, timezone
from pathlib import Path
from openai import OpenAI

# ─── Configuration ───────────────────────────────────────────────────────────

# Known mixer / sanctioned addresses (lowercase for comparison)
WATCHED_ADDRESSES = {
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash (0.1 ETH Pool)",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash (100 ETH Pool)",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash (10 ETH Pool)",
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": "Tornado Cash (1 ETH Pool)",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash Router",
    "0xba214c1c1928a32bffe790263e38b4af9bfcd659": "eXch Exchange (flagged)",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Lazarus Group (DPRK)",
    "0xa7e5d5a720f06526557c513402f2e6b5fa20b008": "Lazarus Group (DPRK) #2",
}

# Etherscan free API — no key needed for basic queries, but key gives higher rate limits
ETHERSCAN_API = "https://api.etherscan.io/api"
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_API_KEY", "")  # Optional — works without it

# Groq (free LLM via OpenAI-compatible API)
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_MODEL = "llama-3.3-70b-versatile"

# Output
REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Thresholds
HIGH_VALUE_ETH = 10  # Flag transfers above this amount
RAPID_TX_WINDOW = 300  # seconds — flag multiple txs within this window
RAPID_TX_COUNT = 3  # minimum tx count to flag as rapid-fire


# ─── Blockchain Data Layer ───────────────────────────────────────────────────

def get_latest_block() -> int:
    """Get the latest Ethereum block number from Etherscan."""
    params = {"module": "proxy", "action": "eth_blockNumber"}
    if ETHERSCAN_KEY:
        params["apikey"] = ETHERSCAN_KEY
    try:
        r = requests.get(ETHERSCAN_API, params=params, timeout=15)
        data = r.json()
        return int(data["result"], 16)
    except Exception as e:
        print(f"[ERROR] Failed to get latest block: {e}")
        return 0


def get_block_transactions(block_num: int) -> list:
    """Get all transactions from a specific block."""
    params = {
        "module": "proxy",
        "action": "eth_getBlockByNumber",
        "tag": hex(block_num),
        "boolean": "true",
    }
    if ETHERSCAN_KEY:
        params["apikey"] = ETHERSCAN_KEY
    try:
        r = requests.get(ETHERSCAN_API, params=params, timeout=15)
        data = r.json()
        if data.get("result") and data["result"].get("transactions"):
            return data["result"]["transactions"]
    except Exception as e:
        print(f"[ERROR] Failed to get block {block_num}: {e}")
    return []


def get_internal_transactions(address: str, start_block: int, end_block: int) -> list:
    """Get internal transactions for an address within a block range."""
    params = {
        "module": "account",
        "action": "txlistinternal",
        "address": address,
        "startblock": start_block,
        "endblock": end_block,
        "sort": "desc",
    }
    if ETHERSCAN_KEY:
        params["apikey"] = ETHERSCAN_KEY
    try:
        r = requests.get(ETHERSCAN_API, params=params, timeout=15)
        data = r.json()
        if data.get("result") and isinstance(data["result"], list):
            return data["result"]
    except Exception as e:
        print(f"[ERROR] Failed to get internal txs: {e}")
    return []


def get_normal_transactions(address: str, start_block: int, end_block: int) -> list:
    """Get normal transactions for an address within a block range."""
    params = {
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": start_block,
        "endblock": end_block,
        "sort": "desc",
    }
    if ETHERSCAN_KEY:
        params["apikey"] = ETHERSCAN_KEY
    try:
        r = requests.get(ETHERSCAN_API, params=params, timeout=15)
        data = r.json()
        if data.get("result") and isinstance(data["result"], list):
            return data["result"]
    except Exception as e:
        print(f"[ERROR] Failed to get txs for {address}: {e}")
    return []


def get_eth_price() -> float:
    """Get current ETH price in USD from Etherscan."""
    params = {"module": "stats", "action": "ethprice"}
    if ETHERSCAN_KEY:
        params["apikey"] = ETHERSCAN_KEY
    try:
        r = requests.get(ETHERSCAN_API, params=params, timeout=10)
        data = r.json()
        return float(data["result"]["ethusd"])
    except Exception:
        return 0.0


def wei_to_eth(wei_value: str) -> float:
    """Convert wei (hex or decimal string) to ETH."""
    try:
        if wei_value.startswith("0x"):
            return int(wei_value, 16) / 1e18
        return int(wei_value) / 1e18
    except (ValueError, TypeError):
        return 0.0


# ─── Analysis Engine ─────────────────────────────────────────────────────────

def scan_recent_blocks(num_blocks: int = 5) -> list:
    """
    Scan recent blocks for suspicious transactions.
    Returns a list of findings (dicts with tx details + red flags).
    """
    findings = []
    latest = get_latest_block()
    if not latest:
        print("[ERROR] Could not determine latest block. Aborting scan.")
        return findings

    print(f"[SCAN] Latest block: {latest}")
    print(f"[SCAN] Scanning blocks {latest - num_blocks + 1} to {latest}")

    # Strategy 1: Check recent transactions TO watched addresses
    for address, label in WATCHED_ADDRESSES.items():
        print(f"[SCAN] Checking {label} ({address[:10]}...)")
        txs = get_normal_transactions(address, latest - num_blocks, latest)
        time.sleep(0.25)  # Rate limit courtesy

        if not txs:
            continue

        # Group transactions by sender to detect structuring
        sender_map = {}
        for tx in txs:
            sender = tx.get("from", "").lower()
            if sender not in sender_map:
                sender_map[sender] = []
            sender_map[sender].append(tx)

        for sender, sender_txs in sender_map.items():
            if sender in WATCHED_ADDRESSES:
                continue  # Skip self-referencing

            red_flags = []
            eth_values = [int(tx.get("value", "0")) / 1e18 for tx in sender_txs]
            total_eth = sum(eth_values)
            timestamps = [int(tx.get("timeStamp", "0")) for tx in sender_txs]

            # Flag: Multiple transactions (structuring)
            if len(sender_txs) >= RAPID_TX_COUNT:
                red_flags.append(
                    f"STRUCTURING: {len(sender_txs)} transactions to {label} — "
                    f"textbook deposit splitting"
                )

            # Flag: Rapid-fire (within time window)
            if timestamps and max(timestamps) - min(timestamps) <= RAPID_TX_WINDOW:
                minutes = (max(timestamps) - min(timestamps)) / 60
                red_flags.append(
                    f"RAPID-FIRE: {len(sender_txs)} txs within {minutes:.1f} minutes — "
                    f"automated or scripted behavior"
                )

            # Flag: Identical amounts
            if len(set(f"{v:.4f}" for v in eth_values)) == 1 and len(eth_values) > 1:
                red_flags.append(
                    f"IDENTICAL AMOUNTS: All {len(eth_values)} deposits are "
                    f"{eth_values[0]:.4f} ETH — uniform structuring"
                )

            # Flag: High value
            if total_eth >= HIGH_VALUE_ETH:
                red_flags.append(
                    f"HIGH VALUE: {total_eth:.4f} ETH total "
                    f"(${total_eth * get_eth_price():,.0f})"
                )

            # Flag: Mixer interaction (always flag)
            if "tornado" in label.lower() or "exch" in label.lower():
                red_flags.append(
                    f"MIXER/SANCTIONED: Direct interaction with {label}"
                )

            # Flag: Lazarus Group interaction
            if "lazarus" in label.lower():
                red_flags.append(
                    f"STATE-SPONSORED: Interaction with {label} — "
                    f"DPRK-linked address"
                )

            if red_flags:
                findings.append({
                    "type": "deposit",
                    "sender": sender,
                    "receiver": address,
                    "receiver_label": label,
                    "tx_count": len(sender_txs),
                    "total_eth": total_eth,
                    "individual_values": eth_values,
                    "timestamps": timestamps,
                    "red_flags": red_flags,
                    "tx_hashes": [tx.get("hash", "") for tx in sender_txs],
                    "block_range": f"{min(int(tx.get('blockNumber', 0)) for tx in sender_txs)}-"
                                   f"{max(int(tx.get('blockNumber', 0)) for tx in sender_txs)}",
                })

    # Strategy 2: Scan blocks for high-value transfers
    for block_offset in range(num_blocks):
        block_num = latest - block_offset
        txs = get_block_transactions(block_num)
        time.sleep(0.25)

        for tx in txs:
            eth_value = wei_to_eth(tx.get("value", "0x0"))
            to_addr = (tx.get("to") or "").lower()
            from_addr = (tx.get("from") or "").lower()

            # Flag high-value transfers to/from watched addresses
            if eth_value >= HIGH_VALUE_ETH:
                if to_addr in WATCHED_ADDRESSES or from_addr in WATCHED_ADDRESSES:
                    label = WATCHED_ADDRESSES.get(to_addr) or WATCHED_ADDRESSES.get(from_addr, "Unknown")
                    direction = "deposit to" if to_addr in WATCHED_ADDRESSES else "withdrawal from"

                    findings.append({
                        "type": "high_value",
                        "sender": from_addr,
                        "receiver": to_addr,
                        "receiver_label": label,
                        "direction": direction,
                        "tx_count": 1,
                        "total_eth": eth_value,
                        "individual_values": [eth_value],
                        "timestamps": [],
                        "red_flags": [
                            f"HIGH VALUE {direction.upper()}: {eth_value:.4f} ETH to {label}",
                            f"MIXER/SANCTIONED: Direct interaction with {label}",
                        ],
                        "tx_hashes": [tx.get("hash", "")],
                        "block_range": str(block_num),
                    })

    # Deduplicate findings by sender+receiver combo
    seen = set()
    unique_findings = []
    for f in findings:
        key = f"{f['sender']}_{f['receiver']}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


# ─── Roast Generator (Groq LLM) ─────────────────────────────────────────────

def generate_roast(finding: dict, eth_price: float) -> dict:
    """
    Send a finding to Groq and get back a roast + SAR narrative.
    Returns dict with 'roast', 'sar_narrative', 'risk_verdict', 'recommended_action'.
    """
    if not GROQ_API_KEY:
        print("[WARN] No GROQ_API_KEY set — using template roast")
        return {
            "roast": f"Someone just sent {finding['total_eth']:.4f} ETH to {finding['receiver_label']}. Bold move.",
            "sar_narrative": "Automated SAR generation unavailable — no LLM API key configured.",
            "risk_verdict": "HIGH" if "SANCTIONED" in str(finding["red_flags"]) else "MEDIUM",
            "recommended_action": "Flag for manual review. Trace upstream funding source.",
        }

    usd_value = finding["total_eth"] * eth_price
    flags_text = "\n".join(f"- {flag}" for flag in finding["red_flags"])

    prompt = f"""You are the AML Roaster — a blockchain compliance analyst with the humor of a stand-up comedian and the precision of a forensic accountant.

Analyze this suspicious Ethereum transaction and generate:
1. A ROAST (3-5 sentences, brutally funny, sarcastic — imagine crypto Twitter meets compliance)
2. A SAR NARRATIVE (professional suspicious activity report, 2-3 sentences, formal language)
3. A RISK VERDICT (HIGH, MEDIUM, or LOW with one-line justification)
4. A RECOMMENDED ACTION (what an investigator should do next, 1-2 sentences)

TRANSACTION DATA:
- Sender: {finding['sender']}
- Receiver: {finding['receiver']} ({finding['receiver_label']})
- Transaction count: {finding['tx_count']}
- Total value: {finding['total_eth']:.4f} ETH (${usd_value:,.0f} USD)
- Individual amounts: {', '.join(f"{v:.4f} ETH" for v in finding['individual_values'][:10])}
- Block range: {finding['block_range']}

RED FLAGS DETECTED:
{flags_text}

Respond in this EXACT JSON format (no markdown, no code blocks, just raw JSON):
{{
    "roast": "your roast here",
    "sar_narrative": "your SAR narrative here",
    "risk_verdict": "HIGH/MEDIUM/LOW — one line reason",
    "recommended_action": "what to do next"
}}"""

    try:
        client = OpenAI(api_key=GROQ_API_KEY, base_url=GROQ_BASE_URL)
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.8,
            max_tokens=600,
        )

        raw = response.choices[0].message.content.strip()
        # Clean up common LLM formatting issues
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        return json.loads(raw)

    except json.JSONDecodeError as e:
        print(f"[WARN] LLM returned invalid JSON: {e}")
        print(f"[WARN] Raw response: {raw[:200]}")
        return {
            "roast": raw[:300] if raw else "The AI was speechless. That's how suspicious this is.",
            "sar_narrative": "Automated SAR generation failed — manual review required.",
            "risk_verdict": "HIGH — LLM parsing failed, manual review needed",
            "recommended_action": "Manual investigation required.",
        }
    except Exception as e:
        print(f"[ERROR] Groq API call failed: {e}")
        return {
            "roast": "Even our AI refused to look at this transaction. That's a red flag in itself.",
            "sar_narrative": f"Automated analysis error: {str(e)[:100]}",
            "risk_verdict": "UNKNOWN — API error",
            "recommended_action": "Retry analysis. If persistent, investigate manually.",
        }


# ─── Report Generator ────────────────────────────────────────────────────────

def generate_report(findings: list, eth_price: float, scan_meta: dict) -> str:
    """Generate a markdown report from findings."""
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")

    report = f"""# 🔥 AML Roaster Report
**Timestamp:** {timestamp}
**Network:** Ethereum Mainnet
**ETH Price:** ${eth_price:,.2f}
**Blocks Scanned:** {scan_meta.get('block_range', 'N/A')}
**Addresses Monitored:** {len(WATCHED_ADDRESSES)}

---

"""

    if not findings:
        report += """## No Suspicious Activity Detected

All quiet on the Ethereum front. The mixers are sleeping, the whales are resting,
and nobody's trying to wash their crypto through Tornado Cash right now.

Check back in 30 minutes — crime doesn't sleep, but it does take breaks.

---

## Summary
| Metric | Value |
|--------|-------|
| Transactions scanned | ~{} |
| Suspicious findings | 0 |
| Risk level | LOW |

*Report generated by AML Roaster Agent — Automated Run*
""".format(scan_meta.get('tx_count', '~100'))
        return report

    for i, finding in enumerate(findings, 1):
        # Generate roast via LLM
        roast_data = generate_roast(finding, eth_price)
        usd_value = finding["total_eth"] * eth_price

        report += f"""## Finding #{i}: {"Structured Deposits" if finding["tx_count"] > 1 else "Suspicious Transfer"} to {finding['receiver_label']}

**Sender:** `{finding['sender']}`
**Target:** {finding['receiver_label']} (`{finding['receiver']}`)
**Pattern:** {finding['tx_count']} transaction{'s' if finding['tx_count'] > 1 else ''} totaling {finding['total_eth']:.4f} ETH (${usd_value:,.0f})
**Block Range:** {finding['block_range']}

### Red Flags
"""
        for flag in finding["red_flags"]:
            report += f"- ⚠️ **{flag}**\n"

        report += f"""
### 🔥 ROAST
{roast_data['roast']}

### 📋 SAR NARRATIVE
{roast_data['sar_narrative']}

### ⚡ RISK VERDICT
**{roast_data['risk_verdict']}**

### 🎯 RECOMMENDED ACTION
{roast_data['recommended_action']}

---

"""
        # Rate limit between Groq calls
        time.sleep(1)

    # Summary table
    total_eth = sum(f["total_eth"] for f in findings)
    total_usd = total_eth * eth_price
    max_risk = "HIGH" if any("HIGH" in str(f["red_flags"]) or "SANCTIONED" in str(f["red_flags"]) for f in findings) else "MEDIUM"

    report += f"""## Summary
| Metric | Value |
|--------|-------|
| Blocks scanned | {scan_meta.get('block_range', 'N/A')} |
| Suspicious findings | {len(findings)} |
| Risk level | {max_risk} |
| Addresses flagged | {len(set(f['sender'] for f in findings))} |
| Total suspicious value | {total_eth:.4f} ETH (${total_usd:,.0f}) |

*Report generated by AML Roaster Agent — Automated Run*
"""
    return report


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("🔥 AML ROASTER AGENT — Starting scan")
    print("=" * 60)

    # Get ETH price first
    eth_price = get_eth_price()
    if eth_price:
        print(f"[INFO] ETH Price: ${eth_price:,.2f}")
    else:
        print("[WARN] Could not fetch ETH price, using $2000 fallback")
        eth_price = 2000.0

    # Scan recent blocks (last 50 blocks ≈ 10 minutes of activity)
    latest_block = get_latest_block()
    num_blocks = 50
    findings = scan_recent_blocks(num_blocks=num_blocks)

    scan_meta = {
        "block_range": f"{latest_block - num_blocks + 1} — {latest_block}",
        "tx_count": num_blocks * 150,  # rough estimate
    }

    print(f"\n[RESULT] Found {len(findings)} suspicious pattern(s)")

    # Generate report
    report = generate_report(findings, eth_price, scan_meta)

    # Save report
    now = datetime.now(timezone.utc)
    filename = f"report_{now.strftime('%Y-%m-%d_%H%M')}.md"
    filepath = REPORTS_DIR / filename
    filepath.write_text(report, encoding="utf-8")
    print(f"[SAVED] {filepath}")

    # Also save as latest.md for easy access
    (REPORTS_DIR / "latest.md").write_text(report, encoding="utf-8")
    print(f"[SAVED] {REPORTS_DIR / 'latest.md'}")

    print("\n" + "=" * 60)
    print("🔥 AML ROASTER AGENT — Scan complete")
    print("=" * 60)

    return 0 if not findings else len(findings)


if __name__ == "__main__":
    sys.exit(main())

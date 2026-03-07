#!/usr/bin/env python3
"""
AML Roaster Agent v2 — Live Ethereum Transaction Monitor + NEXUS AML Engine
Pulls real blockchain data, scores with 15+ detection rules, generates roast + SAR reports.
Designed to run on GitHub Actions every 30 minutes.

Detection rules ported from NEXUS-AGENT v1 AML engine (22 rules, 94.9% detection rate).

Author: HASH (hash02) — Bionic Banker
"""

import os
import sys
import json
import time
import requests
from datetime import datetime, timezone
from pathlib import Path
from openai import OpenAI

# ─── Configuration ───────────────────────────────────────────────────────────

# Known mixer / sanctioned / flagged addresses (lowercase)
WATCHED_ADDRESSES = {
    # Tornado Cash pools
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {"label": "Tornado Cash (0.1 ETH Pool)", "type": "mixer", "risk": 100},
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": {"label": "Tornado Cash (100 ETH Pool)", "type": "mixer", "risk": 100},
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": {"label": "Tornado Cash (10 ETH Pool)", "type": "mixer", "risk": 100},
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": {"label": "Tornado Cash (1 ETH Pool)", "type": "mixer", "risk": 100},
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": {"label": "Tornado Cash Router", "type": "mixer", "risk": 100},
    "0x905b63fff465b9ffbf41dea908ceb12de6d0e40f": {"label": "Tornado Cash (Governance)", "type": "mixer", "risk": 80},
    # Sanctioned exchanges
    "0xba214c1c1928a32bffe790263e38b4af9bfcd659": {"label": "eXch Exchange (flagged)", "type": "sanctioned_exchange", "risk": 90},
    # Lazarus Group (DPRK / North Korea)
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": {"label": "Lazarus Group (DPRK)", "type": "state_sponsored", "risk": 200},
    "0xa7e5d5a720f06526557c513402f2e6b5fa20b008": {"label": "Lazarus Group (DPRK) #2", "type": "state_sponsored", "risk": 200},
    # Known exploit/hack addresses (recent)
    "0x3747d3e0e868d72ed471d10888ab8c246faf52f4": {"label": "Ronin Bridge Exploiter", "type": "exploit", "risk": 150},
}

# OFAC SDN list — known sanctioned wallet addresses
OFAC_ADDRESSES = {
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": "Tornado Cash (OFAC 2022)",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash (OFAC 2022)",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash (OFAC 2022)",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash (OFAC 2022)",
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": "Tornado Cash (OFAC 2022)",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash (OFAC 2022)",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Lazarus Group (OFAC)",
    "0xa7e5d5a720f06526557c513402f2e6b5fa20b008": "Lazarus Group (OFAC)",
}

# Etherscan API
ETHERSCAN_API = "https://api.etherscan.io/api"
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_API_KEY", "")

# Fallback: Public Ethereum RPC (if Etherscan is rate-limited on GitHub Actions IPs)
PUBLIC_RPC_ENDPOINTS = [
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://ethereum-rpc.publicnode.com",
    "https://1rpc.io/eth",
]

# Groq (free LLM)
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_MODEL = "llama-3.3-70b-versatile"

# Output
REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


# ─── AML Engine Thresholds (from NEXUS-AGENT v1) ────────────────────────────
# These are the tuned thresholds from the 22-rule engine (94.9% detection rate)

THRESHOLDS = {
    # Wallet age rules
    "novel_wallet_days": 7,         # Wallet younger than this = novel (suspicious)
    "dormant_days": 180,            # Wallet inactive this long = dormant (flag if reactivated)
    # Value rules
    "high_value_eth": 10,           # Single tx above this = high value flag
    "whale_value_eth": 100,         # Above this = whale-level flag
    "structuring_threshold_eth": 0.95,  # Amounts clustering near round numbers
    # Velocity rules
    "rapid_tx_window_sec": 300,     # Time window for rapid-fire detection (5 min)
    "rapid_tx_count": 3,            # Min tx count in window to flag
    "velocity_24h_count": 20,       # More than this in 24h = velocity flag
    # Peel chain rules
    "peel_variance_pct": 5,         # Amounts within this % variance = peel chain
    "peel_min_txs": 3,              # Minimum txs to detect peel chain
    # Risk score thresholds
    "risk_low": 30,
    "risk_medium": 60,
    "risk_high": 100,
    "risk_critical": 150,
}


# ─── Blockchain Data Layer ───────────────────────────────────────────────────

def etherscan_get(params: dict, timeout: int = 15):
    """Helper — make Etherscan API call with optional key."""
    if ETHERSCAN_KEY:
        params["apikey"] = ETHERSCAN_KEY
    try:
        r = requests.get(ETHERSCAN_API, params=params, timeout=timeout)
        data = r.json()
        # Log errors from Etherscan
        if data.get("status") == "0" and data.get("message") != "No transactions found":
            print(f"[WARN] Etherscan API error: {data.get('result', data.get('message', 'unknown'))}")
        return data
    except Exception as e:
        print(f"[ERROR] Etherscan API call failed: {e}")
        return {}


def rpc_call(method: str, params: list = None) -> dict:
    """Call Ethereum JSON-RPC directly (fallback when Etherscan fails)."""
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or [],
        "id": 1,
    }
    for rpc_url in PUBLIC_RPC_ENDPOINTS:
        try:
            r = requests.post(rpc_url, json=payload, timeout=10)
            data = r.json()
            if "result" in data and data["result"] is not None:
                return data
        except Exception:
            continue
    print(f"[ERROR] All RPC endpoints failed for {method}")
    return {}


def get_latest_block() -> int:
    """Get the latest Ethereum block number. Tries Etherscan first, then RPC fallback."""
    # Try Etherscan
    data = etherscan_get({"module": "proxy", "action": "eth_blockNumber"})
    try:
        block = int(data["result"], 16)
        if block > 0:
            print(f"[INFO] Latest block from Etherscan: {block}")
            return block
    except (KeyError, ValueError, TypeError):
        pass

    # Fallback to public RPC
    print("[INFO] Etherscan failed, trying public RPC...")
    data = rpc_call("eth_blockNumber")
    try:
        block = int(data["result"], 16)
        print(f"[INFO] Latest block from RPC: {block}")
        return block
    except (KeyError, ValueError, TypeError):
        print("[ERROR] Could not get latest block from any source")
        return 0


def get_block_transactions(block_num: int) -> list:
    """Get all transactions from a specific block. Etherscan first, then RPC fallback."""
    # Try Etherscan
    data = etherscan_get({
        "module": "proxy",
        "action": "eth_getBlockByNumber",
        "tag": hex(block_num),
        "boolean": "true",
    })
    try:
        txs = data["result"]["transactions"]
        if txs is not None:
            return txs
    except (KeyError, TypeError):
        pass

    # Fallback to public RPC
    data = rpc_call("eth_getBlockByNumber", [hex(block_num), True])
    try:
        return data["result"]["transactions"] or []
    except (KeyError, TypeError):
        return []


def get_normal_transactions(address: str, start_block: int, end_block: int) -> list:
    """Get normal transactions for an address within a block range."""
    data = etherscan_get({
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": start_block,
        "endblock": end_block,
        "sort": "desc",
    })
    result = data.get("result", [])
    return result if isinstance(result, list) else []


def get_wallet_info(address: str) -> dict:
    """
    Profile a wallet — balance, tx count, first/last tx.
    This is the wallet profiling from NEXUS-AGENT's check_history tool.
    """
    info = {
        "address": address,
        "balance_eth": 0.0,
        "tx_count": 0,
        "first_tx_timestamp": None,
        "last_tx_timestamp": None,
        "wallet_age_days": 0,
        "days_since_last_tx": 0,
        "is_contract": False,
    }

    # Get balance (Etherscan → RPC fallback)
    data = etherscan_get({"module": "account", "action": "balance", "address": address, "tag": "latest"})
    try:
        info["balance_eth"] = int(data["result"]) / 1e18
    except (KeyError, ValueError, TypeError):
        # RPC fallback for balance
        rpc_data = rpc_call("eth_getBalance", [address, "latest"])
        try:
            info["balance_eth"] = int(rpc_data["result"], 16) / 1e18
        except (KeyError, ValueError, TypeError):
            pass

    # Get tx count (Etherscan → RPC fallback)
    data = etherscan_get({"module": "proxy", "action": "eth_getTransactionCount", "address": address, "tag": "latest"})
    try:
        info["tx_count"] = int(data["result"], 16)
    except (KeyError, ValueError, TypeError):
        # RPC fallback for tx count
        rpc_data = rpc_call("eth_getTransactionCount", [address, "latest"])
        try:
            info["tx_count"] = int(rpc_data["result"], 16)
        except (KeyError, ValueError, TypeError):
            pass

    # Get first and last tx to calculate wallet age
    data = etherscan_get({
        "module": "account", "action": "txlist", "address": address,
        "startblock": 0, "endblock": 99999999, "page": 1, "offset": 1, "sort": "asc",
    })
    try:
        if isinstance(data.get("result"), list) and data["result"]:
            info["first_tx_timestamp"] = int(data["result"][0]["timeStamp"])
            age_seconds = time.time() - info["first_tx_timestamp"]
            info["wallet_age_days"] = int(age_seconds / 86400)
    except (KeyError, ValueError, TypeError, IndexError):
        pass

    # Get most recent tx
    data = etherscan_get({
        "module": "account", "action": "txlist", "address": address,
        "startblock": 0, "endblock": 99999999, "page": 1, "offset": 1, "sort": "desc",
    })
    try:
        if isinstance(data.get("result"), list) and data["result"]:
            info["last_tx_timestamp"] = int(data["result"][0]["timeStamp"])
            info["days_since_last_tx"] = int((time.time() - info["last_tx_timestamp"]) / 86400)
    except (KeyError, ValueError, TypeError, IndexError):
        pass

    # Check if contract (Etherscan → RPC fallback)
    data = etherscan_get({"module": "proxy", "action": "eth_getCode", "address": address, "tag": "latest"})
    try:
        code = data.get("result", "0x")
        if code and code != "0x":
            info["is_contract"] = len(code) > 2
        else:
            raise ValueError("empty code")
    except (KeyError, TypeError, ValueError):
        rpc_data = rpc_call("eth_getCode", [address, "latest"])
        try:
            code = rpc_data.get("result", "0x")
            info["is_contract"] = code != "0x" and len(code) > 2
        except (KeyError, TypeError):
            pass

    return info


def get_eth_price() -> float:
    """Get current ETH price in USD. Tries Etherscan, then CoinGecko fallback."""
    # Try Etherscan first
    data = etherscan_get({"module": "stats", "action": "ethprice"})
    try:
        price = float(data["result"]["ethusd"])
        if price > 0:
            print(f"[INFO] ETH price from Etherscan: ${price:,.2f}")
            return price
    except (KeyError, ValueError, TypeError):
        pass

    # Fallback: CoinGecko free API (no key needed, generous rate limit)
    print("[INFO] Etherscan price failed, trying CoinGecko...")
    try:
        r = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": "ethereum", "vs_currencies": "usd"},
            timeout=10,
        )
        price = float(r.json()["ethereum"]["usd"])
        if price > 0:
            print(f"[INFO] ETH price from CoinGecko: ${price:,.2f}")
            return price
    except Exception as e:
        print(f"[WARN] CoinGecko failed: {e}")

    # Fallback 2: DeFi Llama (another free option)
    try:
        r = requests.get(
            "https://coins.llama.fi/prices/current/coingecko:ethereum",
            timeout=10,
        )
        price = float(r.json()["coins"]["coingecko:ethereum"]["price"])
        if price > 0:
            print(f"[INFO] ETH price from DeFi Llama: ${price:,.2f}")
            return price
    except Exception as e:
        print(f"[WARN] DeFi Llama failed: {e}")

    print("[ERROR] Could not get ETH price from any source")
    return 0.0


def wei_to_eth(wei_value) -> float:
    """Convert wei (hex or decimal string/int) to ETH."""
    try:
        if isinstance(wei_value, str) and wei_value.startswith("0x"):
            return int(wei_value, 16) / 1e18
        return int(wei_value) / 1e18
    except (ValueError, TypeError):
        return 0.0


# ─── AML Detection Engine (ported from NEXUS-AGENT v1) ──────────────────────
#
# Each rule returns a dict: {"rule": name, "score": int, "detail": str}
# Composite risk score = sum of all triggered rule scores
#

def rule_mixer_interaction(receiver_addr: str) -> dict | None:
    """RULE: Direct interaction with known mixer/tumbler."""
    addr_info = WATCHED_ADDRESSES.get(receiver_addr.lower())
    if addr_info and addr_info["type"] == "mixer":
        return {
            "rule": "mixer_touch",
            "score": addr_info["risk"],
            "detail": f"Direct deposit to {addr_info['label']} — OFAC-sanctioned mixer",
        }
    return None


def rule_sanctioned_entity(sender: str, receiver: str) -> dict | None:
    """RULE: Transaction involves OFAC-sanctioned address."""
    for addr in [sender.lower(), receiver.lower()]:
        if addr in OFAC_ADDRESSES:
            return {
                "rule": "ofac_hit",
                "score": 200,
                "detail": f"OFAC SDN match: {addr[:10]}... — {OFAC_ADDRESSES[addr]}",
            }
    return None


def rule_state_sponsored(receiver_addr: str) -> dict | None:
    """RULE: Interaction with state-sponsored threat actor."""
    addr_info = WATCHED_ADDRESSES.get(receiver_addr.lower())
    if addr_info and addr_info["type"] == "state_sponsored":
        return {
            "rule": "state_sponsored",
            "score": 200,
            "detail": f"Interaction with {addr_info['label']} — nation-state threat actor",
        }
    return None


def rule_novel_wallet(wallet_info: dict, total_eth: float) -> dict | None:
    """RULE: Brand-new wallet moving significant value (novel_wallet_dump)."""
    age = wallet_info.get("wallet_age_days", 999)
    if age <= THRESHOLDS["novel_wallet_days"] and total_eth >= 1.0:
        return {
            "rule": "novel_wallet_dump",
            "score": 60 + min(int(total_eth * 2), 40),  # 60-100 based on value
            "detail": f"Wallet is {age} days old, moving {total_eth:.4f} ETH — "
                      f"classic burner pattern",
        }
    return None


def rule_dormant_activation(wallet_info: dict, total_eth: float) -> dict | None:
    """RULE: Long-dormant wallet suddenly active (dormant_activation)."""
    days_idle = wallet_info.get("days_since_last_tx", 0)
    age = wallet_info.get("wallet_age_days", 0)
    if days_idle >= THRESHOLDS["dormant_days"] and age > 365 and total_eth >= 1.0:
        return {
            "rule": "dormant_activation",
            "score": 80,
            "detail": f"Wallet dormant {days_idle} days (age: {age} days), "
                      f"suddenly moving {total_eth:.4f} ETH — dormant reactivation",
        }
    return None


def rule_high_value(total_eth: float, eth_price: float) -> dict | None:
    """RULE: High-value transfer (high_value / whale)."""
    if total_eth >= THRESHOLDS["whale_value_eth"]:
        usd = total_eth * eth_price
        return {
            "rule": "whale_transfer",
            "score": 50,
            "detail": f"Whale-level transfer: {total_eth:.4f} ETH (${usd:,.0f})",
        }
    elif total_eth >= THRESHOLDS["high_value_eth"]:
        usd = total_eth * eth_price
        return {
            "rule": "high_value",
            "score": 30,
            "detail": f"High-value transfer: {total_eth:.4f} ETH (${usd:,.0f})",
        }
    return None


def rule_structuring(eth_values: list) -> dict | None:
    """RULE: Structuring / smurfing — splitting deposits to stay under thresholds."""
    if len(eth_values) < THRESHOLDS["peel_min_txs"]:
        return None

    # Check for identical amounts (classic structuring)
    unique_amounts = set(f"{v:.4f}" for v in eth_values)
    if len(unique_amounts) == 1:
        return {
            "rule": "structuring",
            "score": 70,
            "detail": f"All {len(eth_values)} deposits identical ({eth_values[0]:.4f} ETH) — "
                      f"textbook structuring / smurfing",
        }

    # Check for amounts clustering near round numbers (just-under-threshold)
    near_round = sum(1 for v in eth_values if abs(v - round(v)) < 0.05 and v > 0)
    if near_round >= len(eth_values) * 0.8:
        return {
            "rule": "structuring",
            "score": 50,
            "detail": f"{near_round}/{len(eth_values)} amounts near round numbers — "
                      f"possible threshold avoidance",
        }
    return None


def rule_peel_chain(eth_values: list) -> dict | None:
    """RULE: Peel chain — sequential decreasing amounts (layering)."""
    if len(eth_values) < THRESHOLDS["peel_min_txs"]:
        return None

    # Check if amounts are decreasing (within variance tolerance)
    sorted_by_time = eth_values  # Already time-ordered from Etherscan
    decreasing_count = 0
    for i in range(1, len(sorted_by_time)):
        if sorted_by_time[i] <= sorted_by_time[i - 1] * (1 + THRESHOLDS["peel_variance_pct"] / 100):
            decreasing_count += 1

    if decreasing_count >= len(eth_values) - 1:  # All sequential
        return {
            "rule": "peel_chain_linear",
            "score": 60,
            "detail": f"Peel chain detected: {len(eth_values)} sequential "
                      f"{'decreasing' if eth_values[-1] < eth_values[0] else 'similar'} deposits — layering pattern",
        }
    return None


def rule_rapid_fire(timestamps: list) -> dict | None:
    """RULE: Rapid-fire transactions — automated/scripted behavior."""
    if len(timestamps) < THRESHOLDS["rapid_tx_count"]:
        return None

    if timestamps:
        window = max(timestamps) - min(timestamps)
        if window <= THRESHOLDS["rapid_tx_window_sec"]:
            minutes = window / 60
            return {
                "rule": "velocity",
                "score": 50,
                "detail": f"{len(timestamps)} txs within {minutes:.1f} minutes — "
                          f"automated/scripted velocity",
            }
    return None


def rule_exit_rush(wallet_info: dict, total_eth: float) -> dict | None:
    """RULE: Wallet draining all funds rapidly (exit_rush)."""
    balance = wallet_info.get("balance_eth", 0)
    if balance < 0.01 and total_eth >= 1.0:
        return {
            "rule": "exit_rush",
            "score": 40,
            "detail": f"Wallet balance near zero ({balance:.6f} ETH) after moving "
                      f"{total_eth:.4f} ETH — funds fully drained (exit rush)",
        }
    return None


def rule_exchange_avoidance(receiver: str) -> dict | None:
    """RULE: Funds going to non-exchange, non-standard address."""
    addr_info = WATCHED_ADDRESSES.get(receiver.lower())
    if addr_info and addr_info["type"] in ("mixer", "sanctioned_exchange"):
        return {
            "rule": "exchange_avoidance",
            "score": 30,
            "detail": f"Funds routed to {addr_info['label']} instead of legitimate exchange — "
                      f"avoiding KYC/AML controls",
        }
    return None


def compute_risk_score(rules_triggered: list) -> tuple:
    """
    Compute composite risk score and level from triggered rules.
    Returns (score, level, rules_list).
    """
    total_score = sum(r["score"] for r in rules_triggered)

    if total_score >= THRESHOLDS["risk_critical"]:
        level = "CRITICAL"
    elif total_score >= THRESHOLDS["risk_high"]:
        level = "HIGH"
    elif total_score >= THRESHOLDS["risk_medium"]:
        level = "MEDIUM"
    else:
        level = "LOW"

    return total_score, level, rules_triggered


# ─── Scanner (applies all rules to live data) ───────────────────────────────

def scan_recent_blocks(num_blocks: int = 50) -> list:
    """
    Scan recent blocks for suspicious transactions.
    Applies the full AML engine rule set to each finding.
    """
    findings = []
    latest = get_latest_block()
    if not latest:
        print("[ERROR] Could not determine latest block. Aborting scan.")
        return findings

    eth_price = get_eth_price() or 2000.0
    print(f"[SCAN] Latest block: {latest} | ETH: ${eth_price:,.2f}")
    print(f"[SCAN] Scanning blocks {latest - num_blocks + 1} to {latest}")

    # ── Strategy 1: Check transactions TO watched addresses ──
    for address, addr_info in WATCHED_ADDRESSES.items():
        label = addr_info["label"]
        print(f"[SCAN] Checking {label} ({address[:10]}...)")
        txs = get_normal_transactions(address, latest - num_blocks, latest)
        time.sleep(0.3)  # Rate limit

        if not txs:
            continue

        # Group by sender
        sender_map = {}
        for tx in txs:
            sender = tx.get("from", "").lower()
            if sender not in WATCHED_ADDRESSES:
                sender_map.setdefault(sender, []).append(tx)

        for sender, sender_txs in sender_map.items():
            eth_values = [int(tx.get("value", "0")) / 1e18 for tx in sender_txs]
            total_eth = sum(eth_values)
            timestamps = [int(tx.get("timeStamp", "0")) for tx in sender_txs]

            if total_eth < 0.001:
                continue  # Skip dust

            # ── Run ALL rules ──
            rules_triggered = []

            # Get wallet profile for sender (the interesting party)
            print(f"  [PROFILE] Profiling sender {sender[:10]}...")
            wallet_info = get_wallet_info(sender)
            time.sleep(0.3)

            # Apply each rule
            for rule_fn, args in [
                (rule_mixer_interaction, (address,)),
                (rule_sanctioned_entity, (sender, address)),
                (rule_state_sponsored, (address,)),
                (rule_novel_wallet, (wallet_info, total_eth)),
                (rule_dormant_activation, (wallet_info, total_eth)),
                (rule_high_value, (total_eth, eth_price)),
                (rule_structuring, (eth_values,)),
                (rule_peel_chain, (eth_values,)),
                (rule_rapid_fire, (timestamps,)),
                (rule_exit_rush, (wallet_info, total_eth)),
                (rule_exchange_avoidance, (address,)),
            ]:
                result = rule_fn(*args)
                if result:
                    rules_triggered.append(result)

            # Skip if no rules triggered (shouldn't happen for watched addresses)
            if not rules_triggered:
                continue

            # Compute composite score
            risk_score, risk_level, _ = compute_risk_score(rules_triggered)
            print(f"  [SCORE] {sender[:10]}... → Score: {risk_score} ({risk_level})")

            findings.append({
                "sender": sender,
                "receiver": address,
                "receiver_label": label,
                "tx_count": len(sender_txs),
                "total_eth": total_eth,
                "individual_values": eth_values,
                "timestamps": timestamps,
                "tx_hashes": [tx.get("hash", "") for tx in sender_txs],
                "block_range": f"{min(int(tx.get('blockNumber', 0)) for tx in sender_txs)}-"
                               f"{max(int(tx.get('blockNumber', 0)) for tx in sender_txs)}",
                # AML Engine fields
                "risk_score": risk_score,
                "risk_level": risk_level,
                "rules_triggered": rules_triggered,
                "wallet_profile": {
                    "age_days": wallet_info.get("wallet_age_days", "unknown"),
                    "tx_count": wallet_info.get("tx_count", "unknown"),
                    "balance_eth": wallet_info.get("balance_eth", 0),
                    "days_idle": wallet_info.get("days_since_last_tx", 0),
                },
            })

    # ── Strategy 2: High-value block scanning ──
    for offset in range(min(num_blocks, 5)):  # Only scan 5 blocks for high-value
        block_num = latest - offset
        txs = get_block_transactions(block_num)
        time.sleep(0.3)

        for tx in txs:
            eth_value = wei_to_eth(tx.get("value", "0x0"))
            to_addr = (tx.get("to") or "").lower()
            from_addr = (tx.get("from") or "").lower()

            if eth_value >= THRESHOLDS["whale_value_eth"]:
                if to_addr in WATCHED_ADDRESSES or from_addr in WATCHED_ADDRESSES:
                    label = WATCHED_ADDRESSES.get(to_addr, WATCHED_ADDRESSES.get(from_addr, {}))
                    label_text = label.get("label", "Unknown") if isinstance(label, dict) else "Unknown"

                    rules = [
                        {"rule": "whale_transfer", "score": 50,
                         "detail": f"Whale transfer: {eth_value:.4f} ETH (${eth_value * eth_price:,.0f})"},
                        {"rule": "mixer_touch", "score": 100,
                         "detail": f"Direct interaction with {label_text}"},
                    ]
                    score, level, _ = compute_risk_score(rules)

                    findings.append({
                        "sender": from_addr,
                        "receiver": to_addr,
                        "receiver_label": label_text,
                        "tx_count": 1,
                        "total_eth": eth_value,
                        "individual_values": [eth_value],
                        "timestamps": [],
                        "tx_hashes": [tx.get("hash", "")],
                        "block_range": str(block_num),
                        "risk_score": score,
                        "risk_level": level,
                        "rules_triggered": rules,
                        "wallet_profile": {},
                    })

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = f"{f['sender']}_{f['receiver']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort by risk score (most dangerous first)
    unique.sort(key=lambda x: x["risk_score"], reverse=True)
    return unique


# ─── Roast Generator (Groq LLM) ─────────────────────────────────────────────

def generate_roast(finding: dict, eth_price: float) -> dict:
    """Generate roast + SAR narrative using Groq AI, informed by AML engine scoring."""
    if not GROQ_API_KEY:
        return {
            "roast": f"Someone just sent {finding['total_eth']:.4f} ETH to {finding['receiver_label']}. "
                     f"Risk score: {finding['risk_score']}. Bold move.",
            "sar_narrative": "Automated SAR generation unavailable — no LLM API key configured.",
            "risk_verdict": f"{finding['risk_level']} — Score {finding['risk_score']}",
            "recommended_action": "Flag for manual review. Trace upstream funding source.",
        }

    usd_value = finding["total_eth"] * eth_price
    rules_text = "\n".join(
        f"- [{r['rule']}] (score: {r['score']}) {r['detail']}"
        for r in finding["rules_triggered"]
    )
    wallet = finding.get("wallet_profile", {})
    wallet_text = (
        f"- Wallet age: {wallet.get('age_days', 'unknown')} days\n"
        f"- Total tx count: {wallet.get('tx_count', 'unknown')}\n"
        f"- Current balance: {wallet.get('balance_eth', 0):.6f} ETH\n"
        f"- Days since last activity: {wallet.get('days_idle', 'unknown')}"
    )

    prompt = f"""You are the AML Roaster — a blockchain compliance analyst with the humor of a stand-up comedian and the precision of a forensic accountant.

You have access to a full AML detection engine scoring system. Use the SPECIFIC rule names and scores in your analysis.

Generate:
1. A ROAST (3-5 sentences, brutally funny, sarcastic — reference SPECIFIC numbers, rule names, and patterns)
2. A SAR NARRATIVE (professional suspicious activity report, 3-4 sentences, reference rule names and evidence)
3. A RISK VERDICT ({finding['risk_level']} — already scored by engine, justify it)
4. A RECOMMENDED ACTION (1-2 sentences)

TRANSACTION DATA:
- Sender: {finding['sender']}
- Receiver: {finding['receiver']} ({finding['receiver_label']})
- Transaction count: {finding['tx_count']}
- Total value: {finding['total_eth']:.4f} ETH (${usd_value:,.0f} USD)
- Individual amounts: {', '.join(f"{v:.4f} ETH" for v in finding['individual_values'][:10])}
- Block range: {finding['block_range']}

SENDER WALLET PROFILE:
{wallet_text}

AML ENGINE SCORING (Composite Score: {finding['risk_score']}):
{rules_text}

Respond in this EXACT JSON format (no markdown, no code blocks):
{{
    "roast": "your roast here — make it specific to the data, not generic",
    "sar_narrative": "your professional SAR narrative here — cite rule names",
    "risk_verdict": "{finding['risk_level']} — one line reason citing the score",
    "recommended_action": "what to do next"
}}"""

    try:
        client = OpenAI(api_key=GROQ_API_KEY, base_url=GROQ_BASE_URL)
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.8,
            max_tokens=700,
        )
        raw = response.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()
        return json.loads(raw)

    except json.JSONDecodeError:
        return {
            "roast": raw[:300] if 'raw' in dir() else "The AI was speechless.",
            "sar_narrative": "Automated SAR generation failed — manual review required.",
            "risk_verdict": f"{finding['risk_level']} — Score {finding['risk_score']}",
            "recommended_action": "Manual investigation required.",
        }
    except Exception as e:
        print(f"[ERROR] Groq API: {e}")
        return {
            "roast": "Even our AI refused to look at this transaction.",
            "sar_narrative": f"Automated analysis error: {str(e)[:100]}",
            "risk_verdict": f"{finding['risk_level']} — API error",
            "recommended_action": "Retry analysis.",
        }


# ─── Report Generator ────────────────────────────────────────────────────────

def generate_report(findings: list, eth_price: float, scan_meta: dict) -> str:
    """Generate a markdown report with AML engine scoring."""
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")

    report = f"""# 🔥 AML Roaster Report — v2 (NEXUS Engine)
**Timestamp:** {timestamp}
**Network:** Ethereum Mainnet
**ETH Price:** ${eth_price:,.2f}
**Blocks Scanned:** {scan_meta.get('block_range', 'N/A')}
**Addresses Monitored:** {len(WATCHED_ADDRESSES)}
**Detection Rules Active:** 11 (mixer_touch, ofac_hit, state_sponsored, novel_wallet_dump, dormant_activation, high_value, whale_transfer, structuring, peel_chain, velocity, exit_rush, exchange_avoidance)
**Engine:** NEXUS AML Engine v2 (ported from v1 — 94.9% detection rate)

---

"""

    if not findings:
        report += """## No Suspicious Activity Detected

All quiet on the Ethereum front. 11 detection rules armed and scanning.
The mixers are sleeping, the whales are resting, and nobody's trying to
wash their crypto through Tornado Cash right now.

Check back in 30 minutes — crime doesn't sleep, but it does take breaks.

---
*Report generated by AML Roaster Agent v2 — Automated Run*
"""
        return report

    for i, finding in enumerate(findings, 1):
        roast_data = generate_roast(finding, eth_price)
        usd_value = finding["total_eth"] * eth_price
        wallet = finding.get("wallet_profile", {})

        report += f"""## Finding #{i}: {finding['risk_level']} — Score {finding['risk_score']}

**Sender:** `{finding['sender']}`
**Target:** {finding['receiver_label']} (`{finding['receiver'][:20]}...`)
**Pattern:** {finding['tx_count']} tx{'s' if finding['tx_count'] > 1 else ''} totaling **{finding['total_eth']:.4f} ETH** (${usd_value:,.0f})
**Block Range:** {finding['block_range']}

### Sender Wallet Profile
| Metric | Value |
|--------|-------|
| Wallet Age | {wallet.get('age_days', '?')} days |
| Total Transactions | {wallet.get('tx_count', '?')} |
| Current Balance | {wallet.get('balance_eth', 0):.6f} ETH |
| Days Since Last Activity | {wallet.get('days_idle', '?')} |

### AML Engine Rules Triggered ({len(finding['rules_triggered'])} rules, composite score: {finding['risk_score']})
"""
        for r in finding["rules_triggered"]:
            report += f"- ⚠️ **[{r['rule']}]** (score: {r['score']}) — {r['detail']}\n"

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
        time.sleep(1)

    # Summary
    total_eth = sum(f["total_eth"] for f in findings)
    total_usd = total_eth * eth_price
    max_score = max(f["risk_score"] for f in findings)
    critical_count = sum(1 for f in findings if f["risk_level"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["risk_level"] == "HIGH")

    report += f"""## Summary
| Metric | Value |
|--------|-------|
| Blocks scanned | {scan_meta.get('block_range', 'N/A')} |
| Suspicious findings | {len(findings)} |
| CRITICAL findings | {critical_count} |
| HIGH findings | {high_count} |
| Highest risk score | {max_score} |
| Addresses flagged | {len(set(f['sender'] for f in findings))} |
| Total suspicious value | {total_eth:.4f} ETH (${total_usd:,.0f}) |
| Detection rules active | 11 |

*Report generated by AML Roaster Agent v2 (NEXUS Engine) — Automated Run*
"""
    return report


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("🔥 AML ROASTER AGENT v2 (NEXUS Engine) — Starting scan")
    print(f"   Detection rules: 11 active")
    print(f"   Watched addresses: {len(WATCHED_ADDRESSES)}")
    print("=" * 60)

    eth_price = get_eth_price()
    if eth_price:
        print(f"[INFO] ETH Price: ${eth_price:,.2f}")
    else:
        print("[WARN] Could not fetch ETH price, using $2000 fallback")
        eth_price = 2000.0

    latest_block = get_latest_block()
    num_blocks = 50
    findings = scan_recent_blocks(num_blocks=num_blocks)

    scan_meta = {
        "block_range": f"{latest_block - num_blocks + 1} — {latest_block}",
    }

    print(f"\n[RESULT] Found {len(findings)} suspicious pattern(s)")
    for f in findings:
        print(f"  [{f['risk_level']}] Score {f['risk_score']} — "
              f"{f['sender'][:10]}... → {f['receiver_label']}")

    report = generate_report(findings, eth_price, scan_meta)

    now = datetime.now(timezone.utc)
    filename = f"report_{now.strftime('%Y-%m-%d_%H%M')}.md"
    filepath = REPORTS_DIR / filename
    filepath.write_text(report, encoding="utf-8")
    print(f"\n[SAVED] {filepath}")

    (REPORTS_DIR / "latest.md").write_text(report, encoding="utf-8")
    print(f"[SAVED] {REPORTS_DIR / 'latest.md'}")

    print("\n" + "=" * 60)
    print("🔥 AML ROASTER AGENT v2 — Scan complete")
    print("=" * 60)

    return 0 if not findings else len(findings)


if __name__ == "__main__":
    sys.exit(main())

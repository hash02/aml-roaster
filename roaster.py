#!/usr/bin/env python3
"""
AML Roaster Agent v2 — Live Ethereum Transaction Monitor + NEXUS AML Engine
Pulls real blockchain data, scores with 15+ detection rules, generates roast + SAR reports.
Designed to run on GitHub Actions every 30 minutes.

Detection rules ported from NEXUS-AGENT v1 AML engine (22 rules, 94.9% detection rate).

Author: HASH (hash02) — Bionic Banker
"""

import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import requests
from openai import OpenAI

# ─── Configuration ───────────────────────────────────────────────────────────

# Known mixer / sanctioned / flagged addresses (lowercase)
# Tornado Cash contract addresses verified against tornadocash/docs
# (general/tornado-cash-smart-contracts.md). All pools listed here were
# added to OFAC SDN in August 2022.
WATCHED_ADDRESSES = {
    # ── Tornado Cash ETH Pools ────────────────────────────────────────────
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": {"label": "Tornado Cash (0.1 ETH Pool)", "type": "mixer", "risk": 100},
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": {"label": "Tornado Cash (1 ETH Pool)", "type": "mixer", "risk": 100},
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": {"label": "Tornado Cash (10 ETH Pool)", "type": "mixer", "risk": 100},
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": {"label": "Tornado Cash (100 ETH Pool)", "type": "mixer", "risk": 100},
    # ── Tornado Cash DAI Pools ────────────────────────────────────────────
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": {"label": "Tornado Cash (100 DAI Pool)", "type": "mixer", "risk": 100},
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": {"label": "Tornado Cash (1,000 DAI Pool)", "type": "mixer", "risk": 100},
    "0x07687e702b410fa43f4cb4af7fa097918ffd2730": {"label": "Tornado Cash (10,000 DAI Pool)", "type": "mixer", "risk": 100},
    "0x23773e65ed146a459791799d01336db287f25334": {"label": "Tornado Cash (100,000 DAI Pool)", "type": "mixer", "risk": 100},
    # ── Tornado Cash cDAI Pools ───────────────────────────────────────────
    "0x22aaa7720ddd5388a3c0a3333430953c68f1849b": {"label": "Tornado Cash (5,000 cDAI Pool)", "type": "mixer", "risk": 100},
    "0x03893a7c7463ae47d46bc7f091665f1893656003": {"label": "Tornado Cash (50,000 cDAI Pool)", "type": "mixer", "risk": 100},
    "0x2717c5e28cf931547b621a5dddb772ab6a35b701": {"label": "Tornado Cash (500,000 cDAI Pool)", "type": "mixer", "risk": 100},
    "0xd21be7248e0197ee08e0c20d4a96debdac3d20af": {"label": "Tornado Cash (5,000,000 cDAI Pool)", "type": "mixer", "risk": 100},
    # ── Tornado Cash USDC Pools ───────────────────────────────────────────
    "0x4736dcf1b7a3d580672cce6e7c65cd5cc9cfba9d": {"label": "Tornado Cash (100 USDC Pool)", "type": "mixer", "risk": 100},
    "0xd96f2b1c14db8458374d9aca76e26c3d18364307": {"label": "Tornado Cash (1,000 USDC Pool)", "type": "mixer", "risk": 100},
    # ── Tornado Cash USDT Pools ───────────────────────────────────────────
    "0x169ad27a470d064dede56a2d3ff727986b15d52b": {"label": "Tornado Cash (100 USDT Pool)", "type": "mixer", "risk": 100},
    "0x0836222f2b2b24a3f36f98668ed8f0b38d1a872f": {"label": "Tornado Cash (1,000 USDT Pool)", "type": "mixer", "risk": 100},
    # ── Tornado Cash WBTC Pools ───────────────────────────────────────────
    "0x178169b423a011fff22b9e3f3abea13414ddd0f1": {"label": "Tornado Cash (0.1 WBTC Pool)", "type": "mixer", "risk": 100},
    "0x610b717796ad172b316836ac95a2ffad065ceab4": {"label": "Tornado Cash (1 WBTC Pool)", "type": "mixer", "risk": 100},
    "0xbb93e510bbcd0b7beb5a853875f9ec60275cf498": {"label": "Tornado Cash (10 WBTC Pool)", "type": "mixer", "risk": 100},
    # ── Tornado Cash Routers ──────────────────────────────────────────────
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {"label": "Tornado Cash Router", "type": "mixer", "risk": 100},
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": {"label": "Tornado Cash (deprecated proxy)", "type": "mixer", "risk": 80},
    # ── Tornado Cash Infra (cataloged; rules do not fire on mixer_infra) ─
    "0x5efda50f22d34f262c29268506c5fa42cb56a1ce": {"label": "Tornado Cash Governance", "type": "mixer_infra", "risk": 40},
    "0x77777feddddffc19ff86db637967013e6c6a116c": {"label": "Tornado Cash TORN Token", "type": "mixer_infra", "risk": 40},
    "0x58e8dcc13be9780fc42e8723d8ead4cf46943df2": {"label": "Tornado Cash RelayerRegistry", "type": "mixer_infra", "risk": 40},
    # ── Sanctioned Exchanges ──────────────────────────────────────────────
    "0xba214c1c1928a32bffe790263e38b4af9bfcd659": {"label": "eXch Exchange (flagged)", "type": "sanctioned_exchange", "risk": 90},
    # ── Lazarus Group (DPRK) ──────────────────────────────────────────────
    # Note: 0x47ce...2936 was previously mislabelled here as "Lazarus #1";
    # it is actually Tornado's 1 ETH pool (Lazarus deposits to it, but does
    # not control it). Corrected above.
    "0xa7e5d5a720f06526557c513402f2e6b5fa20b008": {"label": "Lazarus Group (DPRK)", "type": "state_sponsored", "risk": 200},
    # ── Known exploit addresses ───────────────────────────────────────────
    "0x3747d3e0e868d72ed471d10888ab8c246faf52f4": {"label": "Ronin Bridge Exploiter", "type": "exploit", "risk": 150},
    # ── Privacy protocols beyond Tornado ──────────────────────────────────
    # Verified via Etherscan labels / canonical deployment records.
    "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9": {"label": "Railgun Relay", "type": "privacy_protocol", "risk": 75},
    "0xe8a8b458bcd1ececc6b6b58f80929b29ccecff40": {"label": "Railgun Treasury", "type": "privacy_protocol", "risk": 75},
    "0xff1f2b4adb9df6fc8eafecdcbf96a2b351680455": {"label": "Aztec Connect RollupProcessor", "type": "privacy_protocol", "risk": 75},
    "0x6818809eefce719e480a7526d76bd3e561526b46": {"label": "Privacy Pools (0xbow) Entrypoint", "type": "privacy_protocol", "risk": 75},
    "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb": {"label": "Privacy Pools (0xbow)", "type": "privacy_protocol", "risk": 75},
    # ── No-KYC swap / off-ramp services ───────────────────────────────────
    # Initial list; expand as additional hot wallets are identified.
    # Note: Cryptex is already covered by the OFAC_ADDRESSES feed.
    "0x975d9bd9928f398c7e01f6ba236816fa558cd94b": {"label": "ChangeNOW Hot Wallet 1", "type": "no_kyc_offramp", "risk": 85},
    "0xa96be652a08d9905f15b7fbe2255708709becd09": {"label": "ChangeNOW Hot Wallet 2", "type": "no_kyc_offramp", "risk": 85},
    "0xa12e1462d0ced572f396f58b6e2d03894cd7c8a4": {"label": "ChangeNOW 10", "type": "no_kyc_offramp", "risk": 85},
    "0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2": {"label": "SideShift Hot Wallet", "type": "no_kyc_offramp", "risk": 85},
}

# OFAC SDN list — known sanctioned wallet addresses
# Labels corrected: several Tornado pool addresses were previously labelled
# as "Lazarus Group" here (e.g. 0x47ce...2936 is a TC 1 ETH pool, not a
# Lazarus wallet). Full OFAC sync is planned via the `addresses/ofac.json`
# feed in a subsequent change.
OFAC_ADDRESSES = {
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": "Tornado Cash (OFAC 2022)",
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": "Tornado Cash 0.1 ETH Pool (OFAC 2022)",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 1 ETH Pool (OFAC 2022)",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 10 ETH Pool (OFAC 2022)",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 100 ETH Pool (OFAC 2022)",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash 100 DAI Pool (OFAC 2022)",
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": "Tornado Cash 1,000 DAI Pool (OFAC 2022)",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash Router (OFAC 2022)",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash deprecated proxy (OFAC 2022)",
    "0xa7e5d5a720f06526557c513402f2e6b5fa20b008": "Lazarus Group (OFAC)",
}


def _load_ofac_feed() -> int:
    """Merge `addresses/ofac.json` into OFAC_ADDRESSES at startup.

    Feed is a vendored snapshot of ultrasoundmoney/ofac-ethereum-addresses
    (MIT), refreshed weekly via .github/workflows/refresh-addresses.yml.
    Any address already present keeps its curated label; new addresses
    adopt the upstream name. Missing / malformed file is non-fatal —
    scanner keeps running with the hardcoded list.
    """
    feed_path = Path(__file__).parent / "addresses" / "ofac.json"
    if not feed_path.exists():
        return 0
    try:
        feed = json.loads(feed_path.read_text())
        new_entries = feed.get("addresses", {})
    except (json.JSONDecodeError, OSError) as e:
        print(f"[WARN] OFAC feed load failed: {e}")
        return 0
    added = 0
    for addr, name in new_entries.items():
        addr = addr.lower()
        if addr not in OFAC_ADDRESSES:
            OFAC_ADDRESSES[addr] = name
            added += 1
    return added


_ofac_added = _load_ofac_feed()
if _ofac_added:
    print(f"[INFO] OFAC feed merged: +{_ofac_added} addresses (total {len(OFAC_ADDRESSES)})")

# Etherscan API V2 (V1 deprecated Aug 2025 — must use V2 with chainid)
ETHERSCAN_API = "https://api.etherscan.io/v2/api"
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
ETHERSCAN_CHAINID = "1"  # Ethereum mainnet

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
    "rapid_tx_min_value_eth": 0.5,  # Ignore dust — only count txs above this value
    "velocity_24h_count": 20,       # More than this in 24h = velocity flag
    # Peel chain rules
    "peel_variance_pct": 5,         # Amounts within this % variance = peel chain
    "peel_min_txs": 3,              # Minimum txs to detect peel chain
    # Sub-threshold tranching (DPRK bracketing pattern)
    "tranche_min_txs": 4,           # Min txs clustered under a USD band to flag
    "tranche_cv_max": 0.15,         # Max coefficient of variation across cluster
    "tranche_usd_bands": [7_000, 9_500, 500_000, 1_000_000],  # US CTR / FinCEN brackets
    "tranche_usd_gap_pct": 10,      # How close to the band (e.g. 9000 counts as "under 9500")
    # Risk score thresholds
    "risk_low": 30,
    "risk_medium": 60,
    "risk_high": 100,
    "risk_critical": 150,
}

# Backfill window for addresses we've just started watching.
# Covers ~7 days at 12s/block so a newly-added Railgun / ChangeNOW entry
# doesn't miss recent deposits that happened before the first cron run.
BACKFILL_BLOCKS = 50_000
SCAN_STATE_PATH = Path(__file__).parent / "reports" / "scan_state.json"


def load_scan_state() -> dict:
    """Read {last_scanned_block, first_seen} state for watched addresses.

    Malformed / missing file is non-fatal — returns empty defaults so the
    scanner falls back to the default window.
    """
    if not SCAN_STATE_PATH.exists():
        return {"last_scanned_block": {}, "first_seen": {}}
    try:
        data = json.loads(SCAN_STATE_PATH.read_text())
        data.setdefault("last_scanned_block", {})
        data.setdefault("first_seen", {})
        return data
    except (json.JSONDecodeError, OSError) as e:
        print(f"[WARN] scan_state load failed, starting fresh: {e}")
        return {"last_scanned_block": {}, "first_seen": {}}


def save_scan_state(state: dict) -> None:
    SCAN_STATE_PATH.parent.mkdir(exist_ok=True)
    SCAN_STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


# ─── Blockchain Data Layer ───────────────────────────────────────────────────

# Retry configuration for transient network / rate-limit errors.
# Exponential backoff: 2s, 4s, 8s. Anything past that indicates a real outage
# and the scan should fail loudly rather than silently produce "no findings".
_RETRY_ATTEMPTS = 3
_RETRY_BASE_SECONDS = 2


def _sleep_backoff(attempt: int) -> None:
    time.sleep(_RETRY_BASE_SECONDS * (2 ** attempt))


def etherscan_get(params: dict, timeout: int = 15) -> dict:
    """Call Etherscan V2 with retries.

    Retries with exponential backoff on network errors, HTTP 5xx, and HTTP
    429. Returns the decoded JSON dict on success. On total failure returns
    an empty dict — caller is expected to check for an empty/missing result
    and either fall back to RPC or fail loudly.
    """
    params["chainid"] = ETHERSCAN_CHAINID
    if ETHERSCAN_KEY:
        params["apikey"] = ETHERSCAN_KEY

    for attempt in range(_RETRY_ATTEMPTS):
        try:
            r = requests.get(ETHERSCAN_API, params=params, timeout=timeout)
            if r.status_code == 429 or r.status_code >= 500:
                print(f"[WARN] Etherscan HTTP {r.status_code} (attempt {attempt + 1}/{_RETRY_ATTEMPTS})")
                if attempt < _RETRY_ATTEMPTS - 1:
                    _sleep_backoff(attempt)
                    continue
                return {}
            data = r.json()
            if data.get("status") == "0" and data.get("message") != "No transactions found":
                print(f"[WARN] Etherscan API error: {data.get('result', data.get('message', 'unknown'))}")
            return data
        except requests.RequestException as e:
            print(f"[WARN] Etherscan network error (attempt {attempt + 1}/{_RETRY_ATTEMPTS}): {e}")
            if attempt < _RETRY_ATTEMPTS - 1:
                _sleep_backoff(attempt)
                continue
    print("[ERROR] Etherscan API unreachable after retries")
    return {}


def rpc_call(method: str, params: list = None) -> dict:
    """Call Ethereum JSON-RPC across multiple public endpoints.

    Each endpoint gets one retry with backoff before moving on. Returns the
    first successful response. Empty dict means every endpoint is unreachable.
    """
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or [],
        "id": 1,
    }
    for rpc_url in PUBLIC_RPC_ENDPOINTS:
        for attempt in range(2):
            try:
                r = requests.post(rpc_url, json=payload, timeout=10)
                if r.status_code == 429 or r.status_code >= 500:
                    if attempt == 0:
                        _sleep_backoff(attempt)
                        continue
                    break
                data = r.json()
                if "result" in data and data["result"] is not None:
                    return data
                break
            except requests.RequestException:
                if attempt == 0:
                    _sleep_backoff(attempt)
                    continue
                break
    print(f"[ERROR] All RPC endpoints failed for {method}")
    return {}


def get_latest_block() -> int:
    """Get the latest Ethereum block number. Tries Etherscan first, then RPC.

    Fails loudly if no source returns a valid block — a silent "block=0" here
    would make the scanner report "no findings" when it actually never
    scanned anything.
    """
    data = etherscan_get({"module": "proxy", "action": "eth_blockNumber"})
    try:
        block = int(data["result"], 16)
        if block > 0:
            print(f"[INFO] Latest block from Etherscan: {block}")
            return block
    except (KeyError, ValueError, TypeError):
        pass

    print("[INFO] Etherscan failed, trying public RPC...")
    data = rpc_call("eth_blockNumber")
    try:
        block = int(data["result"], 16)
        if block > 0:
            print(f"[INFO] Latest block from RPC: {block}")
            return block
    except (KeyError, ValueError, TypeError):
        pass

    print("[FATAL] Could not get latest block from any source — aborting scan")
    sys.exit(1)


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


def get_token_transfers(address: str, start_block: int, end_block: int) -> list:
    """
    Get ERC-20 token transfers for an address within a block range.
    This catches USDT, DAI, USDC, etc. flowing through mixers — invisible to normal tx scanning.
    """
    data = etherscan_get({
        "module": "account",
        "action": "tokentx",
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


def rule_rapid_fire(timestamps: list, eth_values: list) -> dict | None:
    """RULE: Rapid-fire transactions — automated/scripted behavior.

    Only counts transactions above rapid_tx_min_value_eth to avoid
    false positives from dust / airdrop spam.
    """
    min_value = THRESHOLDS["rapid_tx_min_value_eth"]
    paired = [ts for ts, val in zip(timestamps, eth_values, strict=False) if val >= min_value]
    if len(paired) < THRESHOLDS["rapid_tx_count"]:
        return None

    window = max(paired) - min(paired)
    if window <= THRESHOLDS["rapid_tx_window_sec"]:
        minutes = window / 60
        return {
            "rule": "velocity",
            "score": 50,
            "detail": f"{len(paired)} txs ≥{min_value} ETH within {minutes:.1f} minutes — "
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


def rule_contract_interaction(receiver_addr: str, total_eth: float) -> dict | None:
    """RULE: Zero-value contract call to mixer — likely withdrawal relay or governance."""
    if total_eth >= 0.001:
        return None  # Not a zero-value call, other rules handle this
    addr_info = WATCHED_ADDRESSES.get(receiver_addr.lower())
    if addr_info and addr_info["type"] in ("mixer", "sanctioned_exchange", "state_sponsored"):
        return {
            "rule": "mixer_contract_call",
            "score": 70,
            "detail": f"Zero-value contract call to {addr_info['label']} — "
                      f"likely withdrawal relay, governance vote, or obfuscation technique",
        }
    return None


def rule_stablecoin_mixing(token_transfers: list, receiver_addr: str) -> dict | None:
    """
    RULE: Stablecoin deposits to mixer/sanctioned addresses.
    Catches USDT/DAI/USDC flowing through Tornado Cash stablecoin pools.
    This is the gap Phone Claude identified — ETH-only scanning misses token layering.
    """
    if not token_transfers:
        return None

    addr_info = WATCHED_ADDRESSES.get(receiver_addr.lower())
    if not addr_info:
        return None

    # Known stablecoins (by symbol)
    stablecoin_symbols = {"USDT", "USDC", "DAI", "BUSD", "TUSD", "FRAX"}

    stable_transfers = []
    for tx in token_transfers:
        symbol = tx.get("tokenSymbol", "").upper()
        if symbol in stablecoin_symbols:
            try:
                decimals = int(tx.get("tokenDecimal", "18"))
                value = int(tx.get("value", "0")) / (10 ** decimals)
                if value > 0:
                    stable_transfers.append({"symbol": symbol, "value": value, "from": tx.get("from", "")})
            except (ValueError, TypeError):
                continue

    if not stable_transfers:
        return None

    total_usd = sum(t["value"] for t in stable_transfers)
    symbols_seen = set(t["symbol"] for t in stable_transfers)
    unique_senders = len(set(t["from"].lower() for t in stable_transfers))

    # Round-number detection (100, 1000, 10000 — classic denomination layering)
    round_count = sum(1 for t in stable_transfers if t["value"] in (10, 50, 100, 500, 1000, 5000, 10000))

    detail = (
        f"{len(stable_transfers)} stablecoin transfer(s) to {addr_info['label']}: "
        f"${total_usd:,.0f} total ({', '.join(symbols_seen)}) from {unique_senders} unique sender(s)"
    )
    if round_count > 0:
        detail += f" — {round_count} round-number amount(s) (denomination layering)"

    # Score: base 80 for stablecoin mixing + bonus for round numbers + bonus for multiple senders
    score = 80
    if round_count >= 2:
        score += 20  # Classic layering denomination pattern
    if unique_senders >= 3:
        score += 20  # Multiple sources converging = structuring
    if total_usd >= 10000:
        score += 30  # Big money through a mixer

    return {
        "rule": "stablecoin_mixing",
        "score": score,
        "detail": detail,
    }


def rule_sub_threshold_tranching(eth_values: list, eth_price: float) -> dict | None:
    """RULE: Sub-threshold tranching (DPRK-style bracketing).

    Flags clusters of transactions sitting just under well-known US reporting
    / CTR / FinCEN thresholds ($7K, $9.5K, $500K, $1M). The current
    `rule_structuring` catches identical near-round amounts; this rule
    catches the more specific pattern where multiple transfers bracket just
    below a regulatory threshold with low variance.

    Reference: Chainalysis 2025 (DPRK ~60% of laundering < $500K per
    transfer); Merkle Science (NoOnes Jan 2025 breach used sub-$7K
    bracketing); FATF 6th Targeted Update June 2025.
    """
    if not eth_values or eth_price <= 0:
        return None
    if len(eth_values) < THRESHOLDS["tranche_min_txs"]:
        return None

    usd_values = [v * eth_price for v in eth_values]
    gap_pct = THRESHOLDS["tranche_usd_gap_pct"] / 100

    for band in THRESHOLDS["tranche_usd_bands"]:
        lo = band * (1 - gap_pct)
        # "Just under" means within `gap_pct` below the band.
        cluster = [v for v in usd_values if lo <= v < band]
        if len(cluster) < THRESHOLDS["tranche_min_txs"]:
            continue
        mean = sum(cluster) / len(cluster)
        if mean == 0:
            continue
        var = sum((v - mean) ** 2 for v in cluster) / len(cluster)
        cv = (var ** 0.5) / mean
        if cv <= THRESHOLDS["tranche_cv_max"]:
            return {
                "rule": "sub_threshold_tranching",
                "score": 70,
                "detail": (
                    f"{len(cluster)} txs clustered just under ${band:,.0f} "
                    f"(avg ${mean:,.0f}, CV {cv:.3f}) — "
                    f"regulatory-threshold bracketing"
                ),
            }
    return None


def rule_privacy_protocol_non_tornado(receiver_addr: str) -> dict | None:
    """RULE: Interaction with privacy protocols beyond Tornado Cash.

    Covers Railgun, Aztec Connect, Privacy Pools (0xbow). Lazarus and
    other threat actors have been observed migrating to these protocols
    as Tornado Cash became sanctioned (Elliptic Nov 2024).
    """
    addr_info = WATCHED_ADDRESSES.get(receiver_addr.lower())
    if addr_info and addr_info["type"] == "privacy_protocol":
        return {
            "rule": "privacy_protocol",
            "score": 75,
            "detail": f"Deposit to {addr_info['label']} — non-Tornado privacy protocol",
        }
    return None


def rule_exit_to_no_kyc_offramp(receiver_addr: str) -> dict | None:
    """RULE: Deposit to a known no-KYC swap / off-ramp service.

    Scored higher than mixer interaction because reaching a no-KYC
    off-ramp is typically the *final* laundering step before fiat
    conversion or cross-chain extraction.
    """
    addr_info = WATCHED_ADDRESSES.get(receiver_addr.lower())
    if addr_info and addr_info["type"] == "no_kyc_offramp":
        return {
            "rule": "no_kyc_offramp",
            "score": 85,
            "detail": f"Deposit to {addr_info['label']} — no-KYC off-ramp",
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

def scan_recent_blocks(num_blocks: int = 200) -> list:
    """
    Scan recent blocks for suspicious transactions.
    Applies the full AML engine rule set to each finding.

    Default 200 blocks (~25-30 min) to match the 30-min cron interval.
    Scans BOTH native ETH transfers AND ERC-20 token transfers.
    """
    findings = []
    latest = get_latest_block()  # fails loudly on total source failure
    default_start = latest - num_blocks + 1
    eth_price = get_eth_price() or 2000.0
    print(f"[SCAN] Latest block: {latest} | ETH: ${eth_price:,.2f}")
    print(f"[SCAN] Default window: blocks {default_start}-{latest} ({num_blocks} blocks)")

    # Per-address backfill state. Newly-added watched addresses look back
    # BACKFILL_BLOCKS (~7 days) once; thereafter we pick up where we left off.
    scan_state = load_scan_state()
    last_scanned = scan_state["last_scanned_block"]
    first_seen = scan_state["first_seen"]
    scan_started_at = datetime.now(UTC).isoformat()

    # ── Strategy 1: Check ETH + token transactions TO watched addresses ──
    for address, addr_info in WATCHED_ADDRESSES.items():
        label = addr_info["label"]
        print(f"[SCAN] Checking {label} ({address[:10]}...)")

        addr_last = last_scanned.get(address)
        if addr_last is None:
            addr_start = max(1, latest - BACKFILL_BLOCKS + 1)
            first_seen.setdefault(address, scan_started_at)
            print(f"  [BACKFILL] Newly-watched — scanning last {BACKFILL_BLOCKS:,} blocks")
        else:
            addr_start = max(addr_last + 1, default_start)
            if addr_last + 1 < default_start:
                print(f"  [CATCHUP] Last scanned at {addr_last}, continuing from {addr_start}")

        # Fetch BOTH normal txs and token transfers
        txs = get_normal_transactions(address, addr_start, latest)
        time.sleep(0.5)
        token_txs = get_token_transfers(address, addr_start, latest)
        time.sleep(0.5)
        last_scanned[address] = latest

        has_eth = bool(txs)
        has_tokens = bool(token_txs)

        if not has_eth and not has_tokens:
            continue

        print(f"  [DATA] {len(txs)} ETH txs, {len(token_txs)} token transfers")

        # ── Process ETH transactions ──
        if has_eth:
            sender_map = {}
            for tx in txs:
                sender = tx.get("from", "").lower()
                if sender not in WATCHED_ADDRESSES:
                    sender_map.setdefault(sender, []).append(tx)

            # DEBUG: show what was filtered
            watched_senders = sum(1 for tx in txs if tx.get("from", "").lower() in WATCHED_ADDRESSES)
            if watched_senders:
                print(f"  [DEBUG] {watched_senders} txs from watched→watched (kept for reference)")

            for sender, sender_txs in sender_map.items():
                eth_values = [int(tx.get("value", "0")) / 1e18 for tx in sender_txs]
                total_eth = sum(eth_values)
                timestamps = [int(tx.get("timeStamp", "0")) for tx in sender_txs]

                # Smart dust filter: skip dust ONLY for non-watched receivers
                # ANY interaction with a mixer/sanctioned address is suspicious,
                # even zero-value contract calls (withdrawal relay, governance, etc.)
                is_watched_receiver = address in WATCHED_ADDRESSES
                if total_eth < 0.001 and not is_watched_receiver:
                    continue  # Skip dust for normal addresses only

                # For zero-value txs to watched addresses, mark as contract interaction
                is_contract_call = (total_eth < 0.001 and is_watched_receiver)
                if is_contract_call:
                    print(f"  [DETECT] Zero-value contract call to {label} from {sender[:10]}... — likely withdrawal/relay")

                rules_triggered = []

                print(f"  [PROFILE] Profiling sender {sender[:10]}...")
                wallet_info = get_wallet_info(sender)
                time.sleep(0.5)

                for rule_fn, args in [
                    (rule_mixer_interaction, (address,)),
                    (rule_sanctioned_entity, (sender, address)),
                    (rule_state_sponsored, (address,)),
                    (rule_contract_interaction, (address, total_eth)),
                    (rule_novel_wallet, (wallet_info, total_eth)),
                    (rule_dormant_activation, (wallet_info, total_eth)),
                    (rule_high_value, (total_eth, eth_price)),
                    (rule_structuring, (eth_values,)),
                    (rule_peel_chain, (eth_values,)),
                    (rule_rapid_fire, (timestamps, eth_values)),
                    (rule_sub_threshold_tranching, (eth_values, eth_price)),
                    (rule_privacy_protocol_non_tornado, (address,)),
                    (rule_exit_to_no_kyc_offramp, (address,)),
                    (rule_exit_rush, (wallet_info, total_eth)),
                    (rule_exchange_avoidance, (address,)),
                ]:
                    result = rule_fn(*args)
                    if result:
                        rules_triggered.append(result)

                if not rules_triggered:
                    continue

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
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "rules_triggered": rules_triggered,
                    "wallet_profile": {
                        "age_days": wallet_info.get("wallet_age_days", "unknown"),
                        "tx_count": wallet_info.get("tx_count", "unknown"),
                        "balance_eth": wallet_info.get("balance_eth", 0),
                        "days_idle": wallet_info.get("days_since_last_tx", 0),
                    },
                    "token_transfers": [],  # No tokens in this finding
                })

        # ── Process ERC-20 token transfers (NEW — catches USDT/DAI/USDC through mixers) ──
        if has_tokens:
            # Group token transfers by sender
            token_sender_map = {}
            for tx in token_txs:
                sender = tx.get("from", "").lower()
                if sender not in WATCHED_ADDRESSES:
                    token_sender_map.setdefault(sender, []).append(tx)

            for sender, sender_token_txs in token_sender_map.items():
                # Run stablecoin mixing rule
                stablecoin_result = rule_stablecoin_mixing(sender_token_txs, address)
                if not stablecoin_result:
                    continue

                # Also check if this sender did OFAC / state-sponsored / mixer touch
                rules_triggered = [stablecoin_result]
                ofac = rule_sanctioned_entity(sender, address)
                if ofac:
                    rules_triggered.append(ofac)
                mixer = rule_mixer_interaction(address)
                if mixer:
                    rules_triggered.append(mixer)
                state = rule_state_sponsored(address)
                if state:
                    rules_triggered.append(state)

                risk_score, risk_level, _ = compute_risk_score(rules_triggered)
                print(f"  [TOKEN] {sender[:10]}... → Score: {risk_score} ({risk_level}) — stablecoin mixing")

                # Build token transfer summary for the report
                token_summary = []
                for tx in sender_token_txs:
                    symbol = tx.get("tokenSymbol", "?")
                    try:
                        decimals = int(tx.get("tokenDecimal", "18"))
                        value = int(tx.get("value", "0")) / (10 ** decimals)
                    except (ValueError, TypeError):
                        value = 0
                    if value > 0:
                        token_summary.append({"symbol": symbol, "value": value, "hash": tx.get("hash", "")})

                total_token_usd = sum(t["value"] for t in token_summary)

                findings.append({
                    "sender": sender,
                    "receiver": address,
                    "receiver_label": label,
                    "tx_count": len(sender_token_txs),
                    "total_eth": 0,  # Token transfers, not ETH
                    "total_token_usd": total_token_usd,
                    "individual_values": [t["value"] for t in token_summary],
                    "timestamps": [int(tx.get("timeStamp", "0")) for tx in sender_token_txs],
                    "tx_hashes": [tx.get("hash", "") for tx in sender_token_txs],
                    "block_range": f"{min(int(tx.get('blockNumber', 0)) for tx in sender_token_txs)}-"
                                   f"{max(int(tx.get('blockNumber', 0)) for tx in sender_token_txs)}",
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "rules_triggered": rules_triggered,
                    "wallet_profile": {},
                    "token_transfers": token_summary,
                })

    # ── Strategy 2: High-value block scanning ──
    for offset in range(min(num_blocks, 5)):  # Only scan 5 blocks for high-value
        block_num = latest - offset
        txs = get_block_transactions(block_num)
        time.sleep(0.5)

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

    # Persist per-address scan progress so new additions backfill once and
    # resume from where we left off on subsequent runs.
    save_scan_state({"last_scanned_block": last_scanned, "first_seen": first_seen})

    return unique


# ─── Roast Generator (Groq LLM) ─────────────────────────────────────────────

def generate_roast(finding: dict, eth_price: float) -> dict:
    """Generate roast + SAR narrative using Groq AI, informed by AML engine scoring."""
    if not GROQ_API_KEY:
        return {
            "what_happened": f"A wallet interacted with {finding['receiver_label']}, a flagged address on our watchlist. "
                             f"The engine scored this {finding['risk_score']} out of a possible 500+ — that's a serious red flag.",
            "roast": f"Someone just sent {finding['total_eth']:.4f} ETH to {finding['receiver_label']}. "
                     f"Risk score: {finding['risk_score']}. Bold move.",
            "sar_narrative": "Automated SAR generation unavailable — no LLM API key configured.",
            "risk_verdict": f"{finding['risk_level']} — Score {finding['risk_score']}",
            "recommended_action": "Flag for manual review. Trace upstream funding source.",
        }

    # Handle both ETH findings and token findings
    token_transfers = finding.get("token_transfers", [])
    if token_transfers:
        usd_value = finding.get("total_token_usd", 0)
    else:
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

You have access to a full AML detection engine scoring system.

IMPORTANT WRITING RULES:
- The audience is MIXED — some readers know crypto, some don't.
- In the "what_happened" field: write in PLAIN ENGLISH. No jargon. Explain it like you're telling a friend what happened. Use analogies. If you mention a technical concept, explain it in parentheses immediately.
- In the "roast" field: be funny and specific. When you reference a rule name, explain what it means in plain language the FIRST time. Example: "scored 200 on the OFAC hit (meaning this address is literally on the U.S. Treasury's sanctions blacklist)."
- In the "sar_narrative" field: this IS for compliance professionals — use proper AML terminology and cite rule names.
- Keep the risk_verdict to ONE clear sentence.
- Keep recommended_action to 1-2 practical sentences.

Generate these 5 fields:

1. WHAT HAPPENED (2-3 sentences, plain English, zero jargon — a non-crypto person should fully understand this. Use real-world analogies like "this is like walking into a known money laundering front" etc.)
2. ROAST (3-5 sentences, brutally funny, sarcastic — reference specific data but explain technical terms inline the first time)
3. SAR NARRATIVE (professional suspicious activity report for compliance teams, 3-4 sentences, cite rule names and evidence)
4. RISK VERDICT ({finding['risk_level']} — one sentence justification)
5. RECOMMENDED ACTION (1-2 sentences, practical next steps)

TRANSACTION DATA:
- Sender: {finding['sender']}
- Receiver: {finding['receiver']} ({finding['receiver_label']})
- Transaction count: {finding['tx_count']}
- Total value: {f"{finding['total_eth']:.4f} ETH" if finding['total_eth'] > 0 else f"${finding.get('total_token_usd', 0):,.0f} (stablecoin)"} (${usd_value:,.0f} USD)
- Individual amounts: {', '.join(f"{v:.4f}" for v in finding['individual_values'][:10])}
- Block range: {finding['block_range']}
- Token transfers: {', '.join(f"{t['symbol']} {t['value']:,.0f}" for t in token_transfers[:5]) if token_transfers else 'None (ETH only)'}

CONTEXT: Tornado Cash is a crypto mixing service that was sanctioned by the U.S. Treasury (OFAC) in August 2022 for helping launder $7+ billion including funds stolen by North Korea's Lazarus Group. Any interaction with it is a major red flag.

SENDER WALLET PROFILE:
{wallet_text}

AML ENGINE SCORING (Composite Score: {finding['risk_score']}):
{rules_text}

Respond in this EXACT JSON format (no markdown, no code blocks, no backticks):
{{
    "what_happened": "plain English explanation here — a non-crypto person should understand this completely",
    "roast": "your roast here — funny but explain jargon inline",
    "sar_narrative": "professional SAR narrative — cite rule names, this section IS for compliance pros",
    "risk_verdict": "{finding['risk_level']} — one sentence reason",
    "recommended_action": "practical next steps"
}}"""

    try:
        client = OpenAI(api_key=GROQ_API_KEY, base_url=GROQ_BASE_URL)
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.8,
            max_tokens=900,
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
            "what_happened": f"A wallet was caught interacting with {finding['receiver_label']}. Our engine flagged it at score {finding['risk_score']}.",
            "roast": raw[:300] if 'raw' in dir() else "The AI was speechless.",
            "sar_narrative": "Automated SAR generation failed — manual review required.",
            "risk_verdict": f"{finding['risk_level']} — Score {finding['risk_score']}",
            "recommended_action": "Manual investigation required.",
        }
    except Exception as e:
        print(f"[ERROR] Groq API: {e}")
        return {
            "what_happened": f"A wallet was caught interacting with {finding['receiver_label']}. Our engine flagged it at score {finding['risk_score']}.",
            "roast": "Even our AI refused to look at this transaction.",
            "sar_narrative": f"Automated analysis error: {str(e)[:100]}",
            "risk_verdict": f"{finding['risk_level']} — API error",
            "recommended_action": "Retry analysis.",
        }


# ─── Report Generator ────────────────────────────────────────────────────────

def generate_report(findings: list, eth_price: float, scan_meta: dict) -> str:
    """Generate a markdown report with AML engine scoring."""
    now = datetime.now(UTC)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")

    report = f"""# 🔥 AML Roaster Report
**{timestamp}** · Ethereum Mainnet · ETH ${eth_price:,.2f}
**Blocks:** {scan_meta.get('block_range', 'N/A')} · **Watched Addresses:** {len(WATCHED_ADDRESSES)} · **Detection Rules:** 13
**Engine:** NEXUS AML v2 — 94.9% detection rate

---

"""

    if not findings:
        report += """## No Suspicious Activity Detected

All quiet on the Ethereum front. 13 detection rules armed and scanning.
The mixers are sleeping, the whales are resting, and nobody's trying to
wash their crypto through Tornado Cash right now.

Check back in 30 minutes — crime doesn't sleep, but it does take breaks.

---
*Report generated by AML Roaster Agent v2 — Automated Run*
"""
        return report

    for i, finding in enumerate(findings, 1):
        roast_data = generate_roast(finding, eth_price)
        # Store roast text on finding dict so save_scan_data() can capture it
        finding["_roast_data"] = roast_data
        token_transfers = finding.get("token_transfers", [])
        if token_transfers:
            usd_value = finding.get("total_token_usd", 0)
        else:
            usd_value = finding["total_eth"] * eth_price
        wallet = finding.get("wallet_profile", {})

        # Build value line based on ETH vs token finding
        if token_transfers:
            token_detail = ", ".join(f"{t['value']:,.0f} {t['symbol']}" for t in token_transfers[:5])
            value_line = f"**{finding['tx_count']}** token transfer{'s' if finding['tx_count'] > 1 else ''} totaling **${usd_value:,.0f}** ({token_detail})"
        else:
            value_line = f"**{finding['tx_count']}** tx{'s' if finding['tx_count'] > 1 else ''} totaling **{finding['total_eth']:.4f} ETH** (${usd_value:,.0f})"

        report += f"""## Finding #{i}: {finding['risk_level']} — Score {finding['risk_score']}

| | |
|---|---|
| **Sender** | `{finding['sender']}` |
| **Target** | {finding['receiver_label']} (`{finding['receiver'][:20]}...`) |
| **Activity** | {value_line} |
| **Blocks** | {finding['block_range']} |

### 💬 What Happened
{roast_data.get('what_happened', 'Analysis unavailable.')}

### 🔥 The Roast
{roast_data['roast']}

### 🎯 Verdict & Next Steps
**{roast_data['risk_verdict']}**

{roast_data['recommended_action']}

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | {wallet.get('age_days', '?')} days |
| Total Transactions | {wallet.get('tx_count', '?')} |
| Current Balance | {wallet.get('balance_eth', 0):.6f} ETH |
| Days Since Last Activity | {wallet.get('days_idle', '?')} |

**Rules Triggered** ({len(finding['rules_triggered'])} rules, composite score: {finding['risk_score']}):
"""
        for r in finding["rules_triggered"]:
            report += f"- **{r['rule']}** (+{r['score']}) — {r['detail']}\n"

        report += f"""
**SAR Narrative** *(for compliance teams)*:
{roast_data['sar_narrative']}

</details>

---

"""
        time.sleep(1)

    # Summary
    total_eth = sum(f["total_eth"] for f in findings)
    total_usd = total_eth * eth_price
    total_token_usd = sum(f.get("total_token_usd", 0) for f in findings)
    max_score = max(f["risk_score"] for f in findings)
    critical_count = sum(1 for f in findings if f["risk_level"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["risk_level"] == "HIGH")

    token_line = f" + ${total_token_usd:,.0f} in stablecoins" if total_token_usd > 0 else ""
    unique_senders = len(set(f['sender'] for f in findings))
    report += f"""## Scan Summary

**{len(findings)} suspicious finding{'s' if len(findings) != 1 else ''}** detected across {unique_senders} unique wallet{'s' if unique_senders != 1 else ''}. Highest risk score: **{max_score}**.

| | |
|---|---|
| 🔴 CRITICAL | {critical_count} |
| 🟠 HIGH | {high_count} |
| Wallets flagged | {unique_senders} |
| Suspicious value | {total_eth:.4f} ETH (${total_usd:,.0f}){token_line} |
| Blocks scanned | {scan_meta.get('block_range', 'N/A')} |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*
"""
    return report


# ─── JSON Data Layer (for Dashboard) ─────────────────────────────────────────

def save_scan_data(findings: list, eth_price: float, scan_meta: dict):
    """Append scan results to data.json — cumulative data source for dashboard."""
    data_file = REPORTS_DIR / "data.json"

    # Load existing data or start fresh
    if data_file.exists():
        try:
            existing = json.loads(data_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, Exception):
            existing = {"scans": []}
    else:
        existing = {"scans": []}

    now = datetime.now(UTC)

    # Build scan entry
    scan_entry = {
        "timestamp": now.isoformat(),
        "eth_price": eth_price,
        "block_range": scan_meta.get("block_range", ""),
        "total_findings": len(findings),
        "findings": [],
    }

    for f in findings:
        roast = f.get("_roast_data", {})
        scan_entry["findings"].append({
            "sender": f["sender"],
            "receiver": f["receiver"],
            "receiver_label": f["receiver_label"],
            "risk_score": f["risk_score"],
            "risk_level": f["risk_level"],
            "tx_count": f["tx_count"],
            "total_eth": f["total_eth"],
            "total_token_usd": f.get("total_token_usd", 0),
            "rules_triggered": [r["rule"] for r in f["rules_triggered"]],
            "rule_scores": {r["rule"]: r["score"] for r in f["rules_triggered"]},
            # Roast content for dashboard display
            "what_happened": roast.get("what_happened", ""),
            "roast": roast.get("roast", ""),
            "risk_verdict": roast.get("risk_verdict", ""),
            "recommended_action": roast.get("recommended_action", ""),
        })

    existing["scans"].append(scan_entry)

    # Keep last 500 scans max (~10 days at 30-min intervals)
    if len(existing["scans"]) > 500:
        existing["scans"] = existing["scans"][-500:]

    # Write stats summary for quick dashboard access
    all_findings = [f for s in existing["scans"] for f in s["findings"]]
    existing["stats"] = {
        "total_scans": len(existing["scans"]),
        "total_findings": len(all_findings),
        "unique_senders": len(set(f["sender"] for f in all_findings)) if all_findings else 0,
        "highest_score": max((f["risk_score"] for f in all_findings), default=0),
        "critical_count": sum(1 for f in all_findings if f["risk_level"] == "CRITICAL"),
        "high_count": sum(1 for f in all_findings if f["risk_level"] == "HIGH"),
        "first_scan": existing["scans"][0]["timestamp"],
        "last_scan": existing["scans"][-1]["timestamp"],
    }

    data_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    print(f"[SAVED] {data_file} ({existing['stats']['total_scans']} scans, {existing['stats']['total_findings']} total findings)")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("🔥 AML ROASTER AGENT v2 (NEXUS Engine) — Starting scan")
    print("   Detection rules: 13 active (incl. stablecoin_mixing, contract_interaction)")
    print(f"   Watched addresses: {len(WATCHED_ADDRESSES)}")
    print("   Scan window: 200 blocks (~25 min)")
    print("=" * 60)

    eth_price = get_eth_price()
    if eth_price:
        print(f"[INFO] ETH Price: ${eth_price:,.2f}")
    else:
        print("[WARN] Could not fetch ETH price, using $2000 fallback")
        eth_price = 2000.0

    latest_block = get_latest_block()
    num_blocks = 200  # ~25-30 min to match 30-min cron interval
    findings = scan_recent_blocks(num_blocks=num_blocks)

    scan_meta = {
        "block_range": f"{latest_block - num_blocks + 1} — {latest_block}",
    }

    print(f"\n[RESULT] Found {len(findings)} suspicious pattern(s)")
    for f in findings:
        print(f"  [{f['risk_level']}] Score {f['risk_score']} — "
              f"{f['sender'][:10]}... → {f['receiver_label']}")

    report = generate_report(findings, eth_price, scan_meta)

    now = datetime.now(UTC)
    filename = f"report_{now.strftime('%Y-%m-%d_%H%M')}.md"
    filepath = REPORTS_DIR / filename
    filepath.write_text(report, encoding="utf-8")
    print(f"\n[SAVED] {filepath}")

    (REPORTS_DIR / "latest.md").write_text(report, encoding="utf-8")
    print(f"[SAVED] {REPORTS_DIR / 'latest.md'}")

    # Save structured data for dashboard
    save_scan_data(findings, eth_price, scan_meta)

    print("\n" + "=" * 60)
    print("🔥 AML ROASTER AGENT v2 — Scan complete")
    print("=" * 60)

    # Always exit 0 — findings aren't errors, they're the whole point.
    # GitHub Actions treats non-zero exit as failure, which blocks the
    # commit-and-push step from saving the report.
    print(f"\n   Findings count: {len(findings)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Unit tests for the 16 AML detection rules.

Each rule is tested with at least one positive (fires) and one negative
(returns None) case. Tests use the real WATCHED_ADDRESSES registry so
address-lookup rules exercise the actual data we ship.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure the repo root is importable before `import roaster`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import roaster  # noqa: E402

# ─── Address fixtures (pulled from the real registry) ────────────────────

TC_1_ETH_POOL = "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936"
TC_ROUTER = "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b"
TC_GOVERNANCE = "0x5efda50f22d34f262c29268506c5fa42cb56a1ce"  # type=mixer_infra
LAZARUS = "0xa7e5d5a720f06526557c513402f2e6b5fa20b008"
EXCH_EXCHANGE = "0xba214c1c1928a32bffe790263e38b4af9bfcd659"
RAILGUN_RELAY = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
CHANGENOW_HW1 = "0x975d9bd9928f398c7e01f6ba236816fa558cd94b"
UNKNOWN_ADDR = "0x1234567890123456789012345678901234567890"
RANDOM_SENDER = "0xabcdef0000000000000000000000000000000001"


# ─── Rule 1: mixer_interaction ───────────────────────────────────────────

def test_mixer_interaction_fires_on_tornado():
    r = roaster.rule_mixer_interaction(TC_1_ETH_POOL)
    assert r is not None
    assert r["rule"] == "mixer_touch"
    assert r["score"] == 100


def test_mixer_interaction_none_on_mixer_infra():
    # mixer_infra type (governance) should NOT fire the mixer rule.
    assert roaster.rule_mixer_interaction(TC_GOVERNANCE) is None


def test_mixer_interaction_none_on_unknown():
    assert roaster.rule_mixer_interaction(UNKNOWN_ADDR) is None


# ─── Rule 2: sanctioned_entity (OFAC) ────────────────────────────────────

def test_sanctioned_entity_fires_on_ofac_receiver():
    r = roaster.rule_sanctioned_entity(RANDOM_SENDER, TC_1_ETH_POOL)
    assert r is not None
    assert r["score"] == 200


def test_sanctioned_entity_none_on_clean_pair():
    assert roaster.rule_sanctioned_entity(RANDOM_SENDER, UNKNOWN_ADDR) is None


# ─── Rule 3: state_sponsored ─────────────────────────────────────────────

def test_state_sponsored_fires_on_lazarus():
    r = roaster.rule_state_sponsored(LAZARUS)
    assert r is not None
    assert r["score"] == 200


def test_state_sponsored_none_on_mixer():
    # A Tornado pool is type=mixer, not state_sponsored.
    assert roaster.rule_state_sponsored(TC_1_ETH_POOL) is None


# ─── Rule 4: novel_wallet ────────────────────────────────────────────────

def test_novel_wallet_fires_on_young_wallet_moving_value():
    r = roaster.rule_novel_wallet({"wallet_age_days": 3}, total_eth=2.0)
    assert r is not None
    assert r["score"] >= 60


def test_novel_wallet_none_on_old_wallet():
    assert roaster.rule_novel_wallet({"wallet_age_days": 400}, total_eth=5.0) is None


def test_novel_wallet_none_on_dust():
    assert roaster.rule_novel_wallet({"wallet_age_days": 3}, total_eth=0.01) is None


# ─── Rule 5: dormant_activation ──────────────────────────────────────────

def test_dormant_activation_fires_on_long_idle_old_wallet():
    r = roaster.rule_dormant_activation(
        {"wallet_age_days": 500, "days_since_last_tx": 200},
        total_eth=2.0,
    )
    assert r is not None
    assert r["score"] == 80


def test_dormant_activation_none_on_recent_activity():
    assert roaster.rule_dormant_activation(
        {"wallet_age_days": 500, "days_since_last_tx": 30}, total_eth=2.0
    ) is None


# ─── Rule 6: high_value ──────────────────────────────────────────────────

def test_high_value_fires_at_whale_level():
    r = roaster.rule_high_value(total_eth=150.0, eth_price=3000.0)
    assert r is not None
    assert r["rule"] == "whale_transfer"


def test_high_value_fires_at_high_band():
    r = roaster.rule_high_value(total_eth=15.0, eth_price=3000.0)
    assert r is not None
    assert r["rule"] == "high_value"


def test_high_value_none_below_threshold():
    assert roaster.rule_high_value(total_eth=1.0, eth_price=3000.0) is None


# ─── Rule 7: structuring ─────────────────────────────────────────────────

def test_structuring_fires_on_identical_amounts():
    r = roaster.rule_structuring([0.5, 0.5, 0.5, 0.5])
    assert r is not None


def test_structuring_none_on_varied_amounts():
    assert roaster.rule_structuring([0.5, 1.3, 0.1, 2.8]) is None


def test_structuring_none_on_too_few_txs():
    assert roaster.rule_structuring([0.5, 0.5]) is None


# ─── Rule 8: peel_chain ──────────────────────────────────────────────────

def test_peel_chain_none_on_diverse_amounts():
    # Rule looks for sequential near-constant progression.
    assert roaster.rule_peel_chain([10.0, 1.0, 100.0]) is None


# ─── Rule 9: rapid_fire ──────────────────────────────────────────────────

def test_rapid_fire_fires_on_fast_value_txs():
    # 3 txs ≥0.5 ETH within a 2-min window.
    r = roaster.rule_rapid_fire(
        timestamps=[1_700_000_000, 1_700_000_060, 1_700_000_120],
        eth_values=[1.0, 1.5, 2.0],
    )
    assert r is not None


def test_rapid_fire_ignores_dust():
    r = roaster.rule_rapid_fire(
        timestamps=[1_700_000_000, 1_700_000_060, 1_700_000_120],
        eth_values=[0.001, 0.002, 0.001],
    )
    assert r is None


def test_rapid_fire_none_on_wide_window():
    r = roaster.rule_rapid_fire(
        timestamps=[1_700_000_000, 1_700_001_000, 1_700_002_000],
        eth_values=[1.0, 1.0, 1.0],
    )
    assert r is None


# ─── Rule 10: exit_rush ──────────────────────────────────────────────────

def test_exit_rush_fires_when_wallet_drained():
    r = roaster.rule_exit_rush({"balance_eth": 0.005}, total_eth=5.0)
    assert r is not None


def test_exit_rush_none_when_balance_remains():
    assert roaster.rule_exit_rush({"balance_eth": 10.0}, total_eth=5.0) is None


# ─── Rule 11: exchange_avoidance ─────────────────────────────────────────

def test_exchange_avoidance_fires_on_sanctioned_exchange():
    r = roaster.rule_exchange_avoidance(EXCH_EXCHANGE)
    assert r is not None


def test_exchange_avoidance_none_on_unknown():
    assert roaster.rule_exchange_avoidance(UNKNOWN_ADDR) is None


# ─── Rule 12: contract_interaction ───────────────────────────────────────

def test_contract_interaction_fires_on_zero_value_to_mixer():
    r = roaster.rule_contract_interaction(TC_1_ETH_POOL, total_eth=0.0)
    assert r is not None


def test_contract_interaction_none_on_normal_value():
    assert roaster.rule_contract_interaction(TC_1_ETH_POOL, total_eth=1.0) is None


# ─── Rule 13: stablecoin_mixing ──────────────────────────────────────────

def test_stablecoin_mixing_fires_on_usdc_to_mixer():
    transfers = [
        {"tokenSymbol": "USDC", "tokenDecimal": "6", "value": str(10_000 * 10**6), "from": RANDOM_SENDER},
    ]
    r = roaster.rule_stablecoin_mixing(transfers, TC_1_ETH_POOL)
    assert r is not None


def test_stablecoin_mixing_none_on_non_stable_token():
    transfers = [
        {"tokenSymbol": "SHIB", "tokenDecimal": "18", "value": "1000000000000000000000", "from": RANDOM_SENDER},
    ]
    assert roaster.rule_stablecoin_mixing(transfers, TC_1_ETH_POOL) is None


def test_stablecoin_mixing_none_on_unknown_receiver():
    transfers = [
        {"tokenSymbol": "USDC", "tokenDecimal": "6", "value": str(10_000 * 10**6), "from": RANDOM_SENDER},
    ]
    assert roaster.rule_stablecoin_mixing(transfers, UNKNOWN_ADDR) is None


# ─── Rule 14: sub_threshold_tranching ────────────────────────────────────

def test_tranching_fires_on_dprk_style_bracket():
    r = roaster.rule_sub_threshold_tranching(
        eth_values=[3.0, 2.95, 3.0, 2.98, 3.02],
        eth_price=3000.0,
    )
    assert r is not None
    assert r["score"] == 70


def test_tranching_none_on_high_variance():
    assert roaster.rule_sub_threshold_tranching(
        eth_values=[3.0, 1.0, 5.0, 0.5, 4.0], eth_price=3000.0
    ) is None


def test_tranching_none_on_zero_price():
    assert roaster.rule_sub_threshold_tranching(
        eth_values=[3.0, 2.95, 3.0, 2.98], eth_price=0.0
    ) is None


# ─── Rule 15: privacy_protocol_non_tornado ───────────────────────────────

def test_privacy_protocol_fires_on_railgun():
    r = roaster.rule_privacy_protocol_non_tornado(RAILGUN_RELAY)
    assert r is not None
    assert r["score"] == 75


def test_privacy_protocol_none_on_tornado_pool():
    # Tornado pool is type=mixer, not privacy_protocol — must not fire here.
    assert roaster.rule_privacy_protocol_non_tornado(TC_1_ETH_POOL) is None


# ─── Rule 16: exit_to_no_kyc_offramp ─────────────────────────────────────

def test_no_kyc_offramp_fires_on_changenow():
    r = roaster.rule_exit_to_no_kyc_offramp(CHANGENOW_HW1)
    assert r is not None
    assert r["score"] == 85


def test_no_kyc_offramp_none_on_unknown():
    assert roaster.rule_exit_to_no_kyc_offramp(UNKNOWN_ADDR) is None


# ─── Rule 17: bridge_hop ─────────────────────────────────────────────────

STARGATE_ROUTER = "0x8731d54e9d02c286767d56ac03e8037c07e01e98"
ACROSS_SPOKE = "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5"


def test_bridge_hop_fires_on_stargate():
    r = roaster.rule_bridge_hop(STARGATE_ROUTER)
    assert r is not None
    assert r["score"] == 65


def test_bridge_hop_fires_on_across():
    r = roaster.rule_bridge_hop(ACROSS_SPOKE)
    assert r is not None


def test_bridge_hop_none_on_mixer():
    # Tornado pool is type=mixer, not bridge — must not fire here.
    assert roaster.rule_bridge_hop(TC_1_ETH_POOL) is None


def test_bridge_hop_none_on_unknown():
    assert roaster.rule_bridge_hop(UNKNOWN_ADDR) is None


# ─── Rule 18: lrt_restaking_wash ─────────────────────────────────────────

ETHERFI_POOL = "0x308861a430be4cce5502d0a12724771fc6daf216"
KELP_POOL = "0x036676389e48133b63a802f8635ad39e752d375d"


def test_lrt_wash_fires_on_etherfi():
    r = roaster.rule_lrt_restaking_wash(ETHERFI_POOL)
    assert r is not None
    assert r["score"] == 55


def test_lrt_wash_fires_on_kelp():
    r = roaster.rule_lrt_restaking_wash(KELP_POOL)
    assert r is not None


def test_lrt_wash_none_on_bridge():
    assert roaster.rule_lrt_restaking_wash(STARGATE_ROUTER) is None


def test_lrt_wash_none_on_unknown():
    assert roaster.rule_lrt_restaking_wash(UNKNOWN_ADDR) is None


# ─── Rule 19: phishing_contact ───────────────────────────────────────────

def test_phishing_contact_fires_when_receiver_is_phishing():
    # Seed the lookup directly so the test is independent of which exact
    # addresses happen to be in the vendored feed.
    roaster.PHISHING_ADDRESSES["0xdeadbeef00000000000000000000000000000001"] = "test phish"
    try:
        r = roaster.rule_phishing_contact(
            RANDOM_SENDER, "0xdeadbeef00000000000000000000000000000001"
        )
        assert r is not None
        assert r["score"] == 60
    finally:
        roaster.PHISHING_ADDRESSES.pop("0xdeadbeef00000000000000000000000000000001", None)


def test_phishing_contact_none_on_clean_pair():
    assert roaster.rule_phishing_contact(RANDOM_SENDER, UNKNOWN_ADDR) is None


# ─── Rule 20: exploit_contact ────────────────────────────────────────────

def test_exploit_contact_fires_when_sender_is_exploit():
    roaster.EXPLOIT_ADDRESSES["0xdeadbeef00000000000000000000000000000002"] = "test exploit"
    try:
        r = roaster.rule_exploit_contact(
            "0xdeadbeef00000000000000000000000000000002", UNKNOWN_ADDR
        )
        assert r is not None
        assert r["score"] == 80
    finally:
        roaster.EXPLOIT_ADDRESSES.pop("0xdeadbeef00000000000000000000000000000002", None)


def test_exploit_contact_none_on_clean_pair():
    assert roaster.rule_exploit_contact(RANDOM_SENDER, UNKNOWN_ADDR) is None


# ─── Rule 21: live_sanctions_oracle ──────────────────────────────────────

def test_live_sanctions_oracle_fires_on_oracle_hit(monkeypatch):
    # Stub the oracle helper so tests don't make network calls.
    calls = []

    def stub_oracle_check(addr: str) -> bool:
        calls.append(addr)
        return addr == "0xcafecafecafecafecafecafecafecafecafecafe"

    monkeypatch.setattr(roaster, "chainalysis_oracle_check", stub_oracle_check)
    r = roaster.rule_live_sanctions_oracle(
        RANDOM_SENDER, "0xcafecafecafecafecafecafecafecafecafecafe"
    )
    assert r is not None
    assert r["score"] == 200


def test_live_sanctions_oracle_skips_known_ofac(monkeypatch):
    # Addresses already in OFAC_ADDRESSES should be skipped so the oracle
    # doesn't waste a call on what rule_sanctioned_entity already flagged.
    seen = []

    def stub_oracle_check(addr: str) -> bool:
        seen.append(addr)
        return False

    monkeypatch.setattr(roaster, "chainalysis_oracle_check", stub_oracle_check)
    # TC_1_ETH_POOL is already in OFAC_ADDRESSES.
    roaster.rule_live_sanctions_oracle(RANDOM_SENDER, TC_1_ETH_POOL)
    assert TC_1_ETH_POOL not in seen


def test_live_sanctions_oracle_none_when_clean(monkeypatch):
    monkeypatch.setattr(roaster, "chainalysis_oracle_check", lambda _addr: False)
    assert roaster.rule_live_sanctions_oracle(RANDOM_SENDER, UNKNOWN_ADDR) is None


# ─── Intent-solver additions (reuse rule_bridge_hop) ─────────────────────

COW_SETTLEMENT = "0x9008d19f58aabd9ed0d60971565aa8510560ab41"
ACROSS_RELAYER_1 = "0x428ab2ba90eba0a4be7af34c9ac451ab061ac010"


def test_bridge_hop_fires_on_cow_settlement():
    r = roaster.rule_bridge_hop(COW_SETTLEMENT)
    assert r is not None
    assert r["score"] == 65


def test_bridge_hop_fires_on_across_relayer():
    r = roaster.rule_bridge_hop(ACROSS_RELAYER_1)
    assert r is not None


# ─── Rule 22: sybil_fan_in ───────────────────────────────────────────────

def _sybil_setup(n: int, amount: float = 5.0, noise: float = 0.0):
    """Build a (sender_map, sender_eth_totals) pair for N senders."""
    senders = [f"0x{i:040x}" for i in range(1, n + 1)]
    sender_map = {s: [] for s in senders}
    totals = {s: amount + noise * (i - n / 2) for i, s in enumerate(senders)}
    return senders, sender_map, totals


def test_sybil_fan_in_fires_when_cluster_matches():
    senders, sender_map, totals = _sybil_setup(12, amount=5.0, noise=0.05)
    r = roaster.rule_sybil_fan_in(senders[0], sender_map, totals)
    assert r is not None
    assert r["score"] == 70


def test_sybil_fan_in_none_when_too_few_senders():
    senders, sender_map, totals = _sybil_setup(5, amount=5.0, noise=0.05)
    assert roaster.rule_sybil_fan_in(senders[0], sender_map, totals) is None


def test_sybil_fan_in_none_when_high_variance():
    # 12 senders but amounts span 0.1 ETH to 10 ETH — high CV.
    senders = [f"0x{i:040x}" for i in range(1, 13)]
    sender_map = {s: [] for s in senders}
    totals = {s: 0.1 + i * 1.0 for i, s in enumerate(senders)}
    assert roaster.rule_sybil_fan_in(senders[0], sender_map, totals) is None


def test_sybil_fan_in_excludes_outlier_sender():
    # Cluster of 12 at ~5 ETH each, but sender at position 0 sent 50 ETH.
    senders, sender_map, totals = _sybil_setup(12, amount=5.0, noise=0.05)
    totals[senders[0]] = 50.0  # outlier
    # Cluster still triggers, but THIS sender is outside the cluster.
    r = roaster.rule_sybil_fan_in(senders[0], sender_map, totals)
    assert r is None
    # A cluster-member sender still fires.
    r = roaster.rule_sybil_fan_in(senders[5], sender_map, totals)
    assert r is not None


# ─── Rule 23: machine_cadence ────────────────────────────────────────────

def test_machine_cadence_fires_on_metronome():
    # 6 txs exactly 60s apart with identical gas price
    timestamps = [1_700_000_000 + 60 * i for i in range(6)]
    gas_prices = [20_000_000_000] * 6
    r = roaster.rule_machine_cadence(timestamps, gas_prices)
    assert r is not None
    assert r["score"] == 55


def test_machine_cadence_none_on_human_variance():
    # Uneven gaps + varied gas prices
    timestamps = [1_700_000_000, 1_700_000_037, 1_700_000_410, 1_700_001_823, 1_700_003_200, 1_700_005_100]
    gas_prices = [20_000_000_000, 23_500_000_000, 18_000_000_000, 25_000_000_000, 19_500_000_000, 22_000_000_000]
    assert roaster.rule_machine_cadence(timestamps, gas_prices) is None


def test_machine_cadence_none_on_too_few_txs():
    timestamps = [1_700_000_000 + 60 * i for i in range(3)]
    gas_prices = [20_000_000_000] * 3
    assert roaster.rule_machine_cadence(timestamps, gas_prices) is None


# ─── Rule 24: gas_funding_from_mixer ─────────────────────────────────────

def test_gas_funding_fires_on_mixer_seeded_fresh_wallet(monkeypatch):
    # Stub out the network call.
    def stub_first_inbound(addr):
        return {
            "from": TC_1_ETH_POOL,   # Tornado pool, type=mixer
            "value": str(int(0.05 * 10**18)),   # 0.05 ETH — gas-funding amount
        }

    monkeypatch.setattr(roaster, "get_first_inbound", stub_first_inbound)
    r = roaster.rule_gas_funding_from_mixer(
        sender=RANDOM_SENDER,
        wallet_info={"wallet_age_days": 10},
    )
    assert r is not None
    assert r["score"] == 65


def test_gas_funding_none_when_wallet_old(monkeypatch):
    # Old wallets are skipped to bound API cost.
    called = []
    monkeypatch.setattr(roaster, "get_first_inbound", lambda a: called.append(a) or {})
    r = roaster.rule_gas_funding_from_mixer(
        RANDOM_SENDER, {"wallet_age_days": 400}
    )
    assert r is None
    assert called == []  # must not even hit the fetcher


def test_gas_funding_none_when_first_inbound_is_large(monkeypatch):
    monkeypatch.setattr(
        roaster,
        "get_first_inbound",
        lambda a: {"from": TC_1_ETH_POOL, "value": str(int(5.0 * 10**18))},
    )
    # 5 ETH is above gas_funding_max_eth — not gas funding.
    assert roaster.rule_gas_funding_from_mixer(
        RANDOM_SENDER, {"wallet_age_days": 10}
    ) is None


def test_gas_funding_none_when_source_not_mixer(monkeypatch):
    monkeypatch.setattr(
        roaster,
        "get_first_inbound",
        lambda a: {"from": UNKNOWN_ADDR, "value": str(int(0.05 * 10**18))},
    )
    assert roaster.rule_gas_funding_from_mixer(
        RANDOM_SENDER, {"wallet_age_days": 10}
    ) is None


# ─── Commentary cap and report coverage ──────────────────────────────────

class _HttpResp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def _reset_fetch_bookkeeping():
    roaster._fetch_failures["rate_limit"] = 0
    roaster._fetch_failures["other"] = 0
    roaster._etherscan_call_error["kind"] = None


def _sample_finding(**overrides):
    finding = {
        "sender": "0xabcdef0000000000000000000000000000000001",
        "receiver": "0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f",
        "receiver_label": "FixedFloat 1",
        "tx_count": 1,
        "total_eth": 1.5,
        "individual_values": [1.5],
        "block_range": "1-2",
        "risk_score": 155,
        "risk_level": "CRITICAL",
        "rules_triggered": [
            {
                "rule": "exit_to_no_kyc_offramp",
                "score": 155,
                "detail": "Exit to a no-KYC offramp",
            }
        ],
        "wallet_profile": {
            "age_days": 3,
            "tx_count": 4,
            "balance_eth": 0.1,
            "days_idle": 0,
        },
        "token_transfers": [],
    }
    finding.update(overrides)
    return finding


def _silence_scan_io(monkeypatch, tmp_path):
    monkeypatch.setattr(roaster, "SCAN_STATE_PATH", tmp_path / "scan_state.json")
    monkeypatch.setattr(roaster.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(roaster, "_sleep_backoff", lambda _attempt: None)
    monkeypatch.setattr(roaster, "get_latest_block", lambda: 5000)
    monkeypatch.setattr(roaster, "get_eth_price", lambda: 2000.0)
    monkeypatch.setattr(roaster, "get_block_transactions", lambda _n: [])


def test_commentary_cap_is_25_and_not_env_driven(monkeypatch):
    monkeypatch.setenv("MAX_ANALYSES_PER_RUN", "0")
    monkeypatch.setenv("GROQ_API_KEY", "present")
    source = Path(roaster.__file__).read_text()
    assert roaster.MAX_ANALYSES_PER_RUN == 25
    assert 'os.environ.get("MAX_ANALYSES_PER_RUN"' not in source
    assert "os.environ.get('MAX_ANALYSES_PER_RUN'" not in source
    workflow = Path(roaster.__file__).parent / ".github" / "workflows" / "roaster.yml"
    workflow_text = workflow.read_text()
    assert "MAX_ANALYSES" not in workflow_text
    assert "inputs:" not in workflow_text
    assert "python roaster.py" in workflow_text


def test_zero_cap_report_is_template_only(monkeypatch):
    """A configured API key must not produce model text when the cap is 0."""
    _reset_fetch_bookkeeping()
    roaster._last_partial_scan = None
    roaster._last_fetch_failures = None
    roaster._last_coverage = None
    roaster._last_scan_coverage.update(
        {"attempted": 8, "fully_scanned": 5, "rate_limit": 2, "other": 1}
    )
    monkeypatch.setattr(roaster, "GROQ_API_KEY", "present")
    monkeypatch.setattr(roaster, "MAX_ANALYSES_PER_RUN", 0)

    def _boom(*_a, **_k):
        raise AssertionError("model client constructed while cap is 0")

    monkeypatch.setattr(roaster, "OpenAI", _boom)
    finding = _sample_finding()
    direct = roaster.generate_roast(finding, 2000.0)
    assert direct == roaster._capped_commentary(finding)

    report = roaster.generate_report([finding], 2000.0, {"block_range": "10 — 20"})
    assert report.startswith("# 🔥 AML Roaster Report")
    assert report.count("**Coverage:**") == 1
    assert "blocks 10 to 20 checked" in report
    assert "Activity outside these windows is not checked." in report
    assert "8 addresses attempted, 5 addresses fully scanned, 3 fetch failures (2 Etherscan rate-limit, 1 other). AI commentary is disabled." in report
    assert report.index("**Coverage:**") < report.index("## Finding #1")
    assert "exit_to_no_kyc_offramp" in report
    assert "CRITICAL — Score 155" in report
    assert "per-run analysis cap" in report
    assert roaster._analysis_stats["attempted"] == 0
    assert "Automated analysis error" not in report


def test_empty_report_still_states_coverage_and_commentary_limit():
    roaster._last_partial_scan = None
    roaster._last_fetch_failures = None
    roaster._last_coverage = None
    roaster._last_scan_coverage.update(
        {"attempted": 1, "fully_scanned": 1, "rate_limit": 0, "other": 0}
    )
    report = roaster.generate_report([], 2000.0, {"block_range": "10 — 20"})
    assert report.count("**Coverage:**") == 1
    assert "blocks 10 to 20 checked" in report
    assert "1 address attempted, 1 address fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings." in report
    assert report.index("**Coverage:**") < report.index("No Suspicious Activity")


def test_positive_cap_still_calls_model_for_that_many(monkeypatch):
    roaster._last_partial_scan = None
    roaster._last_fetch_failures = None
    roaster._last_coverage = None
    roaster._last_scan_coverage.update(
        {"attempted": 2, "fully_scanned": 2, "rate_limit": 0, "other": 0}
    )
    monkeypatch.setattr(roaster, "GROQ_API_KEY", "present")
    monkeypatch.setattr(roaster, "MAX_ANALYSES_PER_RUN", 1)
    monkeypatch.setattr(roaster.time, "sleep", lambda *_a, **_k: None)
    calls = {"n": 0}

    class _Message:
        content = (
            '{"what_happened":"model-what","roast":"model-roast",'
            '"sar_narrative":"model-sar","risk_verdict":"model-verdict",'
            '"recommended_action":"model-action"}'
        )

    class _Choice:
        message = _Message()

    class _Response:
        choices = [_Choice()]

    class _Completions:
        @staticmethod
        def create(**_kwargs):
            calls["n"] += 1
            return _Response()

    class _Chat:
        completions = _Completions()

    class _Client:
        def __init__(self, *_a, **_k):
            self.chat = _Chat()

    monkeypatch.setattr(roaster, "OpenAI", _Client)
    low = _sample_finding(risk_score=10, risk_level="LOW")
    high = _sample_finding(risk_score=400, risk_level="CRITICAL")
    report = roaster.generate_report([low, high], 2000.0, {"block_range": "1 — 2"})
    assert calls["n"] == 1
    assert "model-roast" in report
    assert "per-run analysis cap" in report
    assert "AI commentary is limited to 1 highest-scoring finding." in report
    assert roaster._analysis_stats["attempted"] == 1


def test_rate_limit_string_counts_once_and_returns_empty(monkeypatch):
    _reset_fetch_bookkeeping()
    monkeypatch.setattr(roaster, "_sleep_backoff", lambda _attempt: None)
    calls = {"n": 0}

    def _get(*_a, **_k):
        calls["n"] += 1
        return _HttpResp(200, {"status": "0", "message": "NOTOK", "result": "Max rate limit reached"})

    monkeypatch.setattr(roaster.requests, "get", _get)
    assert roaster.get_normal_transactions("0xabc", 1, 2) is None
    assert roaster.get_token_transfers("0xabc", 1, 2) is None
    assert calls["n"] == 2 * roaster._RETRY_ATTEMPTS
    assert roaster._fetch_failures == {"rate_limit": 2, "other": 0}


def test_http_429_counts_as_one_rate_limit_after_retries(monkeypatch):
    _reset_fetch_bookkeeping()
    monkeypatch.setattr(roaster, "_sleep_backoff", lambda _attempt: None)
    calls = {"n": 0}

    def _get(*_a, **_k):
        calls["n"] += 1
        return _HttpResp(429, {})

    monkeypatch.setattr(roaster.requests, "get", _get)
    assert roaster.get_normal_transactions("0xabc", 1, 2) is None
    assert calls["n"] == roaster._RETRY_ATTEMPTS
    assert roaster._fetch_failures == {"rate_limit": 1, "other": 0}


def test_http_500_and_network_errors_count_as_other(monkeypatch):
    _reset_fetch_bookkeeping()
    monkeypatch.setattr(roaster, "_sleep_backoff", lambda _attempt: None)

    monkeypatch.setattr(roaster.requests, "get", lambda *_a, **_k: _HttpResp(500, {}))
    assert roaster.get_token_transfers("0xabc", 1, 2) is None
    assert roaster._fetch_failures == {"rate_limit": 0, "other": 1}

    def _boom(*_a, **_k):
        raise roaster.requests.RequestException("offline")

    monkeypatch.setattr(roaster.requests, "get", _boom)
    assert roaster.get_normal_transactions("0xabc", 1, 2) is None
    assert roaster._fetch_failures == {"rate_limit": 0, "other": 2}


def test_genuine_empty_tx_list_is_not_a_fetch_failure(monkeypatch):
    _reset_fetch_bookkeeping()
    monkeypatch.setattr(roaster, "_sleep_backoff", lambda _attempt: None)
    payload = {"status": "0", "message": "No transactions found", "result": []}
    monkeypatch.setattr(roaster.requests, "get", lambda *_a, **_k: _HttpResp(200, payload))
    assert roaster.get_normal_transactions("0xabc", 1, 2) == []
    assert roaster.get_token_transfers("0xabc", 1, 2) == []
    assert roaster._fetch_failures == {"rate_limit": 0, "other": 0}


def test_block_fetch_counts_only_when_both_sources_fail(monkeypatch):
    _reset_fetch_bookkeeping()
    monkeypatch.setattr(roaster, "_sleep_backoff", lambda _attempt: None)
    monkeypatch.setattr(roaster.requests, "get", lambda *_a, **_k: _HttpResp(429, {}))
    monkeypatch.setattr(
        roaster,
        "rpc_call",
        lambda _method, params=None: {"result": {"transactions": [{"hash": "0x1"}]}},
    )
    assert roaster.get_block_transactions(10) == [{"hash": "0x1"}]
    assert roaster._fetch_failures == {"rate_limit": 0, "other": 0}

    monkeypatch.setattr(roaster, "rpc_call", lambda _method, params=None: {})
    assert roaster.get_block_transactions(11) == []
    assert roaster._fetch_failures == {"rate_limit": 1, "other": 0}


def test_fetch_failure_does_not_advance_scan_cursor_and_counts(monkeypatch, tmp_path):
    """A rate-limit payload is counted and does not advance last_scanned_block."""
    _reset_fetch_bookkeeping()
    addr = "0x" + "11" * 20
    _silence_scan_io(monkeypatch, tmp_path)
    monkeypatch.setattr(roaster, "WATCHED_ADDRESSES", {addr: {"label": "Example", "type": "mixer", "risk": 100}})
    monkeypatch.setattr(roaster, "MAX_WATCHED_PER_RUN", 1)
    monkeypatch.setattr(roaster, "TIME_BUDGET_SECONDS", 900)
    monkeypatch.setattr(
        roaster.requests,
        "get",
        lambda *_a, **_k: _HttpResp(200, {"status": "0", "message": "NOTOK", "result": "Max rate limit reached"}),
    )

    findings = roaster.scan_recent_blocks(num_blocks=5)

    assert findings == []
    state = roaster.load_scan_state()
    assert addr not in state["last_scanned_block"]
    assert roaster._last_scan_coverage == {
        "attempted": 1,
        "fully_scanned": 0,
        "rate_limit": 2,
        "other": 0,
    }


def test_unstarted_addresses_are_not_counted_as_attempted(monkeypatch, tmp_path):
    _reset_fetch_bookkeeping()
    addr_a = "0x" + "ab" * 20
    addr_b = "0x" + "cd" * 20
    _silence_scan_io(monkeypatch, tmp_path)
    monkeypatch.setattr(
        roaster,
        "WATCHED_ADDRESSES",
        {
            addr_a: {"label": "A", "type": "mixer", "risk": 100},
            addr_b: {"label": "B", "type": "mixer", "risk": 100},
        },
    )
    monkeypatch.setattr(roaster, "MAX_WATCHED_PER_RUN", 2)
    monkeypatch.setattr(roaster, "TIME_BUDGET_SECONDS", 0)
    initial = {
        "last_scanned_block": {addr_a: 100, addr_b: 200},
        "first_seen": {},
        "next_watch_index": 0,
    }
    (tmp_path / "scan_state.json").write_text(json.dumps(initial))

    def _unexpected(*_a, **_k):
        raise AssertionError("fetch ran for an address the budget never started")

    monkeypatch.setattr(roaster.requests, "get", _unexpected)
    findings = roaster.scan_recent_blocks(num_blocks=5)

    assert findings == []
    state = roaster.load_scan_state()
    assert state["last_scanned_block"] == {addr_a: 100, addr_b: 200}
    assert state["next_watch_index"] == 0
    assert roaster._last_scan_coverage["attempted"] == 0
    assert roaster._last_scan_coverage["fully_scanned"] == 0
    assert roaster._fetch_failures == {"rate_limit": 0, "other": 0}
    assert roaster._last_partial_scan["scanned_count"] == 0
    assert roaster._last_partial_scan["batch_size"] == 2

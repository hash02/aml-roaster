"""Unit tests for the 16 AML detection rules.

Each rule is tested with at least one positive (fires) and one negative
(returns None) case. Tests use the real WATCHED_ADDRESSES registry so
address-lookup rules exercise the actual data we ship.
"""

from __future__ import annotations

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


# ─── Per-finding detail pages ────────────────────────────────────────────

def test_finding_id_is_stable_and_sized():
    a = roaster.finding_id(RANDOM_SENDER, TC_1_ETH_POOL, "2026-01-01T00:00:00Z")
    b = roaster.finding_id(RANDOM_SENDER, TC_1_ETH_POOL, "2026-01-01T00:00:00Z")
    assert a == b
    assert len(a) == 12
    # Case normalization — the id should not change if the caller passes
    # a checksummed address.
    c = roaster.finding_id(RANDOM_SENDER.upper(), TC_1_ETH_POOL.upper(), "2026-01-01T00:00:00Z")
    assert a == c


def test_finding_id_different_for_different_inputs():
    a = roaster.finding_id(RANDOM_SENDER, TC_1_ETH_POOL, "2026-01-01T00:00:00Z")
    b = roaster.finding_id(RANDOM_SENDER, TC_1_ETH_POOL, "2026-01-01T00:30:00Z")
    assert a != b


def test_generate_finding_page_writes_valid_html(tmp_path, monkeypatch):
    # Redirect reports dir into tmp so we don't pollute the real one.
    monkeypatch.setattr(roaster, "REPORTS_DIR", tmp_path)
    f = {
        "sender": RANDOM_SENDER,
        "receiver": TC_1_ETH_POOL,
        "receiver_label": "Tornado Cash (1 ETH Pool)",
        "risk_score": 430,
        "risk_level": "CRITICAL",
        "tx_count": 3,
        "total_eth": 3.0,
        "rules_triggered": [
            {"rule": "mixer_touch", "score": 100, "detail": "x"},
            {"rule": "ofac_hit", "score": 200, "detail": "x"},
            {"rule": "rapid_fire", "score": 50, "detail": "x"},
        ],
        "_timestamp": "2026-01-01T00:00:00Z",
        "_roast_data": {
            "what_happened": "They did the thing.",
            "roast": "Classic.",
            "risk_verdict": "CRITICAL",
            "recommended_action": "File a SAR.",
        },
    }
    fid = roaster.finding_id(f["sender"], f["receiver"], f["_timestamp"])
    path = roaster.generate_finding_page(
        f, fid, scan_meta={"block_range": "100 — 200"}, eth_price=3000.0
    )
    assert path.exists()
    html = path.read_text(encoding="utf-8")
    assert "Finding " + fid in html
    assert f["sender"] in html
    assert f["receiver"] in html
    assert "Tornado Cash (1 ETH Pool)" in html
    assert "mixer_touch" in html
    assert "Classic." in html
    # Cytoscape payload injected
    assert "cytoscape(" in html
    assert '"source"' in html and '"target"' in html

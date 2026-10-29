"""AML v1 closeout: rate-limit fail-closed, mixer wording, commentary scrub."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import roaster  # noqa: E402

RATE_LIMIT_PAYLOAD = {
    "status": "0",
    "message": "NOTOK",
    "result": "Max rate limit reached",
}

NO_TX_PAYLOAD = {
    "status": "0",
    "message": "No transactions found",
    "result": [],
}

SENDER = "0xabcdef0000000000000000000000000000000001"


class _Resp:
    def __init__(self, payload: dict):
        self.status_code = 200
        self._payload = payload

    def json(self) -> dict:
        return self._payload


def _stub_etherscan(monkeypatch, payload: dict) -> None:
    monkeypatch.setattr(roaster.time, "sleep", lambda _seconds: None)

    def _get(*_args, **_kwargs):
        return _Resp(payload)

    monkeypatch.setattr(roaster.requests, "get", _get)


def _prepare_scan(monkeypatch, tmp_path, http_get) -> None:
    monkeypatch.setattr(roaster, "SCAN_STATE_PATH", tmp_path / "scan_state.json")
    monkeypatch.setattr(roaster, "get_latest_block", lambda: 1000)
    monkeypatch.setattr(roaster, "get_eth_price", lambda: 2000.0)
    monkeypatch.setattr(roaster, "get_block_transactions", lambda _block: [])
    monkeypatch.setattr(roaster.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(roaster.requests, "get", http_get)


def _write_state(tmp_path, last_scanned: dict, next_index: int = 0) -> None:
    (tmp_path / "scan_state.json").write_text(json.dumps({
        "last_scanned_block": last_scanned,
        "first_seen": {},
        "next_watch_index": next_index,
    }))


def _http_by_address(fail_addresses: set[str]):
    def _get(*_args, params=None, **_kwargs):
        address = str((params or {}).get("address", "")).lower()
        if address in fail_addresses:
            return _Resp(RATE_LIMIT_PAYLOAD)
        return _Resp(NO_TX_PAYLOAD)

    return _get


def _finding() -> dict:
    return {
        "sender": SENDER,
        "receiver": "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",
        "receiver_label": "Tornado Cash (1 ETH Pool)",
        "tx_count": 1,
        "total_eth": 1.5,
        "individual_values": [1.5],
        "block_range": "10-12",
        "risk_score": 300,
        "risk_level": "CRITICAL",
        "rules_triggered": [
            {
                "rule": "mixer_touch",
                "score": 100,
                "detail": "Direct deposit to Tornado Cash (1 ETH Pool) — known mixer",
            },
        ],
        "wallet_profile": {
            "age_days": 4,
            "tx_count": 2,
            "balance_eth": 0.1,
            "days_idle": 1,
        },
        "token_transfers": [],
    }


class _Completions:
    def __init__(self, content: str, captured: dict):
        self._content = content
        self._captured = captured

    def create(self, **kwargs):
        self._captured["prompt"] = kwargs["messages"][0]["content"]

        class _Message:
            content = self._content

        class _Choice:
            message = _Message()

        class _Response:
            choices = [_Choice()]

        return _Response()


class _Client:
    def __init__(self, content: str, captured: dict):
        self.chat = type("Chat", (), {})()
        self.chat.completions = _Completions(content, captured)


def _install_llm(monkeypatch, content: str) -> dict:
    captured: dict = {}

    def _openai(*_args, **_kwargs):
        return _Client(content, captured)

    monkeypatch.setattr(roaster, "OpenAI", _openai)
    monkeypatch.setattr(roaster, "GROQ_API_KEY", "test-key")
    return captured


# ─── Rate limits fail closed ─────────────────────────────────────────────

def test_rate_limit_payload_is_a_fetch_failure(monkeypatch):
    _stub_etherscan(monkeypatch, RATE_LIMIT_PAYLOAD)
    assert roaster.etherscan_get({"module": "account", "action": "txlist"}) == {}
    assert roaster.get_normal_transactions(SENDER, 1, 10) is None


def test_other_status_zero_is_a_fetch_failure(monkeypatch):
    _stub_etherscan(monkeypatch, {
        "status": "0",
        "message": "NOTOK",
        "result": "Invalid API Key",
    })
    assert roaster.get_normal_transactions(SENDER, 1, 10) is None


def test_no_transactions_found_is_an_empty_list(monkeypatch):
    _stub_etherscan(monkeypatch, NO_TX_PAYLOAD)
    data = roaster.etherscan_get({"module": "account", "action": "txlist"})
    assert data["message"] == "No transactions found"
    assert roaster.get_normal_transactions(SENDER, 1, 10) == []


def test_rate_limit_defers_address_and_suppresses_all_quiet(monkeypatch, tmp_path, capsys):
    watched = list(roaster.WATCHED_ADDRESSES)
    failed = watched[1]
    _write_state(tmp_path, {failed: 400})
    _prepare_scan(monkeypatch, tmp_path, _http_by_address({failed}))

    findings = roaster.scan_recent_blocks(num_blocks=200)
    report = roaster.generate_report(findings, 2000.0, {})
    state = json.loads((tmp_path / "scan_state.json").read_text())

    assert findings == []
    assert state["last_scanned_block"][failed] == 400
    assert state["last_scanned_block"][watched[0]] == 1000
    assert state["next_watch_index"] == 1
    assert "Coverage incomplete: 1 of 8 addresses could not be fetched (rate limit)" in report
    assert "All quiet" not in report
    assert "7 of 49 addresses" in report
    assert "Activity outside these windows is not checked." in report
    assert "[CATCHUP]" not in capsys.readouterr().out


def test_empty_history_advances_cursor_and_states_coverage(monkeypatch, tmp_path, capsys):
    watched = list(roaster.WATCHED_ADDRESSES)
    behind = watched[0]
    _write_state(tmp_path, {behind: 100})
    _prepare_scan(monkeypatch, tmp_path, _http_by_address(set()))

    findings = roaster.scan_recent_blocks(num_blocks=200)
    report = roaster.generate_report(findings, 2000.0, {})
    state = json.loads((tmp_path / "scan_state.json").read_text())
    logs = capsys.readouterr().out

    assert findings == []
    assert state["last_scanned_block"][behind] == 1000
    assert "All quiet on the Ethereum front." in report
    assert "Coverage incomplete:" not in report
    assert "blocks 1 to 1000 checked (about 3 hours)" in report
    assert "8 of 49 addresses" in report
    assert "about every 42 hours" in report
    assert "Activity outside these windows is not checked." in report
    assert "[SKIP]" in logs
    assert "[CATCHUP]" not in logs
    assert len(roaster.WATCHED_ADDRESSES) == 49
    assert roaster._address_revisit_hours() == 42


# ─── Tornado Cash wording ────────────────────────────────────────────────

def test_mixer_detail_says_known_mixer_not_sanctioned():
    pool = "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936"
    detail = roaster.rule_mixer_interaction(pool)["detail"]
    assert "known mixer" in detail
    assert "OFAC" not in detail
    assert "sanction" not in detail.lower()


def test_ofac_sdn_match_only_when_sanctioned_entity_fires():
    pool = "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936"
    mixer = roaster.rule_mixer_interaction(pool)
    assert "OFAC SDN match" not in mixer["detail"]
    hit = roaster.rule_sanctioned_entity(SENDER, pool)
    assert hit is not None
    assert "OFAC SDN match" in hit["detail"]
    assert roaster.rule_sanctioned_entity(SENDER, "0x" + "11" * 20) is None


def test_tornado_delist_is_recorded_on_the_privacy_rule():
    doc = roaster.rule_privacy_protocol_non_tornado.__doc__ or ""
    assert "Tornado Cash: sanctioned 2022-08-08, delisted 2025-03-21" in doc


# ─── Commentary scrub ────────────────────────────────────────────────────

def test_generate_roast_replaces_banned_sentences(monkeypatch):
    content = json.dumps({
        "what_happened": (
            "A wallet sent coins into a mixing service. "
            "This is money laundering. "
            "The transfer was 1.5 ETH."
        ),
        "roast": "Bold move. This is not illegal.",
        "sar_narrative": "Rule 12(mixer_touch) applies. Pattern score is elevated.",
        "risk_verdict": "CRITICAL — sanctions violation.",
        "recommended_action": "Send this to a human reviewer.",
    })
    captured = _install_llm(monkeypatch, content)
    result = roaster.generate_roast(_finding(), 2000.0)
    verdict = "CRITICAL (rule score 300)"

    assert "launder" not in result["what_happened"].lower()
    assert verdict in result["what_happened"]
    assert "The transfer was 1.5 ETH." in result["what_happened"]
    assert "illegal" not in result["roast"].lower()
    assert verdict in result["roast"]
    assert "Bold move." in result["roast"]
    assert "Rule 12(" not in result["sar_narrative"]
    assert "Pattern score is elevated." in result["sar_narrative"]
    assert result["risk_verdict"] == verdict
    assert result["recommended_action"] == "Send this to a human reviewer."
    assert (
        "Mixer use is a risk pattern, not a sanctions violation, "
        "unless the rule output has an SDN match."
    ) in captured["prompt"]


def test_generate_roast_keeps_clean_commentary(monkeypatch):
    content = json.dumps({
        "what_happened": "A wallet sent 1.5 ETH to a mixing service.",
        "roast": "That is a loud way to move coins.",
        "sar_narrative": "mixer_touch scored 100. The pattern needs human review.",
        "risk_verdict": "CRITICAL (rule score 300)",
        "recommended_action": "Send this to a human reviewer.",
    })
    _install_llm(monkeypatch, content)
    result = roaster.generate_roast(_finding(), 2000.0)
    assert result["what_happened"] == "A wallet sent 1.5 ETH to a mixing service."
    assert result["roast"] == "That is a loud way to move coins."
    assert "launder" not in json.dumps(result).lower()
    assert "violat" not in json.dumps(result).lower()

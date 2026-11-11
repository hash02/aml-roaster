# 🔥 AML Roaster Report
**2026-11-11 05:13 UTC** · Ethereum Mainnet · ETH $2,061.30
**Blocks:** 26389313 — 26389512 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26389313 to 26389512 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 385

| | |
|---|---|
| **Sender** | `0x65eba6b80cee4c77e0bdc7c090cce4a7b1309f2f` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **22** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26389335-26389463 |

### 💬 What Happened
A brand-new wallet sent 22 identical, zero‑value ETH deposits to the Tornado Cash router. It’s like a person repeatedly dropping empty envelopes into a mailbox that hides the sender’s identity. The activity happened in a tight burst of transactions, all within the same block range, with no real money moving.

### 🔥 The Roast
Looks like this wallet decided to play the ‘Zero‑Value, High‑Frequency’ game with a 385‑point score. The mixer_touch rule (meaning a direct hit to the infamous Tornado Cash router) got 100 points, and the mixer_contract_call rule (a fancy way of saying the wallet hit a contract that probably just spun the coins around) added another 70. The structuring rule (identical 0.0000 ETH deposits—classic smurfing) and peel_chain_linear rule (a straight‑line series of deposits) gave it another 140. The machine_cadence rule (transactions spaced like a metronome, proof the bot is in action) added 55, and exchange_avoidance (skipping the KYC exchange step) brought 30 more. Bottom line: this is a high‑risk pattern, not a harmless prank.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of mixer usage, structuring, peel chain, and bot‑like cadence indicates a high‑risk layering pattern that warrants immediate human review.**

Flag the wallet for further investigation, review the subsequent transactions in the chain, and consider placing a temporary hold pending deeper analysis of the source and destination of the funds.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 27 |
| Current Balance | 39.274287 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (6 rules, composite score: 385):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **structuring** (+70) — All 22 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 22 sequential similar deposits — layering pattern
- **machine_cadence** (+55) — 22 txs with metronome cadence (gap CV 0.086, gas CV 0.0011) — AI-agent / bot signature
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Rule [mixer_touch] was triggered by direct deposits to the Tornado Cash router address, indicating potential use of a known mixer. Rule [mixer_contract_call] was triggered by zero‑value contract calls to the same address, suggesting possible withdrawal relay or obfuscation activity. Rule [structuring] identified 22 identical 0.0000 ETH deposits, consistent with structuring or smurfing attempts. Rule [peel_chain_linear], [machine_cadence], and [exchange_avoidance] further corroborate a systematic layering and KYC avoidance strategy.

</details>

---

## Finding #2: HIGH — Score 130

| | |
|---|---|
| **Sender** | `0x53d7a142e6097d866ef752b8cb3bef140d69bc8e` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($206) |
| **Blocks** | 26389508-26389508 |

### 💬 What Happened
The sender moved 0.1 ETH (about $206) straight into a Tornado Cash router, a service that mixes coins to hide where they came from. Think of it like dropping a pizza slice into a mysterious box that then shuffles it with other slices before giving you a new, anonymous topping. The transaction was the only one on that block, and the sender's wallet is brand new, active, and still holding almost the same amount of ETH.

### 🔥 The Roast
Looks like this wallet decided to play hide-and-seek with its 0.1 ETH. The address (0x53d7a142e6097d866ef752b8cb3bef140d69bc8e) just dropped a chunk of crypto into Tornado Cash—yes, that’s the same mixer that makes your coins look like they’re from a different kitchen. The engine gave it a 100 on [mixer_touch] (meaning it landed right on the mixer radar) and 30 on [exchange_avoidance] (because it skipped the usual exchange checkpoints). So, if you’re looking for a smooth ride, this wallet chose the detour that would make a detective sigh.

### 🎯 Verdict & Next Steps
**HIGH — the transaction scores 130 with a direct mixer deposit and avoidance of regulated exchanges, indicating significant risk of anonymity and potential illicit use.**

Flag the wallet for manual review, trace the originating source of the 0.1 ETH, and consider adding the address to the internal watchlist pending further due diligence.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1 days |
| Total Transactions | 16 |
| Current Balance | 0.110391 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 130):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Transaction 26389508: Sender 0x53d7a142e6097d866ef752b8cb3bef140d69bc8e transferred 0.1000 ETH to Tornado Cash Router 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b. Rule [mixer_touch] triggered at 100 points for direct deposit to a known mixer. Rule [exchange_avoidance] triggered at 30 points for routing funds to a mixer instead of a regulated exchange, indicating potential KYC circumvention. The wallet is new (1 day old), has high activity (16 tx), and retains a balance of 0.110391 ETH, suggesting recent source of funds. This pattern warrants further investigation per AML policy.

</details>

---

## Scan Summary

**2 suspicious findings** detected across 2 unique wallets. Highest risk score: **385**.

| | |
|---|---|
| 🔴 CRITICAL | 1 |
| 🟠 HIGH | 1 |
| Wallets flagged | 2 |
| Suspicious value | 0.1000 ETH ($206) |
| Blocks scanned | 26389313 — 26389512 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

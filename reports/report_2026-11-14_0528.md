# 🔥 AML Roaster Report
**2026-11-14 05:28 UTC** · Ethereum Mainnet · ETH $1,901.67
**Blocks:** 26410930 — 26411129 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26410930 to 26411129 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 330

| | |
|---|---|
| **Sender** | `0x35a91969fbc917c5a5d10faf30223690ddd879ac` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **19** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26410935-26411046 |

### 💬 What Happened
The sender wallet, brand‑new and empty, made 19 identical deposits of 0.0000 ETH into a Tornado Cash router address. It’s like someone dropping a thousand identical empty cups into a sink, hoping no one will notice the pattern. The wallet has no balance and no history, but it just spent the exact same tiny amount over and over again.

### 🔥 The Roast
Looks like a fresh‑out‑of‑the‑oven wallet that’s trying to hide behind a mixer. 19 zero‑eth deposits? That’s the crypto version of a vending machine that only accepts change from a magician’s hat. The engine flags it as a mixer touch (meaning the wallet is directly depositing into a known mixer), a mixer contract call (a zero‑value call that probably just pretends to do something), and even structuring (smurfing) and peel chain linear (a straight‑line layering pattern). Exchange avoidance? Yeah, they’re skipping the KYC gate and going straight to the shady side. All in all, it’s the kind of activity that makes you want to put the wallet on a red‑flag list faster than a pizza delivery guy can say “extra cheese.”

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of mixer usage, structuring, and peel chain linearity indicates a high‑risk pattern requiring immediate human investigation.**

Flag the wallet for manual review, request source of funds, and monitor for any subsequent transactions. If additional suspicious activity emerges, consider reporting to the relevant regulatory authorities.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 22 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (5 rules, composite score: 330):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **structuring** (+70) — All 19 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 19 sequential similar deposits — layering pattern
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The account 0x35a91969fbc917c5a5d10faf30223690ddd879ac exhibited suspicious activity between blocks 26410935 and 26411046, making 19 identical zero‑ETH deposits to the Tornado Cash Router address 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b. This behavior matches Rule mixer_touch (score: 100) indicating direct interaction with a known mixer, Rule mixer_contract_call (score: 70) for the zero‑value contract call, Rule structuring (score: 70) due to identical deposit amounts, Rule peel_chain_linear (score: 60) for the sequential deposit pattern, and Rule exchange_avoidance (score: 30) as funds bypassed traditional exchanges. The composite score of 330 exceeds the critical threshold, warranting a formal SAR filing and human review. No token transfers were recorded, and the wallet balance remains zero, further underscoring the lack of legitimate activity.

</details>

---

## Scan Summary

**1 suspicious finding** detected across 1 unique wallet. Highest risk score: **330**.

| | |
|---|---|
| 🔴 CRITICAL | 1 |
| 🟠 HIGH | 0 |
| Wallets flagged | 1 |
| Suspicious value | 0.0000 ETH ($0) |
| Blocks scanned | 26410930 — 26411129 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

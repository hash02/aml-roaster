# 🔥 AML Roaster Report
**2026-11-08 21:50 UTC** · Ethereum Mainnet · ETH $2,215.92
**Blocks:** 26372751 — 26372950 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26372751 to 26372950 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0xd04e9f0945dea8373d882c730e2c93a74b591796` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26372836-26372836 |

### 💬 What Happened
A wallet that has been around for almost three years just sent a tiny, zero-value Ethereum transaction to Tornado Cash, a service that scrambles the origin of funds. It’s like dropping an empty envelope into a slot that hides who dropped it, but the fact that the envelope was addressed to a known mixer is enough to raise eyebrows. The sender still has a little balance left, and the transaction was made right now.

### 🔥 The Roast
Score 200 on mixer_touch (means the address tried to hide like a cat behind a curtain) and mixer_contract_call (a zero-value call that’s basically a fancy way of saying "I’m not actually sending anything, just messing with the system") topped off with exchange_avoidance (because nobody likes getting checked by KYC folks). Even though the ETH value was $0, the pattern screams "I want to be anonymous," like someone trying to sneak a snack through a security checkpoint. If you’re wondering why the wallet still has ETH, it’s probably just hoarding the loot for a later, more suspicious time.

### 🎯 Verdict & Next Steps
**The composite score of 200 indicates a high-risk mixer activity that warrants immediate review.**

Flag this transaction for manual compliance review; investigate the source of the ETH balance and monitor future activity for additional suspicious patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1245 days |
| Total Transactions | 8297 |
| Current Balance | 0.553668 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction involving wallet 0xd04e9f0945dea8373d882c730e2c93a74b591796 to the Tornado Cash Router (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b) on block 26372836 was flagged under Rule [mixer_touch] with a score of 100, indicating a direct deposit to a known mixer. Rule [mixer_contract_call] assigned 70 points for a zero-value contract call, suggesting possible obfuscation or governance activity. Rule [exchange_avoidance] added 30 points for routing funds to a mixer instead of a regulated exchange. The composite score of 200 signals a high-risk pattern requiring further investigation.

</details>

---

## Finding #2: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x4750bcfcc340aa4b31be7e71fa072716d28c29c5` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26372754-26372754 |

### 💬 What Happened
The sender sent a tiny, almost invisible amount of Ethereum (worth $0) straight into Tornado Cash's router. It's like dropping a note into a secret mailbox that hides who left it. CRITICAL (rule score 200)

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their wallet, but the only thing hidden is the fact that they used a mixer. They sent a zero‑value ETH to Tornado Cash, which is like trying to get a free pizza by ordering a coupon that costs nothing. The engine gave it a 200 score—so big deal, because 200 is the high‑score in the game of suspicious activity. The [mixer_touch] rule hit 100 (meaning a direct deposit to a known mixer), and the [exchange_avoidance] 30 shows they're trying to avoid the real world, like a kid avoiding school by riding a scooter straight to the playground.

### 🎯 Verdict & Next Steps
**The transaction triggers a critical risk flag due to mixer activity and potential exchange avoidance.**

Flag the wallet for manual review, investigate downstream transactions and potential links to other suspicious addresses. Consider adding the address to a watchlist for ongoing monitoring.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1593 days |
| Total Transactions | 17116 |
| Current Balance | 7.364785 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction triggers multiple AML rules: [mixer_touch] (direct deposit to Tornado Cash Router), [mixer_contract_call] (zero‑value contract call indicating possible withdrawal relay or obfuscation), and [exchange_avoidance] (routing funds to a mixer instead of a regulated exchange). The composite score of 200 exceeds our critical threshold. CRITICAL (rule score 200) The wallet has a high activity volume and is currently active, raising further concern.

</details>

---

## Scan Summary

**2 suspicious findings** detected across 2 unique wallets. Highest risk score: **200**.

| | |
|---|---|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 0 |
| Wallets flagged | 2 |
| Suspicious value | 0.0000 ETH ($0) |
| Blocks scanned | 26372751 — 26372950 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

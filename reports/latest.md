# 🔥 AML Roaster Report
**2026-11-01 21:49 UTC** · Ethereum Mainnet · ETH $2,263.94
**Blocks:** 26322511 — 26322710 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26322511 to 26322710 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x542db1a465fe63941fff367094e511fe81ad41b4` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26322570-26322570 |

### 💬 What Happened
A wallet with about 0.027 ETH sent a zero‑value transaction to the Tornado Cash router, a service that mixes coins to hide their origin. Think of it like dropping an empty bag into a machine that rearranges all the bags so no one knows who owns them. The wallet was active today, so the activity wasn’t buried in a long‑ago history.

### 🔥 The Roast
So this guy just handed over a virtual empty pizza box to Tornado Cash – the blockchain’s version of a smuggler’s hide‑and‑seek game. The engine gave him a 100 on mixer_touch (meaning he touched the mixer directly, like stepping into a shady alley). Then 70 on mixer_contract_call (he called the mixer’s contract with no money, probably a trick to get the coins to re‑appear somewhere else). And 30 on exchange_avoidance (he avoided the usual ‘KYC’ gate, like trying to sneak past the bouncer without a ticket). CRITICAL (rule score 200)

### 🎯 Verdict & Next Steps
**CRITICAL: The combination of mixer usage and zero‑value contract calls indicates high suspicious activity requiring immediate human review.**

Flag the wallet for manual investigation and monitor subsequent transactions for pattern confirmation. Consider cross‑referencing with internal watchlists and reporting to the compliance team for further action.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 117 days |
| Total Transactions | 795 |
| Current Balance | 0.027423 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction (block 26322570) shows a zero‑value ETH transfer from 0x542db1a465fe63941fff367094e511fe81ad41b4 to 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b, the Tornado Cash Router. Rule mixer_touch was triggered (score 100) due to the direct deposit to a known mixer. Rule mixer_contract_call was also triggered (score 70) because the transaction is a contract call with no ETH sent, indicating potential withdrawal relay or obfuscation. Rule exchange_avoidance (score 30) applied as funds bypassed a regulated exchange. The wallet is 117 days old, has 795 total transactions, and currently holds 0.027423 ETH, with no inactivity period.

</details>

---

## Finding #2: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x5555555731006f71f121144534ca7c8799f66aa3` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26322533-26322533 |

### 💬 What Happened
Someone sent a zero‑value amount of ETH to a special address that scrambles who owns it. It’s like dropping a blank envelope into a black‑hole box that hides the sender, all in a single block with no time for anyone to check the details.

### 🔥 The Roast
So the guy just whispered "zero" into the mixer, like a secret handshake to the blockchain mafia. He hit the Tornado Cash Router, which is basically the blockchain equivalent of a shady bar where you can trade without showing your ID. He scored a perfect 100 on the mixer_touch rule—think of it as a red flag on a driver’s license. Then he triggered mixer_contract_call for 70, maybe voting on a governance proposal or just messing around. And, because he avoided the exchange, he scored 30 on exchange_avoidance—like skipping the bank and going straight to the underground club.

### 🎯 Verdict & Next Steps
**The composite score of 200 indicates a high‑risk activity pattern requiring immediate compliance review.**

Flag the transaction for manual review by the compliance team and monitor the sender for additional suspicious activity. Consider cross‑checking the wallet against known risk lists and request further information if the sender is identified in future transactions.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1305 days |
| Total Transactions | 9051 |
| Current Balance | 16.168484 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The account 0x5555555731006f71f121144534ca7c8799f66aa3 executed a transaction to the Tornado Cash Router (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b) with a zero ETH value. The transaction triggered the following AML engine rules: [mixer_touch] (score 100) indicating a direct deposit to a known mixer; [mixer_contract_call] (score 70) indicating a zero‑value contract call to the mixer; and [exchange_avoidance] (score 30) indicating routing to a mixer rather than a regulated exchange. CRITICAL (rule score 200)

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
| Blocks scanned | 26322511 — 26322710 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

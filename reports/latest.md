# 🔥 AML Roaster Report
**2026-10-29 17:54 UTC** · Ethereum Mainnet · ETH $2,334.48
**Blocks:** 26299822 — 26300021 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26299822 to 26300021 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x7a2ea6ab500c17fd9e11c5d6f26fd4b2c1afd465` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26300005-26300013 |

### 💬 What Happened
The sender moved two tiny, zero‑value ETH amounts into a Railgun Relay, which is a privacy tool that hides the source of funds. It’s like dropping a pair of invisible envelopes into a locked box that only the box owner can open, but the envelopes themselves contain nothing. The sender’s wallet still holds 0.177 ETH, so the move doesn’t change their balance but might be a step toward mixing or layering the coins.

### 🔥 The Roast
So we have a wallet that’s been around for 310 days, already sent 2,242 transactions, and now it’s playing hide‑and‑seek with a Railgun Relay. Railgun is basically a fancy Swiss‑Army knife for privacy, but it’s not the same as the outlawed Tornado Cash that got delisted in 2025. MEDIUM (rule score 75) The big joke? The sender is moving zero‑value ETH like a magician slipping invisible coins into a hat—only the hat knows where they came from. If this is a legit test, the wallet is basically practicing its disappearing act before the next big trick.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Flag the wallet for manual review, monitor future transactions for further layering or conversion to fiat, and cross‑reference with known P2P exchange activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 310 days |
| Total Transactions | 2242 |
| Current Balance | 0.177238 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Rule [privacy_protocol] (Deposit to Railgun Relay) triggered a composite score of 75. The transaction history shows 2242 transfers from a 310‑day‑old wallet with 0.177238 ETH balance, and the last activity was immediate. Two zero‑value ETH transfers to a privacy protocol suggest a potential layering or obfuscation pattern. Recommend a manual review of subsequent activity for signs of conversion to fiat or further layering.

</details>

---

## Finding #2: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x1ed98663fd1000002e283a0402bd531c54ce6abc` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26299921-26299989 |

### 💬 What Happened
A user sent a very small amount of ETH (virtually nothing) to a Railgun Relay, which is a privacy tool that hides where the money comes from. Think of it like dropping a package into a hidden slot that makes it hard to trace the sender. The transaction was recorded in block numbers 26299921 to 26299989.

### 🔥 The Roast
Scored 75 on the privacy_protocol rule (meaning this transfer was routed through a privacy service that obscures its origin). The sender’s wallet is 310 days old and has 2267 transactions, yet it still holds 0.185852 ETH—like a bank account that never empties. The transfer amount was 0.0000 ETH, which is basically sending an invisible envelope through a secret tunnel. Regulators probably need a magnifying glass to see who’s behind this. MEDIUM (rule score 75)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Conduct a manual review of the source and destination addresses, gather additional transaction metadata, and assess whether this transfer is part of a larger suspicious activity pattern.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 310 days |
| Total Transactions | 2267 |
| Current Balance | 0.185852 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: Transaction block range 26299921-26299989 shows a transfer of 0 ETH from sender 0x1ed98663fd1000002e283a0402bd531c54ce6abc to receiver 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9 (Railgun Relay). The transfer was flagged under Rule [privacy_protocol] with a score of 75 for use of a privacy protocol. MEDIUM (rule score 75) MEDIUM (rule score 75)

</details>

---

## Finding #3: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x38291ed1e67f2691f2bcae513c32e8cb8d7d3d31` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26299850-26299850 |

### 💬 What Happened
A person sent a tiny, invisible packet of ETH (essentially nothing) to a privacy service called Railgun. Imagine dropping a letter into a mailbox that scrambles the sender’s name so nobody can trace who it came from. The transaction happened on a single block and didn’t actually move any money, but it still used a system designed to hide who’s sending what.

### 🔥 The Roast
So this guy decided to play hide‑and‑seek with his crypto, sending a zero‑value packet to a privacy relay—like trying to hide a peanut in a haystack that weighs nothing. The AML engine gave it a 75 on the privacy_protocol rule, meaning the system thinks this is a classic “I want my money to look like a ghost” move. MEDIUM (rule score 75)

### 🎯 Verdict & Next Steps
**MEDIUM – the use of a privacy protocol without accompanying transfer of value signals potential layering, but lacks direct evidence of wrongdoing.**

Review the sender’s transaction history and any linked addresses for patterns of layering or known suspicious activity; consider flagging the wallet for further monitoring and, if needed, request additional context from the user.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 132 days |
| Total Transactions | 10 |
| Current Balance | 0.003471 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The sender wallet (0x38291ed1e67f2691f2bcae513c32e8cb8d7d3d31) executed a transaction to a Railgun Relay address (0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9) with a composite score of 75 on the [privacy_protocol] rule. The transaction involved no token transfers and a value of $0, indicating a deposit to a privacy protocol that obscures the origin of funds. The wallet is 132 days old, has performed 10 prior transactions, and currently holds 0.003471 ETH. This activity pattern warrants scrutiny for potential layering or obfuscation consistent with privacy protocol usage. MEDIUM (rule score 75)

</details>

---

## Scan Summary

**3 suspicious findings** detected across 3 unique wallets. Highest risk score: **75**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| Wallets flagged | 3 |
| Suspicious value | 0.0000 ETH ($0) |
| Blocks scanned | 26299822 — 26300021 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

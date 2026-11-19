# 🔥 AML Roaster Report
**2026-11-19 07:13 UTC** · Ethereum Mainnet · ETH $1,805.56
**Blocks:** 26447351 — 26447550 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26447351 to 26447550 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x1ed98663fd1000002e283a0402bd531c54ce6abc` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26447486-26447486 |

### 💬 What Happened
A user with a wallet that’s been around for 331 days sent a tiny, almost zero‑value transaction to a privacy service (Railgun Relay) that hides the origin of funds. Think of it as dropping a note into a locked box that only the sender knows the key to, so no one can trace where the note came from. The transaction didn't move any tokens, so it’s like sending an empty envelope through a secret post office.

### 🔥 The Roast
Looks like someone’s trying to hide their moves in a privacy‑filled maze. Scored 75 on the privacy_protocol rule (meaning the address is using a privacy service that obfuscates transaction details). They sent a $0 transaction to a Railgun Relay—talk about putting a lot of effort into a zero‑sum game. If you’re playing hide‑and‑seek with your money, at least bring a map. At least the wallet is old enough to have a history, but still, a 331‑day‑old account with 2,568 transactions can’t be too clean.

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol with a moderately active wallet raises concerns about potential layering, but no direct evidence of illicit activity.**

Flag the transaction for manual review; request additional context on the sender’s source of funds and monitor for subsequent activity to the same or related addresses.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 331 days |
| Total Transactions | 2568 |
| Current Balance | 0.009522 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Rule: privacy_protocol triggered. Evidence: Transaction to Railgun Relay, no token transfer, wallet age 331 days, transaction count 2,568, and zero days since last activity. The composite score of 75 indicates moderate concern for potential layering or obfuscation. The transaction is flagged for further manual review under AML policy section 3.2.

</details>

---

## Finding #2: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x282d8b141c4e325fadc81154aa94f63f2cb27185` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26447432-26447432 |

### 💬 What Happened
The user sent a tiny amount of nothing—zero ETH—to a privacy service called Railgun. Think of it like dropping a blank envelope into a locked box that hides who mailed it. The transaction was recorded on the blockchain but carried no value, so it looks like a test or a prank.

### 🔥 The Roast
So this wallet decided to play hide and seek with the blockchain, sending a zero‑value packet to Railgun (a privacy protocol that obfuscates transaction details) because who needs money when you can have mystery? The privacy_protocol rule flagged this with a 75 score, which is like giving a gold star to the most suspicious ‘no money, just vibes’ transaction. It’s almost like the wallet is trying to get a free privacy upgrade for the price of a snack. If you think zero ETH is nothing, just remember that a zero is still a number, and in crypto, numbers can be as mysterious as your grandma’s attic. Basically, the wallet is acting like a cat that only comes out at midnight to check on the neighbor’s fence.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Conduct a manual review of the wallet’s recent and future activity, monitor for subsequent transactions to privacy protocols or large transfers, and consider adding the address to a high‑risk watchlist.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 192 days |
| Total Transactions | 48 |
| Current Balance | 0.150464 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Rule: privacy_protocol – deposit to Railgun Relay (non‑Tornado privacy protocol). Composite score 75 indicates medium‑to‑high risk. The transaction involved zero ETH but the pattern of sending to a privacy protocol may suggest testing or obfuscation. Further investigation of wallet activity and potential watchlist inclusion is recommended.

</details>

---

## Finding #3: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xccef06b2e82a184e34b118ed81f5ded120f8136c` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26447364-26447364 |

### 💬 What Happened
A wallet was caught interacting with Railgun Relay. Our engine flagged it at score 75.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 779 days |
| Total Transactions | 2691 |
| Current Balance | 0.377245 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

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
| Blocks scanned | 26447351 — 26447550 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 1 of 3 attempted analyses this run.

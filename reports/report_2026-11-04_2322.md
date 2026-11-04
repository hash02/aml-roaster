# 🔥 AML Roaster Report
**2026-11-04 23:22 UTC** · Ethereum Mainnet · ETH $2,423.06
**Blocks:** 26344507 — 26344706 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26344507 to 26344706 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x05839e02ff4e49e5b2a274fb2eaa148adcf52753` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$140** (140 USDC) |
| **Blocks** | 26344688-26344688 |

### 💬 What Happened
MEDIUM (rule score 80) Think of it like dropping a $140 envelope into a secret box that hides who put it there. The transaction happened in one block and nothing else was involved.

### 🔥 The Roast
MEDIUM (rule score 80) MEDIUM (rule score 80) MEDIUM (rule score 80) The wallet’s balance is zero ETH, so it’s basically a dead‑end wallet, like a mailbox that never receives a reply. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for manual review by the compliance team, and consider cross‑checking the sender’s address against internal and external watchlists before any further processing.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $140 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) The composite AML score is 80, indicating moderate risk. MEDIUM (rule score 80) This activity should be documented and referred for further review per AML policy guidelines.

</details>

---

## Finding #2: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x05839e02ff4e49e5b2a274fb2eaa148adcf52753` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26344688-26344688 |

### 💬 What Happened
Someone with the digital wallet 0x05839e02ff4e49e5b2a274fb2eaa148adcf52753 sent zero ETH to a Railgun Relay address, which is like dropping a note into a sealed envelope that hides who wrote it. The transaction was recorded on block 26344688 and no tokens were actually transferred. Basically, it looks like a test or placeholder transaction into a privacy service.

### 🔥 The Roast
Well, congratulations, you just dropped a zero‑ETH into a Railgun Relay—like sending a postcard with no postage. The [privacy_protocol] rule (meaning the system flagged you for using a privacy protocol that hides transaction details) gave it a 75, as if the engine thinks you’re hiding a rabbit in a hat. The sender’s wallet is only 133 days old with 19 moves, so it’s as mysterious as a toddler with a calculator. MEDIUM (rule score 75) Maybe you’re just messing with the blockchain like a kid with a toy car—just don’t forget the toy car’s wheels!

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

MEDIUM (rule score 75) If additional transactions to privacy protocols occur, consider applying stricter due diligence or reporting.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 133 days |
| Total Transactions | 19 |
| Current Balance | 0.046023 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: The transaction involved a deposit to the Railgun Relay, a privacy protocol, triggering the [privacy_protocol] rule with a composite score of 75. The sender’s wallet, aged 133 days with 19 total transactions and a current balance of 0.046023 ETH, shows low activity but a potential attempt to obfuscate asset movement. No token transfers or monetary value were recorded, indicating a test or placeholder action rather than a substantive transfer. MEDIUM (rule score 75)

</details>

---

## Finding #3: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xccef06b2e82a184e34b118ed81f5ded120f8136c` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26344573-26344573 |

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
| Wallet Age | 765 days |
| Total Transactions | 1379 |
| Current Balance | 0.255469 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #4: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x9b2d5b96764bca81d448456d4a3a4017b71e3ae8` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26344543-26344543 |

### 💬 What Happened
A user sent a negligible amount of ETH (virtually zero) into a privacy service that scrambles transaction trails. It's like dropping a note into a black box so no one knows who wrote it. The transaction itself didn't move any money, but the action is a common way to hide the source of funds.

### 🔥 The Roast
Scored a 75 on the privacy protocol radar, meaning this address is basically the blockchain's version of a secret Santa. It's like paying with invisible money—zero value, but the mystery stays. MEDIUM (rule score 75) If you thought 0 ETH was harmless, think again: even a whisper can carry a secret. The Railgun relay is the blockchain's own private club—membership is exclusive, but the entry fee is a joke.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Review the sender's transaction history for patterns of layering or structuring. MEDIUM (rule score 75)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 276 days |
| Total Transactions | 319 |
| Current Balance | 0.023394 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction is a deposit to a Railgun relay, a privacy protocol used to obfuscate transaction flows. This activity triggers the AML engine's privacy_protocol rule, resulting in a composite score of 75. The sender wallet is relatively new (276 days) with 319 total transactions, and the transaction value is zero, which may be typical for test or dust transactions. MEDIUM (rule score 75)

</details>

---

## Scan Summary

**4 suspicious findings** detected across 3 unique wallets. Highest risk score: **80**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| Wallets flagged | 3 |
| Suspicious value | 0.0000 ETH ($0) + $140 in stablecoins |
| Blocks scanned | 26344507 — 26344706 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 1 of 4 attempted analyses this run.

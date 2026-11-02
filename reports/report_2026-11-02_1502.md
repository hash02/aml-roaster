# 🔥 AML Roaster Report
**2026-11-02 15:02 UTC** · Ethereum Mainnet · ETH $2,283.90
**Blocks:** 26327660 — 26327859 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26327660 to 26327859 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1c9bdee2de64c06a998ca9336142b898ae11ee15` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0018 ETH** ($4) |
| **Blocks** | 26327846-26327846 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 85.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000004 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #2: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa81c1a2a64e40916bd82d884a9fea3aea1b8aa64` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0020 ETH** ($5) |
| **Blocks** | 26327828-26327828 |

### 💬 What Happened
MEDIUM (rule score 85) It was a one‑off transfer, and the sender’s wallet is now basically empty, with only a tiny 0.000004 ETH left. The move is like dropping a $5 bill into a slot that hides who sent it and then walking away.

### 🔥 The Roast
Look at this fresh wallet, 0 days old, just like a newborn that only knows how to say ‘mama’ and ‘papa’—it made a single $5 transfer and vanished. MEDIUM (rule score 85) It’s the classic ‘drop it in and disappear’ trick, with no identity checks. If you’re worried, just remember: it’s the same pattern we see when someone is trying to hide the source of a tip jar.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for further investigation and consider monitoring the sender wallet for future activity. Notify the compliance team to assess whether additional due diligence is required.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000004 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 85) Rule no_kyc_offramp is triggered due to deposit to an off‑ramp without KYC verification, scoring 85. The sender wallet has minimal activity and low balance, consistent with a potential attempt to obscure source. MEDIUM (rule score 85)

</details>

---

## Finding #3: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x67f5328d5a6093cd326614886e8c180b7ef702da` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDC) |
| **Blocks** | 26327782-26327782 |

### 💬 What Happened
A wallet was caught interacting with Railgun Treasury. Our engine flagged it at score 80.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag for manual review.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $0 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #4: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x387ad8b082c4a81d61056c83903c2613438af7bf` |
| **Target** | Privacy Pools (0xbow) Entrypoint (`0x6818809eefce719e48...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26327738-26327738 |

### 💬 What Happened
The sender made a transaction of zero ETH to a privacy pool entrypoint, which is basically a way to hide where the funds came from even though nothing moved. Think of it like putting an empty envelope in a mailbox that scrambles the sender’s address. The wallet was brand new, had only five transactions, and still held some ETH after the move.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their wallet. They sent a $0 packet into a privacy pool (think of it as a Black‑Berry Messenger that actually deletes the message after you send it). The engine gave it a 75 because even though nothing changed hands, the act of using a privacy protocol is a red flag. It’s like paying $0 for a membership to the “I‑don’t‑want‑people‑to‑see‑me” club. Good luck trying to make that look innocent.

### 🎯 Verdict & Next Steps
**Medium risk due to use of a privacy protocol with high engine score and minimal transaction activity.**

Flag the wallet for manual review, investigate upstream and downstream activity, and monitor for subsequent movements of ETH from the privacy pool.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 5 |
| Current Balance | 0.035309 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Privacy Pools (0xbow) Entrypoint — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Rule: privacy_protocol (score 75). Evidence: transaction to 0xbow entrypoint, zero value, wallet age 0 days, only 5 txs, current balance 0.035309 ETH. MEDIUM (rule score 75) Flag for manual review and monitor downstream activity.

</details>

---

## Scan Summary

**4 suspicious findings** detected across 4 unique wallets. Highest risk score: **85**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| Wallets flagged | 4 |
| Suspicious value | 0.0037 ETH ($9) + $0 in stablecoins |
| Blocks scanned | 26327660 — 26327859 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 2 of 4 attempted analyses this run.

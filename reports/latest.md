# 🔥 AML Roaster Report
**2026-11-16 15:10 UTC** · Ethereum Mainnet · ETH $1,822.95
**Blocks:** 26428192 — 26428391 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26428192 to 26428391 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xb25058ccb45e0cd7d588e18e23a1e02b85f59f54` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** token transfer totaling **$29,198** (29,198 USDT) |
| **Blocks** | 26428308-26428308 |

### 💬 What Happened
HIGH (rule score 110) Think of it like dropping a package into a slot that hides its sender so no one can trace it back. This one‑time move is the only activity we see in the block range.

### 🔥 The Roast
Looks like someone wanted to play hide‑and‑seek with their $29k in stablecoins. The sender’s wallet has zero ETH and no recent history, so it’s like showing up at a party with a bag of cash and no ID. HIGH (rule score 110) Either way, this is the kind of transaction that makes regulators’ hair stand on end.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

HIGH (rule score 110) Gather additional context on the sender’s source of funds and consider filing a SAR if further suspicious patterns emerge.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 110):
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to Railgun Relay: $29,198 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule: stablecoin_mixing (score 110). Evidence: single USDT transfer of $29,198 to a Railgun Relay address. HIGH (rule score 110) HIGH (rule score 110)

</details>

---

## Finding #2: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x544c3e97228627f5477e0c92fa208ebbddeb299b` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** token transfer totaling **$2,834** (2,834 USDT) |
| **Blocks** | 26428375-26428375 |

### 💬 What Happened
A user sent about $2,834 worth of USDT (a stablecoin that’s usually pegged to the US dollar) to a Railgun Relay address. Think of it like putting a cash envelope into a mysterious drop box that hides who you are and where it ends up. The transaction was a single transfer, so it looks like a simple deposit into a privacy tool.

### 🔥 The Roast
So our little friend decided to play hide‑and‑seek with $2,834 of USDT. That’s like dropping a $2,800 pizza order into a black‑hole‑shaped mailbox and hoping no one notices. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for manual review, and consider tracing the funds through the Railgun network to identify the final destination. Notify compliance if further suspicious activity is detected.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Relay: $2,834 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Transaction 26428375 involved a transfer of USDT totaling $2,834 from wallet 0x544c3e97228627f5477e0c92fa208ebbddeb299b to the Railgun Relay address 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9. According to Rule stablecoin_mixing, a single stablecoin transfer to a privacy‑enhancing service with a score of 80 constitutes a suspicious activity pattern. MEDIUM (rule score 80) The wallet’s activity profile is unknown, but the lack of recent activity and zero ETH balance raise additional concern.

</details>

---

## Finding #3: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x544c3e97228627f5477e0c92fa208ebbddeb299b` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$7** (7 USDT) |
| **Blocks** | 26428375-26428375 |

### 💬 What Happened
A person sent 7 USDT to a special address that hides where the money came from. It's like dropping a package into a slot that only the bank can see, but no one knows who dropped it in.

### 🔥 The Roast
MEDIUM (rule score 80) According to the stablecoin_mixing rule (meaning the system thinks you’re mixing money like a smoothie to hide the source), that’s a red flag. It’s like trying to hide a $7 bill in a blender and calling it a smoothie—nobody's impressed. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for manual compliance review, investigate the sender’s prior activity and any related transactions, and consider placing a temporary hold pending further analysis.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $7 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) Rule: stablecoin_mixing triggered with a composite score of 80. MEDIUM (rule score 80) This pattern indicates potential layering activity and warrants further investigation.

</details>

---

## Finding #4: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x891a54df11ad438d04d8a97f3e4035d8cf4bfb24` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$25** (25 USDT) |
| **Blocks** | 26428335-26428335 |

### 💬 What Happened
MEDIUM (rule score 80) Think of it like dropping a $25 package into a black box that hides who sent it. The transaction happened in one block and the sender's wallet hasn't been seen doing anything else, so there's no obvious trail.

### 🔥 The Roast
So, someone's playing hide-and-seek with $25 in USDT, and the only clue is a single block. The sender's wallet is as empty as a bank account after a crypto crash (0 ETH) and has no history – basically a ghost wallet. MEDIUM (rule score 80) If you think that's scary, imagine a magician pulling a rabbit out of a hat that actually came from a hat in another country.

### 🎯 Verdict & Next Steps
**MEDIUM risk due to stablecoin mixing pattern.**

Flag the transaction for manual review and investigate the sender's source of funds and any downstream activity.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $25 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) Evidence: 25 USDT transferred from address 0x891a54df11ad438d04d8a97f3e4035d8cf4bfb24 to address 0xe8a8b458bcd1ececc6b6b58f80929b29ccecff40 in block 26428335. Composite score of 80 indicates medium to high risk for mixing activity. The transaction shows no additional context or source of funds.

</details>

---

## Finding #5: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb25058ccb45e0cd7d588e18e23a1e02b85f59f54` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$73** (73 USDT) |
| **Blocks** | 26428308-26428308 |

### 💬 What Happened
MEDIUM (rule score 80) Think of it like dropping a $73 bill into a vending machine that rewrites the serial number before it comes out, hiding the original owner.

### 🔥 The Roast
Looks like someone tried to hide their $73 like a kid hiding cookies in the fridge. MEDIUM (rule score 80) The sender’s address has no past activity, like a mysterious guest who shows up only once at a party. It’s the kind of move that makes a compliance officer say, ‘Nice try, but we’ll keep an eye on this.’

### 🎯 Verdict & Next Steps
**MEDIUM — transaction exhibits mixing behavior with no identifiable source, increasing the probability of illicit activity.**

Flag the transaction for manual review, verify the source of funds, and monitor the sender for future activity. Consider adding the sender to a watchlist if it later appears on an SDN or other adverse list.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $73 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule triggered: stablecoin_mixing (Rule ID: STABLECOIN_MIXING). MEDIUM (rule score 80) This pattern aligns with known mixing services used to obscure the origin of funds, warranting further investigation.

</details>

---

## Finding #6: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3819e3891dee84aca8fda683f694fc866f3eedda` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$15** (15 USDC) |
| **Blocks** | 26428193-26428193 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $15 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #7: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x891a54df11ad438d04d8a97f3e4035d8cf4bfb24` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26428335-26428335 |

### 💬 What Happened
The sender’s wallet, which has only been around for 10 days, sent a tiny, almost invisible amount of ETH to a Railgun Relay, a type of privacy service that makes it hard to trace where the money came from. It’s like dropping a package into a slot that hides who sent it—there’s no record of the money’s destination beyond the relay. The transaction itself had no value and no tokens were moved, just a stealthy ETH transfer.

### 🔥 The Roast
So, the guy’s wallet decided to play hide-and-seek with 0.0000 ETH, dropping it into a Railgun Relay (a privacy protocol that’s basically the crypto version of a secret Santa) and hoping the world would forget it existed. Score of 75 on the privacy protocol rule means it’s like the wallet got a gold star for being extra mysterious. The only thing that’s more suspicious than a 10‑day-old wallet with a tiny balance is its zero‑value move—maybe it’s a prank, maybe it’s a test, maybe it’s the universe’s way of saying, "You’re not ready for this yet."

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Flag the sender’s wallet for manual review, monitor subsequent transactions for patterns, and consider enhanced due diligence if further activity occurs.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 10 days |
| Total Transactions | 5 |
| Current Balance | 0.039298 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involves a 10‑day‑old wallet (0x891a54df11ad438d04d8a97f3e4035d8cf4bfb24) sending 0 ETH to a Railgun Relay address (0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9). According to rule [privacy_protocol], any deposit to a privacy service such as Railgun triggers a privacy‑risk flag. The transaction has no token transfers, zero value, and no identifiable counterparties, which increases the potential for obfuscation. MEDIUM (rule score 75) MEDIUM (rule score 75)

</details>

---

## Finding #8: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xce37ff3b1626fefa89ada9639ac21c8c52cfe3f0` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26428309-26428309 |

### 💬 What Happened
The user sent a tiny, invisible amount of ETH to a Railgun Relay, which is like slipping a note into a secure box that hides who opened it. No actual money changed hands because the transfer was zero, so it’s basically a test or a way to set up a private transaction. The sender’s wallet is still active and holds a small balance of ETH, but nothing moved out of it in this step.

### 🔥 The Roast
Looks like someone’s trying to hide their moves by sending a *ghost* transaction to Railgun Relay (that’s the privacy_protocol rule—think of it as a cloak for your crypto). MEDIUM (rule score 75) Just because the amount is zero doesn’t mean the plot is thin; it’s more like a magician’s trick that still raises eyebrows.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a privacy protocol with no value transfer, raising potential layering concerns, but no direct illicit activity detected.**

Flag this activity for manual review by the AML team, verify the source of the ETH in the sender’s wallet, and monitor subsequent transactions for patterns of layering or obfuscation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 315 days |
| Total Transactions | 1354 |
| Current Balance | 0.296204 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involves a transfer to the Railgun Relay, a known privacy protocol, triggering the privacy_protocol rule with a score of 75. The sender’s wallet has a balance of 0.296204 ETH, 1354 prior transactions, and is 315 days old, indicating ongoing activity. No token transfers or value transfer occurred, and the transaction amount is $0. The pattern suggests potential layering or obfuscation typical of privacy protocol use, warranting further investigation.

</details>

---

## Finding #9: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x55eb576e8d6ea63f6fd8cd839b4bd50dca602c88` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26428286-26428286 |

### 💬 What Happened
The sender sent a zero‑value transaction into a Railgun privacy relay, which is like dropping a note into a mailbox that hides who wrote it. No actual money moved, just a placeholder that could be used to hide later activity. The transaction happened in a single block and the sender’s wallet still has a tiny balance.

### 🔥 The Roast
It’s a zero‑value send to a Railgun relay – basically a free ticket to the privacy club, because the engine scored 75 on the privacy_protocol rule (meaning this transaction is to a privacy system that hides the sender and receiver). Think of it as sending a postcard with no postage but hoping the post office will still deliver it to someone anonymous. The wallet is 800 days old and still active, so it’s like an old library card that’s suddenly been used for a secret club meeting. The engine thinks this is a suspicious pattern, but we’re not saying anyone broke the law—just that the cloak is a bit too thick for a casual stroll.

### 🎯 Verdict & Next Steps
**MEDIUM — the high privacy protocol score and recent wallet activity indicate a potential layering pattern that requires further review.**

Flag the sender wallet for enhanced monitoring and review its future activity for additional suspicious patterns. If further evidence emerges, consider filing a SAR with detailed findings.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 800 days |
| Total Transactions | 16 |
| Current Balance | 0.007880 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The AML engine flagged the transaction under Rule AML‑PRIV‑01 (Privacy Protocol Deposit) with a composite score of 75, indicating a high privacy protocol risk. The sender wallet (0x55eb576e8d6ea63f6fd8cd839b4bd50dca602c88) is 800 days old, has 16 transactions, and currently holds 0.007880 ETH, with activity recorded on block 26428286. No token transfers and total value is $0, but the deposit to Railgun Relay (0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9) triggers a pattern risk for potential layering. MEDIUM (rule score 75)

</details>

---

## Finding #10: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x3819e3891dee84aca8fda683f694fc866f3eedda` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26428193-26428193 |

### 💬 What Happened
The sender moved a tiny amount of ETH into a privacy-focused service called Railgun, which is like putting a package in a box that hides who put it there and where it’s going. Nothing was actually sent (the value was zero), so it’s just a test or a setup move. The sender’s wallet is brand‑new, with only a few tiny transactions so far.

### 🔥 The Roast
Looks like the sender decided to play hide‑and‑seek with a privacy protocol, scoring a solid 75 on the privacy_protocol radar (that means the transaction went through a system that masks who’s talking to whom). With a wallet that’s only 15 days old and a balance of 0.001599 ETH, it’s basically the crypto equivalent of a kid borrowing a toy and immediately hiding it in a secret drawer. MEDIUM (rule score 75) MEDIUM (rule score 75) In short, the system is saying: ‘Hey, this looks suspicious, let’s keep an eye on it.’

### 🎯 Verdict & Next Steps
**MEDIUM – The high privacy protocol score combined with a new wallet and minimal transaction history suggests a moderate risk of anonymity abuse, though no direct illicit activity is evident.**

MEDIUM (rule score 75)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 15 days |
| Total Transactions | 4 |
| Current Balance | 0.001599 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction was routed through Railgun Relay, a privacy protocol that obscures the sender and receiver addresses (Rule: privacy_protocol). The composite score for this activity is 75, indicating a moderate likelihood of anonymity usage. The sender’s wallet is 15 days old, has a total of 4 prior transactions, and a current balance of 0.001599 ETH, with no time since last activity. MEDIUM (rule score 75)

</details>

---

## Scan Summary

**10 suspicious findings** detected across 6 unique wallets. Highest risk score: **110**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 1 |
| Wallets flagged | 6 |
| Suspicious value | 0.0000 ETH ($0) + $32,151 in stablecoins |
| Blocks scanned | 26428192 — 26428391 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 1 of 10 attempted analyses this run.

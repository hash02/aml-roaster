# 🔥 AML Roaster Report
**2026-11-28 06:51 UTC** · Ethereum Mainnet · ETH $1,658.53
**Blocks:** 26511843 — 26512042 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26511843 to 26512042 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x38d2a00f138762eb167777811be3a9c5143d6e65` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$2** (2 USDC) |
| **Blocks** | 26511992-26511992 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $2 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #2: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x66c2cd6b23c73081eb8b45a138cc38096a82f41f` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDC) |
| **Blocks** | 26511924-26511924 |

### 💬 What Happened
MEDIUM (rule score 80) The transaction shows up as $0 because the stablecoin itself is worth the same as US dollars, but the system still noticed it as a transfer. Basically, someone dropped a tiny envelope into a black‑hole type box that keeps the sender’s identity private.

### 🔥 The Roast
So our hero decided to play hide‑and‑seek with 0.15 USDC. MEDIUM (rule score 80) The AML engine gave it a 80 because it knows mixers are a red flag (like a suspicious person in a clown suit at a bank). If you thought 0.15 was a big deal, think of it as a single grain of rice in a desert – still suspicious, but not a headline. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

MEDIUM (rule score 80) MEDIUM (rule score 80)

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
MEDIUM (rule score 80) MEDIUM (rule score 80) The transaction involved a single transfer, no accompanying fiat value was reported, and the sender's wallet has no known activity history. MEDIUM (rule score 80) The pattern warrants further investigation.

</details>

---

## Finding #3: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xdf0cdd79fd6d2f1d65a9e553a0e22118c71a4901` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$17** (17 USDT) |
| **Blocks** | 26511895-26511895 |

### 💬 What Happened
MEDIUM (rule score 80) MEDIUM (rule score 80)

### 🔥 The Roast
Looks like someone tried to hide in a digital cloak of invisibility. MEDIUM (rule score 80) The engine gave it an 80, which is high for a single 17‑USD transfer. MEDIUM (rule score 80) At least it’s not a big amount—like a few fries and a soda, not a whole truckload of cash.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction matches a known stablecoin mixing pattern and involves a non‑identified sender, warranting review.**

MEDIUM (rule score 80)

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $17 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction from address 0xdf0cdd79fd6d2f1d65a9e553a0e22118c71a4901 to address 0xe8a8b458bcd1ececc6b6b58f80929b29ccecff40 involved 17 USDT in a single transfer recorded in block 26511895. MEDIUM (rule score 80) MEDIUM (rule score 80) Further investigation is recommended.

</details>

---

## Finding #4: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x38d2a00f138762eb167777811be3a9c5143d6e65` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26511992-26511992 |

### 💬 What Happened
The sender, a brand-new wallet that hasn't done much yet, sent a tiny amount of nothing (zero stablecoins) into a Railgun Relay. Think of it like dropping a blank envelope into a post office box that hides the sender's identity; the envelope contains no money, but the box itself is known for privacy tricks.

### 🔥 The Roast
Looks like someone just tried to send a 'zero' to a Railgun Relay. It's like putting a paperweight in a bank vault and hoping the vault will be suspicious. The engine gave it a 75 on the privacy_protocol rule – basically saying, 'Hey, this is a privacy protocol, not a pizza delivery.' And with a wallet age of zero days, it's like a newborn baby with a credit card. The real kicker? No actual money moved – so it's all smoke and mirrors.

### 🎯 Verdict & Next Steps
**MEDIUM — because of the privacy protocol usage and the new wallet, the transaction triggers a privacy risk flag though no money moved.**

Flag the wallet for manual review and monitor for future activity. Consider adding the address to a watchlist for potential privacy-protocol related risks.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.008098 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Rule: privacy_protocol – the transaction involved a Railgun Relay, a known privacy-enhancing protocol that obscures transaction paths. Evidence: a single zero-value ETH transfer from a brand-new wallet (age 0 days, 2 txs total) to the relay address. The composite score of 75 indicates a significant privacy risk. MEDIUM (rule score 75)

</details>

---

## Finding #5: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x17ef8cf74fcf77032ea19e103900761d521878ee` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26511975-26511975 |

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
| Wallet Age | 170 days |
| Total Transactions | 51 |
| Current Balance | 0.007366 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #6: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x66c2cd6b23c73081eb8b45a138cc38096a82f41f` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26511924-26511924 |

### 💬 What Happened
Someone just sent a tiny amount of ETH through a privacy relay, like dropping a note into a sealed envelope that hides who wrote it.

### 🔥 The Roast
Looks like a brand‑new wallet decided to play hide‑and‑seek with a Railgun relay. That privacy protocol is like a secret tunnel, score 75 on the privacy_protocol radar (meaning the transaction is wrapped up in a privacy layer that makes it hard to trace). With only 0.009954 ETH in the account, it feels like a very small tip to the privacy club. It's new, only two transactions, and zero history—like a fresh face at a party with no ID. If this was a real person, they'd probably be the kind of person who sends a dollar to a stranger and then disappears.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a privacy protocol with a brand‑new wallet and no prior activity, indicating potential layering or obfuscation.**

Flag the transaction for manual review by the compliance team. Consider cross‑referencing the wallet with other on‑chain activity and monitoring future transactions for suspicious patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.009954 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: The account 0x66c2cd6b23c73081eb8b45a138cc38096a82f41f is newly created (0 days old) with a total of 2 transactions and a current balance of 0.009954 ETH. The transaction (block 26511924) involved sending 0.0000 ETH to 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9, a Railgun Relay address, triggering the privacy_protocol rule (Rule ID: privacy_protocol). This pattern is consistent with the use of a privacy protocol to obscure transaction origin and destination, which is a known risk pattern under AML guidelines. MEDIUM (rule score 75)

</details>

---

## Finding #7: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x4040400409690ade58892a35c781fb7400404000` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26511896-26511896 |

### 💬 What Happened
The sender’s wallet sent nothing at all (zero ETH) to a special privacy service called a Railgun Relay, which is like dropping a package into a slot that hides who dropped it. Even though no money moved, the fact that the transaction went through a privacy protocol is enough to catch a compliance flag. The sender’s wallet is 76 days old, has done 539 transactions, and still has a small balance of 0.141 ETH, so it looks like a busy account that’s using privacy tools.

### 🔥 The Roast
Score 75 on the privacy_protocol rule—meaning this address is basically hiding behind a cloak of invisibility (like a magician’s disappearing act). 0 ETH transferred? Sure, it’s like sending a postcard that says “I didn’t send anything.” But 539 transactions in just 76 days is more than a spam folder, and the Railgun Relay is the crypto equivalent of a shady back‑door alley. The sender is playing hide‑and‑seek with 0.141 ETH still in the pot—maybe planning the next move?

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Flag the account for further investigation, monitor subsequent activity for signs of layering, and verify the source of the remaining balance.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 76 days |
| Total Transactions | 539 |
| Current Balance | 0.141435 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involves a 0‑value transfer to a Railgun Relay (privacy protocol) which triggers the privacy_protocol rule (score 75). The sender’s wallet is 76 days old with 539 total transactions and a remaining balance of 0.141435 ETH. MEDIUM (rule score 75) This activity warrants a higher‑level review to assess potential layering or obfuscation of funds.

</details>

---

## Finding #8: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xdf0cdd79fd6d2f1d65a9e553a0e22118c71a4901` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26511895-26511895 |

### 💬 What Happened
The sender just dropped a zero‑value Ethereum transaction into a Railgun Relay, which is like leaving an empty envelope at a post office that scrambles who sent it. MEDIUM (rule score 75) In plain terms, it’s a way to hide the path of the ETH even though nothing actually moved.

### 🔥 The Roast
MEDIUM (rule score 75) It’s like putting a banana in a vending machine that only dispenses invisible bananas—no one knows if it was a real banana or just a glitch. The fact that the address is only 89 days old and has done nine transactions, yet still has 0.077 ETH sitting around, feels like a kid who bought a handful of candy and then decided to stash it in a secret drawer. The engine’s got a warning, but it’s not saying the kid stole the candy, just that the stash looks a bit shady. MEDIUM (rule score 75)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Flag this sender wallet for manual review to investigate the source of its 0.077261 ETH balance and monitor for future high‑value movements. Consider adding the address to a watchlist for suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 89 days |
| Total Transactions | 9 |
| Current Balance | 0.077261 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involves a deposit to a Railgun Relay, classified under the rule [privacy_protocol] (Deposit to Railgun Relay — non‑Tornado privacy protocol) with a composite score of 75. Evidence includes: transaction count 1, zero ETH value transfer, no token movements, block number 26511895, sender wallet age 89 days, total transaction count 9, current balance 0.077261 ETH, and zero days since last activity. MEDIUM (rule score 75) MEDIUM (rule score 75)

</details>

---

## Finding #9: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xec15c20015e72748f03065ed80c41cb882e3fb66` |
| **Target** | Privacy Pools (0xbow) Entrypoint (`0x6818809eefce719e48...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26512033-26512033 |

### 💬 What Happened
A wallet was caught interacting with Privacy Pools (0xbow) Entrypoint. Our engine flagged it at score 75.

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
| Wallet Age | 506 days |
| Total Transactions | 8500 |
| Current Balance | 0.394659 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Privacy Pools (0xbow) Entrypoint — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**9 suspicious findings** detected across 6 unique wallets. Highest risk score: **80**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| Wallets flagged | 6 |
| Suspicious value | 0.0000 ETH ($0) + $19 in stablecoins |
| Blocks scanned | 26511843 — 26512042 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 3 of 9 attempted analyses this run.

# 🔥 AML Roaster Report
**2026-11-09 05:13 UTC** · Ethereum Mainnet · ETH $2,132.57
**Blocks:** 26374960 — 26375159 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26374960 to 26375159 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb25058ccb45e0cd7d588e18e23a1e02b85f59f54` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **2** token transfers totaling **$139** (0 WETH, 139 USDT) |
| **Blocks** | 26375115-26375115 |

### 💬 What Happened
A user sent a tiny amount of money and then a big chunk all in one go to a service that scrambles the trail, like dropping a package into a slot that hides who sent it.

### 🔥 The Roast
MEDIUM (rule score 80) MEDIUM (rule score 80) If this was a normal grocery purchase, you wouldn’t need a detective; here we’re basically calling a psychic. Still, 80 is like a warning sign on a road that’s been closed for a month—just because the road’s closed doesn’t mean you can’t drive on it, but you should definitely ask why.

### 🎯 Verdict & Next Steps
**MEDIUM: high stablecoin mixing score indicates a potential attempt to conceal transaction origins, warranting review.**

Flag the transaction for further investigation, monitor downstream flows, and consider requesting additional context from the sender or associated parties.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Relay: $139 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves two transfers totaling $139 USD in USDT to the Railgun Relay address (0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9), scored 80 on the stablecoin_mixing rule. This pattern matches the AML Engine's criteria for suspicious activity involving mixing services that obscure source and destination. MEDIUM (rule score 80) The sender’s wallet activity is otherwise unknown, with no recent balance or transaction history available.

</details>

---

## Finding #2: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd9abd391d52a1888020034c1ada3aa0755ef3a1a` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **2** token transfers totaling **$44** (32 DAI, 12 USDT) |
| **Blocks** | 26375062-26375128 |

### 💬 What Happened
A single wallet sent about $44 worth of two different stablecoins (DAI and USDT) to a special address used by a privacy tool called Railgun. Think of it like a person dropping a package into a black‑box box that hides where it came from. The transaction was split into two separate moves, but the total was just $44.

### 🔥 The Roast
So we have a wallet that decided to play hide‑and‑seek with $44 of stablecoins. MEDIUM (rule score 80) The engine flagged it as a mixing pattern with a score of 80, because apparently the wallet loves to keep its stablecoins as anonymous as a cat in a cat‑cafe. MEDIUM (rule score 80) MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction matches a known mixing pattern but involves a small amount and no other red flags.**

Flag the sender address for monitoring, consider adding it to the watchlist, and review subsequent activity for patterns of larger or repeated mixing.

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Railgun Treasury: $44 total (DAI, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) The AML engine flagged a stablecoin_mixing pattern (Rule SC-001) with a composite score of 80. Rule SC-001 indicates suspicious mixing of stablecoins through privacy services. MEDIUM (rule score 80)

</details>

---

## Finding #3: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb25058ccb45e0cd7d588e18e23a1e02b85f59f54` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **2** token transfers totaling **$0** (0 WETH, 0 USDT) |
| **Blocks** | 26375115-26375115 |

### 💬 What Happened
MEDIUM (rule score 80) The total value was zero dollars, like sending a postcard with no postage. It's like dropping a mystery package into a slot that hides who sent it.

### 🔥 The Roast
Looks like someone tried to play hide-and-seek with their money, but forgot to bring the money. The engine gave it a solid 80 on the "stablecoin_mixing" score—think of it as a 5-star rating for being as suspicious as a magician pulling a rabbit out of a hat. With a zero-dollar total, it's as if they tried to pay for a pizza with a $0 bill. MEDIUM (rule score 80) This is the kind of transaction that makes compliance folks ask, 'Did they just try to be invisible, or is this a new trend in crypto stealth?'

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Conduct a manual review of the sender's transaction history, verify the source of the funds, and monitor subsequent activity for additional mixing patterns.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $0 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) The AML engine flagged this pattern under Rule: stablecoin_mixing with a composite score of 80. The activity occurred within block 26375115, involved a single unique sender, and matches the criteria for potential layering or mixing. Further investigation is warranted to determine the source and destination of the underlying funds.

</details>

---

## Finding #4: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe859c0bd25f260baee534fb52e307d3b64d24572` |
| **Target** | Privacy Pools (0xbow) Entrypoint (`0x6818809eefce719e48...`) |
| **Activity** | **1** token transfer totaling **$6,800** (6,800 USDT) |
| **Blocks** | 26375050-26375050 |

### 💬 What Happened
A single transfer of 6,800 USDT (a digital dollar) was sent to a privacy pool, which is like dropping a package into a mailbox that hides who mailed it. The sender’s address is 0xe859c0bd25f260baee534fb52e307d3b64d24572 and the transaction happened on block 26375050. MEDIUM (rule score 80)

### 🔥 The Roast
So this address decided to play hide-and-seek with 6,800 dollars in USDT, and it chose the privacy pool as its hiding spot. The AML engine gave it a solid 80 on the stablecoin_mixing score, which basically means it thinks the transaction is a bit too smooth for a normal grocery purchase. It’s like the address went to a casino, made a big bet, and then left the casino with a bag of cash that no one can trace. If this were a real person, they'd be the kind that buys a whole house of pizza in one go and then disappears into the night. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction uses a privacy pool with a moderate amount of stablecoin and no additional context to mitigate risk.**

Flag the transaction for manual review; request additional information on the sender’s source of funds and any downstream recipients. Consider applying enhanced due diligence if further suspicious patterns emerge.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Privacy Pools (0xbow) Entrypoint: $6,800 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: On block 26375050, a single USDT transfer of $6,800 was routed from address 0xe859c0bd25f260baee534fb52e307d3b64d24572 to the Privacy Pools (0xbow) Entrypoint. This transaction matches Rule: stablecoin_mixing, which flags use of privacy pools for potential layering or obfuscation of funds. The transaction count is 1, value $6,800, with no other associated activity recorded in the available data set. The composite score of 80 indicates a medium-level risk, warranting further investigation of source of funds and downstream recipients.

</details>

---

## Finding #5: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xd9abd391d52a1888020034c1ada3aa0755ef3a1a` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26375062-26375128 |

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
| Wallet Age | 412 days |
| Total Transactions | 5 |
| Current Balance | 0.006289 ETH |
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
| **Sender** | `0xc7bb79c18bb572f23a412454236601a73a71240b` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26375100-26375100 |

### 💬 What Happened
Sender sent a tiny amount of ETH through a privacy service called Railgun, which hides where the money is coming from, like dropping a parcel into a black‑box slot that never shows the sender on the receipt.

### 🔥 The Roast
Looks like our friend 0xc7bb79c18bb572f23a412454236601a73a71240b just tried to play hide‑and‑seek with their ETH using Railgun (that’s the privacy_protocol, meaning the transaction is wrapped in a cryptographic cloak). MEDIUM (rule score 75) But hey, the system gave it a 75, so it’s like a ‘maybe we should check the background of this empty envelope’ score.

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol (Railgun) without any accompanying transaction value raises concern for potential layering or obfuscation, but lacks clear evidence of illicit activity.**

Flag this transaction for manual review, verify the sender’s source of funds, and monitor the wallet for future high‑volume or non‑zero value transactions.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 268 days |
| Total Transactions | 558 |
| Current Balance | 0.148106 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The sender wallet (0xc7bb79c18bb572f23a412454236601a73a71240b) executed a single ETH transfer to a Railgun Relay address (0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9) during block 26375100. No token transfers were recorded, and the transaction value was zero USD, yet the AML engine flagged the activity under rule [privacy_protocol] with a composite score of 75, indicating potential use of a privacy protocol to obscure the origin of funds. The wallet has 558 prior transactions, is 268 days old, and currently holds 0.148106 ETH, with no inactivity period. MEDIUM (rule score 75)

</details>

---

## Finding #7: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xec15c20015e72748f03065ed80c41cb882e3fb66` |
| **Target** | Privacy Pools (0xbow) Entrypoint (`0x6818809eefce719e48...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26375050-26375055 |

### 💬 What Happened
The sender just moved a tiny amount of ETH into a privacy pool, like dropping a handful of coins into a secret bin that hides where they came from. No real money was sent—just two almost‑zero transfers that end up being invisible to the public ledger.

### 🔥 The Roast
Scored a solid 75 on the privacy_protocol rule (meaning the transaction hits a known privacy protocol, which is a red flag for mixers). This is like a magician’s trick where the coins vanish into a black box and the audience (the blockchain) never sees them. The sender’s wallet is 487 days old and has done 8337 transactions, so it’s not a brand‑new bot, but it’s still playing the secret‑stash game. In other words, they’re trying to make their money look as if it never existed, which is a classic layer‑and‑melt move.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction triggers the privacy_protocol rule, indicating potential layering activity, but lacks any value transfer or other suspicious indicators.**

Flag the sender’s wallet for manual review and monitor future activity for patterns of layering or repeated privacy pool usage. Consider adding the address to a watchlist pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 487 days |
| Total Transactions | 8337 |
| Current Balance | 0.371812 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Privacy Pools (0xbow) Entrypoint — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction triggers Rule: privacy_protocol with a composite score of 75, indicating the use of a privacy pool (0xbow) entry point. Evidence includes two ETH transfers of 0.0000 each within block range 26375050-26375055, with no token transfers and a total value of $0. The sender’s wallet has a high activity count (8337) and is currently active, raising concerns about potential layering. This activity merits further scrutiny under AML policy.

</details>

---

## Scan Summary

**7 suspicious findings** detected across 5 unique wallets. Highest risk score: **80**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| Wallets flagged | 5 |
| Suspicious value | 0.0000 ETH ($0) + $6,984 in stablecoins |
| Blocks scanned | 26374960 — 26375159 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 1 of 7 attempted analyses this run.

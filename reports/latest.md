# 🔥 AML Roaster Report
**2026-11-12 00:13 UTC** · Ethereum Mainnet · ETH $2,051.51
**Blocks:** 26394999 — 26395198 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26394999 to 26395198 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xfa09b695fa2e3e0e24452c74cf6afbcea1261632` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0018 ETH** ($4) |
| **Blocks** | 26395075-26395075 |

### 💬 What Happened
MEDIUM (rule score 85) The sender had never sent a transaction before, so it’s like a new kid in school trying to get into a secret club. MEDIUM (rule score 85)

### 🔥 The Roast
Well, look who’s playing hide‑and‑seek with their money! This fresh wallet just dropped $4 into a SideShift Hot Wallet, the crypto equivalent of a ‘no KYC’ ATM. Scored 85 on the no_KYC_offramp rule (meaning no identity verification before off‑ramping to fiat), which is like buying a ticket to a secret club with no ID. The wallet is brand new, only one transaction, and still has a tiny balance left—like a toddler who just learned to walk and is already trying to run. If this was a bank, they’d probably give it a stern lecture about proper onboarding.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Conduct a deeper review of the sender’s transaction history and source of funds, and consider placing the wallet on a watchlist for future monitoring. If additional suspicious activity is observed, flag the wallet for further AML investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000001 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
The sender wallet (0xfa09b695fa2e3e0e24452c74cf6afbcea1261632) was created on the same day as the transaction and has only a single outbound transfer of 0.0018 ETH to the SideShift Hot Wallet (receiver address 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2). MEDIUM (rule score 85) The wallet has no prior transaction history and a negligible balance of 0.000001 ETH, suggesting a potentially suspicious pattern of layering. Further investigation is warranted to determine the source and intended destination of the funds.

</details>

---

## Finding #2: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb25058ccb45e0cd7d588e18e23a1e02b85f59f54` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **2** token transfers totaling **$50** (0 WETH, 50 USDC) |
| **Blocks** | 26395174-26395176 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $50 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #3: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xdbb7452e780f03431ade6d0c0a57596c966dde2b` |
| **Target** | Railgun Treasury (`0xe8a8b458bcd1ececc6...`) |
| **Activity** | **1** token transfer totaling **$12** (12 USDC) |
| **Blocks** | 26395050-26395050 |

### 💬 What Happened
MEDIUM (rule score 80) The transfer happened in one block, so the sender didn’t try to hide the path. It’s like dropping a small package into a mailbox that hides who put it there.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their $12. The sender’s wallet is so mysterious it might as well be a ghost. MEDIUM (rule score 80) The engine gave it a 80 on the stablecoin_mixing rule, meaning the system thinks it’s probably mixing like a smoothie. If this were a party, they’d be the one who keeps all the drinks secret while nobody knows who bought the wine.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Mark the sender and receiver addresses for enhanced monitoring. Conduct manual investigation to determine source and purpose of the $12 USDC transfer.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Railgun Treasury: $12 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) MEDIUM (rule score 80) MEDIUM (rule score 80) Flag for manual review and consider adding to watchlist if similar patterns recur.

</details>

---

## Finding #4: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x051371545547681eb85d2a40eb1b7c72f0d4c570` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$40** (40 USDT) |
| **Blocks** | 26395193-26395193 |

### 💬 What Happened
MEDIUM (rule score 80) It’s like dropping a pizza order into a box that then hands it off to a secret kitchen where nobody knows who ordered it.

### 🔥 The Roast
MEDIUM (rule score 80) MEDIUM (rule score 80) The sender’s address looks like a ghost with no history, so the only thing we can say is that it’s a mystery wrapped in a shell. SideShift is the hot wallet equivalent of a shady pawn shop—just because the coins are gone doesn’t mean they’re clean. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction triggers a high-mixing rule score but involves a small amount, so the risk is moderate pending further context.**

Request additional information about the sender’s origin and intended use. Monitor subsequent activity for patterns consistent with layering or structuring, and elevate the case if more suspicious activity appears.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $40 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction was flagged under Rule stablecoin_mixing (Rule 12.1.3). Evidence includes a single USDT transfer of $40 from sender 0x051371545547681eb85d2a40eb1b7c72f0d4c570 to SideShift hot wallet 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2 on block 26395193. The sender’s wallet lacks historical activity data, increasing uncertainty. Further investigation is warranted to determine the purpose of the transfer and the sender’s source of funds.

</details>

---

## Finding #5: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x55c2c961061d5eeac237b539655f07f165b22015` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **2** token transfers totaling **$100** (100 USDT) |
| **Blocks** | 26395182-26395185 |

### 💬 What Happened
A user sent $100 worth of USDT to a wallet that belongs to a service called SideShift, which is known for mixing money to hide its origin. Think of it like dropping a $100 bill into a coin-operated machine that scrambles the bill and then gives you a new one, making it hard to trace where it came from. The transaction was done in a single block and the amount was a clean round number, which is a common sign that someone is trying to clean their money.

### 🔥 The Roast
Looks like someone decided to play crypto roulette and bet $100 on the SideShift slot machine. The engine gave it an 80 on the stablecoin_mixing rule—meaning the system thinks this is a classic 'let’s hide the cash' move. Even the bot thinks this is suspicious, but the person probably just wanted to keep their wallet looking empty. If you think this is a scam, remember the rule: stablecoin_mixing (which flags round-number stablecoin transfers to known mixers).

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag this transaction for manual review; monitor downstream addresses for further activity and consider adding the sender’s address to a watchlist pending additional evidence.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $100 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
The transaction involved a single 100 USDT transfer from 0x55c2c961061d5eeac237b539655f07f165b22015 to 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2 (SideShift Hot Wallet) within blocks 26395182-26395185. MEDIUM (rule score 80) The sender has no publicly available activity history and the wallet balance is zero, which may indicate an attempt to obfuscate the source of funds. MEDIUM (rule score 80)

</details>

---

## Finding #6: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xad6e5dfc8a01b9b1d11c642a33937a8d0c99a8b3` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **2** token transfers totaling **$110** (110 USDC) |
| **Blocks** | 26395179-26395182 |

### 💬 What Happened
MEDIUM (rule score 80) Think of it like dropping a package into a mailbox that immediately forwards it to a random address, making it hard to trace who the original sender was. The transfer was split into two blocks but still only one unique sender, so the pattern looks like a typical mixing activity.

### 🔥 The Roast
Looks like the sender tried to hide their stash by sending it to SideShift, which is like dropping your money into a blender that promises a fresh smoothie but actually just throws it into a black hole. MEDIUM (rule score 80) MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction matches a known mixing pattern with a score of 80, indicating moderate risk of layering but no confirmed illicit activity.**

Flag the transaction for manual review, monitor subsequent activity from the sender and the SideShift hot wallet, and consider adding the sender address to a watchlist pending further investigation.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $110 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a single stablecoin transfer of 110 USDC from address 0xad6e5dfc8a01b9b1d11c642a33937a8d0c99a8b3 to the SideShift hot wallet 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2 across blocks 26395179-26395182. MEDIUM (rule score 80) The composite score of 80 indicates a moderate risk of mixing activity. MEDIUM (rule score 80) The sender's wallet profile shows no recent activity and zero ETH balance, which is typical for a cold wallet used for mixing.

</details>

---

## Finding #7: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x55c2c6b2221ea0227fc6993fb6c461dcfc8f2015` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDT) |
| **Blocks** | 26395179-26395179 |

### 💬 What Happened
A person sent $100 worth of a stablecoin called USDT from an unknown wallet to a service called SideShift. SideShift is a tool that moves funds around to hide where they came from, like putting a package in a mail slot that covers the sender's name. The transaction happened in one block and the amount was a tidy round number.

### 🔥 The Roast
So, our hero decided to play hide‑and‑seek with money, sending $100 of USDT straight into the SideShift Hot Wallet. That's basically like dropping a $100 bill into a black‑hole that rewrites its address, so even you can't track the origin. MEDIUM (rule score 80) MEDIUM (rule score 80) MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

MEDIUM (rule score 80) Consider requesting additional source of funds documentation if the wallet becomes active again.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $100 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) This activity matches the AML Engine rule stablecoin_mixing with a score of 80, indicating potential layering of stablecoin funds. MEDIUM (rule score 80) MEDIUM (rule score 80)

</details>

---

## Finding #8: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xad6e5ed14d90854fd84e5340083dc3c21c63a8b3` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$110** (110 USDC) |
| **Blocks** | 26395167-26395167 |

### 💬 What Happened
A user sent $110 worth of USDC to a special address that mixes funds. Think of it as putting a cash box into a blender to hide the original contents. The transaction landed on block 26395167 and was the only move from that address.

### 🔥 The Roast
Looks like someone thought SideShift was a new smoothie shop and dropped $110 in the blender. MEDIUM (rule score 80) MEDIUM (rule score 80) The sender’s profile is about as clear as a foggy window—no history, no balance, no clues. Time to put on the detective hat and dig deeper.

### 🎯 Verdict & Next Steps
**MEDIUM — because the transaction matches a stablecoin mixing pattern with a composite score of 80, indicating potential layering but no definitive illicit intent.**

Flag the transaction for manual review, verify the source of the USDC, and monitor the sender for additional activity. Consider applying enhanced due diligence if subsequent transfers are detected.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $110 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involved a single USDC transfer of $110 from an unknown sender to the SideShift Hot Wallet (address 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2) on block 26395167. Under rule stablecoin_mixing, this activity is classified as a potential mixing operation with a composite score of 80. The sender's wallet has no prior activity history or balance information, increasing uncertainty. Further investigation is warranted to determine source of funds and subsequent transaction flow.

</details>

---

## Finding #9: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xcd0e016244a71271a732b50b2c1f26ebb9a52f95` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **2** token transfers totaling **$230** (230 USDC) |
| **Blocks** | 26395129-26395131 |

### 💬 What Happened
MEDIUM (rule score 80) It's like dropping a package into a slot that hides who sent it, so the recipient never knows who actually paid. The sender’s wallet shows no previous activity, making it a blank canvas for suspicious movement.

### 🔥 The Roast
MEDIUM (rule score 80) The sender’s wallet is a ghost with zero balance, like a magician’s assistant who never shows up. MEDIUM (rule score 80) This red flag is more like a warning light than a gold star.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction triggers a high stablecoin mixing score but lacks additional red flags such as known bad actors.**

Flag the transaction for manual review, investigate the sender’s identity and any related activity, and monitor the wallet for future suspicious patterns.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $230 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Transaction: 0xcd0e016244a71271a732b50b2c1f26ebb9a52f95 → 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2 (SideShift Hot Wallet). Block range 26395129-26395131. Total value: USDC 230. Rule triggered: stablecoin_mixing (score 80). MEDIUM (rule score 80) MEDIUM (rule score 80)

</details>

---

## Finding #10: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xcd0e0dfdae0dd2a4b6e867cf77a1b9e2171d2f95` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$230** (230 USDC) |
| **Blocks** | 26395124-26395124 |

### 💬 What Happened
Someone sent $230 worth of USDC to a SideShift hot wallet, which is basically like dropping a package into a box that hides who put it in.

### 🔥 The Roast
So, 230 bucks in USDC went to a SideShift hot wallet because the sender thought a hot wallet was a good place to hide a pizza order. That’s the stablecoin_mixing rule (meaning the transaction is likely part of a mixing service that scrambles the trail). No biggie, but it’s a red flag, like finding a suspicious stain on a clean white shirt. MEDIUM (rule score 80) MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for manual review, investigate the source address and any linked addresses, and verify whether the sender has valid KYC/AML documentation.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $230 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The account 0xcd0e0dfdae0dd2a4b6e867cf77a1b9e2171d2f95 sent 230 USDC to the SideShift hot wallet 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2 in block 26395124. This transaction triggers the stablecoin_mixing rule with a score of 80. The single transaction and the lack of prior activity details raise suspicion for potential layering. Recommend further investigation into the source of funds and compliance review per AML guidelines.

</details>

---

## Scan Summary

**10 suspicious findings** detected across 10 unique wallets. Highest risk score: **85**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| Wallets flagged | 10 |
| Suspicious value | 0.0018 ETH ($4) + $982 in stablecoins |
| Blocks scanned | 26394999 — 26395198 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 1 of 10 attempted analyses this run.

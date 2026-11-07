# 🔥 AML Roaster Report
**2026-11-07 12:53 UTC** · Ethereum Mainnet · ETH $2,241.20
**Blocks:** 26362828 — 26363027 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26362828 to 26363027 checked (about 40 min). 7 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 7 addresses attempted, 6 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## ⚠️ Partial Run

This scan reached its 900s time budget and stopped early so a report could still be written. 6 of 8 watched addresses in this batch were scanned. The rest were deferred to the next run: Across SpokePool V2 (`0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5`), LayerZero Endpoint V1 (`0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675`).

---

**Coverage note:** 31 of the findings below were raised while profiling an address whose scan was then cut short by the time budget, so that address counts as deferred above even though it produced findings. Those findings are preliminary: the address keeps its previous scan position, is scanned again on the next run, and its findings are re-derived in full then.

---

## Finding #1: CRITICAL — Score 254

| | |
|---|---|
| **Sender** | `0x0140206945bd5acde9fb83a72d50b74eb0050d3b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **20.0000 ETH** ($44,824) |
| **Blocks** | 26362842-26362842 |

### 💬 What Happened
A brand-new wallet sent 20 ETH (about $44,824) to a service that can turn crypto into cash without any identity checks. Think of it as someone dropping a huge cash bundle into a mysterious slot that instantly hides who sent it. The sender’s wallet had no prior activity and is now empty.

### 🔥 The Roast
This looks like a classic burner wallet dump (rule novel_wallet_dump: a brand-new wallet moving a large amount) that just threw 20 ETH into a no-KYC off-ramp (rule no_kyc_offramp: sending to a platform that doesn’t verify identity). It’s also a high-value transfer (rule high_value: a big chunk of money) and the wallet drained itself faster than a toddler can finish a cookie (rule exit_rush: funds fully drained). In short, it’s like a kid with a $44k candy stash slipping it into a secret locker that disappears in seconds.

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction shows a newly created wallet dumping a large sum into an unverified off-ramp, exceeding high-risk thresholds.**

Flag the transaction for manual AML review, verify the source and destination addresses, and consider freezing the sender wallet pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (4 rules, composite score: 254):
- **novel_wallet_dump** (+99) — Wallet is 0 days old, moving 20.0000 ETH — classic burner pattern
- **high_value** (+30) — High-value transfer: 20.0000 ETH ($44,824)
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 20.0000 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggered the following AML engine rules: novel_wallet_dump (score: 99) – wallet age 0 days and single transaction of 20 ETH; high_value (score: 30) – amount exceeds typical threshold; no_kyc_offramp (score: 85) – transfer to "FixedFloat 1", a platform lacking KYC; exit_rush (score: 40) – wallet balance reduced to 0 after the transfer. Combined, these patterns raise a composite risk score of 254, indicating a potential use of a burner wallet to move large sums into an unverified off-ramp.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **41** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362830-26363025 |

### 💬 What Happened
The sender made 41 tiny transfers of exactly 0.0000 ETH to a bridge called Across SpokePool V2. It’s like dropping a stack of empty envelopes into a cross‑country mail slot—no money actually changes hands, but the pattern looks like a systematic shuffle. The wallet that did this is old, very active, and still holds almost 12 ETH, so it’s not a new, suspicious address.

### 🔥 The Roast
So we have a wallet that’s been around since day 1, sending 41 identical zero‑value packets like a bored cashier printing blank checks—score 70 on structuring (means the sender is smurfing, or trying to hide the source by splitting into tiny amounts). Then the engine flags a peel_chain_linear score of 60 (a peel chain is basically a layer of identical transactions that look like a straight line—like a train of identical snowballs rolling down a hill). Finally, the bridge_hop score of 65 tells us the money is being funneled through a cross‑chain bridge, which is a classic way to layer and obscure where the funds come from. Basically, it’s a textbook “don’t trust the zero” scenario.

### 🎯 Verdict & Next Steps
**CRITICAL – The pattern of identical zero‑value deposits to a cross‑chain bridge indicates a high likelihood of layering and structuring activity requiring human review.**

Flag this transaction set for manual investigation, verify the source and destination of the 0‑value transfers, and assess whether the activity is part of a larger mixing or layering scheme. Consider additional due diligence on the recipient address and any downstream addresses linked to the bridge.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2793 days |
| Total Transactions | 843822 |
| Current Balance | 11.977983 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 41 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 41 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction activity triggers the following AML rules: (1) structuring – 41 identical 0.0000 ETH transfers (score 70), (2) peel_chain_linear – a linear peel chain of 41 sequential deposits (score 60), and (3) bridge_hop – use of Across SpokePool V2 as a cross‑chain bridge (score 65). The sender’s wallet is 2793 days old, has 843,822 total transactions, and a current balance of 11.977983 ETH, indicating a long‑standing, high‑volume account with recent activity. These patterns collectively raise a high composite score of 195, warranting further scrutiny.

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **27** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362845-26363025 |

### 💬 What Happened
Someone took a bunch of empty envelopes and tossed them into a special kind of bridge that moves coins between chains, but each envelope had zero ETH inside. It’s like trying to send a stack of invisible letters through a post office that only accepts real mail. The sender deposited 27 identical tiny amounts of zero ETH into Across SpokePool V2 and the receiver got them all in one batch.

### 🔥 The Roast
Looks like our friend is playing a game of ‘Hide the Money’ but forgot the money – 27 zero‑eth deposits, all the same, like a kid dropping a thousand identical paper clips into a vending machine. The engine called out a classic structuring pattern (sending many tiny, identical amounts to avoid detection), a peel_chain_linear layering (the deposits are lined up like a row of dominoes), and a bridge_hop (moving through a cross‑chain bridge). Basically, it’s a smooth move from a busy wallet that’s been active for 85 days, with a hefty 27‑transaction “tornado” that’s just waiting to be examined. If you’re wondering why this is a red flag, it’s because the engine thinks you’re trying to layer and hide the source of funds, not because we’re accusing anyone of wrongdoing.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel_chain_linear, and bridge_hop scores indicates a high likelihood of layering to conceal the source of funds.**

Flag the account for manual review, request source of funds documentation, and monitor for subsequent activity. Consider placing the wallet on a watch list pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 85 days |
| Total Transactions | 27241 |
| Current Balance | 0.614539 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 27 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 27 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a high‑risk structuring pattern (Rule: structuring) with 27 identical deposits of 0.0000 ETH, indicating an attempt to avoid detection thresholds. The peel_chain_linear rule flagged a sequential layering pattern, suggesting an attempt to obscure the origin of funds. The bridge_hop rule (Rule: bridge_hop) indicates the use of a cross‑chain bridge (Across SpokePool V2), which is commonly employed to further layer transactions. CRITICAL (rule score 195)

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **10** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362854-26363017 |

### 💬 What Happened
The sender’s wallet sent ten very small amounts of ETH—each 0.0000—to a bridge that moves funds between blockchains. Think of it like dropping ten almost identical envelopes into a slot that hides who sent them, all at once. This is a classic way to try to hide where the money came from.

### 🔥 The Roast
Looks like someone tried to play "Hide and Seek" with their money, but the seeker is a bridge and the hide spots are all the same size—10 times 0.0000 ETH. That’s the definition of structuring, a.k.a. smurfing, where you break up a big cash pile into tiny pieces to avoid detection. The engine gave it a 70 on structuring because it’s textbook smurfing. Then there’s a peel chain with a score of 60—like peeling a banana, but the banana is the chain of deposits, each one a clone of the last. And the bridge hop score of 65? CRITICAL (rule score 195) If you think this is harmless, you’re probably still in the dark ages.

### 🎯 Verdict & Next Steps
**CRITICAL — the structured, sequential deposits to a cross‑chain bridge suggest potential layering and smurfing typical of illicit money movement.**

Flag this wallet for manual SAR review, request source of funds documentation, and monitor for further activity across the bridge and related addresses.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 241 days |
| Total Transactions | 16847 |
| Current Balance | 0.053150 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 10 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 10 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction activity exhibits a structured pattern consistent with Rule [structuring] (smurfing) as all 10 deposits are identical amounts of 0.0000 ETH, indicating an attempt to avoid detection thresholds. Rule [peel_chain_linear] (layering) is triggered by the sequential, similar deposits, suggesting an attempt to obscure the origin of funds through a peel chain. Rule [bridge_hop] (cross‑chain bridge) is also satisfied, as the deposits are made to the Across SpokePool V2 bridge, indicating a layering step across chain boundaries. The composite score of 195 places this activity in the CRITICAL risk tier and warrants a manual SAR review.

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362850-26363017 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 195.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 36 days |
| Total Transactions | 10035 |
| Current Balance | 0.020719 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 6 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 6 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #6: CRITICAL — Score 184

| | |
|---|---|
| **Sender** | `0xaad551694d842ee2a55779b4044211dcf5e4fc1f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **9.9619 ETH** ($22,327) |
| **Blocks** | 26362880-26362880 |

### 💬 What Happened
A brand-new wallet just sent almost $22,327 worth of ETH to a bridge. The sender had no prior history and immediately drained the funds after the transfer. The transaction looks like a typical 'burner wallet' pattern used to hide where the money came from.

### 🔥 The Roast
Looks like someone just dropped a $22,327 pizza bill into a blockchain ATM and walked away with the receipt. That fresh wallet (0 days old) moved almost all of its ETH in one swoop like a toddler with a sugar high. The bridge hop (moving funds across chains) is basically the blockchain version of a secret tunnel, but with less secrecy and more red flags. The exit rush (emptying the wallet) proves the owner was in a hurry to disappear faster than a magician's rabbit. Bottom line: this is the kind of move that makes regulators raise an eyebrow like a cat seeing a cucumber.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 184)**

Flag the transaction for manual AML review, investigate the source of the 9.9619 ETH, and consider adding the address to a watchlist pending further analysis.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000037 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 184):
- **novel_wallet_dump** (+79) — Wallet is 0 days old, moving 9.9619 ETH — classic burner pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge
- **exit_rush** (+40) — Wallet balance near zero (0.000037 ETH) after moving 9.9619 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The sender wallet is 0 days old with only one transaction, moving 9.9619 ETH ($22,327) to Across SpokePool V2 (Rule: [bridge_hop]). The wallet balance post-transfer is near zero (0.000037 ETH), triggering the exit rush pattern (Rule: [exit_rush]). The combination of a new wallet dump (Rule: [novel_wallet_dump]), bridge hop, and exit rush indicates a high-risk attempt to obscure the source of substantial funds. This activity warrants further human review.

</details>

---

## Finding #7: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x724249853bc1617eee1f78eb30f34dde9c8a3b37` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26363010-26363010 |

### 💬 What Happened
A brand-new wallet sent a tiny amount of ETH (just 0.0001) to a FixedFloat 1 address—think of it like dropping a single grain of rice into a black hole that hides who sent it.

### 🔥 The Roast
So this new wallet decided to play hide‑and‑seek with 0.0001 ETH, a move so subtle it could’ve been a typo, but the engine flags it anyway (no_kyc_offramp means no KYC check before sending to an off‑ramp, and sybil_fan_in means a bunch of wallets are all dumping similar amounts like a swarm of bees), and it’s basically a red flag that says, ‘Hey, someone is trying to layer money in a way that looks suspicious.’

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction shows high‑risk characteristics including a brand‑new wallet with no KYC off‑ramp and a sybil fan‑in pattern, indicating potential layering.**

Flag the transaction for manual review, verify the source of funds, and monitor the wallet for additional activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet aged 0 days with only 2 prior transactions, and the total value is negligible, yet the AML engine flagged it under Rule [no_kyc_offramp] (score 85) for depositing to a FixedFloat 1 address without a KYC off‑ramp, and under Rule [sybil_fan_in] (score 70) for exhibiting a fan‑in pattern with 54 similar senders depositing roughly the same amount. These indicators suggest a possible layering or mixing activity, warranting further investigation. CRITICAL (rule score 155)

</details>

---

## Finding #8: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x7ff35e5bf5655dafed62c9afd57dcb29b6564603` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362994-26362994 |

### 💬 What Happened
CRITICAL (rule score 155) CRITICAL (rule score 155)

### 🔥 The Roast
This wallet is fresher than a latte in a coffee shop—0 days old, two transactions, and a zero balance after the move. It's basically the crypto equivalent of a kid dropping a handful of pennies in a secret piggy bank that you can't track. The engine gave it a high score for no‑KYC off‑ramp (meaning it didn't go through a verified exit, like a bank) and flagged it as part of a Sybil fan‑in (a bunch of wallets doing the same tiny trick). In other words, it's like a group of pranksters all sending the same amount of dough to the same anonymous cash‑cobbling machine. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review by the AML team, request additional context on the origin of the funds, and monitor for any further activity from the sender address or related wallets.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
This activity is flagged under rule [no_kyc_offramp] due to the deposit into FixedFloat 1, which provides an anonymous off‑ramp with no KYC verification. Additionally, rule [sybil_fan_in] was triggered by the presence of 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) within the same block. The wallet is brand new (0 days), has only 2 transactions, and a zero balance post‑transfer, indicating a potential pattern of layering. CRITICAL (rule score 155)

</details>

---

## Finding #9: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x2f1cfc3e3ca2589b5af7248f286b6f2761f9b3fa` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362992-26362992 |

### 💬 What Happened
A brand-new wallet (just created) sent a tiny amount of ETH—only 0.0001, about $0—to a FixedFloat address. It's like dropping a package into a slot that hides the sender, then hoping the receiver can claim the money later with no identity check.

### 🔥 The Roast
Looks like the wallet’s first move was to play hide‑and‑seek with a 0.0001 ETH tip to FixedFloat 1 (the no‑KYC off‑ramp, meaning you can get cash out without proving who you are). The AML engine gave it a solid 85 on the no_kyc_offramp rule, basically saying, ‘This address is a perfect place for a cloak of anonymity.’ Then it got another 70 on sybil_fan_in, because there are 54 other wallets dropping similar amounts—it's like a fan club of micro‑donors who all think 0.0001 ETH is the new gold. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 155, driven by high no_kyc_offramp and sybil_fan_in scores, indicates a strong risk of anonymous money movement.**

Flag the transaction for manual review and request additional source‑of‑funds information; monitor the FixedFloat address for subsequent activity and consider blocking if further suspicious patterns emerge.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Transaction involves a wallet with zero days of age, only two total transactions, and no current balance, sending 0.0001 ETH to a FixedFloat 1 address. Rule no_kyc_offramp was triggered with a score of 85, indicating the transfer goes to a service that allows withdrawals without KYC verification. Rule sybil_fan_in scored 70, reflecting a fan‑in pattern where multiple newly created wallets send comparable amounts to the same destination. The composite score of 155 exceeds the critical threshold, warranting further investigation.

</details>

---

## Finding #10: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xce676acf548bba8ad2dc5a60abfea31023f06fca` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362989-26362989 |

### 💬 What Happened
A brand-new wallet just dropped a tiny packet of ETH into a fixed‑rate exchange that hides where the money goes, like handing a mystery package to a courier with no tracking. The sender has only sent two transactions total and has zero balance left, so it looks like a one‑off cash‑in to an off‑ramp that bypasses KYC. The transfer was almost invisible in value (0.0001 ETH), but the pattern matches a crowd of similar small deposits that often signal a Sybil fan‑in attack.

### 🔥 The Roast
So this fresh wallet (0 days old) decided to play the crypto version of a toddler dropping a dollar into a piggy bank that refuses to show its face. It scored a whopping 85 on the no‑KYC off‑ramps rule (meaning the money can disappear without a proper identity check) and a 70 on the Sybil fan‑in rule (think 54 siblings all sending the same tiny amount to the same place, like a family of rabbits all dropping a single carrot into the same bowl). CRITICAL (rule score 155) The composite score of 155 says this is a high‑risk event, not a harmless tip‑off.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction meets both high‑risk AML patterns: a new wallet with no KYC off‑ramp and a Sybil fan‑in pattern, resulting in a composite score of 155.**

Flag for manual review by compliance. Verify source of funds, check for association with known mixers, and consider freezing the receiving address if further suspicious activity is identified.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggers rule no_kyc_offramp due to deposit into FixedFloat 1, an off‑ramp lacking KYC verification. It also triggers rule sybil_fan_in because the sender is one of 54 wallets sending similar amounts (~0.0001 ETH ±30%) to the same address, indicating a Sybil fan‑in pattern. The sender wallet is 0 days old, has only 2 total transactions, and a current balance of 0 ETH, which aligns with typical high‑risk profiles. The composite score of 155 warrants a compliance review.

</details>

---

## Finding #11: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x767087deffdf77ebe81d9ee1e3dba693ca26ef30` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362987-26362987 |

### 💬 What Happened
A brand-new wallet just sent 0.0001 ETH to a service called FixedFloat 1. It's like dropping a tiny parcel into a mailbox that never asks for your ID. Since the sender has no history and the amount is almost nothing, it's a red flag that someone is trying to hide where the money came from.

### 🔥 The Roast
This wallet is fresher than a loaf of bread and it just dropped a micro‑ETH into FixedFloat 1 with the confidence of a kid who just learned to walk. The AML engine gave it a 155 composite score—no‑KYC off‑ramp (meaning the service lets people cash out without verifying who they are) and a sybil fan‑in (meaning 54 similar wallets are all funneling almost identical tiny amounts). If this was a grocery store, they'd put the cart in the back‑room and call a detective. Seriously, it's like a group of ninjas all sending one tiny coin to a hidden box—nice try, but we’ve got the radar on that.

### 🎯 Verdict & Next Steps
**Critical – the combination of a new, unverified wallet and a Sybil fan‑in pattern to a no‑KYC off‑ramp warrants immediate scrutiny.**

Flag the transaction for a detailed compliance review and consider placing a temporary hold until the source of funds can be verified.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transfer originates from a zero‑age wallet with only two prior transactions and a zero current balance. The AML engine flagged the activity under [no_kyc_offramp] (score 85) due to the deposit to FixedFloat 1, a known no‑KYC off‑ramp service, and under [sybil_fan_in] (score 70) because the wallet is one of 54 similar senders contributing near‑identical amounts (~0.0001 ETH ± 30%). CRITICAL (rule score 155) The transaction should be escalated for manual review per internal policy.

</details>

---

## Finding #12: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x6c4cd56609b4450a291cacfb7888e9cb2ae83d18` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362983-26362983 |

### 💬 What Happened
A brand‑new wallet just sent a tiny 0.0001 ETH (about zero dollars) to a FixedFloat address, like dropping a single grain of rice into a secret silo that nobody can trace back to the original owner.

### 🔥 The Roast
Looks like a fresh‑from‑the‑forge wallet tried to play hide‑and‑seek by slipping 0.0001 ETH into a no‑KYC off‑ramp (that's the 'no_kyc_offramp' rule, meaning the money is heading to a place where nobody has to prove who they are). And the pattern? 1 out of 54 identical tiny deposits—classic Sybil fan‑in (the 'sybil_fan_in' rule, basically a swarm of identical bots feeding the same address). The composite score of 155 means the engine thinks this is as suspicious as a toddler trying to sneak cookies from the cookie jar.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Initiate a manual SAR review, trace the upstream sources of the 0.0001 ETH, and monitor the FixedFloat address for subsequent activity. Flag the sender wallet for future surveillance.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction was initiated from a wallet aged 0 days with only two prior transactions and a zero balance, immediately depositing 0.0001 ETH to FixedFloat address 1. Rule [no_kyc_offramp] flagged the transfer as a deposit to a no‑KYC off‑ramp (score 85). Rule [sybil_fan_in] identified the sender as part of a fan‑in Sybil pattern (score 70), indicating a cluster of similar low‑value deposits. The composite risk score of 155 warrants a review for potential layering or obfuscation.

</details>

---

## Finding #13: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb944784581cb2f4c4372261288f39e39542e0d54` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362982-26362982 |

### 💬 What Happened
A brand new wallet just sent a tiny amount of ETH (0.0001) to a fixed float address. The sender had no history and sent almost exactly the same amount that many other new wallets sent, making it look like a coordinated batch. The transaction was so small that it might just be a test, but the pattern flags it.

### 🔥 The Roast
So, a brand‑new wallet decided to play the lottery by sending a single 0.0001 ETH ticket to a fixed‑float address that doesn’t even ask for ID—like a kid dropping a penny in a vending machine that says "no ID required." And guess what? It’s not the only one; 53 other fresh wallets did the same, forming a fan‑club of tiny coins—classic Sybil fan‑in, or as I like to call it, the crypto version of a sock‑puppet support group. The engine gave it 155 points, which is basically saying, "Hey, we’re seeing a bunch of new kids with the same tiny coins, and no KYC, so we’re suspicious."

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review and investigate the originating wallets and subsequent movements; consider blocking the fixed float address if further suspicious activity is confirmed.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Transaction matches Rule: no_kyc_offramp (Deposit to a FixedFloat address with no identity verification). It also matches Rule: sybil_fan_in (multiple new wallets depositing similar amounts). The sender wallet age is 0 days and only 2 transactions, current balance zero, days since last activity 0, indicating a potentially suspicious new wallet. The transaction value is negligible but the pattern suggests a possible attempt to obscure origin.

</details>

---

## Finding #14: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf4a6af79da8350139e0946ad9cacaec3f55d8b8f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362978-26362978 |

### 💬 What Happened
A brand‑new wallet, just created yesterday, sent a tiny 0.0001 ETH (about the price of a cup of coffee) to a service that mixes coins. This is like dropping a small parcel into a dropbox that hides who mailed it. CRITICAL (rule score 155)

### 🔥 The Roast
Score 85 on no_kyc_offramp – meaning the sender is trying to get into a place that doesn’t ask for identity, like a shady bar that never checks IDs. Score 70 on sybil_fan_in – we’re looking at a bunch of cloned wallets all sending the same minuscule amount to the same spot, like a swarm of identical drones all dropping the same micro‑package. Composite 155 is the kind of high score that would make a video‑game cheat alert pop up. At 0.0001 ETH the transaction is so tiny it could be a test, but the pattern screams ‘watch me, I’m a layerer’ – if only we knew the sender’s real name, right?

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual compliance review; request additional source‑of‑funds information and verify whether the activity is a legitimate test or part of a layering scheme.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggers rule [no_kyc_offramp] because the sender deposited to FixedFloat 1, an address that does not provide a KYC off‑ramp, which is a high‑risk activity for potential layering. It also triggers rule [sybil_fan_in] due to a fan‑in pattern: 1 of 54 senders deposited similar amounts (~0.0001 ETH ± 30%) to the same address, indicating possible Sybil behavior. The wallet is brand new (0 days old) with only two transactions and no balance, further supporting the suspicion of a new, potentially illicit address. These factors combine to produce a composite score of 155, indicating a high likelihood of suspicious activity. CRITICAL (rule score 155)

</details>

---

## Finding #15: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xd1c15592417a3435c96ef947435e1f90c080ca6d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362977-26362977 |

### 💬 What Happened
A brand-new wallet just opened and sent a tiny amount of 0.0001 ETH (about a few cents in US dollars) to a FixedFloat address. Think of it like dropping a single grain of rice into a slot machine that hides where the rice came from. The sender had only a couple of transactions and no balance left after the send, so it looks like a fresh, anonymous source trying to move money through a non‑KYC channel.

### 🔥 The Roast
This new wallet is as new as a fresh phone in a dumpster, and it’s trying to sneak a micro‑payment through a FixedFloat address like it’s a secret club that doesn’t do ID checks. With a score of 85 on the no‑KYC off‑ramp rule, it’s basically saying, “I’m not going to show you my ID, just let me go!” Then, on top of that, 70 points for the sybil_fan_in rule means it’s part of a big fan‑in party where dozens of new wallets are all sending roughly the same tiny amount. It’s like a school of minnows all swimming into the same black hole, but nobody knows who’s driving the ship. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual compliance review, request source‑of‑funds verification for the sender, and monitor or block the FixedFloat address if further suspicious activity is detected.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction from wallet 0xd1c15592417a3435c96ef947435e1f90c080ca6d to 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1) has triggered two high‑risk AML engine rules: [no_kyc_offramp] (score: 85) indicating a deposit to a non‑KYC off‑ramp and [sybil_fan_in] (score: 70) indicating a Sybil fan‑in pattern with many new wallets sending similar low‑value amounts. CRITICAL (rule score 155) The composite score of 155 places this activity in the critical risk tier. CRITICAL (rule score 155)

</details>

---

## Finding #16: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x475dc5a8df2080b18950a0d75aa9f131de57d0bc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362973-26362973 |

### 💬 What Happened
A brand-new wallet sent a tiny amount of ETH to a fixed float address in a single transaction. Think of it like dropping a single grain of rice into a funnel that hides who sent it. CRITICAL (rule score 155)

### 🔥 The Roast
This wallet is fresher than a fresh roll of bread (0 days old) and it just tried to sneak 0.0001 ETH into a no‑KYC off‑ramp. Rule [no_kyc_offramp] (meaning the funds go to an address that doesn't require identity verification) gave it 85 points. Rule [sybil_fan_in] (meaning a bunch of wallets are all sending the same tiny amount to the same place, like a choir of spam) added 70. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction displays both a no‑KYC off‑ramp and Sybil fan‑in patterns, indicating high risk of illicit layering activity.**

Flag the transaction for manual review, investigate the source of the sender wallet, and assess whether the funds may be part of a larger structuring scheme.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits characteristics consistent with the AML Engine's [no_kyc_offramp] rule (score 85) due to the transfer to a FixedFloat 1 address that does not provide KYC verification. Additionally, the pattern matches the [sybil_fan_in] rule (score 70), indicating fan‑in activity from 1 of 54 similar senders depositing amounts within ±30% of 0.0001 ETH. The sender wallet is newly created (0 days old) and has a total of only 2 transactions, with no balance remaining, further raising concerns. The combination of a fresh wallet, minimal activity, and a no‑KYC off‑ramp suggests potential layering or structuring behavior.

</details>

---

## Finding #17: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x845e769747b19087cfc831ddf95c94a7a431de0d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362967-26362967 |

### 💬 What Happened
CRITICAL (rule score 155) Think of it like someone slipping a note into a mail slot that has no return address—now it’s hard to know who left it. The wallet did this in a single, almost invisible transaction that could be part of a bigger, hidden scheme.

### 🔥 The Roast
CRITICAL (rule score 155) It’s basically the crypto equivalent of a group of toddlers all tossing the same size cookie into a black‑hole. CRITICAL (rule score 155) CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the wallet for detailed manual investigation, verify the source of the 0.0001 ETH, and monitor for any subsequent activity that may indicate layering or further off‑ramp transactions. Report findings to the compliance team for possible escalation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 155) CRITICAL (rule score 155) These indicators suggest potential layering or obfuscation of funds, warranting heightened scrutiny.

</details>

---

## Finding #18: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xbcb3fef84258ff571e33ab414c898d233c2d7cfc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362966-26362966 |

### 💬 What Happened
A brand-new wallet just dropped a tiny coin (0.0001 ETH) into a big, anonymous exchange-like address called FixedFloat 1. Think of it as a new kid in school handing over a handful of pennies to a vending machine that doesn’t keep receipts. The transaction is almost invisible in value but the lack of identity checks and the way it’s routed raise eyebrows.

### 🔥 The Roast
So this brand‑new wallet decided to play hide‑and‑seek by sending a blink‑and‑you‑miss‑it amount of ETH to a no‑KYC off‑ramp (meaning the receiver never asks for your ID). The engine even gave it a 85 on the no_kyc_offramp score, because who needs paperwork when you can just vanish? On top of that, it’s part of a Sybil fan‑in pattern (score 70) – 1 of 54 wallets all sending the same teeny‑tiny amount like a synchronized swarm of paper cranes. Basically, it’s a perfect storm of newness, anonymity, and mass participation, like a flash mob of crypto‑minimalists at a secret party.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction combines a new, KYC‑unverified wallet with a high‑risk off‑ramp and a Sybil fan‑in pattern, warranting immediate human review.**

CRITICAL (rule score 155) Consider blocking the FixedFloat 1 address if further suspicious activity is identified.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created wallet (age 0 days) that sent 0.0001 ETH to a FixedFloat 1 address, a known high‑risk off‑ramp lacking KYC verification. The AML engine flagged the activity with a composite score of 155, driven by a no_kyc_offramp rule (85) and a sybil_fan_in rule (70), indicating a potential Sybil fan‑in pattern and lack of identity checks. The sender’s wallet has no balance and only two total transactions, suggesting a potential attempt to obfuscate source funds. CRITICAL (rule score 155)

</details>

---

## Finding #19: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x78cc118df635a5591c85d6a478220ccc6ac1b8e1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362966-26362966 |

### 💬 What Happened
A brand‑new wallet just sent a tiny 0.0001 ETH (about $0) to a FixedFloat address that doesn’t do KYC. It’s like dropping a single coin into a mystery box that hides who put it in. The sender only had two transactions in its history and no money left in the account after this one.

### 🔥 The Roast
So we got a fresh wallet, no identity checks (no_KYC_offramp – meaning the recipient doesn’t ask for ID), and it sent a micro‑payment to a fixed‑float service. Then we see a whole squad of 54 similar wallets all churning out 0.0001 ETH to the same place – classic fan‑in Sybil (sybil_fan_in – many fake identities feeding the same target). It’s like a bunch of pranksters all slipping tiny coins into the same hidden jar. If this were a game, it would be “Who can send the smallest coin the fastest?” Spoiler: the answer is a red flag.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction and sender wallet for manual investigation, request source of funds and wallet activity history, and consider placing the address on a watchlist pending further analysis.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Rule no_kyc_offramp triggered with a score of 85 due to the transaction to FixedFloat 1, a service lacking KYC. Rule sybil_fan_in scored 70, indicating 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) to the same receiver, consistent with a Sybil fan‑in pattern. The sender wallet is 0 days old, has only 2 total transactions, and a current balance of 0.000000 ETH, indicating it is a newly created, low‑volume address. The composite AML engine score of 155 signals elevated risk for potential mixing or layering activity.

</details>

---

## Finding #20: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x93e02f263f2f650b34f0e99fc0b53f4d55339e41` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362951-26362951 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #21: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa49615d7488e5a4711b769f10e7b382879711d5b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362950-26362950 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #22: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x372504815a18ac337c0889a2d80d79916205ce74` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362948-26362948 |

### 💬 What Happened
A brand‑new wallet, like a freshly opened envelope, sent a minuscule amount of crypto (0.0001 ETH) to a fixed‑rate exchange. The sender had barely existed—just one day old and had only made two transactions—so it’s like a new kid in class who just posted a tiny note to a friend. The receiver’s address is a known fixed‑rate service that locks the value of the crypto, making it hard to trace where the money ultimately ends up.

### 🔥 The Roast
Score of 155? That’s like getting a perfect score on a quiz that only asks you to pick a color. The engine flagged a [no_kyc_offramp] (meaning the money goes to an off‑ramp that doesn’t ask for identity—like a shady ATM with no ID check) and a [sybil_fan_in] (so we’re seeing a bunch of identical, tiny deposits from almost identical addresses—like a group of pranksters sending the same joke to the same friend). CRITICAL (rule score 155) 0.0001 is less than a cent—just a blink in the ether, yet the engine is on high‑alert because the sender is brand new and the receiver is a known fixed‑float service.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, request additional context on the origin of the funds, and monitor for subsequent activity involving the same receiver address.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 155) Rule [no_kyc_offramp] identified the absence of identity verification at the off‑ramp. Rule [sybil_fan_in] detected a fan‑in pattern with 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) suggesting a Sybil attack or wash‑trading activity. CRITICAL (rule score 155)

</details>

---

## Finding #23: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa748b47caa4f83a38ae3ae2767f71edf2c455ad3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362943-26362943 |

### 💬 What Happened
A brand-new wallet just sent a minuscule 0.0001 ETH (about nothing in dollars) to a service called FixedFloat 1. Think of it like someone dropping a tiny coin into a slot machine that hides who gave it. The wallet was created today, hasn't held any funds, and hasn't made any other moves yet.

### 🔥 The Roast
CRITICAL (rule score 155) The AML engine gave it an 85 for no‑KYC off‑ramp (meaning the service doesn’t ask for your ID) and a 70 for Sybil fan‑in (like a choir of tiny wallets all singing the same tiny song). Combined, that’s a 155 composite score, higher than a barista’s latte art. If you’re looking for a recipe for a suspicious transaction, this is the first page.

### 🎯 Verdict & Next Steps
**The transaction exhibits high AML risk due to no‑KYC off‑ramp and Sybil fan‑in patterns, justifying a critical review.**

Flag the transaction for manual review by the compliance team and request additional context on the source wallet's activity. Consider monitoring subsequent transactions from this address for patterns of layering or structuring.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created wallet (age 0 days, total tx count 2) sending 0.0001 ETH to FixedFloat 1, an off‑ramp service with no KYC verification. Rule [no_kyc_offramp] is triggered with a score of 85, indicating high risk due to lack of identity verification. Rule [sybil_fan_in] scores 70, reflecting a fan‑in Sybil pattern where multiple new wallets send similar amounts to the same destination. The composite score of 155 exceeds the threshold for a high‑risk alert and warrants further investigation.

</details>

---

## Finding #24: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb3a840fb9ac81d5d9d32f46087e94924fc30f91f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362943-26362943 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (0.0001, about nothing) to a service called FixedFloat 1. Think of it as someone dropping a single coin into a hidden slot that hides where it came from. Because the wallet was created today and had almost no history, it looks suspiciously fresh.

### 🔥 The Roast
So we have a fresh wallet that just dropped 0.0001 ETH into FixedFloat 1, a place that doesn't even ask for your ID (no_kyc_offramp, meaning there's no identity check before you can take the money out). On top of that, it looks like a fan‑in Sybil pattern: 54 other new wallets are all sending about the same tiny amount, like a group of copy‑cats all trying to hide behind the same cheap cloak. Basically, it’s the crypto equivalent of a bunch of kids all stuffing a single dollar bill into the same invisible slot on a vending machine – no one knows who actually paid for what. If this were a real world scenario, it would be like a group of anonymous shoppers all buying the same tiny souvenir and then walking out of a shop that doesn't record their names.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review. CRITICAL (rule score 155)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet with zero days of age, only two prior transactions, and a current balance of 0.000000 ETH. The wallet deposited 0.0001 ETH into the FixedFloat 1 service, which is categorized by the AML engine under the rule [no_kyc_offramp] (deposit to an off‑ramp without KYC). Additionally, the engine flagged the pattern as [sybil_fan_in] with a score of 70, indicating that this wallet is part of a cluster of 54 senders depositing similar amounts (~0.000 ETH ± 30%). CRITICAL (rule score 155)

</details>

---

## Finding #25: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x5ba6e3d22971123d47ba9fa28b0f437fde958a48` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362942-26362942 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #26: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc36adceaffc3366a841627175b27d44b16037b2a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362937-26362937 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x4491996d1a2acae14ca49c9992e75beeba703aff` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362934-26362934 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x899579b744c6dcabb53528a73c971391011ec79b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362933-26362933 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf3e6e98e9712ec8ed34716e3836f3d01a7f6bca0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362932-26362932 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xed578e79ae06dce9553c231998926abcbab74868` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362932-26362932 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xbe31cc72456379c9be84382c06c7a0dcd02c5b6f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362929-26362929 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x40a17cf86b2c9d0a40272f441caeaf3cdec405bd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362921-26362921 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb3f5e18abdda3f51a3c87f2017833a394f80bca3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362916-26362916 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x222c9ed729b182d9e957ac3331f7906242ed322f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362915-26362915 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xdcd3d414c458369981e938b89f3916f0a3a5948f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362912-26362912 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xccb9d9b6245bf78f486af9568ad7097e61083083` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362910-26362910 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x312c2cb7e4c04dd77b27c8356684089c1f83fe4b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362908-26362908 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xec8df316176085604636da4ec28ca9f6a0ab0eb3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362904-26362904 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x342512f3bd981dfdc296890aa1ecc7c56fe6321e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362895-26362895 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x37f829345ddaf45d3be090d578bbcde1b9ba49ab` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362894-26362894 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x635511417cd0e1a41c470f4e8d7d59bb2eceb201` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362891-26362891 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc1c5218ad7f7d0e7f01b2867953e56eaffd39af1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362890-26362890 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xcae457be60e02a4d788fb179b2a34e6b0ba2ee87` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362888-26362888 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x21d0a9f58124b1b829d6398ee461b68680de5393` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362879-26362879 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x5416d73d632fdb2724f0dbd0d845016dd33b0ce8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362877-26362877 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x3026c7f40c9b717c0156683ef2dd578045b91421` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362875-26362875 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #47: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x213f0edcdea58604acac12253c2ac8c4037586d5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362873-26362873 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x8210eae544b8081161cb57834bb188948d41c101` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362869-26362869 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x4fcc7fba80432040e31eddf7f4c58708a2d9e7bd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362865-26362865 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x815793c2e179563d794b649c13732a68d0ff975d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362864-26362864 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #51: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x21d36765c6acff4751b5c68631541aee5fd47320` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362862-26362862 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #52: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc395688111e3e93c888c177a016d169baafdde44` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362861-26362861 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #53: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xae0a93f68fae019314dfe0ab3c037b403b2a29e2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362859-26362859 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #54: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf81279ad619d85e53b24ab61c9ca6b38cff5d133` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362855-26362855 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #55: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xd327c3b25be371837e1940fbbc4597d31edaf40b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362850-26362850 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #56: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x25e62ac274c4cc1ba6890255d640bf990044f813` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362840-26362840 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #57: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x32b3b8c237ae286b1b785a214c35163e2b99b9cd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362839-26362839 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #58: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x45f90a78f730f775f0a8b37e0608b4357e0d9938` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362837-26362837 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #59: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x2ab2f6e7c21718df8a443ea5a9e37820476e0865` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362836-26362836 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #60: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x1eba078a54ebf80b3028c69c59a89eef33a34551` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26362829-26362829 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 54 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #61: HIGH — Score 105

| | |
|---|---|
| **Sender** | `0x1e0fa0e83f3c55da84fc078f106530d07c8e211d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **4.4010 ETH** ($9,864) |
| **Blocks** | 26362928-26362941 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 105.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 105)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 765 days |
| Total Transactions | 546 |
| Current Balance | 0.008598 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 105):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge
- **exit_rush** (+40) — Wallet balance near zero (0.008598 ETH) after moving 4.4010 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #62: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x07db335457309aea164c43ab6ee13753709569c9` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0654 ETH** ($147) |
| **Blocks** | 26362840-26362840 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000001 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #63: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x172cc31054c59cb7a4bdde48f62b29e355deb4ad` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0259 ETH** ($58) |
| **Blocks** | 26363019-26363019 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #64: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x6a513d1fed89c9a3ba4d2807006a84ea87381a31` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.8020 ETH** ($1,797) |
| **Blocks** | 26363017-26363017 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #65: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa407e0147e72f2752537e92ea721c00c23133ee3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1076 ETH** ($241) |
| **Blocks** | 26363008-26363008 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #66: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x49976fb38b82eb51e85a5d521433b0603e79af3a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0270 ETH** ($61) |
| **Blocks** | 26362988-26362988 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #67: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x454824868959eb7d015572cf38e48c35469b54d1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0070 ETH** ($16) |
| **Blocks** | 26362980-26362980 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #68: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x0ef7fabb8586b5cafc5a093739b5b9c11e844945` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1249 ETH** ($280) |
| **Blocks** | 26362976-26362976 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #69: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x18f5e944c47ff0d2aa75ca53fdbf8edef084a8d3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0050 ETH** ($11) |
| **Blocks** | 26362962-26362962 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #70: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4852745988b3539b6ce7a2181d9f1064f8ca54d8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0050 ETH** ($11) |
| **Blocks** | 26362941-26362941 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #71: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3c9b8abc6115346dca3456e8d99a991d1b329d25` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2162 ETH** ($485) |
| **Blocks** | 26362914-26362914 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #72: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5138d7ca8d8ddc1bedd60efc393cf17bb90ed83c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0600 ETH** ($134) |
| **Blocks** | 26362913-26362913 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #73: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd0570613066d5c8ee99668141969b6f14392589b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1696 ETH** ($380) |
| **Blocks** | 26362876-26362876 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #74: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xfc9bdbb273074ece65376ac33a5430cfd7515411` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0250 ETH** ($56) |
| **Blocks** | 26362874-26362874 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #75: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc8c2a7cf6b38fd75ed35122c8301fbf6761f6869` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0450 ETH** ($101) |
| **Blocks** | 26362858-26362858 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #76: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x59b4f2bcdc4ac017e625537ecbe553c1e210ed88` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$4** (4 USDC) |
| **Blocks** | 26362945-26362945 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 80.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $4 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #77: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9c84569daa3f8e1671ea6a769760507d4f991731` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$25** (25 USDC) |
| **Blocks** | 26362875-26362875 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 80.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $25 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #78: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7affe54057326488d212100d2797d4d457453a78` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$400** (400 USDC) |
| **Blocks** | 26363021-26363021 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 80.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $400 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #79: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x083af5d00796f6545cb0f60cf0335c89a92f15bd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$200** (200 USDC) |
| **Blocks** | 26363021-26363021 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 80.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $200 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #80: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x41d4e4ca1fc033d8fec56c7c947e12141d0aafc0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26363022-26363022 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1778 days |
| Total Transactions | 281 |
| Current Balance | 0.602026 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #81: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xedc968aac2d6c80a43ad35458ea080157337028f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26363021-26363021 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 651 days |
| Total Transactions | 49 |
| Current Balance | 0.000040 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #82: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x3cc14937c8b861a9ea42c5cd5631f1002fbd0bb6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26363008-26363008 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 175 days |
| Total Transactions | 3689 |
| Current Balance | 0.006527 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #83: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xb6014aac3fbc97a521d7345e73831eac15dd87fb` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0021 ETH** ($5) |
| **Blocks** | 26363000-26363000 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 12 days |
| Total Transactions | 2 |
| Current Balance | 0.000025 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #84: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x439687934040fd57365f9c1600d7e84831c01daf` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0600 ETH** ($134) |
| **Blocks** | 26362994-26362994 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1858 days |
| Total Transactions | 302 |
| Current Balance | 0.005654 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #85: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x9e90e763135bc4ca236fa0c5edf8555ebde32513` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362986-26362986 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1322 days |
| Total Transactions | 12 |
| Current Balance | 0.000517 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #86: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x9b0e51fec28dd95a38b5a50633afcaf355cb0700` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0111 ETH** ($25) |
| **Blocks** | 26362982-26362982 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 666 days |
| Total Transactions | 62 |
| Current Balance | 0.005190 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #87: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa41c4575d306d8186151ab0f34c5d400699fb898` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362954-26362954 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1490 days |
| Total Transactions | 31 |
| Current Balance | 7.749761 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #88: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x5dee419d66aba90beee1a9d539147b8d90c9538f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362943-26362943 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2256 days |
| Total Transactions | 71 |
| Current Balance | 0.003855 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #89: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x511e6fd8c87e617575e3778ec068fc6fccd47450` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362934-26362938 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 81 days |
| Total Transactions | 1138 |
| Current Balance | 0.003372 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #90: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa03849b3f4840a8a8c56a61db6c866c07ff42c1d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362924-26362924 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 11 days |
| Total Transactions | 5 |
| Current Balance | 0.000013 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #91: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x7693d74ca91c597e2c99c9bb402000d88029db15` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0500 ETH** ($112) |
| **Blocks** | 26362923-26362923 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1450 days |
| Total Transactions | 56 |
| Current Balance | 0.028279 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #92: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa4db5c5dc6fa43fd868ab47d8801036939c67f56` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362921-26362921 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.001886 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #93: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x6fb737d1ebb73cda6cfa36fd16d9273065d1b084` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0321 ETH** ($72) |
| **Blocks** | 26362908-26362908 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2605 days |
| Total Transactions | 4702 |
| Current Balance | 0.059979 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #94: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x88ba7d18c2766b0f2e1f8d464952f2f3520cf66b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.1230 ETH** ($276) |
| **Blocks** | 26362905-26362905 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1496 days |
| Total Transactions | 485 |
| Current Balance | 0.000444 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #95: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362903-26362903 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1082 days |
| Total Transactions | 213508 |
| Current Balance | 0.851470 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #96: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x49719d256a5ea16bfa579ea16e95bea9fa41a452` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362892-26362892 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 536 days |
| Total Transactions | 161633 |
| Current Balance | 0.179323 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #97: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x8458017d47ad8dbe80cfc1d427d4970e02cc7385` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362890-26362890 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 557 days |
| Total Transactions | 645 |
| Current Balance | 341.786359 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #98: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x12cf25ecaa060eee5e5b31ce0aa6e0595358acdb` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0090 ETH** ($20) |
| **Blocks** | 26362881-26362881 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 61 days |
| Total Transactions | 9 |
| Current Balance | 0.002120 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #99: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x17e03a9f526d73dea85a151727acbede25c69a6d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0176 ETH** ($39) |
| **Blocks** | 26362879-26362879 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1069 days |
| Total Transactions | 296 |
| Current Balance | 0.005746 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #100: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xcfab1066c172c8f36dbb866d5402c07271f33c45` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362863-26362863 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1887 days |
| Total Transactions | 209 |
| Current Balance | 0.002195 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #101: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xba567d3722d81c11e7c8169166c287bd78c423b0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362861-26362861 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1922 days |
| Total Transactions | 360 |
| Current Balance | 0.000126 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #102: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x364ae24b97637b470dc7493c08555bb8ed635991` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26362851-26362851 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1240 days |
| Total Transactions | 545 |
| Current Balance | 1.637187 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #103: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xc0ec829c4d0839d63ae504a881483763cdaeefad` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0009 ETH** ($2) |
| **Blocks** | 26362847-26362850 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 10 |
| Current Balance | 0.005265 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #104: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x2be26a2872c350e17b78ca0eb44143d06d9e3269` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26362833-26362833 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 65.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 65)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 245 days |
| Total Transactions | 5 |
| Current Balance | 0.000348 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**104 suspicious findings** detected across 104 unique wallets. Highest risk score: **254**.

| | |
|---|---|
| 🔴 CRITICAL | 60 |
| 🟠 HIGH | 1 |
| Wallets flagged | 104 |
| Suspicious value | 36.3588 ETH ($81,487) + $629 in stablecoins |
| Blocks scanned | 26362828 — 26363027 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 4 of 25 attempted analyses this run.

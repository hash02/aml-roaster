# 🔥 AML Roaster Report
**2026-11-25 21:28 UTC** · Ethereum Mainnet · ETH $1,684.93
**Blocks:** 26494627 — 26494826 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26494627 to 26494826 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **24** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494628-26494826 |

### 💬 What Happened
The sender sent 24 tiny payments of 0 ETH to a bridge, like someone dropping 24 identical empty envelopes into a mailbox to hide that they actually sent something. Each payment looked identical, so it looks like a smurfing attempt.

### 🔥 The Roast
Structuring (splitting a single transfer into many tiny ones) got 70 points – a textbook example of trying to hide a big move by making it look like a bunch of small ones. Peel chain linear (a chain of similar moves that hide the source) scored 60 – imagine a magician sliding the same coin down a line of cups. Bridge hop (moving funds across chains) hit 65 – like sending a package through a maze of post offices just to make the delivery address hard to trace. Together, this is the blockchain equivalent of a bad magic trick: the trick is obvious, but the illusion is still entertaining to the fraudsters.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of structuring, peel chain, and bridge hop indicates high risk of layering or obfuscation.**

Flag the account for manual review, request transaction source information, and monitor subsequent activity for additional suspicious patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2812 days |
| Total Transactions | 869037 |
| Current Balance | 11.991622 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 24 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 24 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits characteristics consistent with rule [structuring] (multiple identical transfers totaling 0 ETH), rule [peel_chain_linear] (a peel chain of 24 sequential deposits), and rule [bridge_hop] (transfer via Across SpokePool V2). The sender’s wallet has a long history but recent activity indicates potential layering. CRITICAL (rule score 195) The pattern suggests possible structuring and layering, warranting further investigation.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x78523764b9ab9d04145d50a51e1d9b2d615250af` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **10** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494627-26494825 |

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
| Wallet Age | 5 days |
| Total Transactions | 733 |
| Current Balance | 0.068647 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 10 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 10 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **8** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494627-26494825 |

### 💬 What Happened
A single wallet sent eight identical, zero‑value ETH transfers to a bridge contract called Across SpokePool V2. It’s like a person dropping eight empty envelopes into a mailbox that hides who actually sent them, just to create a suspicious pattern.

### 🔥 The Roast
CRITICAL (rule score 195) Basically, it’s the blockchain version of a 3‑step dance where everyone’s doing the same move, and the judge says ‘yeah, that’s a red flag!’

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of structuring, linear peel chain, and bridge hop patterns warrants immediate review.**

Flag the wallet for manual investigation, request source of funds documentation, and monitor for additional suspicious activity on the same address.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 104 days |
| Total Transactions | 38189 |
| Current Balance | 0.047770 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 8 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 8 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction set exhibits characteristics of Rule [structuring] (score: 70) due to the identical zero‑value deposits, Rule [peel_chain_linear] (score: 60) indicated by the sequential pattern of eight similar transfers, and Rule [bridge_hop] (score: 65) because the funds were routed through the Across SpokePool V2 bridge. The wallet’s high activity volume (38,189 tx) and recent activity (0 days since last tx) further support potential layering. CRITICAL (rule score 195)

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **12** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494645-26494811 |

### 💬 What Happened
Someone moved a bunch of tiny, identical amounts of ETH from one address to a bridge service that mixes funds. Think of it like a cashier putting the same blank envelope into a machine that hides who wrote it, doing it 12 times in a row. The total value was zero, but the pattern looks like someone trying to make a trail that’s hard to follow.

### 🔥 The Roast
12 times the same 0.0000 ETH? That’s like a magician pulling the same card from a deck over and over – the audience gets bored, the machine gets confused. The AML engine gave it 70 for structuring (because all the amounts were identical), 60 for peel_chain_linear (a straight‑line layering pattern), and 65 for bridge_hop (because it went through a cross‑chain bridge). The composite score of 195 is basically the crypto equivalent of a red flag at a bar: "We see you’re trying to hide the money trail, buddy."

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual review, request additional KYC information from any associated accounts, and monitor downstream transactions for further suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 259 days |
| Total Transactions | 20562 |
| Current Balance | 0.067362 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 12 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 12 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender address 0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427 performed 12 identical ETH transfers of 0.0000 ETH to the Across SpokePool V2 contract between blocks 26494645 and 26494811. This activity triggered the AML rules: [structuring] (score 70) for identical transaction amounts, [peel_chain_linear] (score 60) for sequential layering, and [bridge_hop] (score 65) for cross‑chain bridge usage. The composite score of 195 exceeds the critical threshold, warranting a suspicious activity report. CRITICAL (rule score 195)

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494706-26494811 |

### 💬 What Happened
The sender sent three tiny, identical amounts of ETH (each 0.0000) into a bridge pool that moves tokens between blockchains. It's like dropping three identical, empty envelopes into a mailbox that automatically forwards them to another city—no real money moved, but the pattern looks like someone is trying to hide the source by splitting it into identical tiny pieces and sending them through a bridge to make the trail harder to follow.

### 🔥 The Roast
So, we have a wallet that’s been around for 345 days, just slipped three *identical* 0.0000 ETH packets into Across SpokePool V2. The AML engine gave it a 195 score, which is higher than most people get for their grocery bill. The structuring rule (same tiny amount repeated) and peel_chain_linear (layering with identical deposits) are shouting ‘smurfing’ louder than a clown at a circus. And the bridge_hop? That’s the cherry on top—because who doesn’t love a good bridge to hide a smurf? Basically, this is crypto’s version of a magician’s trick: *now you see the money, now you don’t*.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual review, investigate the origin of the 0.0000 ETH deposits, and monitor subsequent activity across the bridge. Document findings and submit a SAR if further suspicious patterns emerge.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 345 days |
| Total Transactions | 31243 |
| Current Balance | 0.199997 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Three consecutive ETH transfers of 0.0000 ETH were sent from address 0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a to address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2 between blocks 26494706 and 26494811. The activity triggered the AML engine rules: structuring (score 70) for identical minimal deposits, peel_chain_linear (score 60) indicating a linear layering pattern, and bridge_hop (score 65) for cross-chain bridging. CRITICAL (rule score 195) The sender wallet has a high transaction volume (31,243 tx) and a balance of 0.199997 ETH, suggesting active usage. CRITICAL (rule score 195)

</details>

---

## Finding #6: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **7** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494631-26494808 |

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
| Wallet Age | 1101 days |
| Total Transactions | 219092 |
| Current Balance | 0.480941 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 7 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 7 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #7: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0xe6ddcfae9a04d4478c5ffbe125fbf17b26bcf9a3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.3736 ETH** ($3,999) |
| **Blocks** | 26494666-26494666 |

### 💬 What Happened
A brand‑new wallet sent almost 3,000 dollars worth of ETH to a service that lets you move funds around without anyone knowing who you are. The sender had never used the wallet before and already had its balance wiped out after the move—like dropping a pizza in a bag and then immediately eating it. This pattern looks suspicious because the funds disappear into a place that hides their origin.

### 🔥 The Roast
Look at that fresh‑out wallet, 0 days old, dropping 2.3736 ETH into a FixedFloat 1 like it just found a secret hide‑and‑seek spot. The engine gave it a 64 for novel_wallet_dump (new wallet doing a big dump) and a 85 for no_kyc_offramp (sending to a place that doesn't check ID), so it’s basically a burner with no paperwork. The exit rush score of 40 (wallet balance hits zero after the transfer) shows the money left faster than a pizza delivery guy on a caffeine binge. In short, this is a classic “burner‑then‑vanish” move that even your grandma would call “dodgy.”

### 🎯 Verdict & Next Steps
**CRITICAL — the high composite score and pattern of a new burner wallet draining funds into a no‑KYC off‑ramp indicate elevated AML risk.**

Flag the transaction for manual review and trace downstream flows to any related addresses. CRITICAL (rule score 189)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 189):
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.3736 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.3736 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Rule novel_wallet_dump: Wallet age 0 days, single transaction of 2.3736 ETH, indicating a potential burner wallet. CRITICAL (rule score 189) Rule exit_rush: Post‑transaction balance 0.000000 ETH, suggesting immediate withdrawal or dispersal of funds. The combined composite score of 189 exceeds the critical threshold, warranting human review.

</details>

---

## Finding #8: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x45e477f77e64e1dcb850752e3d7182e9354ee1da` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9467 ETH** ($3,280) |
| **Blocks** | 26494737-26494737 |

### 💬 What Happened
The sender’s brand‑new wallet sent almost $3,300 worth of Ethereum to a service that immediately forwards the money to other users without any identity check. It’s like dropping a freshly printed check into a black hole that vanishes the cash and never reveals who paid it. The transaction happened in a single block and the sender’s balance dropped to zero in an instant.

### 🔥 The Roast
This is a classic burner wallet dump (meaning the wallet is brand new and just dumped money). The no‑KYC off‑ramp (meaning the recipient is a service that doesn’t ask for identity) made the money disappear faster than a magician’s coin trick. CRITICAL (rule score 188) Bottom line: you’ve got a wallet that was born to burn, no one knows who it’s paying to, and it vanished in a flash—like a bad Tinder date that disappears after the first swipe.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits classic burner wallet dumping with a KYC‑free off‑ramp and immediate balance depletion, indicating a high likelihood of illicit activity.**

CRITICAL (rule score 188)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 188):
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9467 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9467 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers the following AML rules: [novel_wallet_dump] (score 63) indicating a brand‑new wallet used for a large transfer, [no_kyc_offramp] (score 85) showing the funds were moved to a KYC‑free off‑ramp service, and [exit_rush] (score 40) reflecting an immediate depletion of the wallet’s balance. CRITICAL (rule score 188) The receiver address is associated with FixedFloat 1, a known service used to anonymize funds. This pattern warrants a suspicious activity report (SAR) and further investigation.

</details>

---

## Finding #9: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x2448ea88fe25cb1911a99b37403269415e476aad` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.8450 ETH** ($3,109) |
| **Blocks** | 26494648-26494648 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 188.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 188)**

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

**Rules Triggered** (3 rules, composite score: 188):
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.8450 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.8450 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #10: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x4733d070169ae70f4672b5c9ca1e2e839ae9b7c1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494824-26494824 |

### 💬 What Happened
A brand‑new wallet sent a tiny amount of ETH (0.0003) to a service called FixedFloat 1. Think of it like someone dropping a micro‑package into a vending machine that then redistributes it to many people, making it hard to trace where the money originally came from.

### 🔥 The Roast
So, we have a fresh wallet that just popped into existence and immediately decided to play hide‑and‑seek with 0.0003 ETH. Rule no_kyc_offramp (meaning the wallet sent money to an off‑ramp that doesn’t ask for identity verification) gave it a hefty 85 points. And sybil_fan_in (meaning lots of new wallets are all sending similar tiny amounts to the same place, like a choir of microwaves) added another 70. It’s basically a crypto version of a ‘who’s that kid in the cafeteria?’ scenario.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a newly created wallet, KYC‑less off‑ramp, and Sybil fan‑in pattern signals a high likelihood of an attempt to obfuscate the source of funds.**

Flag the wallet for manual review, request additional transaction context (e.g., upstream and downstream activity), and consider applying enhanced due diligence before any further processing.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a 0‑day wallet with only 2 prior transfers and a zero balance, indicating a potentially newly created address. Rule [no_kyc_offramp] scored 85, flagging the transfer to FixedFloat 1 which lacks KYC verification. Rule [sybil_fan_in] scored 70 due to the high volume of similar low‑value deposits from 37 distinct senders within the same block, consistent with a fan‑in Sybil pattern. These indicators warrant further investigation.

</details>

---

## Finding #11: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x48a0e2962d026bbae9cdedb503ad32a9f425bca2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494820-26494820 |

### 💬 What Happened
A brand-new wallet sent a tiny amount of ETH (about 0.0003, practically nothing) to a service called FixedFloat 1. It's like dropping a single penny into a slot machine that then hides who the penny came from. The sender's wallet just appeared and had only two transactions, so it's a very fresh, low‑balance account.

### 🔥 The Roast
Looks like someone tried to hide a drop of digital gold in a secret box called FixedFloat 1, hoping the world would forget the 0.0003 ETH. The AML engine gave it a whopping 85 points for "no‑KYC off‑ramp" (meaning the wallet is basically a cloak‑and‑dagger cash‑out with no identity attached) and another 70 for "sybil fan‑in" (so it’s the first of a bunch of wallets all doing the same tiny trick). With a composite score of 155, the system thinks this is about as suspicious as a kid with a lollipop at a bank robbery.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, request additional contextual information from the sender if possible, and monitor subsequent activity for further signs of structured mixing or wash‑trading.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 155) Rule no_kyc_offramp was triggered with a score of 85, indicating a deposit to a service that provides an off‑ramp without any KYC verification. CRITICAL (rule score 155) The composite score of 155 exceeds the critical threshold, flagging the activity for further review.

</details>

---

## Finding #12: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xd5caf6b1c58ea0a2dac2b2838c2bbc9ee946b2c9` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26494819-26494819 |

### 💬 What Happened
CRITICAL (rule score 155) Think of it as dropping a dollar bill into a vending machine that instantly reshuffles the coins so no one can tell where it came from. No other activity or balance is visible, making it look suspicious.

### 🔥 The Roast
This fresh‑from‑the‑cryptosphere wallet is playing a game of hide‑and‑seek with its money. CRITICAL (rule score 155) Basically, the wallet is like a teenager trying to sneak a pizza delivery into a school cafeteria by slipping it through a secret door. If this were a real pizza, you’d want to trace it back to the kitchen. Good luck, buddy!

### 🎯 Verdict & Next Steps
**CRITICAL: This transaction is high risk due to no‑KYC off‑ramp and sybil fan‑in patterns.**

Manually investigate the sender’s wallet activity and trace the origin of the funds. Verify whether the FixedFloat address has any known illicit links and consider freezing or blocking the transaction if further evidence surfaces.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 155) The AML engine flagged the activity with the following rules: no_kyc_offramp (score 85) indicating a no‑KYC off‑ramp deposit, and sybil_fan_in (score 70) indicating a sybil fan‑in pattern with 1 of 37 similar senders. The sender wallet is brand new (0 days old) with only two transactions and a zero balance, which further raises suspicion. The composite risk score of 155 warrants a high‑priority review.

</details>

---

## Finding #13: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x0d4bcacb08aa245f6fe784c47d12cbff990037af` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494818-26494818 |

### 💬 What Happened
A brand new wallet just dropped a tiny amount of ETH into a service that turns ETH into a more anonymous form. Think of it like a fresh mailbox that immediately forwards your letter to a secret drop box. The transaction was barely noticeable in size—just a few millionths of an ETH.

### 🔥 The Roast
Score 85 on the no_kyc_offramp rule (meaning the user sent ETH to a service that lets you withdraw without any identity verification). Score 70 on the sybil_fan_in rule (meaning 1 out of 37 senders are sending almost the same tiny amounts, a classic fan‑in Sybil pattern). This new wallet is basically a fresh face with zero history, but it’s already playing the same game as 37 other fresh faces, like a freshman trying to be a senior in a club that only accepts old‑timers.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The wallet at address 0x0d4bcacb08aa245f6fe784c47d12cbff990037af is a newly created account with a zero‑day age and only two prior transactions, currently holding no balance. CRITICAL (rule score 155) The AML engine flagged the activity with a composite score of 155, including a score of 85 on the no_kyc_offramp rule and 70 on the sybil_fan_in rule, indicating potential use of a no‑KYC off‑ramp and a Sybil fan‑in pattern. CRITICAL (rule score 155)

</details>

---

## Finding #14: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x23368649a7c349f60d5316d0a13921371d49b50a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26494817-26494817 |

### 💬 What Happened
A brand‑new wallet, just created today, sent a tiny 0.0003 ETH (about $1) to a FixedFloat 1 address. It's like someone dropping a single candy into a vending machine that then hides where it came from, and the wallet now has no balance left.

### 🔥 The Roast
CRITICAL (rule score 155) The engine slapped on an 85‑point hit for [no_kyc_offramp] (meaning the address is a one‑way, no‑KYC exit to a fixed‑float pool). Then it added another 70 for [sybil_fan_in] (like a fan club of 37 identical wallets each dropping a similar small amount, all pointing to the same pool). CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL – the composite score of 155, driven by a high no‑KYC off‑ramp score and a Sybil fan‑in pattern, indicates a high‑risk layering or mixing activity that warrants immediate investigation.**

Flag the transaction for manual review and request additional KYC information from the sender. Investigate the source of the 0.0003 ETH and monitor the FixedFloat 1 address for subsequent deposits or withdrawals.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created address (age 0 days, 2 total transactions) sending 0.0003 ETH to a FixedFloat 1 pool. Rule [no_kyc_offramp] triggered with a score of 85 due to the lack of KYC verification on the off‑ramp, and rule [sybil_fan_in] scored 70 indicating a fan‑in pattern with 37 similar senders. CRITICAL (rule score 155) The transaction’s small size, single‑block occurrence, and absence of wallet balance further raise concern for layering or mixing schemes.

</details>

---

## Finding #15: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x0bd46861cd02bc06de201353b218f6b03ed3f6f7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494809-26494809 |

### 💬 What Happened
A brand-new wallet just sent a tiny fraction of ETH (about the value of a paperclip) to a service that mixes coins, which is like dropping a very small package into a drop box that scrambles who sent it, hiding the origin of the funds.

### 🔥 The Roast
So we have a wallet that’s 0 days old, still has zero balance, and just sent 0.0003 ETH to a no‑KYC off‑ramp (meaning you can deposit and withdraw without proving who you are) – that’s score 85 on the no_kyc_offramp rule. Then we see 37 other senders, each sending a similar tiny amount to the same place – a classic fan‑in Sybil pattern (score 70 on sybil_fan_in). It’s like 37 friends all dropping a dollar into the same tip jar, but the tip jar is a black hole that forgets who gave it.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual compliance review and consider placing a temporary hold on the receiving address until identity verification is completed. Monitor for additional related transfers and report findings to the AML team.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a new wallet (age 0 days) with only two prior transactions and a current balance of 0.000000 ETH. It sent 0.0003 ETH ($0) to FixedFloat 1, a known no‑KYC off‑ramp (rule no_kyc_offramp, score 85). Additionally, the pattern matches a sybil fan‑in (rule sybil_fan_in, score 70) as 1 of 37 senders deposited similar amounts (~0.000 ETH ± 30%). These red‑flags warrant a manual SAR review.

</details>

---

## Finding #16: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x0a3fd7a955c2eb8dc2bfe5b2f8f05593c3a5b4a8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494806-26494806 |

### 💬 What Happened
A brand-new wallet just created today sent a very small amount of ETH to a platform that lets people move money without asking for ID. Think of it like dropping a tiny envelope into a new mailbox that has no recorded owner. The receiver is a known service that accepts deposits but doesn't verify who’s sending the money.

### 🔥 The Roast
Score 155? That’s the crypto equivalent of a bad credit report for a newborn account. CRITICAL (rule score 155) The [sybil_fan_in] rule (meaning lots of fresh wallets are all sending almost identical amounts to the same spot, like a bunch of toddlers dumping the same snack into the same bowl) scored 70. In plain terms, it’s like a group of kids with identical lunchboxes all trying to sneak the same snack into the same lunchbox without the teacher noticing.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction demonstrates a new wallet sending funds to an off‑ramp without KYC, coupled with a Sybil fan‑in pattern, raising a high suspicion of potential layering or mixing activity.**

Flag the transaction for manual AML review, verify the identities of the sender and receiver, and monitor the receiver for additional suspicious inflows or outflows.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The source address is a zero‑day wallet with only two transactions and a zero balance, fitting the profile of a freshly created, potentially anonymous account. Rule [no_kyc_offramp] was triggered with a score of 85 due to the transfer to FixedFloat 1, an off‑ramp service that does not perform KYC on users. Rule [sybil_fan_in] was also triggered with a score of 70, indicating a fan‑in pattern where multiple new wallets send similar amounts to the same receiver, a known layering technique. This combination of a new wallet, lack of identity verification, and fan‑in behavior warrants a closer AML investigation.

</details>

---

## Finding #17: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa038d3ba98c518ac0d6cb0c124c30a1fe84c1558` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494796-26494796 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (0.0003, practically a dust coin) to a FixedFloat 1 address. Imagine someone slipping a single penny into a slot machine that hides who gave it. The sender's account was created the same day and had only two transactions, so it’s like a new kid in school who just handed over a handful of marbles to a mysterious box.

### 🔥 The Roast
This transaction scored a whopping 85 on no_KYC_offramp (meaning the money is going to a place where you can’t trace who’s pulling it out without identity verification). Then it got a 70 on sybil_fan_in (so it’s part of a crowd of 37 similar wallets all dumping almost the same tiny amount – like a fan club that only sends out 0.000 ETH). The wallet is 0 days old, has no balance, and the only thing it knows is how to send dust. Basically, it’s the crypto equivalent of a new kid who brings a bag of coins to a black box that will make the coins disappear faster than you can say ‘anonymity’. If you thought this was a simple transfer, think again – this is a classic “don’t look at the sender” setup.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual compliance review, request additional source‑of‑funds information, and monitor the receiver address for further suspicious activity.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggers rule no_KYC_offramp (score 85) indicating a deposit to an off-ramp that lacks KYC procedures, and rule sybil_fan_in (score 70) indicating a fan‑in pattern involving 37 senders depositing similar amounts (~0.000 ETH ± 30%). The sender wallet is brand new (age 0 days), has only 2 total transactions, and a zero balance, suggesting a potential attempt to obfuscate source and destination. This pattern raises significant concerns for potential layering or integration stages of illicit activity.

</details>

---

## Finding #18: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x2cab973c086b14623ea6c10753c38c14011052f2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494795-26494795 |

### 💬 What Happened
The sender just dropped a tiny amount of ETH (0.0003, basically nothing) into a special contract called FixedFloat 1. The wallet is brand‑new, has only made two moves, and now holds nothing. It’s like someone slipping a small note into a mailbox that hides the sender’s name.

### 🔥 The Roast
Wow, a brand‑new wallet with zero balance and a single transaction of 0.0003 ETH? That’s like a toddler trying to invest in Bitcoin. The AML engine gave it a 155 composite score — high enough to make a banker raise an eyebrow. The [no_kyc_offramp] rule (meaning the user deposited into a contract that doesn’t allow easy KYC‑verified withdrawal) scored 85, and the [sybil_fan_in] rule (meaning lots of similar tiny deposits from a bunch of new accounts) gave another 70. Looks like a classic ‘fan‑in Sybil’ party where everyone is playing the same game. If this was a real party, we’d need a security guard, but for now, we just flag it.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of a brand‑new wallet depositing into a non‑KYC contract and fan‑in Sybil activity indicates high risk for illicit money movement.**

Flag the transaction for manual review by compliance. CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Suspicious activity detected involving wallet 0x2cab973c086b14623ea6c10753c38c14011052f2. The wallet is 0 days old, with only 2 transactions, and a current balance of 0.000000 ETH. It sent 0.0003 ETH to FixedFloat 1 (address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f) on block 26494795. The transaction triggers rule [no_kyc_offramp] (deposit to a contract lacking KYC‑verified off‑ramp) and rule [sybil_fan_in] (fan‑in Sybil pattern with 1 of 37 similar senders). CRITICAL (rule score 155)

</details>

---

## Finding #19: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xace738dabda8f6b91abb6e3838b269856e1c8737` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494795-26494795 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (about 0.0003, roughly zero dollars) to a service that lets you convert it into a fixed float without any identity check. It's like dropping a small package into a slot that hides who sent it. The transaction was processed in a single block, with no other tokens involved.

### 🔥 The Roast
Looks like a fresh wallet tried to play hide‑and‑seek with a fixed float service, scoring a perfect 85 on the no‑KYC off‑ramp rule (meaning it can slip out of the system without anyone asking for ID). Then it joined a Sybil fan club, sending the same tiny amount as 36 other wallets in a fan‑in pattern, grabbing a 70 on the sybil_fan_in rule (so it’s basically a group of copycats). The whole thing feels like a micro‑cash drop at a laundromat where everyone uses the same tiny bucket. Bottom line: this is a textbook case of a wallet that was probably just created for a quick wash, no KYC, no trace, just a tiny amount to stay under the radar.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual AML review, investigate the source of the sender’s funds, and monitor subsequent activity from both the sender and receiver addresses. Consider placing the receiver address on a watchlist pending further investigation.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggers two high‑risk AML rules: no_kyc_offramp (score 85) indicating the sender used a service that allows withdrawal without identity verification, and sybil_fan_in (score 70) indicating the wallet is part of a group of 37 senders depositing similar amounts (~0.000 ETH ±30%). The sender wallet is brand‑new (0 days old), has only 2 transactions, currently has a zero balance, and the last activity was the same block. These factors together constitute a pattern consistent with potential layering and obfuscation. CRITICAL (rule score 155)

</details>

---

## Finding #20: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x39b449ca5b9ac067d9c1813bd9d66776ee141398` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26494791-26494791 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #21: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc467d4f5efce4f81ef22d6639ea68e49d97bbc15` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26494789-26494789 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #22: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x69340fe59264062bc61be1728c24d95a6f988111` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26494786-26494786 |

### 💬 What Happened
CRITICAL (rule score 155) It’s like someone dropping a small parcel into a mystery box that hides who shipped it. No one knows who actually owns the sender wallet, and it’s basically a one‑way trip to a privacy service.

### 🔥 The Roast
Looks like a new kid on the block decided to play hide‑and‑seek with the money. The sender’s wallet is brand new, has only two moves, and now points to a FixedFloat 1 address—classic ‘no‑KYC off‑ramp’ (meaning the money leaves the system without any identity verification). And with 70 points on the Sybil Fan‑In rule (meaning 1 of 37 senders are all dropping similar amounts into the same spot), this is the crypto equivalent of a suspicious group of friends all buying the same overpriced souvenir from a tourist trap. The engine gave it 155 points, which is like a red flag on a radar screen that screams “pay attention.”

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for enhanced due diligence, request additional source‑of‑funds information, and consider freezing the funds pending further investigation.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet with zero days of age, only two prior transactions, and a zero balance, indicating a newly created, potentially unverified source. The transfer of 0.0003 ETH to a FixedFloat 1 address triggered Rule [no_kyc_offramp] (score 85) due to lack of KYC verification at the off‑ramp, and Rule [sybil_fan_in] (score 70) due to a fan‑in pattern of 1 of 37 senders depositing similar amounts. CRITICAL (rule score 155) The composite score of 155 exceeds the critical threshold, warranting further investigation.

</details>

---

## Finding #23: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xfa6d79b59d3a4cf56e91e24f6de97159593d4d58` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494776-26494776 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #24: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x998a6228a1051a2c441c086633eb87202dcfa0af` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494763-26494763 |

### 💬 What Happened
A brand‑new wallet that never existed before just sent a tiny amount of ETH (about the price of a cup of coffee, but actually 0.0003 ETH, which is practically nothing in dollars) to a service called FixedFloat 1. The wallet had made only one other transaction before this and now has zero balance, so it’s like a fresh‑from‑the‑factory package that drops a single, almost invisible packet into a slot that hides who sent it.

### 🔥 The Roast
So this brand‑new address, with 0 days of life, just decides to drop a blip of ETH into FixedFloat 1 – a place that doesn’t even ask you to show your ID before you can cash out (that’s the [no_kyc_offramp] rule, meaning no KYC off‑ramp). And get this: it’s the 70‑point Sybil fan‑in pattern ([sybil_fan_in]) because 36 other wallets are doing the exact same thing with almost the same amount – like a bunch of pranksters sending identical tiny gifts to the same person. The engine thinks this is a red flag because it looks like a coordinated attempt to hide the source of funds. Basically, a new wallet, a tiny deposit, no ID, and a fan‑in of similar moves – the perfect recipe for a “who‑is‑this‑and‑why‑does‑this‑matter” situation.

### 🎯 Verdict & Next Steps
**CRITICAL — the high composite score and Sybil fan‑in pattern with a no‑KYC off‑ramp service indicate a strong potential for anonymity‑enhancing activity.**

Flag the transaction for manual review; verify the source of the ETH, confirm whether the user is a legitimate customer, and consider freezing the account if further suspicious activity is detected.

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involved a wallet with a 0‑day age, only two prior transactions, and a current balance of 0.000000 ETH, indicating it is newly created and likely used for a single purpose. The wallet deposited 0.0003 ETH into FixedFloat 1, a service identified by the rule [no_kyc_offramp] for offering off‑ramp services without KYC verification, scoring 85 on that rule. Additionally, the pattern of 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) triggers the rule [sybil_fan_in], scoring 70, indicative of a Sybil fan‑in pattern. The composite score of 155 exceeds the high‑risk threshold for potential anonymity‑enhancing service usage and coordinated small deposits. This combination of new wallet, no KYC off‑ramp, and fan‑in behavior warrants further review.

</details>

---

## Finding #25: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x8dba9625b6c4f889b82e95a6fd17e58fd82557bf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494744-26494744 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ether (0.0003 ETH, basically a few pennies) to a FixedFloat 1 address. It’s like dropping a single candy into a vending machine that never asks for your ID. The sender had no previous history and is basically a blank check.

### 🔥 The Roast
So you have a wallet that’s brand new (0 days old) and it’s sending a measly 0.0003 ETH to a FixedFloat 1 address. That’s the crypto equivalent of a kid with a $1 bill slipping a handful of pennies into a coin slot that never asks for the kid’s name. The AML engine gave it a whopping 85 points for no‑KYC off‑ramp—meaning this address is literally a free‑for‑all drop‑off spot. Plus, it’s part of a Sybil fan‑in cluster (score 70), so it’s like a bunch of friends all dropping the same tiny coins into the same slot. Bottom line: this is a textbook “no‑KYC, fan‑in” pattern, and it’s not a nice, legitimate transaction.

### 🎯 Verdict & Next Steps
**CRITICAL: The combination of a no‑KYC off‑ramp and sybil fan‑in pattern yields a high risk for illicit activity.**

Flag the transaction for manual review and investigate the source and destination addresses. CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction (block 26494744, 0.0003 ETH) originates from a wallet with 0 days age, 2 total txs, and no current balance, indicating a fresh, potentially suspicious source. Rule [no_kyc_offramp] was triggered with a score of 85 due to deposit to a FixedFloat 1 address, which is a known no‑KYC off‑ramp. Rule [sybil_fan_in] scored 70, reflecting that this sender is among 37 similar accounts depositing comparable amounts (~0.000 ETH ± 30%). CRITICAL (rule score 155) CRITICAL (rule score 155)

</details>

---

## Finding #26: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x3e1e464c8f8c2185a4853905a32d529e46040f38` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494740-26494740 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x836652144c198e8811c3aa2ce37696c46a5f60b1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494733-26494733 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x805427fdbd4dddc1e47b5dbcbf431cdb887d59a6` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494724-26494724 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xdc1dd6c468efa9991d5cc24613919eed1a13a14c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494723-26494723 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xe97e25cc19190a042da26f06bb338ac6c95ea4d0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494721-26494721 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc6786c6afeedf8b304fd3b364755f362c009137f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494720-26494720 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xe76b935633b81c7ecc25a35ab527a83644d97a3f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494711-26494711 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x4536c8241f0a72ae3a1e5be7cc3670ce2ae45c3c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494710-26494710 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xe275571e0236918277bec21c93c8b84670c8857a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494701-26494701 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x5400fdbb02ce8e50f28b36121ce4aaea70ad77d4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494695-26494695 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf7a2ccdceb80a60c60eac013ffdb785b7cda7be9` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494689-26494689 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa1790ce3ac07661610aa67883a3b135083ad511a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494684-26494684 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x30175d3fc3e113333325109358bdace72310e29b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494678-26494678 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x7ee15b36ee43d57719fd8bc611f5241a99268d1c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26494672-26494672 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x245ea48bd9cc0653e3d82d59abe771b49182cc40` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26494668-26494668 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x14d0fbdf923c7cacc6c77e252909876f7d09e0eb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26494651-26494651 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x452c77711693e41d16a7e3cda161db81d96d2a9b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26494642-26494642 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x89c484a615c3688e66464e8d3b2940178b7544d5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26494641-26494641 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x6f5b4843370d8d7648637028e27788d45b5180b8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26494638-26494638 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xd588890408016ee31097a1f9857c361df06c57a9` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26494637-26494637 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x1b8c632303afbadcf3651d54b70b9253561879b2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26494635-26494635 |

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #47: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **11** token transfers totaling **$28,348** (289 USDC, 30 USDT, 15 USDT, 14,880 USDC, 1,633 USDC) |
| **Blocks** | 26494657-26494824 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 110.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

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

**Rules Triggered** (1 rules, composite score: 110):
- **stablecoin_mixing** (+110) — 11 stablecoin transfer(s) to Across SpokePool V2: $28,348 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x7560f0d8df5c0310af3d16e02a2ec44628866f74` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **10** token transfers totaling **$55,444** (3,009 USDT, 2,436 USDT, 10,146 USDT, 4,269 USDT, 3,004 USDT) |
| **Blocks** | 26494627-26494821 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 110.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

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

**Rules Triggered** (1 rules, composite score: 110):
- **stablecoin_mixing** (+110) — 10 stablecoin transfer(s) to Across SpokePool V2: $55,444 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x9e64d18073cd8ec20e2680124d0551ba1629fa20` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **8** token transfers totaling **$38,789** (0 WETH, 5 WETH, 10,000 USDC, 6,778 USDC, 1,003 USDC) |
| **Blocks** | 26494637-26494821 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 110.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

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

**Rules Triggered** (1 rules, composite score: 110):
- **stablecoin_mixing** (+110) — 5 stablecoin transfer(s) to Across SpokePool V2: $38,783 total (USDT, USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xc186fa914353c44b2e33ebe05f21846f1048beda` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$18,711** (2 WETH, 1,917 USDC, 16,792 USDT) |
| **Blocks** | 26494663-26494818 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 110.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

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

**Rules Triggered** (1 rules, composite score: 110):
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to Across SpokePool V2: $18,709 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #51: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **10** token transfers totaling **$100,996** (400 USDC, 10 USDC, 0 WETH, 4 USDT, 0 WETH) |
| **Blocks** | 26494653-26494798 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 110.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

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

**Rules Triggered** (1 rules, composite score: 110):
- **stablecoin_mixing** (+110) — 6 stablecoin transfer(s) to Across SpokePool V2: $100,995 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #52: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x97ccdbea4632140639ad5ea9b944aa034eb15fd4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **26** token transfers totaling **$5,503** (100 USDT, 525 USDC, 14 USDT, 159 USDC, 600 USDC) |
| **Blocks** | 26494637-26494824 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 100.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 100)**

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

**Rules Triggered** (1 rules, composite score: 100):
- **stablecoin_mixing** (+100) — 26 stablecoin transfer(s) to Across SpokePool V2: $5,503 total (USDT, USDC) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #53: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x28a4d41776968c1201a807ec51ffb405362b8882` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **9** token transfers totaling **$3,392** (50 USDT, 1,000 USDC, 1,499 USDC, 1 USDC, 35 USDT) |
| **Blocks** | 26494652-26494791 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 100.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 100)**

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

**Rules Triggered** (1 rules, composite score: 100):
- **stablecoin_mixing** (+100) — 9 stablecoin transfer(s) to Across SpokePool V2: $3,392 total (USDT, USDC) from 1 unique sender(s) — 3 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #54: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xad1dde3364a311630164f72ba52846e66d0a8eeb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1300 ETH** ($219) |
| **Blocks** | 26494804-26494804 |

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

## Finding #55: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4c6032335da7a4ad438201104c70357c4738f10a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26494791-26494791 |

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
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #56: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x143fcd589b3e93f2ea103b70ffbbac8a0a8520d1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1339 ETH** ($226) |
| **Blocks** | 26494780-26494780 |

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

## Finding #57: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xaa71dd61c41d49f205738d5aefcd0355b7120931` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0593 ETH** ($100) |
| **Blocks** | 26494768-26494768 |

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

## Finding #58: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf7961acb50f0181414ace510ba6fc1331bbdab4d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0600 ETH** ($101) |
| **Blocks** | 26494767-26494767 |

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

## Finding #59: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xbfc144766bb77784e247ee152895f2bc62fc1f38` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.3200 ETH** ($539) |
| **Blocks** | 26494760-26494760 |

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

## Finding #60: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x7a2033cd7c0a81a4d47a5fc56675ca02ff670c1a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0200 ETH** ($34) |
| **Blocks** | 26494757-26494757 |

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

## Finding #61: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb1417a06a3838471526ec9bd3b86c3d5e81b1b9c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0090 ETH** ($15) |
| **Blocks** | 26494749-26494749 |

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

## Finding #62: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa022edaf8f19b11ddd42d4ec24d72b72669f3b7a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.5280 ETH** ($890) |
| **Blocks** | 26494747-26494747 |

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

## Finding #63: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3f04396ae08ff644ff57d4abe6a4627e23e05e9a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1044 ETH** ($176) |
| **Blocks** | 26494745-26494745 |

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
| **Sender** | `0x5c070dc9cda57a52f72209cc2142dcf052e66aba` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.3957 ETH** ($667) |
| **Blocks** | 26494737-26494737 |

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
| **Sender** | `0x2a4f99244c02e782e6c7e6993c98f605b639ba6b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0192 ETH** ($32) |
| **Blocks** | 26494732-26494732 |

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
| **Sender** | `0x4e5c95d2da70486ee5dffeb15bd267d4b74bef80` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1223 ETH** ($206) |
| **Blocks** | 26494731-26494731 |

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
| **Sender** | `0x2fd5d1141d135307f4f9161546b826e9fb6e9a53` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1590 ETH** ($268) |
| **Blocks** | 26494711-26494711 |

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
| **Sender** | `0x91072bbf785e0c80e7c9d451dbd01c35db816bac` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.3600 ETH** ($607) |
| **Blocks** | 26494706-26494706 |

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
| **Sender** | `0x99738b1ec22a437c10fbce11ef25019ddc030c47` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0090 ETH** ($15) |
| **Blocks** | 26494700-26494700 |

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
| **Sender** | `0x4e4edd2b9b421b2516ccbe7aaf557a2dbd44d573` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0120 ETH** ($20) |
| **Blocks** | 26494699-26494699 |

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
| **Sender** | `0x67e227aa12753bc8f070dfe5c80820c21be763fd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.5000 ETH** ($842) |
| **Blocks** | 26494697-26494697 |

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
| **Sender** | `0x532abdbfcde599173c2a71958c5fff02768c04e0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.3407 ETH** ($574) |
| **Blocks** | 26494694-26494694 |

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
| **Sender** | `0x6b87a1abb52014f04db8dbb3908b3ea40bd1e64f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.5000 ETH** ($842) |
| **Blocks** | 26494681-26494681 |

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
| **Sender** | `0x8996c640bec38592c8bcb7a768fbc90f563ada67` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0150 ETH** ($25) |
| **Blocks** | 26494673-26494673 |

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
| **Sender** | `0x0d0465ffcec3e55df78e136eb05320a95805b0fd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0450 ETH** ($76) |
| **Blocks** | 26494670-26494670 |

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

## Finding #76: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xe7d981db276c2cb606abddd7872ce6465711c62c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($168) |
| **Blocks** | 26494663-26494663 |

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

## Finding #77: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x2a86a06c8f96b324ab964877f0a15b79f7e5501e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0090 ETH** ($15) |
| **Blocks** | 26494660-26494660 |

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

## Finding #78: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x195e283573c242e39c79f49a38beca9237d0baa0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0060 ETH** ($10) |
| **Blocks** | 26494653-26494653 |

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

## Finding #79: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x80703ad617fc37c6fd149074075ab6e7f914776b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.3000 ETH** ($505) |
| **Blocks** | 26494647-26494647 |

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

## Finding #80: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x073d7edeec9199b3d1a6dfeba8a9810e1c854a62` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0150 ETH** ($25) |
| **Blocks** | 26494644-26494644 |

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

## Finding #81: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3cc0cc56000c206f20d9823871e260b9999242ce` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1260 ETH** ($212) |
| **Blocks** | 26494638-26494638 |

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

## Finding #82: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6308a385f544aa731b11a2654b517449e1ef3533` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$264** (264 USDC) |
| **Blocks** | 26494747-26494747 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $264 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #83: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x036c4c437af66ffe1f9279dbf6b3f3c4f2316459` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$5** (5 USDC) |
| **Blocks** | 26494648-26494648 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $5 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #84: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9a47f3289794e9bbc6a3c571f6d96ad4e7baed16` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **10** token transfers totaling **$1,555** (41 USDT, 819 USDT, 114 USDT, 27 USDT, 301 USDT) |
| **Blocks** | 26494660-26494826 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 9 stablecoin transfer(s) to Across SpokePool V2: $1,555 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #85: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x50cfe7c1938db66a1a6d2e86d36f39fbef3d5c4a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **5** token transfers totaling **$38** (0 WETH, 1 USDC, 8 USDC, 2 USDC, 27 USDC) |
| **Blocks** | 26494648-26494824 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to Across SpokePool V2: $38 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #86: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xac4585272da01474496d008c8100cd9c9345be6a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$432** (432 USDT) |
| **Blocks** | 26494800-26494800 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $432 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #87: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x31ad8756ed2f819c3993bc3032722caab8744b95` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$7,347** (12 USDC, 7,335 USDC) |
| **Blocks** | 26494651-26494800 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $7,347 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #88: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x69460570c93f9de5e2edbc3052bf10125f0ca22d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$851** (0 WBTC, 1 WETH, 849 USDT) |
| **Blocks** | 26494731-26494797 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $849 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #89: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3d2d2538b2dde72ac9f2730afe1799040f08f4f0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$303** (198 USDT, 100 USDC, 4 USDC) |
| **Blocks** | 26494665-26494796 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $303 total (USDT, USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #90: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4510e7beb511b4bb163c79741d8272cd870ea693` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** token transfers totaling **$269** (0 WETH, 0 WETH, 22 USDT, 0 WETH, 247 USDC) |
| **Blocks** | 26494627-26494793 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $269 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #91: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9c2afea6ba390c712f8e5fd4df20217b94c9ca1a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$405** (405 USDC) |
| **Blocks** | 26494722-26494722 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $405 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #92: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbadff1d66ecb71512900ae1fedda3d17edaf6d62` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$2,010** (2,010 USDC) |
| **Blocks** | 26494700-26494700 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $2,010 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #93: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x60ac95ec1153aa8199751917ede25d0ca49a36e2` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$200** (200 USDT) |
| **Blocks** | 26494628-26494628 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $200 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #94: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xbfbd62da98704d6a706d081772afc1c8b90ffc2f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0040 ETH** ($7) |
| **Blocks** | 26494825-26494825 |

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
| Wallet Age | 635 days |
| Total Transactions | 469 |
| Current Balance | 0.000418 ETH |
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
| **Sender** | `0x511e6fd8c87e617575e3778ec068fc6fccd47450` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494667-26494819 |

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
| Wallet Age | 100 days |
| Total Transactions | 2315 |
| Current Balance | 0.008592 ETH |
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
| **Sender** | `0x49c77152e59c06a06ba5180572c3d9d27ce97c36` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0090 ETH** ($15) |
| **Blocks** | 26494796-26494796 |

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
| Wallet Age | 373 days |
| Total Transactions | 39 |
| Current Balance | 0.000369 ETH |
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
| **Sender** | `0x1e91bdde265fd11a9a62d1a2e8940981eb5d7c9d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0024 ETH** ($4) |
| **Blocks** | 26494794-26494794 |

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
| Wallet Age | 397 days |
| Total Transactions | 70 |
| Current Balance | 0.003869 ETH |
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
| **Sender** | `0x09ac97ad6eb46ebb23b2fddaee815d97255eda13` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0130 ETH** ($22) |
| **Blocks** | 26494773-26494790 |

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
| Wallet Age | 1918 days |
| Total Transactions | 385 |
| Current Balance | 0.001834 ETH |
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
| **Sender** | `0x48f59c41706d9235da60e7fb1649a23ead06fba1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.5500 ETH** ($927) |
| **Blocks** | 26494747-26494747 |

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
| Wallet Age | 6 days |
| Total Transactions | 2 |
| Current Balance | 0.004080 ETH |
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
| **Sender** | `0xbf46d73db7d9336d36eb2230415525c929946b31` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0560 ETH** ($94) |
| **Blocks** | 26494742-26494742 |

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
| Wallet Age | 966 days |
| Total Transactions | 352 |
| Current Balance | 0.000089 ETH |
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
| **Sender** | `0xbb50e9bcd8d0658d34b0a72cc42612fe404feffb` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494740-26494740 |

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
| Wallet Age | 2323 days |
| Total Transactions | 1308 |
| Current Balance | 0.044679 ETH |
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
| **Sender** | `0xe58dc537f30b3abff1803b414c181aa4fa5edc41` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494732-26494732 |

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
| Wallet Age | 16 days |
| Total Transactions | 792 |
| Current Balance | 0.021430 ETH |
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
| **Sender** | `0x25321acc489c04ee5b149f5bcb329c4b37d42ea0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494731-26494731 |

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
| Wallet Age | 943 days |
| Total Transactions | 110 |
| Current Balance | 0.020023 ETH |
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
| **Sender** | `0x987af3f6df756bc7c55af6e248d36752ae523ce5` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494720-26494720 |

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
| Wallet Age | 376 days |
| Total Transactions | 236 |
| Current Balance | 0.017532 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #105: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xafceeda1296ccd832417b80216dec3ad6fd0a1ad` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0200 ETH** ($34) |
| **Blocks** | 26494700-26494710 |

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
| Total Transactions | 29 |
| Current Balance | 0.074826 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #106: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x8a9ac36aec6b8c0ac9c36ef40ea093cef71c588f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0330 ETH** ($56) |
| **Blocks** | 26494707-26494707 |

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
| Wallet Age | 1119 days |
| Total Transactions | 64 |
| Current Balance | 0.001755 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #107: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x5f8e50be79880b16bd75ebdab8638170511a0b5f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494705-26494705 |

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
| Wallet Age | 771 days |
| Total Transactions | 2203 |
| Current Balance | 0.103051 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #108: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xeac0fbba47ea4d3fff69019527092568492f2450` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.3400 ETH** ($573) |
| **Blocks** | 26494698-26494698 |

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
| Wallet Age | 759 days |
| Total Transactions | 2580 |
| Current Balance | 0.010329 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #109: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x33c89c2cef423b051e8e6a6212bb462d80698a2a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494684-26494684 |

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
| Wallet Age | 125 days |
| Total Transactions | 23 |
| Current Balance | 0.007409 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #110: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xd5028779582f6904dfa1e3cb4215c281fc9e9d52` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494684-26494684 |

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
| Wallet Age | 138 days |
| Total Transactions | 12 |
| Current Balance | 0.000348 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #111: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xfbf6ae7416445bba82f82e53c3687bbee2050d4a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.2423 ETH** ($408) |
| **Blocks** | 26494664-26494681 |

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
| Wallet Age | 42 days |
| Total Transactions | 8 |
| Current Balance | 0.017230 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #112: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x690c684ccd1317dfd45f863a1050f068a8ae361f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.4100 ETH** ($691) |
| **Blocks** | 26494672-26494672 |

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
| Wallet Age | 2009 days |
| Total Transactions | 1343 |
| Current Balance | 0.003433 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #113: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x02c89e962cea0e57a9e906df684a8f8812207943` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26494640-26494640 |

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
| Wallet Age | 1363 days |
| Total Transactions | 37 |
| Current Balance | 1.429264 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #114: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x1b5d30f263a385f3e9e467186b679b5e50d2dfa3` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0057 ETH** ($10) |
| **Blocks** | 26494629-26494629 |

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
| Total Transactions | 1 |
| Current Balance | 0.000167 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**114 suspicious findings** detected across 114 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 46 |
| 🟠 HIGH | 7 |
| Wallets flagged | 114 |
| Suspicious value | 12.2603 ETH ($20,658) + $264,863 in stablecoins |
| Blocks scanned | 26494627 — 26494826 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 6 of 25 attempted analyses this run.

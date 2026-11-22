# 🔥 AML Roaster Report
**2026-11-22 23:33 UTC** · Ethereum Mainnet · ETH $1,722.30
**Blocks:** 26473720 — 26473919 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26473720 to 26473919 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **16** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473722-26473904 |

### 💬 What Happened
The sender made 16 tiny, identical deposits of 0.0000 ETH to a cross-chain bridge pool, like dropping a bunch of empty envelopes into a mail slot to hide the real sender. This was done in a single block range, so it looks like a deliberate pattern rather than random traffic.

### 🔥 The Roast
So this guy decided to play the "I’m a very small guy" game 16 times. The structuring rule (breaking a big pot into teeny‑tiny pots) caught the identical deposits, the peel_chain_linear rule (a straight line of peel‑off moves) noticed the 16 in a row, and the bridge_hop rule (moving money across chains like a secret tunnel) flagged the destination. Basically he’s doing the blockchain version of a magician’s trick: same card, same trick, same card. If only the card had any value, he’d be a lot richer.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain layering, and cross-chain bridge activity constitutes a high-risk pattern warranting immediate human review.**

Flag the transaction for manual SAR review, investigate the source and destination addresses, and determine if further red flags warrant freezing or reporting.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2809 days |
| Total Transactions | 866212 |
| Current Balance | 13.231170 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 16 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 16 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The account performed 16 identical 0.0000 ETH transfers to 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 (Across SpokePool V2) between blocks 26473722 and 26473904. Rule structuring identified these as textbook structuring/smurfing due to the identical deposit amounts. Rule peel_chain_linear flagged a linear peel chain pattern of 16 sequential deposits, indicating layering. Rule bridge_hop noted a cross‑chain bridge hop to the SpokePool. CRITICAL (rule score 195)

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **15** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473721-26473897 |

### 💬 What Happened
The sender repeatedly moved 15 identical tiny amounts of ETH (each essentially zero) into a bridging contract, like dropping 15 empty envelopes into a mailbox that forwards them to another address. Even though no money changed hands, the pattern of identical, minuscule transactions is suspicious because it looks like an attempt to disguise the flow of funds.

### 🔥 The Roast
Looks like somebody tried to play a game of "Who can send the least amount of money in the most boring way?" with a score of 195. The engine called it structuring (splitting into tiny amounts) 70, peel_chain_linear (a straight‑line layering pattern) 60, and bridge_hop (jumping through a cross‑chain bridge) 65. With 15 identical 0‑ETH transfers, it’s like a magician’s trick where the rabbit is actually a piece of paper—purely decorative, but still gets you a warning. If you think 0 ETH is harmless, think again: it’s the blockchain equivalent of a paper trail that says "I was here, I did something."

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of 15 identical zero‑value deposits into a cross‑chain bridge triggers high suspicion of structuring and layering under AML rules.**

Flag the wallet for manual review; request source of funds documentation and verify the legitimacy of the bridging activity; consider adding the address to a watchlist pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 51 days |
| Total Transactions | 16401 |
| Current Balance | 0.098592 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 15 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 15 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The AML engine flagged this activity under three rules: [structuring] (score 70) due to 15 identical zero‑value deposits, [peel_chain_linear] (score 60) for a linear sequence of similar transactions, and [bridge_hop] (score 65) for the use of Across SpokePool V2, a cross‑chain bridge. The sender’s wallet is 51 days old, with 16,401 total transactions and a current balance of 0.098592 ETH, suggesting high activity volume. The pattern of identical deposits into a bridge raises red flags for potential layering and structuring schemes, warranting closer scrutiny.

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473721-26473892 |

### 💬 What Happened
The account sent four tiny, identical ETH amounts of zero value to a cross‑chain bridge called Across SpokePool V2, basically dropping the same empty envelope into a slot over and over again; it looks like someone is trying to hide the flow of funds by splitting it into many identical pieces.

### 🔥 The Roast
Looks like a magician tried to pull 0 ETH out of a hat—except the hat was full of 0.0000 ETH bills. The wallet did four identical deposits like a bored toddler with a copy‑paste habit. The engine flagged it as structuring (splitting money into tiny pieces), peel_chain_linear (a chain of identical moves that layer the transaction), and bridge_hop (moving funds through a cross‑chain bridge). It's basically the blockchain equivalent of dropping a package into a slot that hides who sent it. If you want to keep your money untraceable, maybe try a different puzzle.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the transaction for manual review and investigate the source and destination addresses, including any prior activity, to determine if further action is warranted.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 342 days |
| Total Transactions | 30936 |
| Current Balance | 0.199745 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction record shows four identical zero‑ETH transfers from 0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a to 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2, a cross‑chain bridge. The AML engine identified a structuring pattern (score 70), a peel chain layering pattern (score 60), and a bridge hop (score 65), yielding a composite score of 195. The sender wallet has 34.2‑day age, 30,936 total transactions, and a current balance of 0.199745 ETH, with no recent inactivity, indicating active use. These indicators collectively raise suspicion of attempts to obscure the source or destination of funds through layering and cross‑chain movement.

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473720-26473872 |

### 💬 What Happened
A user sent five identical, tiny amounts of ETH (each 0.0000 ETH) to a cross‑chain bridge called Across SpokePool V2. Think of it like dropping five identical coins into a slot that hides who put them in, then hoping no one notices the pattern. The total value was zero, so nothing actually moved, but the pattern itself is suspicious.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with the blockchain: 5 identical 0‑ETH deposits (structuring, 70 points – because smurfing is just a fancy word for splitting the same thing into many tiny packets). Then the same person decided to layer it all up with a peel chain (60 points – the chain is as straight as a ruler, no twists). Finally, they hopped to Across SpokePool V2 (bridge_hop, 65 points – a fancy way of saying they tried to cross the border via a bridge). In other words, it’s like trying to smuggle a paper through a security scanner by sending it in five identical envelopes, all with no ink. Not the most stealthy plan, but it’s definitely a red flag.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag this transaction for manual compliance review. CRITICAL (rule score 195)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1098 days |
| Total Transactions | 217883 |
| Current Balance | 0.499874 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The AML engine flagged this activity under three high‑risk rules: structuring (score 70) due to five identical 0.0000 ETH deposits; peel_chain_linear (score 60) indicating a linear layering pattern; and bridge_hop (score 65) reflecting cross‑chain bridge usage to Across SpokePool V2. The sender wallet is 1098 days old, with 217,883 total transactions, a current balance of 0.499874 ETH, and no inactivity period, further supporting the suspicion of layering. CRITICAL (rule score 195) CRITICAL (rule score 195)

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473772-26473854 |

### 💬 What Happened
A user sent three tiny, identical ETH transfers (each 0.0000 ETH) into a bridge service that moves tokens between blockchains. Even though nothing changed in value, the pattern looks like someone is trying to split a transaction into many tiny parts to hide the origin—like dropping the same empty envelope into a slot over and over to fool the mailman.

### 🔥 The Roast
Looks like a crypto con artist decided to play the ‘I’m so invisible I can’t even send 0 ETH’ game. They’re structuring (smurfing) by sending three identical zero‑value deposits, peel_chain_linear (peeling the onion) by doing them one after another, and bridge_hop (crossing the bridge) to hide the trail. It’s like trying to smuggle a banana through customs by putting it in three empty boxes, but the boxes are all the same and the banana is still there. The engine gave it a 195 score—so the AML team should probably call in the crack team.

### 🎯 Verdict & Next Steps
**Critical – the identical zero‑value deposits into a cross‑chain bridge suggest potential structuring and layering, requiring immediate review.**

Initiate a manual review of the sender’s source of funds and monitor subsequent activity for further suspicious patterns. Consider adding the wallet to watchlist pending investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 101 days |
| Total Transactions | 36897 |
| Current Balance | 0.108898 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Suspicious activity detected involving wallet 0xfd0aa7548823c40be6dd85682f0342f35dee121a. The transaction pattern matches Rule structuring (identical zero‑value deposits), Rule peel_chain_linear (sequential similar deposits indicating layering), and Rule bridge_hop (deposit to Across SpokePool V2, a cross‑chain bridge). Evidence includes three consecutive ETH transfers of 0.0000 ETH between blocks 26473772 and 26473854. The wallet age is 101 days with high activity (36,897 txs) and current balance of 0.108898 ETH. Flag for further investigation per AML policy.

</details>

---

## Finding #6: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x321d2099904a50a3506d2eda6797ef05919f545e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.4139 ETH** ($4,157) |
| **Blocks** | 26473744-26473744 |

### 💬 What Happened
A brand‑new wallet (0 days old) just sent about $4,157 worth of ETH to a service called FixedFloat 1. It moved all the money it had and left the sender with nothing, like a thief who empties a purse and then disappears. The transaction was a single, one‑off move, no other activity, which is a classic burner wallet pattern.

### 🔥 The Roast
So this 0‑day wallet decided to throw a party with 2.4139 ETH and then bail on the host. It scored a 64 on novel_wallet_dump (meaning the wallet is as fresh as a new phone) and 85 on no_kyc_offramp (the off‑ramp is like a cash machine with no ID check). With a 40 on exit_rush, it drained itself faster than a bartender at a happy hour. This is the kind of move that makes regulators do a double‑take. If only the wallet had a KYC selfie, this would be less suspicious.

### 🎯 Verdict & Next Steps
**CRITICAL — the wallet’s zero age, immediate full withdrawal to a no‑KYC off‑ramp, and complete balance depletion constitute a high‑risk activity requiring urgent review.**

CRITICAL (rule score 189) CRITICAL (rule score 189)

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.4139 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.4139 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a 0‑day wallet (wallet age 0 days) sending 2.4139 ETH (~$4,157) to FixedFloat 1, an off‑ramp service lacking KYC verification. Rule [novel_wallet_dump] triggered due to the wallet’s age and high single‑transaction value, scoring 64. Rule [no_kyc_offramp] triggered because the funds were moved to a service without KYC, scoring 85. Rule [exit_rush] triggered because the wallet’s balance dropped to 0.000000 ETH immediately after the transfer, scoring 40. CRITICAL (rule score 189)

</details>

---

## Finding #7: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xcdb922a7ab9da837486d622e689b8990a256c125` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473916-26473916 |

### 💬 What Happened
A brand‑new wallet (0 days old) sent a tiny 0.0002 ETH (about zero dollars) to a special contract called FixedFloat 1. Think of it like a kid dropping a single candy into a locker that nobody can trace back to them. The wallet had only two transactions and now has no balance left.

### 🔥 The Roast
So this fresh‑from‑the‑oven wallet tried to play the “no‑ID” game by dumping a whisper of ETH into FixedFloat 1. CRITICAL (rule score 155) CRITICAL (rule score 155) And the engine thinks it’s a big deal.

### 🎯 Verdict & Next Steps
**CRITICAL – the high composite score, combined with the no‑KYC off‑ramp and fan‑in Sybil pattern, indicates a significant risk of illicit activity.**

Flag the wallet for enhanced due diligence, monitor for additional activity, and consider restricting further transactions if the pattern persists.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet with age 0 days and only 2 total transactions, sending 0.0002 ETH to the FixedFloat 1 contract. The AML engine flagged this activity under rule [no_kyc_offramp] (deposit to a no‑KYC off‑ramp) with a score of 85 and rule [sybil_fan_in] (fan‑in Sybil pattern of similar small deposits) with a score of 70, resulting in a composite score of 155. The wallet’s current balance is 0.000000 ETH, and no token transfers were involved. CRITICAL (rule score 155)

</details>

---

## Finding #8: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x9ee91a6a638ef83ebffd8ba4a48c7778e19f6a19` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473912-26473912 |

### 💬 What Happened
CRITICAL (rule score 155) The sender’s address was created today and has only had two transactions, so it’s basically a brand‑new, low‑balance address. This looks like someone trying to move money through a privacy service without going through a KYC (Know‑Your‑Customer) check.

### 🔥 The Roast
Score 155? That’s like a kid getting a perfect score on a test that was supposed to be a trick question. The wallet’s age is 0 days, so it’s as fresh as a morning coffee, and it just deposited into a FixedFloat service—no KYC off‑ramp (meaning this service lets you withdraw without verifying your identity). And to top it off, 34 other wallets are doing the same thing, so you’ve got a fan‑in Sybil pattern (many accounts pretending to be separate to hide a single source). Looks like the only thing this user is doing is trying to play hide‑and‑seek with their money.

### 🎯 Verdict & Next Steps
**CRITICAL — high composite score and evidence of unverified off‑ramp and Sybil fan‑in pattern.**

Flag the transaction for manual review, request KYC information from the sender, and monitor subsequent activity for further layering or suspicious patterns.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created address (age 0 days) sending 0.0002 ETH to a FixedFloat 1 service, which is classified as an unverified off‑ramp. AML Engine scoring indicates a composite score of 155, driven by [no_kyc_offramp] (score 85) and [sybil_fan_in] (score 70) due to 34 similar senders depositing comparable amounts. The sender’s wallet has only two transactions and a zero balance, fitting the profile of a potential layering activity. These indicators warrant a higher level of scrutiny under AML policy.

</details>

---

## Finding #9: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x94552ae5651d1c81e7c53acfac66949de8643a97` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473907-26473907 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ETH to a service that lets people move crypto without ID. It’s like dropping a small parcel into a mystery box that hides who you are. The wallet had no previous history and the amount is tiny, but the pattern looks suspicious.

### 🔥 The Roast
Looks like we found a fresh‑mint wallet that thinks it’s a ninja. It slipped 0.0002 ETH into a no‑KYC off‑ramp (meaning the service doesn’t ask for your ID, like a shady alley bar). And then, bam, 33 other similar wallets joined the party, all sending the same little coin (that’s the Sybil fan‑in rule, basically a bunch of fake accounts pretending to be real). This is like a group of pranksters all sending the same micro‑tip to hide their identity. If they’re not paying for a pizza, they’re probably paying for a cloak of anonymity.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits both a no‑KYC off‑ramp deposit and a Sybil fan‑in pattern with a composite score of 155, indicating high suspicion.**

Flag the sender wallet for manual review, request source‑of‑funds and ownership verification, and monitor future activity for additional suspicious patterns.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction (block 26473907) involves a new sender wallet (0 days old) that transferred 0.0002 ETH to FixedFloat 1, a known no‑KYC off‑ramp. The AML engine flagged the activity under rule no-KYC-offramp (score 85) due to lack of identity verification, and rule sybil-fan-in (score 70) because the sender is one of 34 accounts depositing similar amounts (~0.000 ETH ±30%). Composite score 155 indicates high risk. This pattern warrants further investigation for potential layering or anonymity services.

</details>

---

## Finding #10: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x20024ff09b46eab05d8eb05c78a462e55afadfc7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473893-26473893 |

### 💬 What Happened
A brand-new wallet with only two transactions sent a tiny 0.0002 ETH to a FixedFloat 1 address. Think of it as a new customer dropping a single penny into a cashier’s slot that hides who put it there. The small amount and the fresh wallet raise red flags.

### 🔥 The Roast
So, a brand‑new wallet just decided to play a game of hide‑and‑seek with 0.0002 ETH, dropping it into a FixedFloat 1 address that doesn’t even ask for your ID (that’s the [no_kyc_offramp] score of 85). And as if that wasn’t enough, it’s one of 34 similar wallets doing the same – a classic Sybil fan‑in (score 70) where a bunch of clones send identical tiny amounts to the same spot. It’s like a school of fish all swimming into the same drain, hoping to drown the net. Bottom line: this is the blockchain equivalent of a toddler hiding a handful of coins in a secret box and then blaming the neighbor’s cat for the mess.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, investigate the source of the funds and the purpose of the transfer, and consider adding the sender to a watchlist pending further investigation.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggered the [no_kyc_offramp] rule (score 85) because the recipient is a FixedFloat 1 address that does not require KYC, creating a potential off‑ramp for unverified funds. It also triggered [sybil_fan_in] (score 70) due to the sender being one of 34 wallets sending similar amounts (~0.000 ETH ± 30%), indicating a Sybil fan‑in pattern. The sender wallet is brand‑new (0 days old) with only 2 prior transactions and zero balance, heightening suspicion for layering or mixing activity. Total value is 0.0002 ETH (~$0), further emphasizing the low‑value, high‑frequency nature of the transfer.

</details>

---

## Finding #11: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa72425ce2004d0f1310b13ea38e7954dc8594603` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473889-26473889 |

### 💬 What Happened
CRITICAL (rule score 155) The sender’s account is only a few minutes old and already has no KYC (know‑your‑customer) info, so it’s like dropping a very small package into a box that hides who delivered it.

### 🔥 The Roast
Looks like someone just opened a brand‑new wallet and decided to test the “no‑KYC off‑ramp” feature—score 85 on the no_kyc_offramp rule (meaning this address is a pure anonymous exit point). Then they hit the sybil_fan_in rule with a score of 70 (so 1 out of 34 tiny senders are all dumping about the same amount, like a group of friends each dropping a single candy into the same bucket). Basically, this is the crypto equivalent of a group of kids all sending the same tiny amount of money to a mystery bank account, hoping the bank won’t notice.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of a brand‑new wallet, no‑KYC off‑ramp, and fan‑in Sybil pattern indicates high suspicion of layering or structuring.**

Flag the transaction for manual review and request source‑of‑funds and beneficiary information; monitor the wallet for additional activity and consider applying stricter due‑diligence checks.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a new wallet (0‑day age) with only 2 total transactions and a zero balance, indicating possible layering. The sender routed 0.0002 ETH to a FixedFloat 1 address, triggering the no_kyc_offramp rule (score: 85) due to the lack of identity verification at the off‑ramp. Additionally, the transaction matches the sybil_fan_in rule (score: 70) as one of 34 similar deposits (~0.000 ETH ± 30%) suggesting a fan‑in Sybil pattern. CRITICAL (rule score 155)

</details>

---

## Finding #12: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x010a937e326b26fb4e19c08860379e3f53c8f7a6` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473885-26473885 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #13: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb2518036167ffb7d292b1e8d21ccb435b93a5d91` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473885-26473885 |

### 💬 What Happened
A brand‑new wallet (it’s only been created today) sent a tiny 0.0002 ETH to a FixedFloat 1 address. Think of it like someone dropping a very small package into a mailbox that doesn’t reveal who dropped it. The sender had no prior activity and now has a zero balance after sending the funds.

### 🔥 The Roast
This wallet is fresher than a pizza that just came out of the oven—zero days old, zero KYC, and it’s already making moves. It sent just a sliver of ETH, but the engine thinks it’s part of a Sybil fan‑in, like a bunch of copycats all dropping the same tiny amount into the same spot. It’s basically a new kid on the block trying to play the anonymous game, and the system is yelling, ‘Hey, you’re a no‑KYC off‑ramp, buddy!’

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction triggers high‑risk flags for no‑KYC off‑ramp and Sybil fan‑in patterns, warranting immediate review.**

Flag the transaction for manual review, verify the source of funds, and consider adding the wallet to a watch list for further monitoring.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction was flagged under rule [no_kyc_offramp] (score: 85) due to the deposit of 0.0002 ETH to FixedFloat 1, an off‑ramp with no identity verification. Rule [sybil_fan_in] (score: 70) was triggered by the similarity of the amount to 33 other senders within a 30% variance, indicating a potential Sybil fan‑in pattern. The sender wallet is 0 days old, has only 2 total transactions, and currently holds a zero balance, further increasing suspicion. CRITICAL (rule score 155)

</details>

---

## Finding #14: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xe3a3880044d2bd7605bffca042e69e411cbf16b0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473883-26473883 |

### 💬 What Happened
CRITICAL (rule score 155) The sender has no previous activity and already made two transactions, so it looks like a quick drop into a privacy tool. There's no way to get the money back without going through KYC, so the system flags it.

### 🔥 The Roast
CRITICAL (rule score 155) The engine gave a whopping 85 on no_kyc_offramp (meaning you can't cash out without a photo ID) and 70 on sybil_fan_in (so you’re one of 34 guys sending the same tiny amounts to the same spot). Basically, the wallet is fresher than a new pizza and the transaction is as suspicious as a magician’s disappearing act. If you’re trying to play hide‑and‑seek with the regulators, you’re doing it right!

### 🎯 Verdict & Next Steps
**CRITICAL — The composite score of 155, driven by high no‑KYC off‑ramp and Sybil fan‑in flags, indicates a high likelihood of suspicious activity requiring immediate review.**

Flag the transaction for manual review by the compliance team, request additional source‑of‑funds information, and consider monitoring the wallet for subsequent activity.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction was executed from a newly created wallet (age 0 days) that has performed two transactions with a total value of 0.0002 ETH. The AML engine scored 155, with a score of 85 for no_kyc_offramp and 70 for sybil_fan_in. CRITICAL (rule score 155) The sybil_fan_in rule indicates a fan‑in Sybil pattern, where multiple senders deposit similar amounts into the same address, further raising suspicion. This pattern warrants a higher risk assessment and should be investigated further.

</details>

---

## Finding #15: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xd8545dbac71c8316ffa3675a5ea7f3d3ccccd7fc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473881-26473881 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #16: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x0670eb9fc308de0b065e45553557e1db1be5bade` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473880-26473880 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of Ethereum (0.0002 ETH) to a service that scrambles coins so no one can tell where the money came from. The sender’s account is brand‑new, has only two tiny moves, and has no money left, so it’s like a fresh drop in a black hole that disappears right away.

### 🔥 The Roast
CRITICAL (rule score 155) CRITICAL (rule score 155) CRITICAL (rule score 155) With a composite score of 155, this is a red flag that even the most cautious accountant would want to see the receipts. The only way to get any sense of this transaction is to ask the sender for a full explanation, or risk getting tangled in the same black hole.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual investigation, request additional source‑of‑funds information from the sender, and consider a temporary hold or enhanced due diligence pending further review.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 155) CRITICAL (rule score 155) The composite score of 155 exceeds the critical threshold, warranting immediate compliance review. Investigate source funds, cross‑match with other suspicious accounts, and consider a temporary hold pending further KYC verification.

</details>

---

## Finding #17: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x5715e2809662d0c95f6bf939bd55a7160d2fe148` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473875-26473875 |

### 💬 What Happened
A brand-new wallet just made a tiny 0.0002 ETH transfer to another address. Think of it like someone who just got a new phone and immediately sends a very small tip to a friend—only the tip is in crypto, and the friend’s wallet is a place that doesn’t ask for any identity paperwork. No other coins or tokens were moved, just that one little ETH bump.

### 🔥 The Roast
This fresh wallet is so new it probably hasn't even had its first coffee yet, yet it’s already offloading 0.0002 ETH to a place that doesn’t care about your ID—no-KYC off-ramp (meaning the destination doesn’t require identity verification). The system flagged it with a 70 on sybil fan-in, which is basically a group of 34 people all sending about the same tiny amount to the same place, like a synchronized choir of micro‑tips. It’s like a bunch of kids all dropping a single penny into the same jar—sure, it’s a jar, but who’s actually putting the pennies in? CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL - The transaction shows high risk due to no‑KYC off‑ramp and sybil fan‑in patterns, requiring immediate human review.**

CRITICAL (rule score 155) If further suspicious patterns emerge, consider freezing the involved wallet and reporting to relevant authorities.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet with 0 days of age, only 2 total transactions, and a current balance of 0 ETH, indicating recent creation and rapid activity. Rule [no_kyc_offramp] scored 85 due to the transfer to FixedFloat 1, an off‑ramp that does not require KYC, raising concerns about anonymity. CRITICAL (rule score 155) The composite score of 155 exceeds the critical threshold, warranting human review for possible illicit activity or source‑of‑funds verification.

</details>

---

## Finding #18: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x3383a25e3e0c20c552f08e6f15e937064623867b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473874-26473874 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #19: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb9b77a302026469f67a0708926a431971a015844` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473873-26473873 |

### 💬 What Happened
CRITICAL (rule score 155) The transaction only happened once and the sender had no previous activity, so it’s like dropping a single grain of rice into a black hole that hides who dropped it.

### 🔥 The Roast
Congrats, you just built a fresh wallet that thinks it’s a magician. That 0.0002 ETH is like dropping a single grain of rice into a black hole, and the engine gave it a 155 score because it knows a brand‑new wallet with no KYC is a red flag. The sybil fan‑in? Looks like a choir of 34 singers all humming the same tiny tune. Good luck finding the lead singer in that crowd.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, verify the sender’s intent, and check for any additional related activity or addresses that may be part of the same funnel.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a 0‑day wallet with no KYC off‑ramp, triggering rule no_kyc_offramp (score 85). The wallet exhibits fan‑in Sybil behavior with 34 similar senders (rule sybil_fan_in, score 70). CRITICAL (rule score 155) No SDN match, but pattern risk warrants further review.

</details>

---

## Finding #20: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x4bd449f995a2179280c14a80d654c5fa7d3e453b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473862-26473862 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #21: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x3346e50c4048d6ce6e6d67f6a5f9ab92e151b569` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473860-26473860 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (about 0.0002, which is basically nothing in dollar terms) to a service called FixedFloat 1. It’s like dropping a single, almost invisible package into a slot that hides who dropped it—no one sees where it came from.

### 🔥 The Roast
So we’ve got a fresh wallet with zero balance, just two tiny moves, and it’s already trying to off‑ramp to FixedFloat 1. That’s like a kid sneaking a pizza into a no‑pizza zone—no KYC, no explanation. The AML engine gave it a 155 score because it’s a ‘no‑KYC off‑ramp’ (meaning the service lets you move money out without checking who you are) and a ‘Sybil fan‑in’ (many similar wallets sending the same tiny amounts). If this was a real person, they’d be the type who uses a burner phone to buy coffee that costs more than the transaction itself.

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction exhibits high‑risk patterns of no‑KYC off‑ramp and Sybil fan‑in, warranting immediate manual review.**

Flag the transaction for manual review, request additional KYC information for the sender, and monitor the FixedFloat 1 address for subsequent activity.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggers the rule [no_kyc_offramp] with a score of 85, indicating a deposit to FixedFloat 1 where the sender has not completed KYC verification, and the rule [sybil_fan_in] with a score of 70, reflecting a pattern of multiple new wallets sending similar amounts (~0.000 ETH ± 30%). CRITICAL (rule score 155) This activity should be reviewed for potential layering or structuring schemes.

</details>

---

## Finding #22: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x8235c7f702c94bc47e7d90e496202146216edfaf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473860-26473860 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (0.0002, about $0) to a service that can turn it into cash without any identity check. It's like dropping a single cookie into a vending machine that later gives you money, but no one knows who left the cookie. The transaction is so small and new that it raises a red flag for suspicious activity.

### 🔥 The Roast
So here we have a fresh wallet that just decided to play hide-and-seek with a 0.0002 ETH snack. That’s like a kid dropping a single candy into a slot machine that promises a jackpot—only the slot machine is a KYC-free off‑ramp called FixedFloat 1. The AML engine gave it an 85 for no‑KYC off‑ramp (meaning nobody knows who the kid is) and 70 for a Sybil fan‑in pattern (like a bunch of kids all sending the same tiny candy to the same machine). The composite score of 155 is basically the alarm system saying, "Hey, this is suspicious, let’s look closer!"

### 🎯 Verdict & Next Steps
**Composite score of 155 indicates a high‑risk pattern due to no‑KYC off‑ramp and Sybil fan‑in activity.**

Flag the transaction for manual review and request source‑of‑funds details. Monitor subsequent activity for any large or frequent deposits.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction was conducted from a wallet that is 0 days old, with only 2 prior transactions and a current balance of 0.000000 ETH. The sender deposited 0.0002 ETH into FixedFloat 1, a service that offers a KYC‑free off‑ramp to fiat. The AML engine flagged the activity with rule [no_kyc_offramp] (score: 85) for the lack of identity verification and rule [sybil_fan_in] (score: 70) indicating a Sybil fan‑in pattern (multiple new wallets depositing similar amounts). The composite score of 155 signals a high‑risk transaction pattern requiring further investigation.

</details>

---

## Finding #23: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb7799b02892adbf4d5fa3bee3b84b0200d1f3c45` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473847-26473847 |

### 💬 What Happened
CRITICAL (rule score 155) It’s like dropping a single coin into a black hole that scrambles who sent it.

### 🔥 The Roast
Look at that new wallet, born yesterday, already trying to hide its tracks. 0.0002 ETH? That’s like sending a single grain of rice to a black hole that pretends to be a bank. The engine gave it a 155 score—more like a spam filter than a detective. [no_kyc_offramp] means the wallet is trying to cash out without any identity verification, and [sybil_fan_in] shows it’s one of dozens of wallets doing the same thing. Basically, it’s a rookie playing hide‑and‑seek with regulators.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits high‑risk behavior due to new wallet activity, no‑KYC off‑ramp, and Sybil fan‑in pattern, warranting immediate review.**

Flag the transaction for manual review by compliance, and consider placing a temporary hold while investigating the source and destination addresses.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 155) The sender wallet is brand‑new (age 0 days), with only 2 prior transactions and no balance. The AML engine flagged the transfer under rule [no_kyc_offramp] (deposit to a no‑KYC off‑ramp) and [sybil_fan_in] (fan‑in Sybil pattern). The composite score of 155 indicates a high likelihood of suspicious activity requiring further investigation.

</details>

---

## Finding #24: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x3d7a954adbfc41f0db2e1b30e8ae66c7dec36271` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473843-26473843 |

### 💬 What Happened
A brand‑new wallet sent 0.0002 ETH (about a few cents) to a fixed‑rate exchange that doesn’t require identity verification. Think of it like a freshly opened envelope that drops a tiny package into a box with no way to trace who opened it.

### 🔥 The Roast
This guy just created a wallet on the spot and sent a minuscule amount to a no‑KYC off‑ramp. He’s basically doing the "send‑it‑away‑so‑no‑one‑knows‑who‑you’re‑with" trick. The engine flagged him with a 155 score, which is like a red‑light signal on a highway full of speed‑bumpers. He’s got a fan‑in Sybil pattern (70 points) – basically a bunch of identical tiny coins coming from 34 different addresses. In plain English: he’s playing the "copy‑and‑paste" game, hoping the system won’t notice the echo.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review. Investigate the wallet’s origin and any subsequent movements to determine whether the funds are tied to suspicious activity.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet created on the same day it was used (wallet age 0 days) with a total transaction count of 2 and a current balance of 0.000000 ETH, indicating immediate depletion. Rule [no_kyc_offramp] was triggered with a score of 85 because the funds were moved to FixedFloat 1, an off‑ramp that does not require Know‑Your‑Customer (KYC) verification. Rule [sybil_fan_in] scored 70, identifying this as a fan‑in Sybil pattern: 1 of 34 senders deposited similar amounts (~0.000 ETH ± 30%), suggesting a coordinated effort to obscure the source. The composite score of 155 places the activity in the critical risk tier for potential layering and obfuscation.

</details>

---

## Finding #25: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x736017753841d98b20f2b763bd6b53911247bb17` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473827-26473827 |

### 💬 What Happened
A brand‑new wallet just sent a tiny 0.0002 ETH to a special “FixedFloat 1” address. Think of it like a brand‑new delivery truck dropping a minuscule package into a mysterious drop box that hides the sender’s identity. The wallet has only made two moves, has no balance left, and was created today, so it’s as fresh as a morning coffee.

### 🔥 The Roast
So this new wallet is basically a crypto version of a mystery shopper who drops a 0.0002 ETH tip into a fancy escrow account that doesn’t ask who you are (that’s the no_kyc_offramp rule). Meanwhile, 33 other wallets are doing the exact same thing, sending almost the same tiny amount to the same address – a classic fan‑in Sybil pattern (sybil_fan_in). It’s like a bunch of people all throwing pennies into the same empty cup, hoping someone will notice the pattern but nobody can tell who tossed the first coin. If you think a single coin is harmless, imagine a thousand of them all piling up. And the best part? The wallet was created today and already sent its first payment – it’s a fresh‑out‑of‑the‑oven fraud recipe. 0 days, 2 tx, and zero balance – it’s a textbook “I’m new here, but I’m already playing the game” move.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review by compliance, request source‑of‑funds documentation, and consider monitoring subsequent activity for additional red flags.

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet created on the same day (wallet age 0) with only two prior transactions and a zero current balance, indicating a newly established account with no historical activity. The wallet sent 0.0002 ETH to a FixedFloat 1 address, which is an off‑ramp service that does not require Know‑Your‑Customer (KYC) verification (no_kyc_offramp rule, score 85). Additionally, the transfer is part of a fan‑in pattern where 34 senders deposit similar amounts (within ±30% of 0.000 ETH) to the same address, triggering the sybil_fan_in rule (score 70). These patterns suggest potential layering or structuring activities, warranting further investigation.

</details>

---

## Finding #26: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xe98db401318a5afaa1c4742176161c7bd6d25c1f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473820-26473820 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xbfae421306540613194592ae4755a02e73ed56dc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473819-26473819 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x40e449f73fc95e0fcaa23ddc65921bfc401f8b66` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473807-26473807 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x48771894f5eea6a71ba88e8d8232d9a8a1b8e900` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473778-26473778 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x6f5ed19be87bdc9204b3a0f007bc85564deffc7e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473777-26473777 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x2e83eaf916233c192fc609eba69cbc72cd91a5fa` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473766-26473766 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc36427e51d2accfc1ecf5ba36d066cc24062b0d8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473765-26473765 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x99000a4f284b0dbddc6f6f5686be5b6ae1106c9f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473762-26473762 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x50a074f98983166905fa377cd386c76ccfa6b760` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473756-26473756 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xeb36b46953c0be9fdcf7fba4cc8ed1ff1aab29d7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473756-26473756 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x58c87c321e7e6edcbdc0e1803acd9726eab97899` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473755-26473755 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xaf7813e1205f94b15ef1fc50f8a2501b8c181ea2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473739-26473739 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x6513c96c1e12f70c878606ae0c3c6b6781b6fadb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473737-26473737 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x16a867a6c548854a2739cb530ecd07a99ed2333c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473723-26473723 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x02c438118664a1c996137b728842fed885d792c6` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26473720-26473720 |

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
- **sybil_fan_in** (+70) — 1 of 34 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **7** token transfers totaling **$25,592** (1 USDC, 2 USDC, 113 USDC, 500 USDC, 24,969 USDC) |
| **Blocks** | 26473724-26473915 |

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
- **stablecoin_mixing** (+110) — 6 stablecoin transfer(s) to Across SpokePool V2: $25,592 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x9e64d18073cd8ec20e2680124d0551ba1629fa20` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **11** token transfers totaling **$27,041** (0 WETH, 19 WETH, 20 WETH, 2,499 USDT, 1,501 USDT) |
| **Blocks** | 26473721-26473905 |

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
- **stablecoin_mixing** (+110) — 7 stablecoin transfer(s) to Across SpokePool V2: $27,001 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xc186fa914353c44b2e33ebe05f21846f1048beda` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$90,828** (0 WETH, 90,828 USDC) |
| **Blocks** | 26473832-26473832 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to Across SpokePool V2: $90,828 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0xd3b11c36404b092645522b682832fcdee07d2668` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$200** (100 USDC, 100 USDC) |
| **Blocks** | 26473853-26473853 |

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
- **stablecoin_mixing** (+100) — 2 stablecoin transfer(s) to Across SpokePool V2: $200 total (USDC) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x102b5d72900f2358b8419802638a40e5e6154965` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1424 ETH** ($245) |
| **Blocks** | 26473916-26473916 |

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

## Finding #46: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x16911687459ce40b30407f542ed4bb3f713dcd42` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0110 ETH** ($19) |
| **Blocks** | 26473898-26473898 |

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

## Finding #47: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4ad577a106127831fba79821b420c783d8069e2a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.3024 ETH** ($521) |
| **Blocks** | 26473884-26473884 |

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

## Finding #48: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4d8f593c7c39659100a0e4b575bdaf6a8ed2e78e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0400 ETH** ($69) |
| **Blocks** | 26473856-26473856 |

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

## Finding #49: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xe754d9c20ce85e00c4b47d1946b97730d68875d5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2000 ETH** ($344) |
| **Blocks** | 26473846-26473846 |

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

## Finding #50: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xe4f58e1fd84a63db8acc0fafbb01ac6bb987d915` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.3706 ETH** ($638) |
| **Blocks** | 26473819-26473819 |

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

## Finding #51: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x15b61c163206b3bd1e90ecfe8b9c9699fd492da4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1769 ETH** ($305) |
| **Blocks** | 26473817-26473817 |

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

## Finding #52: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1548c381e593fe1359491bd0731215d8ff10d830` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1769 ETH** ($305) |
| **Blocks** | 26473814-26473814 |

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

## Finding #53: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x0bf62f64c1916ec6b572295ae4b16bf4cb44cd49` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0426 ETH** ($73) |
| **Blocks** | 26473789-26473789 |

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

## Finding #54: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8dc4cd1806dd8904ce60535533bdaf21a2bf5ad0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2128 ETH** ($366) |
| **Blocks** | 26473783-26473783 |

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
| **Sender** | `0x9e812bdd65600f631fede1922ce3e774349b6620` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0615 ETH** ($106) |
| **Blocks** | 26473766-26473766 |

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

## Finding #56: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xfe377cfce9bb5dfd3ebc063514bdcd1f297f803a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0853 ETH** ($147) |
| **Blocks** | 26473762-26473762 |

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
| **Sender** | `0x922179ff6027a42c386d9304bb1d99b495e29d24` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.4123 ETH** ($710) |
| **Blocks** | 26473760-26473760 |

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
| **Sender** | `0x65d00c16232c9c5a8b7b940e694252fa73a293bd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1841 ETH** ($317) |
| **Blocks** | 26473733-26473733 |

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

## Finding #59: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0038dfb2bbc353daa6ad22cb11ee1d78f41b59cd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** token transfers totaling **$654** (9 USDC, 166 USDC, 0 WETH, 478 USDC, 0 WETH) |
| **Blocks** | 26473759-26473911 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to Across SpokePool V2: $654 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #60: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x97ccdbea4632140639ad5ea9b944aa034eb15fd4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **9** token transfers totaling **$500** (26 USDC, 10 USDC, 101 USDC, 210 USDC, 21 USDC) |
| **Blocks** | 26473746-26473907 |

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
- **stablecoin_mixing** (+80) — 9 stablecoin transfer(s) to Across SpokePool V2: $500 total (USDC, USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #61: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3d2d2538b2dde72ac9f2730afe1799040f08f4f0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$29** (29 USDC) |
| **Blocks** | 26473894-26473894 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $29 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #62: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$105** (6 USDT, 99 USDC) |
| **Blocks** | 26473817-26473880 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $105 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #63: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9a47f3289794e9bbc6a3c571f6d96ad4e7baed16` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** token transfers totaling **$991** (311 USDC, 91 USDC, 36 USDT, 56 USDC, 0 WETH) |
| **Blocks** | 26473787-26473866 |

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
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to Across SpokePool V2: $991 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #64: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x28a4d41776968c1201a807ec51ffb405362b8882` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$141** (141 USDT) |
| **Blocks** | 26473756-26473756 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $141 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #65: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x69460570c93f9de5e2edbc3052bf10125f0ca22d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$17** (17 USDT) |
| **Blocks** | 26473755-26473755 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $17 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #66: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x8b9fc8301ca12968d4f7066ab68031acb41b1183` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0014 ETH** ($2) |
| **Blocks** | 26473905-26473905 |

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
| Wallet Age | 190 days |
| Total Transactions | 139 |
| Current Balance | 0.000451 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #67: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xc39a820d17d6e63e208d68abfc2945f16e1a0c09` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473871-26473871 |

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
| Current Balance | 0.000470 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #68: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x06aada1e39c89b1289d47fb4ccc6a54126fa1a87` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.5199 ETH** ($895) |
| **Blocks** | 26473871-26473871 |

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
| Wallet Age | 212 days |
| Total Transactions | 31 |
| Current Balance | 0.009659 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #69: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x81739ef9ce02bfda5e7ae11d5fb1950243b79596` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0034 ETH** ($6) |
| **Blocks** | 26473871-26473871 |

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
| Wallet Age | 237 days |
| Total Transactions | 149 |
| Current Balance | 0.069773 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #70: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x38913f412df02a9b5bb06617402b41faf8286e21` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.2440 ETH** ($420) |
| **Blocks** | 26473866-26473866 |

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
| Wallet Age | 119 days |
| Total Transactions | 65 |
| Current Balance | 0.000291 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #71: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x11003877a7731062debee59f4b5c594bd8c8f18b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0530 ETH** ($91) |
| **Blocks** | 26473852-26473852 |

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
| Wallet Age | 1753 days |
| Total Transactions | 111 |
| Current Balance | 0.111487 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #72: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x9d9b562ad9726d62b4fa6aa3909542aacb75597e` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473841-26473841 |

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
| Wallet Age | 5 days |
| Total Transactions | 10 |
| Current Balance | 0.003954 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #73: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x0361897d757d13a4afad64a2e1bc561b96a8c7cf` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **4.0000 ETH** ($6,889) |
| **Blocks** | 26473836-26473836 |

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
| Wallet Age | 172 days |
| Total Transactions | 19505 |
| Current Balance | 0.359176 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #74: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x2043232c9c01cae8affde6ed7cb43d5b7d767ff3` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473830-26473830 |

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
| Wallet Age | 1427 days |
| Total Transactions | 54 |
| Current Balance | 0.002197 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #75: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x4041dafa2408123103cee63251ebe14041884a8a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473823-26473823 |

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
| Total Transactions | 81 |
| Current Balance | 0.009786 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #76: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa638985221c7074a1418aa952664860152c161a3` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0240 ETH** ($41) |
| **Blocks** | 26473806-26473806 |

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
| Wallet Age | 1523 days |
| Total Transactions | 160 |
| Current Balance | 0.009163 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #77: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x020bbb92f73b51042572beb2cce4643c532320e9` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473793-26473793 |

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
| Total Transactions | 311 |
| Current Balance | 0.129496 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #78: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x69895949e505f21cca0bf10e38f4969b22061c5d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0800 ETH** ($138) |
| **Blocks** | 26473792-26473792 |

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
| Wallet Age | 2630 days |
| Total Transactions | 236 |
| Current Balance | 0.017802 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #79: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x35ba3008d809cd64612a75a8776b361423d5fa4c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.1664 ETH** ($287) |
| **Blocks** | 26473732-26473738 |

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
| Total Transactions | 17 |
| Current Balance | 0.003223 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #80: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x6456bf5baa0f8fc9a266e4931c4d755bcb795e38` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0292 ETH** ($50) |
| **Blocks** | 26473723-26473729 |

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
| Total Transactions | 5 |
| Current Balance | 0.011643 ETH |
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
| **Sender** | `0x873389c9c288dcf2d6e51547f6a8c9085bac0bd7` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0095 ETH** ($16) |
| **Blocks** | 26473728-26473728 |

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
| Wallet Age | 671 days |
| Total Transactions | 250 |
| Current Balance | 0.000264 ETH |
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
| **Sender** | `0xdccf97582977a4044914d290c895ed21bf4875e3` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26473721-26473721 |

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
| Total Transactions | 3 |
| Current Balance | 0.001682 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**82 suspicious findings** detected across 82 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 40 |
| 🟠 HIGH | 4 |
| Wallets flagged | 82 |
| Suspicious value | 9.9693 ETH ($17,170) + $146,097 in stablecoins |
| Blocks scanned | 26473720 — 26473919 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 4 of 25 attempted analyses this run.

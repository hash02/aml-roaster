# 🔥 AML Roaster Report
**2026-11-20 06:20 UTC** · Ethereum Mainnet · ETH $1,741.70
**Blocks:** 26454247 — 26454446 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26454247 to 26454446 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **9** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26454256-26454445 |

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
| Wallet Age | 254 days |
| Total Transactions | 19691 |
| Current Balance | 0.053049 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 9 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 9 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **18** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26454263-26454442 |

### 💬 What Happened
A user sent 18 tiny, identical packets of zero ETH to a bridge that moves coins between blockchains. It's like someone dropping 18 identical envelopes into a slot machine, hoping the bank will never notice the pattern. The total amount is zero, but the way the packets were sent looks suspicious.

### 🔥 The Roast
So the guy decided to play a game of 'who can send the smallest amount' with 18 identical zero‑ETH moves (scoring 70 on structuring – basically smurfing). CRITICAL (rule score 195) On top of that, he used a cross‑chain bridge (bridge_hop, score 65) – like taking a secret tunnel between two countries. If this was a comedy show, the punchline would be "I’m a banker, but I’m also a magician, because I can make money disappear in 18 steps".

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction pattern demonstrates high risk of structuring and layering across a bridge, warranting immediate human review.**

CRITICAL (rule score 195)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2806 days |
| Total Transactions | 862990 |
| Current Balance | 11.941343 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 18 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 18 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender’s wallet performed 18 identical transfers of 0.0000 ETH to Across SpokePool V2, a cross‑chain bridge. This activity satisfies the following AML rules: [structuring] (identical, small deposits), [peel_chain_linear] (sequential deposits indicating layering), and [bridge_hop] (cross‑chain movement). The pattern is characteristic of structuring and layering, raising concerns about potential illicit fund movement. Human review is warranted to determine the source and legitimacy of these transactions.

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **8** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26454268-26454437 |

### 💬 What Happened
The sender shuffled eight tiny packets of ETH, each worth zero, into a special bridge that moves money between different blockchains. Think of it like dropping eight empty envelopes into a slot that hides who sent them. The whole move happened in one day, and the sender’s wallet is still active.

### 🔥 The Roast
Got a 195 on the composite score—like a high school report card that says you’re a genius at hiding money. The structuring rule hit 70 (that means the system noticed you’re smurfing, or splitting money into tiny bits to avoid detection). The peel_chain_linear rule scored 60 (layering pattern: moving the same zero-value packets in a line, like a line of dominoes that all fall the same way). The bridge_hop rule hit 65 (cross-chain bridge: you’re hopping from one blockchain to another like a squirrel on a power line). All this screams, "Hey, someone’s trying to make a mess of the ledger!"

### 🎯 Verdict & Next Steps
**CRITICAL – The combination of structuring, layering, and cross-chain bridging signals a high-risk suspicious activity pattern.**

Flag the sender for manual compliance review and request source‑of‑fund documentation. Monitor subsequent transactions for additional red‑flag patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1095 days |
| Total Transactions | 216676 |
| Current Balance | 0.548460 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 8 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 8 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction history shows eight consecutive zero-ETH deposits to Across SpokePool V2, a recognized cross-chain bridge. The pattern aligns with Rule structuring (identical micro-deposits), Rule peel_chain_linear (sequential layering), and Rule bridge_hop (cross-chain movement). CRITICAL (rule score 195) Further investigation is warranted to determine the legitimate source of funds and intent.

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **14** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26454251-26454436 |

### 💬 What Happened
A user sent 14 identical tiny transfers of 0 ETH to a bridge contract. It's like a courier dropping 14 identical envelopes into the same slot, so nobody can tell which envelope came from who. The transfers all happened in quick succession, so no actual money moved, but the pattern looks suspicious.

### 🔥 The Roast
Scored 70 on structuring (meaning the guy tried to smurf his way to a bank, but all his packages were empty). The engine even gave a 60 for peel_chain_linear, meaning he thought he was layering his money like a bad sushi roll. And a 65 on bridge_hop, because he hopped into Across SpokePool V2, which is basically a cross‑border transfer that doesn’t actually add any value but looks flashy. If you think this is a prank, remember: even a zero‑ETH transfer can be a red flag, because the pattern is more important than the amount. In other words, he’s playing the long‑distance game with an invisible ball.

### 🎯 Verdict & Next Steps
**CRITICAL — The combination of identical zero‑value deposits, sequential pattern, and bridge usage yields a high composite score, indicating a strong risk of structuring and layering.**

Flag the transaction for manual review by AML compliance. Consider monitoring the sender address for future activity and cross‑reference with other known high‑risk patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 98 days |
| Total Transactions | 35417 |
| Current Balance | 0.216193 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 14 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 14 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender wallet, 0xfd0aa7548823c40be6dd85682f0342f35dee121a, executed 14 identical 0 ETH transfers to Across SpokePool V2 within blocks 26454251-26454436. Rule [structuring] (identical small deposits) scored 70; Rule [peel_chain_linear] (sequential similar deposits) scored 60; Rule [bridge_hop] (bridge usage) scored 65. Combined composite score 195 indicates a high‑risk structuring and layering pattern. This activity warrants immediate review per AML policy.

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **12** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26454275-26454436 |

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
| Wallet Age | 48 days |
| Total Transactions | 15355 |
| Current Balance | 0.058343 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 12 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 12 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #6: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xba1750614805a972f90556575ed3591e15649322` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454446-26454446 |

### 💬 What Happened
The sender's brand‑new wallet (created today) sent a tiny amount of ETH—just 0.0002, like sending a single grain of rice across a table—to a service called FixedFloat 1. FixedFloat is a kind of “no‑ID ATM” that lets people move crypto into fiat without proving who they are. It’s like dropping a small package into a slot that hides who sent it, with no one checking the sender’s identity.

### 🔥 The Roast
This wallet is so fresh it hasn’t even had a birthday yet—only two transactions and zero balance! The 0.0002 ETH transfer is like tossing a paper airplane to a friend in a different city, but the friend is actually a shady middleman. The no‑KYC off‑ramp (score 85) means the service is a cash machine that doesn’t ask for ID, basically a “who‑ever‑wants‑to‑cash‑out‑without‑paperwork” place. And the sybil_fan_in pattern (score 70) shows this is part of a larger army of clones all doing the same tiny transfers, like a choir of identical phones all shouting the same song.

### 🎯 Verdict & Next Steps
**CRITICAL: The transaction exhibits high-risk characteristics due to no‑KYC off‑ramp and Sybil fan‑in pattern, warranting immediate review.**

Flag the transaction for manual investigation to verify source of funds and potential link to known suspicious clusters; consider escalating to higher-level compliance if additional red flags emerge.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Rule no_kyc_offramp (No‑KYC Off‑Ramp) triggered by the transfer to FixedFloat 1, a known platform that allows fiat conversion without identity verification. Rule sybil_fan_in (Sybil Fan‑In Pattern) identified due to multiple addresses (18 in total) depositing similar amounts (~0.0002 ETH ±30%) into the same destination, indicating a possible Sybil attack. The sender wallet is brand new (0 days old) with only two transactions and currently zero balance, which is a typical profile for wash‑money layering. The transaction is a single ETH transfer of 0.0002 ETH ($0 USD) within a single block (26454446), with no token transfers involved. CRITICAL (rule score 155)

</details>

---

## Finding #7: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x6b1658b21b2e3dcdee493089894453ad0bd7dab0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454433-26454433 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ETH—about 0.0002, which is like tossing a single grain of rice into a black hole that hides who gave it. The sender had zero history and no identity verification, so it's a bit like a stranger dropping a note in a mailbox that nobody knows who wrote it. The note (the ETH) ended up at a fixed‑rate exchange that lets you withdraw without checking who you are, which is a red flag.

### 🔥 The Roast
So we have a fresh‑from‑the‑forge wallet with a zero‑day age, sending a minuscule 0.0002 ETH to a place that says "no KYC, no problem"—like a secret club that only accepts anonymous pizza delivery. The engine gave it 85 points on the no_KYC_offramp rule (meaning this is an off‑ramp that doesn’t verify identity, perfect for a quick wash) and 70 on sybil_fan_in (so 17 other fresh wallets are doing the same thing, like a choir of tiny coins all singing the same tune). If you thought this was a harmless micro‑transaction, think again—it's more like a group of pranksters hiding their stash in a dumpster with no receipts.

### 🎯 Verdict & Next Steps
**CRITICAL — the presence of a brand-new, no‑KYC wallet coupled with a Sybil fan‑in pattern indicates a high likelihood of layering activity.**

Flag the transaction for manual review, request source‑of‑funds information, and consider monitoring or blocking the wallet if subsequent suspicious activity occurs.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
This transaction is flagged under rule no_kyc_offramp due to the deposit to FixedFloat 1, an off‑ramp lacking identity verification, and rule sybil_fan_in because the sender is one of 18 addresses depositing similar amounts (~0.0002 ETH ± 30%) within the same block, indicating a potential Sybil fan‑in layering pattern. The sender wallet is brand new (0 days old) with only two total transactions and a current balance of 0.000000 ETH, further raising suspicion of a wash‑layering scheme. CRITICAL (rule score 155)

</details>

---

## Finding #8: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x0aa708eae08c720d6bc605e38eb5afb06b3b8bb5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454423-26454423 |

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #9: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x1eeb3831a357e5a558948ec39afc2cff87e5c4fa` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454420-26454420 |

### 💬 What Happened
CRITICAL (rule score 155) The sender’s wallet had never been used before and had no balance after the transfer, which is like dropping a small package into a slot and then vanishing. CRITICAL (rule score 155)

### 🔥 The Roast
CRITICAL (rule score 155) The engine gave it a score of 155, which is like getting a bad grade in algebra: no‑KYC off‑ramp (meaning there’s no way to trace who will finally cash out the coins) and a sybil fan‑in (meaning 18 other new wallets are also sending the same tiny amounts, like a bunch of friends trying to sneak into a club with the same flimsy ID). The fact that the sender’s balance is now zero after sending all their ETH is the ultimate “I was here, but I didn’t leave any crumbs” move. So yeah, this is like a group of ninjas dropping out of the shadows with a tiny bag of coins and expecting to disappear into the ether.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, investigate the source and destination addresses for additional suspicious patterns, and monitor for any subsequent movements of the 0.0002 ETH or related funds.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction (0x1eeb3831a357e5a558948ec39afc2cff87e5c4fa → 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f) involved 0.0002 ETH on block 26454420. The sender wallet is newly created (0 days old) and has only two total transactions, with a zero balance after the transfer, indicating a possible wash or layering operation. The AML engine flagged two rules: [no_kyc_offramp] (score 85) for deposit to FixedFloat 1, a service that does not provide KYC verification for off‑ramp, and [sybil_fan_in] (score 70) for fan‑in pattern with 18 similar new wallets sending comparable amounts, suggesting a coordinated attempt to obfuscate source. CRITICAL (rule score 155)

</details>

---

## Finding #10: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa7ac05f8e66e6f0b202eb53f5e7e20668d2c67a7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454419-26454419 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (0.0002, basically nothing) to a special mixing address that hides the sender’s identity, like dropping a note into a mailbox that only the post office can read. This happened in a single block, which is just a page in the blockchain ledger that records all transactions at that moment. The sender’s account was created on the same day and has no other activity besides this one tiny transfer.

### 🔥 The Roast
Scored 85 on the no_KYC_offramp rule (meaning this wallet is sending money to an address that doesn’t require identity verification, like sending cash to a friend who doesn’t ask who you are). It also got 70 on sybil_fan_in (so this is one of many similar tiny deposits from a bunch of new wallets, like a fan club of 18 people all sending the same amount). With a composite of 155, the engine is basically shouting, “Hey, we’ve got a suspicious party!” – and it’s not just a prank. CRITICAL (rule score 155) This is the kind of thing that makes compliance folks pull out their magnifying glasses.

### 🎯 Verdict & Next Steps
**CRITICAL — composite score of 155 indicates a high risk of illicit activity via an unverified off‑ramp and potential Sybil pattern.**

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggered Rule no_kyc_offramp with a score of 85 due to the transfer to a FixedFloat 1 address, which is a known unverified off‑ramp. Rule sybil_fan_in scored 70, indicating a fan‑in pattern of 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%), a typical Sybil indicator. The composite score of 155 exceeds the critical threshold set for high‑risk transactions. Evidence includes a single 0.0002 ETH transfer in block 26454419 from a 0‑day old wallet with only two transactions and no balance.

</details>

---

## Finding #11: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xe89a841f7185f5481b9868ede46fa06f61cbf9b4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454408-26454408 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ETH (0.0002) to a service called FixedFloat 1. This is like dropping a small package into a slot that hides who sent it, because the sender has no history and no identity verification. The transaction is tiny but suspicious because it follows a pattern used by mixers to hide money.

### 🔥 The Roast
Looks like a brand‑new wallet tried to play hide‑and‑seek with a 0.0002 ETH note. The no_kyc_offramp rule (meaning the user left no ID trail when moving money to a non‑KYC exit) gave it a whopping 85 points, while the sybil_fan_in rule (meaning this wallet is part of a crowd of 18 similar newbies dumping small amounts) added 70 more. CRITICAL (rule score 155) The engine thinks this is a red flag, not a polite invitation to the crypto club.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction triggers high‑risk patterns (no KYC off‑ramp and Sybil fan‑in) resulting in a composite score of 155.**

Flag the transaction for a manual SAR review by compliance, and consider temporarily freezing the recipient wallet until the source can be verified.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
This transaction exhibits high-risk indicators under rule no_kyc_offramp (score 85) and rule sybil_fan_in (score 70), resulting in a composite score of 155. The sender wallet is 0 days old, has only 2 transactions, a zero balance, and no KYC information, and it deposited ETH into FixedFloat 1, a known off‑ramp service. These factors meet the criteria for a suspicious activity report, warranting further human investigation and potential account monitoring.

</details>

---

## Finding #12: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xd2d9321e7088fb7053fbb128e22e9526aa89ec22` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454382-26454382 |

### 💬 What Happened
CRITICAL (rule score 155) CRITICAL (rule score 155) The wallet had only two transactions before it vanished, leaving no balance behind.

### 🔥 The Roast
This is a textbook case of a no‑KYC off‑ramp (meaning the money is headed to a place where you can cash out without showing ID). The engine even flagged it as a sybil fan‑in (so it’s probably one of many new accounts dumping the same little coin to the same spot, like a fan club of clueless investors). CRITICAL (rule score 155) If this was a real person, they'd be better off using a regular bank.

### 🎯 Verdict & Next Steps
**CRITICAL — the high composite score and patterns indicate a high likelihood of illicit activity, warranting immediate investigation.**

Flag the transaction for manual compliance review, monitor the wallet for additional activity, and consider placing a temporary hold if further suspicious patterns emerge.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Transaction involving sender address 0xd2d9321e7088fb7053fbb128e22e9526aa89ec22 to receiver 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1) on block 26454382. The sender wallet is 0 days old, has only 2 transactions, and currently holds 0.000000 ETH. AML engine scored 85 for rule [no_kyc_offramp] (deposit to a known no‑KYC off‑ramp) and 70 for rule [sybil_fan_in] (fan‑in pattern of multiple new senders depositing similar amounts). Composite score of 155 indicates elevated risk. CRITICAL (rule score 155) Flag for manual review under AML policy for high‑risk transactions involving mixers.

</details>

---

## Finding #13: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xee1c8fcd300673ce259f5774ea130c232f678767` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454376-26454376 |

### 💬 What Happened
A brand‑new wallet (only 0 days old) sent 0.0002 ETH to a service that lets people move money without showing their identity. It was the only transaction in that block, and the sender had no balance left after sending. Think of it like dropping a tiny coin into a mysterious black‑hole that promises to keep it safe but never asks for your name.

### 🔥 The Roast
Scored 85 on the no‑KYC off‑ramp (meaning the sender moved money into a service that doesn’t ask for ID) and 70 on sybil_fan_in (meaning a bunch of wallets with similar tiny deposits are all huddling together like a flock of pigeons). The wallet’s age is 0 days, so it’s probably a new spam account or a bot. If this were a real person, they’d need to prove they’re not a magician pulling money out of a hat. This is like a kid borrowing a library book without ever showing a library card.

### 🎯 Verdict & Next Steps
**CRITICAL — The transaction presents a high risk due to both a no‑KYC off‑ramp and a Sybil fan‑in pattern, warranting immediate scrutiny.**

Flag for manual review, request source of funds and identity verification, and consider freezing the transaction until KYC is verified.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggered rule [no_kyc_offramp] with a score of 85, indicating a deposit to FixedFloat 1, a known no‑KYC off‑ramp service. Rule [sybil_fan_in] scored 70, reflecting a fan‑in pattern where 1 of 18 senders deposited a similar amount (~0.000 ETH ±30%). The wallet is newly created, has a minimal transaction history, and has no remaining balance, all of which align with typical high‑risk profiles. CRITICAL (rule score 155)

</details>

---

## Finding #14: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf90cb8244a1ffde88043b7c08efa2e507dde01e1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454370-26454370 |

### 💬 What Happened
A brand-new wallet, like a freshly opened mail slot, just sent a tiny 0.0002 ETH to a service called FixedFloat 1. The wallet has zero days of history and only two very small moves, so it’s basically a fresh dropbox with one note inside—no background to say who’s behind it. CRITICAL (rule score 155)

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their coins, dropping 0.0002 ETH into FixedFloat 1 (no‑KYC off‑ramp, meaning the service lets you move funds without proving who you are). The wallet is brand‑new (0 days old) and has only two tiny moves, like a toddler with a crayon. With a composite score of 155, it’s basically the blockchain equivalent of a gold star for being suspicious. The sybil fan‑in pattern (70 points) shows this is part of a crowd of 18 similar wallets all doing the same thing—like a group of kids passing the same note in class. The no‑KYC off‑ramp score of 85 is a clear sign that this is a shady alleyway where no one checks IDs.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag this transaction for manual review by AML compliance, request additional context on the source of funds, and consider monitoring future activity from this wallet.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet with 0 days age and only two prior transactions, indicating no established pattern. The transfer of 0.0002 ETH to FixedFloat 1 triggers rule [no_kyc_offramp] with a score of 85, flagging a no‑KYC off‑ramp deposit. Additionally, the pattern matches rule [sybil_fan_in] (score 70) where 1 of 18 senders deposited similar amounts (~0.000 ETH ±30%), indicating potential Sybil activity. Combined, these rules yield a composite score of 155, warranting a high‑priority review.

</details>

---

## Finding #15: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb67c07b66b73b40053f58f13f1f7b98e183d7a1f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26454367-26454367 |

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #16: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x682d8ff2b08b047b356eca3097db9be932d43414` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454355-26454355 |

### 💬 What Happened
CRITICAL (rule score 155) The sender has only had two transactions total and now has no balance left. Basically, someone just tossed a tiny crypto coin into a black hole that will later shuffle it around.

### 🔥 The Roast
It’s like someone who just got a shiny new phone and immediately uses it to send a handful of pennies into a blackhole; no KYC (meaning no identity check) off‑ramp, so the money can disappear faster than you can say “blockchain.” The system flagged it with a 85 on the no_kyc_offramp rule (no identity verification) and 70 on sybil_fan_in (many similar accounts doing the same thing). CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag this wallet for manual investigation, request additional context from the sender if possible, and monitor any subsequent transactions for further suspicious patterns.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a newly created wallet (age 0 days) sending 0.0002 ETH to a FixedFloat address. This activity matches the "no_kyc_offramp" rule (score 85) indicating an off‑ramp with no identity verification, and the "sybil_fan_in" rule (score 70) indicating a Sybil fan‑in pattern where many accounts send similar small amounts. The composite score of 155 exceeds the internal threshold of 120 for high‑risk flags. CRITICAL (rule score 155)

</details>

---

## Finding #17: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x05b56f7be95eefa7b9309a8b419e5203b6b22e80` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454352-26454352 |

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #18: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x6978eb01230d6a461198ccee57f5bb40696f2aef` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($0) |
| **Blocks** | 26454346-26454346 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ETH (0.0003) to a fixed‑float address that is used for off‑ramp services. The sender had no previous balance, had only two transactions, and the transfer is part of a very small amount cluster. In plain terms, it’s like dropping a single coin into a mystery box that promises to turn it into cash later.

### 🔥 The Roast
This new wallet is 0 days old—so it’s basically a newborn. It sent 0.0003 ETH to a fixed‑float address, and the AML engine gave it a composite score of 155 (that’s like a bad Yelp review). The no‑KYC off‑ramp rule scored 85, meaning the wallet is trying to slip into a cash‑out service without ID (think of it as trying to use a cash machine that doesn’t ask for your card). The sybil fan‑in rule added 70, showing this is part of a fan‑in pattern where 1 of 18 similar wallets send nearly the same tiny amount—like a group of pranksters each tossing a penny into the same jar. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — high composite score due to no‑KYC off‑ramp and Sybil fan‑in patterns indicating potential layering or obfuscation.**

Flag the transaction for manual review and verify whether the receiver is a known off‑ramp service. CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggered rule [no_kyc_offramp] with a score of 85 due to the transfer to a fixed‑float address that offers an off‑ramp service without KYC. Rule [sybil_fan_in] scored 70, indicating a Sybil fan‑in pattern with 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%). The sender wallet has an age of 0 days, 2 total transactions, and a balance of 0.000000 ETH, suggesting a newly created, low‑balance account. The composite score of 155 warrants further review for potential layering or obfuscation activity.

</details>

---

## Finding #19: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xdb15f5b38030cd055948fe5bcfd7845efba32d8f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454301-26454301 |

### 💬 What Happened
A brand-new wallet (just created today) sent 0.0002 ETH to a FixedFloat address. The transfer was tiny—like sending a single grain of sand— and the wallet had only made two transactions total. This is like dropping a package into a slot that hides who sent it, because there's no record of who owns the sender.

### 🔥 The Roast
Score 85 on no_kyc_offramp (meaning the wallet deposited to an off‑ramp that doesn't do KYC). Score 70 on sybil_fan_in (so it's part of a fan‑in Sybil pattern where many new wallets send the same small amount). The sender is brand new, with 0 days, basically a fresh‑from‑the‑oven wallet that already has zero balance. It's like a kid with a toy that goes straight into a black‑hole, no trace. This transaction is the kind of 'I’m just a random bot' move that makes auditors raise their eyebrows.

### 🎯 Verdict & Next Steps
**CRITICAL — The transaction exhibits high risk due to a no‑KYC off‑ramp deposit and Sybil fan‑in pattern, warranting immediate review.**

Flag the transaction for manual compliance review and request additional information on the wallet’s source of funds. Consider monitoring the wallet for further activity and, if necessary, place it on the suspicious activity watchlist.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created wallet (age 0 days) that sent 0.0002 ETH to FixedFloat 1, a known no‑KYC off‑ramp. The AML engine assigned a composite score of 155, driven primarily by a score of 85 on rule [no_kyc_offramp] and 70 on rule [sybil_fan_in], indicating a fan‑in Sybil pattern. The sender has a total of 2 transactions and a current balance of 0.000000 ETH, suggesting a lack of ongoing activity. This activity should be flagged for manual review under the no‑KYC off‑ramp and Sybil fan‑in criteria.

</details>

---

## Finding #20: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa825ae757fd92e32eebc8f869d0732a064e01914` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454295-26454295 |

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #21: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x6717d70e8965a8485ac74329469b92900a0f7b88` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454256-26454256 |

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #22: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x175500bbd866ac8d18caf3af86c3f7ccf1ca280f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454251-26454251 |

### 💬 What Happened
CRITICAL (rule score 155) The sender made only one transaction, but the wallet has a total of two tiny moves and now has no balance left, like a kid who spent all their allowance on a single candy bar. In plain terms, it’s like dropping a small package into a slot that hides who sent it and who will get it next.

### 🔥 The Roast
So this wallet is so new it’s probably still in its first week of life—zero days old, like a newborn baby that just learned how to walk. The transfer to FixedFloat 1? That’s the crypto version of a secret club where you pay a fee and nobody knows your name—no-kyc off-ramp (meaning there's no official way for the user to get out of the system with ID verification). And with 18 other accounts funneling almost identical tiny amounts into the same address, we’ve got a classic fan‑in Sybil pattern (multiple accounts acting like a single “super‑account” to disguise activity). CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a brand‑new wallet, no‑KYC off‑ramp, and fan‑in Sybil pattern signals a high likelihood of illicit layering activity.**

Flag the transaction for manual compliance review, request additional transaction context, and monitor the wallet for future activity. Consider freezing the wallet if further suspicious patterns emerge.

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 155) The sender’s wallet exhibits no KYC off‑ramp (rule: no_kyc_offramp, score 85) and is part of a fan‑in Sybil pattern (rule: sybil_fan_in, score 70) with 18 similar senders depositing near‑identical amounts. The wallet’s total transaction count is 2, with zero current balance, indicating potential layering and obfuscation. This activity meets the composite risk threshold and warrants further investigation.

</details>

---

## Finding #23: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x2f9a6dc75c94b1511db2f6f9b12b5929591b3d37` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26454250-26454250 |

### 💬 What Happened
A brand‑new wallet, created just yesterday, sent a tiny 0.0002 ETH to a service called FixedFloat 1, which blends coins together to hide their origin. The sender had no balance before and had only made two transactions, so it looks like a fresh account being used to move a small amount of crypto into a privacy tool. It's like dropping a small package into a slot that hides who sent it.

### 🔥 The Roast
Looks like this new wallet was born with a single transaction in its bank account, like a toddler with a credit card. It hit a no‑KYC off‑ramp (meaning the receiver has no identity verification) and a Sybil fan‑in pattern (many similar tiny senders piling into the same address) – basically a crypto version of a group of strangers sharing a single anonymous box to hide their pizza order. The composite score of 155? That's more than a pizza joint's delivery fee for a single slice. If you think this is a harmless tip, think again – this is the kind of transaction that makes regulators squint and say, "Did someone just drop a micro‑dollar into the black hole?"

### 🎯 Verdict & Next Steps
**CRITICAL — The transaction exhibits high risk due to use of a no‑KYC off‑ramp and Sybil fan‑in pattern.**

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
- **sybil_fan_in** (+70) — 1 of 18 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Rule [no_kyc_offramp] triggered with a score of 85 due to transfer to FixedFloat 1, a known no‑KYC off‑ramp. Rule [sybil_fan_in] triggered with a score of 70 because 1 of 18 senders deposited similar amounts (~0.000 ETH ± 30%) to the same address, indicating a Sybil fan‑in pattern. The sender wallet is new (0 days old) with only two transactions and zero balance, further raising suspicion. The composite risk score of 155 warrants escalation for manual review.

</details>

---

## Finding #24: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **13** token transfers totaling **$14,916** (100 USDC, 30 USDT, 4,843 USDT, 2 USDC, 190 USDC) |
| **Blocks** | 26454263-26454442 |

### 💬 What Happened
A single address sent a series of 13 stablecoin payments to a smart contract that shuffles them around, making it hard to see where the money started. It’s like dropping a handful of coins into a vending machine that mixes them before handing them off to a new customer. The total value was about $15,000, split into a few big chunks and many smaller ones.

### 🔥 The Roast
The sender decided to throw a stablecoin party with 13 guests, all at Across SpokePool V2, scoring a perfect 110 on the stablecoin_mixing radar. That’s like a kid at a birthday cake who refuses to share the frosting, except the frosting is money and the kid is a bot. The mix-up is so good it makes a blender jealous. If this were a cooking show, they'd call it "The Great Disguise".

### 🎯 Verdict & Next Steps
**HIGH — the transaction exhibits a classic stablecoin mixing pattern with a composite score of 110, indicating potential layering and obfuscation of funds.**

Initiate a manual review of the source address and downstream recipients. Cross‑reference the transaction with other known mixing services and flag for further due diligence.

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
- **stablecoin_mixing** (+110) — 13 stablecoin transfer(s) to Across SpokePool V2: $14,916 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction was flagged under rule stablecoin_mixing, which identifies patterns where a single sender conducts multiple stablecoin transfers to a mixing smart contract. Evidence: 13 transfers totaling $14,916 (USDC and USDT) to Across SpokePool V2, all from the same address. This pattern is consistent with layering and obfuscation techniques used by illicit actors. Further investigation is warranted to determine the ultimate source and destination of funds.

</details>

---

## Finding #25: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x7560f0d8df5c0310af3d16e02a2ec44628866f74` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$17,998** (3,854 USDT, 4,793 USDT, 9,351 USDT) |
| **Blocks** | 26454395-26454398 |

### 💬 What Happened
A single wallet sent almost $18,000 worth of USDT (a stablecoin that tracks the US dollar) to a service called Across SpokePool V2, which is like a secret drop box that hides who the real sender is. The money was split into three chunks that landed in the same place, as if someone was trying to make the trail harder to follow. It’s basically a big, single‑handed attempt to mix coins and keep the source of funds anonymous.

### 🔥 The Roast
HIGH (rule score 110) HIGH (rule score 110) The engine gave it a 110 score on the stablecoin_mixing rule (meaning it’s flagged as a high‑risk pattern of mixing stablecoins). If this were a movie, the wallet would be the villain, the SpokePool the secret lair, and the stablecoin the villain’s disguise. Basically, we’re seeing the classic “hide your tracks” move, but with more zeros.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag the transaction for manual AML review, trace the source of the USDT, and consider placing the sender’s address on a watchlist pending further investigation.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to Across SpokePool V2: $17,998 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
HIGH (rule score 110) Evidence: transaction amounts of 3,853.5172, 4,792.8487, and 9,351.3528 USDT; all directed to the same contract address. The pattern matches the engine’s high‑risk composite score of 110, indicating potential layering activity. HIGH (rule score 110)

</details>

---

## Finding #26: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x97ccdbea4632140639ad5ea9b944aa034eb15fd4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **16** token transfers totaling **$4,276** (21 USDC, 500 USDT, 200 USDT, 10 USDT, 500 USDT) |
| **Blocks** | 26454269-26454446 |

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
- **stablecoin_mixing** (+100) — 16 stablecoin transfer(s) to Across SpokePool V2: $4,276 total (USDT, USDC) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x58e67a035a3b8e57de8d4f50d4d8e638999242cf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0097 ETH** ($17) |
| **Blocks** | 26454361-26454361 |

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

## Finding #28: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc606539ec022646436f5cb13baa6a11a483a2f99` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0116 ETH** ($20) |
| **Blocks** | 26454343-26454343 |

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

## Finding #29: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x9af95ff8bae445bce4af258f80fc538463cd7590` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0115 ETH** ($20) |
| **Blocks** | 26454334-26454334 |

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

## Finding #30: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd1b8e19b39b41aabe47bbb57e9dd99a2a2976b4c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0058 ETH** ($10) |
| **Blocks** | 26454329-26454329 |

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

## Finding #31: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8006ac9cd2c2eaf81d965a6b71c93e3f10d74cfe` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0438 ETH** ($76) |
| **Blocks** | 26454316-26454316 |

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

## Finding #32: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x87a6ada4f4a2f287c883b26aaf67781b4725aa28` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1050 ETH** ($183) |
| **Blocks** | 26454306-26454306 |

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

## Finding #33: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x6a9e6bf238e50fccae2236226e6ff467775dd516` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0294 ETH** ($51) |
| **Blocks** | 26454253-26454253 |

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

## Finding #34: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **8** token transfers totaling **$2,475** (14 USDT, 198 USDT, 12 USDT, 956 USDC, 991 USDT) |
| **Blocks** | 26454276-26454446 |

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
- **stablecoin_mixing** (+80) — 8 stablecoin transfer(s) to Across SpokePool V2: $2,475 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc186fa914353c44b2e33ebe05f21846f1048beda` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$4,858** (4,858 USDT) |
| **Blocks** | 26454444-26454444 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $4,858 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9e64d18073cd8ec20e2680124d0551ba1629fa20` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** token transfers totaling **$8,012** (0 WETH, 349 USDT, 1 WETH, 1,583 USDC, 6,078 USDT) |
| **Blocks** | 26454371-26454444 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $8,011 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9a47f3289794e9bbc6a3c571f6d96ad4e7baed16` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$2,949** (1,190 USDC, 20 USDT, 1,739 USDC) |
| **Blocks** | 26454325-26454442 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $2,949 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x69460570c93f9de5e2edbc3052bf10125f0ca22d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$299** (299 USDT) |
| **Blocks** | 26454417-26454417 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $299 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1517e661266d3e903d9bdb78cbf1adeaa0c260e9` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$783** (783 USDC) |
| **Blocks** | 26454417-26454417 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $783 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3d2d2538b2dde72ac9f2730afe1799040f08f4f0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** token transfers totaling **$67** (0 USDT, 12 USDC, 0 USDT, 20 USDC, 25 USDC) |
| **Blocks** | 26454288-26454407 |

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
- **stablecoin_mixing** (+80) — 6 stablecoin transfer(s) to Across SpokePool V2: $67 total (USDT, USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x28a4d41776968c1201a807ec51ffb405362b8882` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$1,588** (40 USDT, 200 USDT, 1,348 USDC) |
| **Blocks** | 26454288-26454399 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $1,588 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0038dfb2bbc353daa6ad22cb11ee1d78f41b59cd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** token transfers totaling **$29** (11 USDT, 0 WETH, 18 USDC, 0 WETH) |
| **Blocks** | 26454272-26454378 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $29 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x68e406ca22ac59b68b3e1be76b1cac90f60e6e73` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$190** (190 USDT) |
| **Blocks** | 26454355-26454355 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $190 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1d7466a3c7c2a2c0e7fa25b80d82fe3d017cc98e` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$241** (241 USDC) |
| **Blocks** | 26454343-26454343 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $241 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x60ac95ec1153aa8199751917ede25d0ca49a36e2` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$3,435** (3,435 USDT) |
| **Blocks** | 26454342-26454342 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $3,435 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xef1a3dc2765890c188f15873f59f8723a57a3248` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$281** (281 USDC) |
| **Blocks** | 26454340-26454340 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $281 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #47: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfb008a1f9a040159b063750d4320f89977f95f6a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$499** (499 USDT) |
| **Blocks** | 26454308-26454308 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $499 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x50cfe7c1938db66a1a6d2e86d36f39fbef3d5c4a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$414** (414 USDC) |
| **Blocks** | 26454274-26454274 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $414 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x449894a1700bc00073bf0c053bfb7c1d73c4c856` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$80** (80 USDC) |
| **Blocks** | 26454262-26454262 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $80 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x7ad417c0566fd87a049717fde7f9138ff4a1f471` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26454445-26454445 |

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
| Wallet Age | 1093 days |
| Total Transactions | 25 |
| Current Balance | 0.004719 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #51: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xe58dc537f30b3abff1803b414c181aa4fa5edc41` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26454422-26454422 |

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
| Total Transactions | 530 |
| Current Balance | 0.004761 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #52: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xe99b86165bcbc52cd231199e319d369d0eea318c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26454403-26454403 |

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
| Wallet Age | 428 days |
| Total Transactions | 555 |
| Current Balance | 0.001985 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #53: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xc8bc16bb77651e0b67a77d44718cd638d688ea51` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0676 ETH** ($118) |
| **Blocks** | 26454401-26454401 |

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
| Current Balance | 0.000102 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #54: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa5fad9f95fce58cf2dc16a53624a842863a161f9` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.2644 ETH** ($461) |
| **Blocks** | 26454398-26454398 |

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
| Wallet Age | 38 days |
| Total Transactions | 55 |
| Current Balance | 0.012038 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #55: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x511e6fd8c87e617575e3778ec068fc6fccd47450` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26454391-26454391 |

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
| Wallet Age | 94 days |
| Total Transactions | 1811 |
| Current Balance | 0.007022 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #56: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x0e5d0447272be22227870d970f0741e764bd8036` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0518 ETH** ($90) |
| **Blocks** | 26454316-26454316 |

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
| Wallet Age | 529 days |
| Total Transactions | 58 |
| Current Balance | 0.002710 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #57: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xe59edc3ddb9b2b9d4625db60a9b7568c194b817b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0300 ETH** ($52) |
| **Blocks** | 26454313-26454313 |

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
| Wallet Age | 162 days |
| Total Transactions | 34 |
| Current Balance | 0.152479 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #58: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x1fa584e0dabee05c063985979d416911538c4430` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.7400 ETH** ($1,289) |
| **Blocks** | 26454289-26454289 |

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
| Wallet Age | 1762 days |
| Total Transactions | 293 |
| Current Balance | 0.016464 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #59: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xb7fd040f87064992c45742be6bfb4bd1b1809373` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0554 ETH** ($97) |
| **Blocks** | 26454272-26454272 |

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
| Current Balance | 0.000092 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**59 suspicious findings** detected across 59 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 23 |
| 🟠 HIGH | 3 |
| Wallets flagged | 59 |
| Suspicious value | 1.4300 ETH ($2,491) + $63,389 in stablecoins |
| Blocks scanned | 26454247 — 26454446 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 7 of 25 attempted analyses this run.

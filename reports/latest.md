# 🔥 AML Roaster Report
**2026-11-17 01:47 UTC** · Ethereum Mainnet · ETH $1,819.45
**Blocks:** 26431352 — 26431551 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26431352 to 26431551 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x784ce13de05f9ec4e3b62197a3e7d25146d28b52` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431540-26431540 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ETH (0.0002) to a fixed exchange address that hides the sender’s identity, like dropping a package into a slot that hides who sent it. The transaction is the first activity from a wallet that has never existed before and has no balance. Because it’s a one‑off tiny send, the system flags it as potentially suspicious.

### 🔥 The Roast
Well, congratulations to the wallet that just hit 0 days old and already trying to play hide‑and‑seek with the blockchain. It scored a whopping 85 on the no_KYC_offramp rule (meaning it’s a deposit to a FixedFloat 1 address that doesn’t require identity verification), and 70 on the sybil_fan_in rule (so it’s one of 16 identical little coins doing the same thing, like a group of identical twins who all decided to send the same amount at the same time). If you think this is a harmless tip, think again – it’s like a magician pulling a rabbit out of a hat that’s actually a smoke‑and‑mirrors trick. The engine is screaming louder than a toddler in a toy store: “Don’t let this go unchecked!”

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits high‑risk features including no‑KYC off‑ramp and Sybil fan‑in pattern, resulting in a composite score above the threshold.**

Flag the transaction for manual review by the compliance team. Consider requesting additional information on the source of funds and the identity of the sender, and monitor the wallet for further activity.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
This transaction triggers the no_KYC_offramp rule (score 85) due to a deposit to a FixedFloat 1 address with no KYC off‑ramp. It also triggers the sybil_fan_in rule (score 70) because it is one of 16 senders depositing a similar amount (0.0002 ETH) within a narrow variance. The wallet is brand‑new (0 days old) with only two transactions, and the balance is zero, indicating potential layering or mixing activity. The composite score of 155 warrants immediate review under AML guidelines.

</details>

---

## Finding #2: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x37797bcd088cdc8e690ab5aefcedeff0802cb766` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431501-26431501 |

### 💬 What Happened
A brand-new wallet just dropped a tiny amount of ETH (about $0) into a FixedFloat address. Think of it like a kid slipping a note into a locked box that nobody can trace back to them. The wallet only ever made two transactions, has no balance, and was created yesterday.

### 🔥 The Roast
This guy's wallet is fresher than a fresh batch of bread, 0 days old, and just sent 0.0002 ETH to a FixedFloat account—like dropping a handful of confetti into a black hole that no one can see where it came from. Scored 85 on no_kyc_offramp (meaning this address is literally sending to a place that doesn't verify identity). And a 70 on sybil_fan_in (so he's part of a crowd of 16 other newbies who are all sending similar amounts—classic fan‑in Sybil pattern). CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a brand‑new wallet, no‑KYC off‑ramp destination, and fan‑in Sybil pattern signals high risk of illicit activity.**

Flag the transaction for manual review by compliance. Consider placing a temporary hold on the FixedFloat address and request additional information or source‑of‑funds verification from the sender.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involved a newly created wallet (age 0 days, total tx count 2) sending 0.0002 ETH to a FixedFloat 1 address. Rule no_kyc_offramp triggered with a score of 85, indicating a non‑KYC off‑ramp destination. Rule sybil_fan_in triggered with a score of 70, indicating fan‑in Sybil activity with 1 of 16 similar senders. CRITICAL (rule score 155)

</details>

---

## Finding #3: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x77069bbc8fd1c48d45788d7dd212986b8d27a126` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431492-26431492 |

### 💬 What Happened
A brand‑new wallet just dropped a tiny amount of ETH into a service that forwards it to another address. Think of it as a brand new parcel being slid into a dropbox that hides who dropped it, then the parcel is forwarded to a random locker. The whole thing took place in a single block, so it looks like a quick, anonymous transfer.

### 🔥 The Roast
First off, this new wallet is so fresh it probably still has its birth certificate in the drawer. It sent 0.0002 ETH to a FixedFloat 1 address (a type of off‑ramp that doesn’t ask for ID – no_kyc_offramp) and that’s basically the crypto version of giving your cash to a shady pawn shop that never asks who you are. Then, it was part of a fan‑in Sybil pattern (sybil_fan_in) where 16 different wallets are all sending roughly the same minuscule amount – like a choir of toddlers all shouting the same tiny song at the same time. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, request source‑of‑funds documentation, and monitor the wallet for additional suspicious activity.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet with zero days of age, only two prior transactions, and no remaining balance, indicating a newly created entity. The transfer of 0.0002 ETH to FixedFloat 1 triggers rule [no_kyc_offramp] (score 85), highlighting a KYC‑free off‑ramp scenario. Additionally, the wallet is part of a fan‑in Sybil pattern with 16 similar senders, triggering rule [sybil_fan_in] (score 70). The composite score of 155 signals a high suspicion that the transfer may be part of a layering or integration step in illicit activity.

</details>

---

## Finding #4: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x3d63ae9d019b84ae6bd129bd72f2c77129abce47` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431480-26431480 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ETH (0.0002, basically nothing) to a service called FixedFloat 1. Think of it like someone dropping a very small parcel into a locked box that only the service can open, and no one has verified who sent it.

### 🔥 The Roast
So we’ve got a fresh wallet that’s literally 0 days old, sending a minuscule amount of crypto to a no‑KYC off‑ramp—like a kid slipping a handful of coins into a piggy bank that doesn’t ask for a receipt. The engine’s shouting "no_kyc_offramp" (meaning the user never proved who they are before cashing out) and "sybil_fan_in" (so this is part of a bunch of wallets all sending similar tiny amounts, like a fan club of micro‑spammers). With a composite score of 155, this is the crypto version of a red flag that says, "Hey, we’re not sure who you are and you’re in a group that looks suspiciously coordinated."

### 🎯 Verdict & Next Steps
**CRITICAL: The transaction meets high‑risk criteria from both no‑KYC off‑ramp and sybil fan‑in patterns, requiring immediate review.**

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggers rule [no_kyc_offramp] (score 85) indicating a deposit to FixedFloat 1 without any KYC verification, and rule [sybil_fan_in] (score 70) due to the wallet being one of 16 senders depositing similar amounts (~0.000 ETH ± 30%). The composite score of 155 exceeds the critical threshold for suspicious activity. CRITICAL (rule score 155)

</details>

---

## Finding #5: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x47a787dde009abdd5a0ba1a6f2c8c12eeb037718` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431474-26431474 |

### 💬 What Happened
A brand-new wallet just sent a tiny 0.0002 ETH (about $0) to a service called FixedFloat 1. It's like a freshly opened envelope slipping a few coins into a hidden box with no record of who the sender is.

### 🔥 The Roast
So this newbie wallet, fresh out of the womb, just dropped a handful of crypto into a no-KYC off-ramp. Score of 85 on the no_kyc_offramp rule means the engine thinks this is a shady move (because there's no identity check). Add a 70 from sybil_fan_in (meaning 16 other wallets are doing the same thing), and you get a composite score of 155 - like a red flag on a toddler's first bike ride. Basically, it's the crypto equivalent of a kid with a backpack full of candy slipping it into a school's lunchbox without anyone noticing.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a 0-day wallet (0 days old) with only 2 prior transactions, transferring 0.0002 ETH to FixedFloat 1, a known no-KYC off-ramp. Composite score of 155 driven by rule [no_kyc_offramp] (score: 85) and rule [sybil_fan_in] (score: 70). CRITICAL (rule score 155)

</details>

---

## Finding #6: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xda725e1fbda0ba1aa1aeeec3e21bc67ddb309dad` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431455-26431455 |

### 💬 What Happened
A brand‑new wallet just sent a tiny 0.0002 ETH (about $0) to a special address that lets people move money around without showing who they are. Think of it like dropping a small, anonymous package into a locker that hides the sender. The wallet only had this one transaction and now holds no ETH.

### 🔥 The Roast
CRITICAL (rule score 155) The engine also flagged a sybil_fan_in (many new wallets depositing almost identical amounts, like a fan club of the same tiny pizza slice). With a composite score of 155, this is like the red flag that says, “Hey, somebody’s trying to hide in plain sight.”

### 🎯 Verdict & Next Steps
**CRITICAL: The high composite score and presence of no‑KYC off‑ramp and Sybil fan‑in patterns indicate a significant risk of anonymous money movement requiring immediate review.**

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction was conducted by a wallet with 0 days of age, only 2 total transactions, and a current balance of 0 ETH, indicating a potential fresh or abandoned wallet. Rule [no_kyc_offramp] scored 85, indicating a deposit to a FixedFloat address with no identity verification, and Rule [sybil_fan_in] scored 70, indicating a fan‑in pattern of 1 of 16 senders depositing similar amounts (~0.000 ETH ±30%). The composite score of 155 exceeds typical monitoring thresholds, warranting a suspicious activity report under the guidelines for unverified off‑ramp and Sybil patterns.

</details>

---

## Finding #7: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x1ece97f80c6ec4b6a795157e1312c61f4fe68f68` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431445-26431445 |

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #8: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x7770556aa839105d60976e30ca1c69968b0094c1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431441-26431441 |

### 💬 What Happened
CRITICAL (rule score 155) The transfer is tiny, but because it’s the first move from a fresh wallet and goes straight to an off‑ramp that doesn’t require KYC, it looks suspicious—like dropping a parcel into a slot that hides who sent it.

### 🔥 The Roast
This newbie wallet is like the kid who just got a new phone and immediately sends all the cash to the same anonymous friend. The engine gave it a whopping 85 on the no‑KYC off‑ramp rule (meaning the money is going to a place that doesn’t ask for identity verification, a classic hide‑and‑seek move). Then it added 70 on the sybil_fan_in rule (meaning 1 of 16 similar wallets sent almost the same amount, which is a sign of a Sybil attack—think of a bunch of clones all pushing the same button). So the composite score is 155—more than a high‑school bully’s score on a dodgeball match. Bottom line: this is a red flag, not a green light.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The sender wallet is newly created (0 days old) with only two transactions and a current balance of 0 ETH, indicating a fresh source of funds. CRITICAL (rule score 155) Additionally, rule [sybil_fan_in] (score 70) is triggered due to the presence of one of sixteen senders depositing a similar small amount (~0.000 ETH ±30%), suggesting a Sybil fan‑in pattern. The composite score of 155 indicates a high‑risk transaction requiring further review.

</details>

---

## Finding #9: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xd722f32e87a312500cb9da12f8c0b56b841176d8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431419-26431419 |

### 💬 What Happened
A brand‑new wallet, created the same day it sent money, slipped 0.0002 ETH (essentially nothing in dollar terms) into a FixedFloat address, which is like dropping a coin into a slot machine that hides who put it in. The transaction was the only one in that block and the sender had only one other move in its history, so it’s a very quiet, fresh activity.

### 🔥 The Roast
Looks like someone tried to sneak a micro‑coin into a FixedFloat address without a KYC passport, scoring a solid 85 on the no_kyc_offramp rule (meaning the wallet is trying to hide its exit route). The engine also gave it a 70 for sybil_fan_in, so it’s part of a choir of 16 tiny wallets all sending similar low‑value amounts—like a choir of tiny choir members singing the same off‑beat tune. If you’re looking for drama, this is about as dramatic as watching a snail cross the finish line, but the AML engine knows better than that.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits high risk due to a new wallet depositing into a FixedFloat address without KYC, combined with a Sybil fan‑in pattern indicating possible layering.**

Manually review the source wallet and the destination FixedFloat address to confirm the legitimacy of the funds; if suspicious, consider freezing the wallet and reporting to relevant authorities.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggers Rule [no_kyc_offramp] due to the deposit of ETH into a FixedFloat address without any KYC verification, indicating a potential unregulated off‑ramp. Additionally, Rule [sybil_fan_in] is activated as the sender is one of 16 wallets sending similar low‑value amounts, suggesting a Sybil fan‑in layering strategy. The wallet is brand new (age 0 days) with only two total transactions, and the balance is zero, raising suspicion of a wash or layering operation. Further investigation is warranted to ascertain the source of funds and the ultimate beneficiary.

</details>

---

## Finding #10: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x7f745987bd1bc769e07eed51fde6629a3b758270` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431418-26431418 |

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #11: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x2915dbc640917256ab3ae93f1e85f4e4364b3d07` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431412-26431412 |

### 💬 What Happened
A brand‑new wallet (just created this block) sent 0.0002 ETH—about the same as a few pennies—to a service called FixedFloat 1. Think of it like dropping a tiny package into a vending machine that doesn’t ask who you are before letting you take the item. The whole thing happened in a single block, so it was a quick, one‑off move.

### 🔥 The Roast
Looks like someone just tried to play hide‑and‑seek with their crypto. They dropped 0.0002 ETH into FixedFloat 1, a place that’s basically a 'no‑ID, no‑questions‑asked' off‑ramp (think a shady gas station that doesn’t check your driver's license). On top of that, the AML engine flagged a 'sybil fan‑in' pattern (meaning 1 of 16 similar addresses sent almost the same tiny amount—like a choir of identical twins all shouting the same song). The score of 155 is basically the system's way of saying, 'I think you’re up to something.'

### 🎯 Verdict & Next Steps
**CRITICAL — The combination of a new wallet depositing into a no‑KYC off‑ramp and a fan‑in Sybil pattern indicates a high risk of illicit activity.**

Flag this transaction for manual AML review and request additional source‑of‑funds information. Monitor the wallet for further activity, especially any subsequent withdrawals or transfers to other addresses.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Rule no_kyc_offramp (deposit to FixedFloat 1, an off‑ramp that does not perform Know‑Your‑Customer checks) was triggered with a score of 85. Rule sybil_fan_in (fan‑in pattern from 1 of 16 senders with similar amounts within ±30%) was triggered with a score of 70. The transaction involved 0.0002 ETH ($0 USD) from a wallet that is 0 days old, with only 2 total transactions and a zero balance. CRITICAL (rule score 155)

</details>

---

## Finding #12: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x1a06b51007b5470db279f0c42a3b488fac5044fc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431386-26431386 |

### 💬 What Happened
A brand‑new wallet that has never sent a single transaction before just pushed a tiny amount of ETH (0.0002, practically nothing) into an address that is part of a service called FixedFloat 1. Think of it like dropping a single grain of rice into a vending machine that then hides who put it in. Because the sender is brand new and the amount is almost zero, it looks suspiciously like the wallet might be trying to hide its trail.

### 🔥 The Roast
So this new wallet just decided to play hide‑and‑seek with 0.0002 ETH, like a kid tossing a paperclip into a black hole. The engine gave it a 155 score, which is like a red flag on a driver's licence. The 'no_kyc_offramp' rule (meaning the wallet sent money to an address that lets you cash out without any identity verification) scored 85, and the 'sybil_fan_in' rule (meaning many similar tiny deposits from a swarm of new wallets) hit 70. Basically, this is the crypto equivalent of a group of strangers all handing a single penny into a stranger’s pocket to make it look like a community donation. If anyone thinks this is legit, they’re probably the first to know what a “fan‑in Sybil pattern” is.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review by AML analysts. CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet with zero age and only two prior transactions, indicating a newly created address. The wallet sent 0.0002 ETH to FixedFloat 1, a service known for providing no‑KYC off‑ramp capabilities (rule: no_kyc_offramp). Additionally, the transaction aligns with a fan‑in Sybil pattern (rule: sybil_fan_in) as multiple wallets are depositing similar minimal amounts. These patterns raise concerns under AML guidelines for potential obfuscation and high‑risk mixing activity.

</details>

---

## Finding #13: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xbae3543ed60831b5b55ff1577f503c2ed2c6a74e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431372-26431372 |

### 💬 What Happened
A brand‑new wallet just sent a tiny 0.0002 ETH to a FixedFloat contract, which is like dropping a single coin into a slot machine that hides who put it in. The sender has zero history and no identity on record, so nobody knows who actually owns that tiny amount. The transaction is so small that it looks like a drop in a big pool of coins, making it hard to track back to a single source.

### 🔥 The Roast
Scored 85 on no‑kyc‑offramp (meaning the sender is basically a ghost with no ID), and a 70 on sybil_fan_in (so it's one of 16 identical little wallets dumping similar amounts – like a bunch of kids each dropping a coin into the same pot). The wallet is brand new (0 days old) and has only two tiny transactions, so it’s probably a burner. CRITICAL (rule score 155) CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, investigate the source wallet’s origin, and monitor for additional activity to or from the same FixedFloat contract.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created wallet (age 0 days, 2 total transactions, current balance 0 ETH) sending 0.0002 ETH to a FixedFloat contract, triggering the following AML engine rules: [no_kyc_offramp] (score 85) and [sybil_fan_in] (score 70). CRITICAL (rule score 155) CRITICAL (rule score 155) Compliance teams should review the source of the funds and monitor for subsequent activity involving the same contract or related addresses.

</details>

---

## Finding #14: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf3626082fbff334aa004712d2ccf093f2c885a4f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431371-26431371 |

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #15: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x95c7ca0a7fbdec61ec9991c53f71504aae556f3b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431368-26431368 |

### 💬 What Happened
A brand‑new wallet just dropped a tiny amount of ETH (about 0.0002, practically nothing in dollars) into a FixedFloat 1 address. Think of it like someone tossing a single coin into a piggy bank that doesn’t let you see who put it in. The whole transaction is a single, almost negligible, move.

### 🔥 The Roast
So we have a fresh wallet that’s literally brand‑new (0 days old) and it just sent 0.0002 ETH to a FixedFloat 1 address. That’s like a kid handing a single penny to a vending machine that claims to be a “no‑KYC” off‑ramp—because, hey, why not let the IRS do the work? The engine gave it a 155 score, with 85 from [no_kyc_offramp] (meaning the wallet can move money out without any identity check) and 70 from [sybil_fan_in] (so it looks like one of 16 other wallets doing the same tiny trick). Basically, it’s a textbook case of a Sybil fan‑in on a no‑KYC off‑ramp. If this were a party, it’d be the guy who keeps bringing the same cheap bottle to the potluck and nobody knows who he is. Watch out!

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a no‑KYC off‑ramp and a Sybil fan‑in pattern signals a high risk of illicit layering.**

Flag the transaction for manual review by the compliance team, and request additional context such as the source of the funds and any related wallet activity. If further suspicious activity is identified, consider placing a temporary hold or reporting to the relevant authorities.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Transaction involves a newly created wallet (age 0 days, only 2 txs, zero balance) sending 0.0002 ETH to a FixedFloat 1 address. The AML engine flagged the transaction with a composite score of 155, driven by the [no_kyc_offramp] rule (score 85) indicating movement to an off‑ramp that does not require KYC, and the [sybil_fan_in] rule (score 70) indicating a fan‑in pattern from multiple similar wallets. CRITICAL (rule score 155) CRITICAL (rule score 155)

</details>

---

## Finding #16: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc2294dac1e204f7d093b6562019c6f2e7c9c0562` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26431356-26431356 |

### 💬 What Happened
A brand‑new wallet (just created today) sent a tiny amount of ETH—about the size of a grain of sand—to a service that acts like a vending machine for crypto. The money disappeared into a “FixedFloat 1” address, which is a type of off‑ramp that doesn't ask for your ID. It’s like dropping a package into a slot that hides the sender, then watching it vanish.

### 🔥 The Roast
So, this fresh wallet just opened its bank account and decided to play hide‑and‑seek with 0.0002 ETH. It hit the no‑KYC off‑ramp (meaning it went to a place that doesn’t require you to show your ID) and the engine gave it a solid 85 points for that. Then it joined a Sybil fan‑in (meaning 1 of 16 wallets sending similar amounts) and got another 70 points. In total, it scored 155—more points than a bad karaoke night. Looks like someone’s trying to hide a tiny bit of digital cash like a squirrel hiding acorns.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the wallet for manual review and consider adding it to the watchlist. Verify the source of funds and monitor subsequent activity for any further suspicious patterns.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created wallet (0 days old) with only two prior transactions and a zero balance, indicating a potential wash or layering activity. Rule no_kyc_offramp was triggered with a score of 85 due to the deposit to a FixedFloat 1 address, which lacks KYC verification. Rule sybil_fan_in was triggered with a score of 70 as the amount matches a known fan‑in pattern of 1 of 16 senders depositing similar amounts (~0.000 ETH ± 30%). CRITICAL (rule score 155)

</details>

---

## Finding #17: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x40c2a7ac9d234cba1c76b28aacc43ab68e565f43` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1079 ETH** ($196) |
| **Blocks** | 26431548-26431548 |

### 💬 What Happened
A brand‑new wallet (just created) sent about 0.1079 ETH, roughly $196, to a service called FixedFloat 1. The sender had never sent or received anything before, and now its balance is zero because it just emptied the wallet. Think of it as a fresh pizza delivery order that disappears right after the tip is dropped.

### 🔥 The Roast
So we have a wallet that’s 0 days old, 0 balance, and it just dumped 0.1079 ETH into FixedFloat 1. That’s like a new kid at school who walks into the cafeteria and immediately throws their lunch into the trash—no KYC (Know Your Customer) check, no off‑ramps, just a clean swipe. The engine gave it a score of 85 on the no_kyc_offramp rule (meaning the wallet is sending money to a place that can’t verify who’s actually behind it). If this were a bank, we’d be yelling at the teller to put a lock on that drawer. MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM – high engine score combined with a new, KYC‑less wallet and a single outbound transfer to an off‑ramp service suggests a moderate risk of layering or obfuscation.**

MEDIUM (rule score 85)

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
The transaction triggers the rule no_kyc_offramp (score: 85), which flags deposits to FixedFloat 1—an off‑ramp service lacking KYC verification. The sender’s wallet is brand‑new (0 days old), with a single outbound transaction and zero prior activity, indicating a potential attempt to obfuscate the source of funds. MEDIUM (rule score 85) This activity warrants further scrutiny under AML monitoring protocols.

</details>

---

## Finding #18: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd7572e8ee729b58d4c56993f89b6e9a4218979e4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0061 ETH** ($11) |
| **Blocks** | 26431525-26431525 |

### 💬 What Happened
A brand‑new wallet just sent about $11 worth of ETH to a FixedFloat 1 address. Think of it as someone dropping a small package into a slot that hides who sent it, then walking away. Since the sender had never used the network before, there’s no history to explain where the money came from.

### 🔥 The Roast
So, we have a fresh wallet that just tried to play hide‑and‑seek with a FixedFloat 1 address. The engine gave it an 85, which is like a high score on a video game – but that just means the game thinks it’s a potential fraudster. No KYC? That’s like showing up to a fancy dinner with a pizza delivery box. And the wallet’s balance is zero – it’s like someone just finished a pizza and left the box open. Basically, the engine is saying, ‘Hey, this is a new kid who just tried to buy a ticket to the secret club with no ID.’

### 🎯 Verdict & Next Steps
**MEDIUM — The transaction is flagged due to new wallet activity, absence of KYC, and transfer to a known off‑ramp service, but no direct evidence of illicit activity.**

Flag this transaction for manual review, request source‑of‑funds verification, and monitor the receiving address for further suspicious activity.

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
The transaction involves a newly created wallet (age 0 days) that performed its sole transaction of 0.0061 ETH ($11) to the FixedFloat 1 address, an off‑ramp service. The AML engine applied rule no_kyc_offramp, scoring 85, indicating a high risk of unverified source funds and potential use of an unlicensed money‑transit service. The lack of prior activity, zero balance post‑transfer, and absence of KYC documentation further elevate suspicion. MEDIUM (rule score 85)

</details>

---

## Finding #19: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8edb21a8cd7fd97f4113e1d0944ee56b199d7e3b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0066 ETH** ($12) |
| **Blocks** | 26431515-26431515 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #20: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xaff5eeb15f9cd4f133ce293747f477702abc5851` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0654 ETH** ($119) |
| **Blocks** | 26431509-26431509 |

### 💬 What Happened
MEDIUM (rule score 85) This is like dropping a package into a slot that hides who sent it. The sender had no previous activity and no identity verification, so it's a textbook example of a fresh, unverified transfer to an anonymity service.

### 🔥 The Roast
So we have a 0‑day wallet that just decided to play the big spender game with $119 and drop it into FixedFloat 1. No KYC? That's like showing up to a bank with a blank ID and a bag of cash and saying, "I'm just here for a quick deposit." The no_kyc_offramp rule (meaning the transaction goes to an off‑ramp that doesn't verify you) gave it a solid 85 score, which is basically a red flag waving at compliance. MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review by the compliance team, and consider requesting additional source‑of‑funds information or monitoring subsequent activity from the same addresses.

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
MEDIUM (rule score 85) The sender wallet lacks any KYC verification and has no prior transaction history, satisfying the no_kyc_offramp rule (Rule: no_kyc_offramp). MEDIUM (rule score 85) Flag for further investigation.

</details>

---

## Finding #21: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5b94b559186db9d1b009b68aabcf623f5b956688` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0280 ETH** ($51) |
| **Blocks** | 26431504-26431504 |

### 💬 What Happened
A brand-new crypto wallet, with no transaction history, just created and immediately sent 0.028 ETH (about $51) to a FixedFloat 1 address. It's like dropping a small parcel into a locker that hides who dropped it, making it hard for anyone to trace the sender.

### 🔥 The Roast
Well, looks like someone's trying to hide their money like a kid hiding a cookie jar. The new wallet is fresh out of the block factory (0 days old) and just used to dump 0.028 ETH into a FixedFloat 1 address, which is basically the crypto equivalent of a cash machine with no ID check. MEDIUM (rule score 85) If this were a real person, they'd be the kind who buys a lottery ticket with a stranger's credit card and never says a word.

### 🎯 Verdict & Next Steps
**MEDIUM — the high score on the no_kyc_offramp rule and the fresh wallet profile suggest a moderate risk of anonymous money movement.**

Flag the wallet for manual review, request additional source‑of‑funds information, and monitor for subsequent transactions to the same or related addresses.

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
The transaction was executed from a newly created wallet (age 0 days, transaction count 1) to a FixedFloat 1 address, a known off‑ramp service that lacks KYC verification. Rule no_kyc_offramp was triggered with a score of 85, indicating a high likelihood of anonymous money movement. The wallet balance post‑transfer is zero, and there is no prior activity to establish a legitimate source of funds. This pattern raises concern for potential layering or obfuscation of the origin of the assets.

</details>

---

## Finding #22: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x7e29eadeecd43ebcf09a6caadaa60c8c787465ba` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.0000 ETH** ($1,819) |
| **Blocks** | 26431490-26431490 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

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
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #23: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x7260a29d2d2dd4d7bc9d74c29eb02e2572de7913` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0139 ETH** ($25) |
| **Blocks** | 26431470-26431470 |

### 💬 What Happened
A brand-new wallet sent 0.0139 ETH (about $25) to a service called FixedFloat 1. The sender had never used the network before and has no balance after sending. It’s like dropping a small package into a dropbox that doesn’t reveal who sent it.

### 🔥 The Roast
So the newbie wallet just decided to play a game of hide‑and‑seek with 25 bucks. No KYC, no history, just a one‑off drop. It’s like a kid doing a one‑time prank: “Hey, I got a new phone number, send me some crypto!” and the receiver is like, “Sure, no problem, you’re on the no‑KYC list now.” The engine gave it a 85, which means it’s a ‘no‑KYC off‑ramp’ flag (meaning the wallet is sending money to a service that lets you withdraw without verifying identity).

### 🎯 Verdict & Next Steps
**Medium risk due to a new wallet with no KYC sending funds to a service that facilitates unverified withdrawals.**

Manually review the transaction and the receiving service’s compliance status; flag the wallet for ongoing monitoring and consider reporting to the exchange if suspicious activity persists.

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
The transaction originates from a wallet with zero age and a single outgoing transfer of 0.0139 ETH to FixedFloat 1. MEDIUM (rule score 85) The absence of prior activity and zero balance suggests the wallet is likely a newly created front. The composite score of 85 warrants further investigation.

</details>

---

## Finding #24: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x7e22f2ffe0c26d9a1fffda57ea5601ec928c2a6f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0096 ETH** ($17) |
| **Blocks** | 26431426-26431426 |

### 💬 What Happened
A brand new wallet (just created today) sent a tiny amount of about $17 worth of ETH to a service called FixedFloat 1. Think of it like dropping a small package into a mystery box that will forward it without asking who you are.

### 🔥 The Roast
This fresh wallet just dropped 0.0096 ETH into a no‑KYC off‑ramp, scoring a solid 85 on the 'no_kyc_offramp' rule. Basically, it's like a new kid at the playground handing over their lunch to a shady vendor who never asks for ID. The engine thinks this is a red flag because the wallet has no history and the receiver is a known anonymous service. If you want to keep your money safe, maybe check if the wallet knows you before sending it to the 'no‑identity' club.

### 🎯 Verdict & Next Steps
**MEDIUM risk due to a new wallet sending funds to a no‑KYC off‑ramp with a high composite score of 85.**

Flag this transaction for manual compliance review to verify source of funds and confirm the legitimacy of the destination service. Monitor the wallet for any future activity that could indicate layering or further suspicious patterns.

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
Transaction involves a wallet with age 0 days, single transaction history, and zero balance prior to sending 0.0096 ETH to FixedFloat 1, a known no‑KYC off‑ramp service. Rule: no_kyc_offramp (score: 85) indicates high risk due to lack of identity verification. Evidence includes new wallet creation, single outbound transfer, and destination address known for facilitating anonymous movement of funds. Recommend escalation for manual compliance review.

</details>

---

## Finding #25: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xfe2f577cee5d30e0561a7f8abc18436f8fb81965` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2006 ETH** ($365) |
| **Blocks** | 26431399-26431399 |

### 💬 What Happened
A brand-new wallet, which had never been used before, just sent 0.2006 ETH (about $365) to a service called FixedFloat 1. Think of it as a fresh envelope that drops money into a bank that doesn’t ask for ID, leaving no paper trail.

### 🔥 The Roast
Looks like someone just opened a fresh wallet, tossed 0.2006 ETH into a non‑KYC piggy bank called FixedFloat 1, and vanished. The AML engine gave it a 85 because the "no_kyc_offramp" rule (meaning the money is going to a place that doesn’t verify who owns it) fired. It’s like sending a pizza order to a place that never asks for your address—no one knows where it’s going. If you’re hoping to keep it anonymous, you’ve just handed your money to a magician who doesn’t keep receipts.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Review the origin of the 0.2006 ETH for ties to known illicit sources and monitor the destination address FixedFloat 1 for subsequent activity. Consider flagging the wallet for ongoing surveillance.

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
MEDIUM (rule score 85) Wallet age: 0 days, transaction count: 1, current balance after transfer: 0 ETH. Composite score of 85 indicates medium‑high risk. Further investigation is warranted to determine the source and destination of the funds.

</details>

---

## Finding #26: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd600bf6672d81a4b8f4eaca279bcb4cc38686be5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0055 ETH** ($10) |
| **Blocks** | 26431387-26431387 |

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

## Finding #27: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x0b5df5c950f519821f974bfa8388ae9b816d80cb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1800 ETH** ($327) |
| **Blocks** | 26431376-26431376 |

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
| **Sender** | `0x59849e78717b131ae9325bbd8738c55b5315d05a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1394 ETH** ($254) |
| **Blocks** | 26431364-26431364 |

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

## Finding #29: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc6314096cf8bf0023d8eee37d92be670da679792` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$21** (21 USDT) |
| **Blocks** | 26431450-26431450 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $21 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x52aa9c26f334078afde8570ac61d8b42fe69e5f2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$44** (44 USDT) |
| **Blocks** | 26431551-26431551 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $44 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**30 suspicious findings** detected across 30 unique wallets. Highest risk score: **155**.

| | |
|---|---|
| 🔴 CRITICAL | 16 |
| 🟠 HIGH | 0 |
| Wallets flagged | 30 |
| Suspicious value | 1.7665 ETH ($3,214) + $65 in stablecoins |
| Blocks scanned | 26431352 — 26431551 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 5 of 25 attempted analyses this run.

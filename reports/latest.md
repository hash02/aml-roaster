# 🔥 AML Roaster Report
**2026-11-19 20:09 UTC** · Ethereum Mainnet · ETH $1,762.31
**Blocks:** 26451226 — 26451425 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26451226 to 26451425 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 150

| | |
|---|---|
| **Sender** | `0x4b98363885ebf124018e5d779aea033d9d04c95b` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **100.0000 ETH** ($176,231) |
| **Blocks** | 26451422 |

### 💬 What Happened
A user sent 100 ETH (about $176,000) to a service that scrambles transactions, like dropping a package into a box that then randomly gives it to other people so no one knows who started it. The sender's wallet had no balance after the transfer and no recent activity, so it looks like a cold wallet that just made one big move. The transaction was the only one in its block, so it stands out as a single, large transfer.

### 🔥 The Roast
So this guy just dropped a 100‑ETH pizza into the Tornado Cash mixer, hoping the service would hide his pizza bill. The engine gave him a 150‑point score: 50 for being a whale (big transfer) and 100 for the mixer hit (meaning he literally used a service that anonymizes transactions). It’s like a crypto version of a secret Santa—no one knows who gave the gift. He might think he’s playing hide‑and‑seek, but the compliance squad is like "Nice try, but we see you."

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a large transfer to a known mixer triggers a high‑risk flag for potential layering and anonymity abuse.**

Flag the transaction for manual review, request source‑of‑funds documentation, and monitor downstream addresses for suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (2 rules, composite score: 150):
- **whale_transfer** (+50) — Whale transfer: 100.0000 ETH ($176,231)
- **mixer_touch** (+100) — Direct interaction with Tornado Cash Router

**SAR Narrative** *(for compliance teams)*:
Transaction involves a direct interaction with Tornado Cash Router (rule: mixer_touch, score 100) and a large ETH transfer of 100.0000 ETH (rule: whale_transfer, score 50). The sender’s wallet shows no balance post‑transaction and has no recorded recent activity, raising concerns about the source and destination of the funds. This pattern warrants a detailed review to assess potential layering or obfuscation of funds.

</details>

---

## Finding #2: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xe859c0bd25f260baee534fb52e307d3b64d24572` |
| **Target** | Privacy Pools (0xbow) Entrypoint (`0x6818809eefce719e48...`) |
| **Activity** | **2** token transfers totaling **$14,116** (6,607 USDT, 7,508 USDT) |
| **Blocks** | 26451246-26451278 |

### 💬 What Happened
The sender moved about $14,116 worth of USDT into a privacy pool entry point, splitting the money into two transfers of roughly $6,600 and $7,500. Think of it like dropping two packages into a mail slot that scrambles the sender’s identity before the packages get forwarded elsewhere. No one can easily tell who sent the money or where it will end up.

### 🔥 The Roast
So, we’ve got a wallet that decided to play hide-and-seek with its cash, tossing $14K into a privacy pool (the blockchain’s version of a secret Santa). That’s what the engine calls a stablecoin_mixing hit (meaning the coins are being mixed to hide their trail). The score? 110—like a detective who’s seen too many red herrings. In plain English: this guy just hid his $14,000 in a blender and sent it off, hoping no one notices. If you’re looking for a clean audit trail, this is about as good as a paper trail left in a hurricane.

### 🎯 Verdict & Next Steps
**HIGH – the transaction matches a high‑risk stablecoin mixing pattern with no mitigating contextual information.**

Flag the sender wallet for manual review and request additional provenance data. HIGH (rule score 110)

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to Privacy Pools (0xbow) Entrypoint: $14,116 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a classic stablecoin mixing pattern, as identified by rule stablecoin_mixing. The sender (0xe859c0bd25f260baee534fb52e307d3b64d24572) executed two separate USDT transfers totaling $14,116 to the Privacy Pools (0xbow) Entrypoint, within block range 26451246-26451278. HIGH (rule score 110) The absence of additional contextual data (e.g., known beneficial owner, KYC status) necessitates heightened scrutiny.

</details>

---

## Finding #3: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x821dbdb1bc7671bff0f1246c0f2b43bbfb00133a` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$10,449** (10,449 USDT) |
| **Blocks** | 26451255-26451255 |

### 💬 What Happened
Someone sent $10,449 worth of USDT to a wallet that is known to be part of a money‑mixing service. Think of it like dropping a pizza box into a slot that scrambles who put it there. The original sender's identity is now hidden in a pile of other coins.

### 🔥 The Roast
HIGH (rule score 110) The engine gave it a 110 score, which is like a high school report card saying "you need to explain yourself". If you think that's a good score, just remember the rule is "stablecoin_mixing" (meaning the coins were moved through a service that blends transactions to hide origin). No need to call the police; just call the compliance team. This is the kind of transaction that makes auditors do a double take.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag this transaction for manual review by the compliance team. Consider tracing the origin of the USDT and monitoring the sender's future activity for additional suspicious patterns.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $10,449 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
HIGH (rule score 110) It matches the AML engine rule "stablecoin_mixing" (score 110), indicating potential source obfuscation. The sender's wallet has no prior activity records, raising additional red flags. Further investigation is warranted to assess the source and destination of the funds.

</details>

---

## Finding #4: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x26f73220037cdf9ba859caa1c87dafbb0a6c2937` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0039 ETH** ($7) |
| **Blocks** | 26451417-26451417 |

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
| Current Balance | 0.000012 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #5: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4f69fcbe16e2a6a234a734ab6e4ac1b9b8b12f22` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.2534 ETH** ($446) |
| **Blocks** | 26451304-26451304 |

### 💬 What Happened
A brand‑new crypto wallet, which had never sent or received anything before, just sent 0.2534 ETH (about $446) straight into a SideShift hot wallet. MEDIUM (rule score 85) This move basically hides the origin of the money without any identity check.

### 🔥 The Roast
Picture a toddler who just learned to walk dropping a handful of dollars into a mystery box. The wallet, fresh out of the womb, sent the money to a SideShift Hot Wallet – a crypto equivalent of a shady ATM that says ‘no‑ID, no‑questions’. The engine gave it a whopping 85 because it’s a no‑KYC off‑ramp, which is basically the red flag for a “I’m not telling anyone who I am” transaction. If you’re looking for drama, this is the kind of thing that would make a detective’s heart race – and a comedian’s punchline.

### 🎯 Verdict & Next Steps
**MEDIUM risk due to high composite score and no‑KYC off‑ramp activity.**

Flag this transaction for manual review and monitor the wallet for additional activity. Consider cross‑checking with other known mixers and applying enhanced due diligence if the wallet continues to transact.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000007 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a 0‑day wallet with only one outgoing transfer of 0.2534 ETH to a SideShift Hot Wallet (Rule: no_kyc_offramp). The wallet’s lack of prior activity, coupled with the high composite score (85), satisfies the criteria for a suspicious activity report under the no‑KYC off‑ramp rule. MEDIUM (rule score 85) Flag for further review.

</details>

---

## Finding #6: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x55c19882c36076b20c7faeead888effe527254df` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.6178 ETH** ($1,089) |
| **Blocks** | 26451272-26451272 |

### 💬 What Happened
The sender’s brand‑new wallet just sent 0.6178 ETH to a hot wallet that mixes transactions—think of it like dropping a package into a blender that hides where it came from. The wallet was created the same day it was used and has never sent any funds before, so there’s no history to explain why this money is being moved.

### 🔥 The Roast
Looks like someone just built a new wallet and did a one‑stop shop: a fresh address, a fresh transaction, and a fresh mystery—like buying a pizza and immediately putting it in a blender. 0.6178 ETH is about the size of a small pizza, and sending it straight to SideShift is like handing that pizza to a shady kitchen that promises you’ll never see the toppings again. No KYC? That’s like driving a car with no license plate—totally untraceable. The engine gave it an 85 on no_kyc_offramp, which is basically the crypto world’s version of a “red flag” emoji. Bottom line: this is the kind of move that makes auditors raise an eyebrow and say, “Hold my coffee, we’ve got a suspect.”

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Conduct a manual review of the sender’s wallet and any subsequent transactions, and file a SAR if further suspicious patterns emerge.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000007 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 85) The sender wallet is brand new (0 days old) and has only performed this single transaction, indicating no historical context to justify the movement. MEDIUM (rule score 85)

</details>

---

## Finding #7: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9bdd18d3115c05b7b091c67e196d12afacf6d57f` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$50** (50 USDC) |
| **Blocks** | 26451401-26451401 |

### 💬 What Happened
A person sent 50 USDC, which is a digital dollar, to a wallet that belongs to a service called SideShift that helps people hide where their money came from. It’s like dropping a $50 bill into a slot machine that then rewrites the receipt so the original owner can’t be traced. This single move is all the evidence we have.

### 🔥 The Roast
MEDIUM (rule score 80) The wallet’s name suggests it’s a hot spot for mixing, meaning the coins are probably getting shuffled with others to hide their trail. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for manual review, request additional context on the source of the USDC, and monitor the wallet for further suspicious activity.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $50 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) MEDIUM (rule score 80) MEDIUM (rule score 80) MEDIUM (rule score 80)

</details>

---

## Finding #8: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x612bc47545e11f9415e0d56f6679c7fec921bfdf` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDT) |
| **Blocks** | 26451383-26451383 |

### 💬 What Happened
A person sent $1,000 worth of USDT (a stablecoin that behaves like a digital dollar) to a wallet that is known to be used for mixing transactions. MEDIUM (rule score 80) The sender's wallet has no recent activity and no balance, so it's unclear where the money came from.

### 🔥 The Roast
Looks like someone tried to play hide-and-seek with their $1,000. They sent it straight to a SideShift Hot Wallet—think of it as the Bitcoin equivalent of a laundromat that only accepts cash, but no receipt. The transaction is a perfect 1,000 USDT, like a banker who insists on writing checks in round numbers because decimals are too much hassle. MEDIUM (rule score 80) If you ask me, it's like sending a pizza to a stranger's address and then hoping nobody notices.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for manual review. Verify source of funds and consider additional due diligence on the sender's wallet.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $1,000 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Transaction involving a single USDT transfer of $1,000 from 0x612bc47545e11f9415e0d56f6679c7fec921bfdf to SideShift Hot Wallet 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2. MEDIUM (rule score 80) MEDIUM (rule score 80) Flag for further review per AML policy.

</details>

---

## Finding #9: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xdd8528a6acd01b4a131a3faa245ff40364c1185e` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$5** (5 USDT) |
| **Blocks** | 26451351-26451351 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $5 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #10: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf788c8f8897d9fca11e417e88f2696c6e8a6bdf0` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$155** (155 USDT) |
| **Blocks** | 26451332-26451332 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $155 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #11: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x42363c07ef6b89f178ed1fde3c790315eb8974db` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$150** (150 USDT) |
| **Blocks** | 26451321-26451321 |

### 💬 What Happened
A single $150 USDT transfer was sent to a SideShift Hot Wallet, a service that scrambles the trail of who owns the money—think of it like dropping a package into a vending machine that hides the sender’s name. The sender’s address has no visible history, and the transfer was the only transaction in that block.

### 🔥 The Roast
So this guy decided to play hide‑and‑seek with his $150, tossing it into SideShift’s hot wallet. MEDIUM (rule score 80) He’s basically trying to make his money as anonymous as a celebrity at a pizza joint, but the audit trail is still there. If only he’d paid more attention to the obvious red flag—like a cashier spotting a counterfeit bill—he’d have saved himself the trouble. This is the kind of move that makes compliance teams go “uh‑uh, we’re not having a party with this.”

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for manual review, request additional sender context, and consider placing a hold on the wallet for further monitoring.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $150 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction (ID: 26451321) involves a single transfer of 150.1652 USDT from address 0x42363c07ef6b89f178ed1fde3c790315eb8974db to a SideShift Hot Wallet (0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2). MEDIUM (rule score 80) The evidence includes the unique sender, the exact amount, and the fact that the transaction occurred in a single block with no prior activity record for the sender. MEDIUM (rule score 80)

</details>

---

## Finding #12: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3cb7308f4bc64a8b9d3da3c1a0dc4519941da276` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$17** (17 USDT) |
| **Blocks** | 26451313-26451313 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $17 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #13: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe2185448cd73297a9d19282447d2b06fb411252d` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$31** (31 USDT) |
| **Blocks** | 26451309-26451309 |

### 💬 What Happened
A user sent 31 USDT (a stablecoin that keeps its value close to the US dollar) to a hot wallet belonging to a service called SideShift. Think of it like dropping a small envelope into a vending machine that then throws the money into a different slot so you can’t tell where it came from. The transaction was the only one in that block, and it was just one single transfer of about $31.

### 🔥 The Roast
MEDIUM (rule score 80) The engine flagged it with a stablecoin_mixing score of 80 (meaning the transaction looks like a classic 'laundry' operation that hides the source). It’s like putting a $31 bill in a coin machine that turns it into a bunch of tiny coins you can’t trace. MEDIUM (rule score 80) If you’re wondering what ‘stablecoin’ means, it’s just a digital dollar that doesn’t swing wildly like Bitcoin.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction triggers a stablecoin mixing pattern with a composite score of 80, indicating moderate risk but not definitive evidence of illicit activity.**

Flag the transaction for manual review and monitor the sender and receiver addresses for additional suspicious activity. MEDIUM (rule score 80)

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $31 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction triggered the stablecoin_mixing rule, which is designed to identify single transfers of stablecoins to known mixing services. Evidence includes the 31 USDT transfer to the SideShift Hot Wallet (address 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2) in block 26451309, with no prior activity data for the sender. MEDIUM (rule score 80) MEDIUM (rule score 80)

</details>

---

## Finding #14: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2498ac162bd1cc662b2f28031c2728e4c8ed7d62` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDC) |
| **Blocks** | 26451306-26451306 |

### 💬 What Happened
A user sent $1,000 worth of USDC to a hot wallet that belongs to SideShift, a service that mixes coins. This is like dropping a package into a mailbox that hides who mailed it; the sender’s identity is obscured. MEDIUM (rule score 80)

### 🔥 The Roast
MEDIUM (rule score 80) 1,000 USDC to a SideShift hot wallet—looks like someone tried to hide their money like a magician with a disappearing coin trick. The sender’s wallet has zero ETH and no visible activity—like a ghost with a bank account. MEDIUM (rule score 80) If you think this is a big deal, you might want to ask the person for a receipt.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Perform a manual review of the sender’s transaction history and source of funds. If no legitimate explanation is found, consider reporting to relevant authorities.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $1,000 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) MEDIUM (rule score 80) The sender has no recorded activity and the wallet balance is zero ETH, raising concern about source of funds. Further investigation is recommended.

</details>

---

## Finding #15: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd70990885beffeadba786ef1294231312d8ec337` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$6,400** (6,400 USDC) |
| **Blocks** | 26451300-26451300 |

### 💬 What Happened
A single payment of $6,400 in USDC was sent from a wallet with no history to a SideShift Hot Wallet, which is a type of online mixing service that shuffles funds to hide their origin. It’s like dropping a money envelope into a vending machine that then hands it out to someone else without showing who paid for it. The transaction happened in one block, so it was a quick one‑time move.

### 🔥 The Roast
So this wallet just decided to send $6,400 to a SideShift Hot Wallet—yes, the same one that pretends to be a regular address but is basically a crypto version of a secret Santa. MEDIUM (rule score 80) The sender has a zero ETH balance, so they’re basically a paper wallet that can’t even pay gas. MEDIUM (rule score 80) Bottom line: this is the kind of transaction that makes compliance folks raise an eyebrow and say, "Hold the phone!"

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Initiate a manual review of the sender and receiver addresses, track any subsequent activity, and consider flagging the transaction for additional compliance investigation.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $6,400 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a single transfer of 6,400 USDC from an unknown, inactive wallet to a SideShift Hot Wallet, which is flagged under the stablecoin_mixing rule (score: 80). This pattern meets the criteria for potential mixing activity as defined by AML Rule stablecoin_mixing, indicating a higher risk of illicit fund movement. MEDIUM (rule score 80) Further investigation is warranted to confirm the source and destination of the funds.

</details>

---

## Finding #16: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6a000f20005980200259b80c5102003040001068` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$8** (8 USDC) |
| **Blocks** | 26451271-26451271 |

### 💬 What Happened
A user sent about $8 worth of USDC to a wallet that belongs to SideShift, a service that mixes coins to hide where they came from. It’s like dropping a package into a mail slot that scrambles the sender’s address so nobody knows who actually mailed it.

### 🔥 The Roast
Scored 80 on the stablecoin_mixing rule (meaning a single stablecoin transfer to a hot wallet that probably scrambles the source) – basically a classic “I’m sending money and nobody knows where it came from” move. MEDIUM (rule score 80) The sender’s wallet is basically a ghost with zero balance and unknown history – perfect for a magician’s disappearing act.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $8 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a single USDC transfer of $8 from an unknown sender (0x6a000f20005980200259b80c5102003040001068) to the SideShift Hot Wallet (0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2) in block 26451271. This matches the rule stablecoin_mixing with a composite score of 80, indicating potential mixing activity. The sender wallet has no recent activity and no balance, increasing the suspicious nature of the transaction. Further investigation is warranted to determine the source and ultimate destination of the funds.

</details>

---

## Finding #17: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa3e8c8007b4b227a6cf1e9ed061a78cb14521e05` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDC) |
| **Blocks** | 26451235-26451235 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $1,000 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #18: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x78a57679a434a2caa3046335195130af6c5a5179` |
| **Target** | Privacy Pools (0xbow) Entrypoint (`0x6818809eefce719e48...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26451278-26451278 |

### 💬 What Happened
The wallet 0x78a57679a434a2caa3046335195130af6c5a5179 just dropped a $0 ETH packet into a privacy pool entry point (think of it as tossing an empty envelope into a mailbox that hides who you are). MEDIUM (rule score 75)

### 🔥 The Roast
So we have a wallet that’s been around for 213 days, made 1,722 trips, and now decides to play hide‑and‑seek with a $0 ETH packet. That’s like showing up at a party, ordering a free drink, and then pretending you never left. The privacy protocol hit (score 75) means it’s using a non‑Tornado privacy pool – basically a new‑age cloak‑room for crypto. If this were a bank, we’d be saying, “Hey, you just tried to hide a $0 bill in a vault. Are you a magician or just messing with us?”

### 🎯 Verdict & Next Steps
**Medium risk due to the use of a privacy protocol without any value transfer, indicating a possible attempt to obscure transaction intent.**

Flag the wallet for monitoring and investigate any subsequent transactions that may flow through the same privacy pool entry point. Consider cross‑checking with other AML rules for potential layering or structuring patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 213 days |
| Total Transactions | 1722 |
| Current Balance | 0.015740 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Privacy Pools (0xbow) Entrypoint — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction from 0x78a57679a434a2caa3046335195130af6c5a5179 to 0x6818809eefce719e480a7526d76bd3e561526b46 (Privacy Pools (0xbow) Entrypoint) was evaluated under Rule [privacy_protocol], scoring 75 for deposit to a privacy protocol. The wallet is 213 days old with 1,722 total transactions and a current balance of 0.015740 ETH, and the transaction value is $0. This pattern is consistent with a potential attempt to obfuscate transaction flow via a privacy pool, warranting further review. MEDIUM (rule score 75)

</details>

---

## Finding #19: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x6c5816afbe2c0cda91742651e3bb63f80d25a59c` |
| **Target** | Privacy Pools (0xbow) Entrypoint (`0x6818809eefce719e48...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26451246-26451246 |

### 💬 What Happened
The sender made a transaction that looks like they slipped a zero‑dollar envelope into a privacy box—no real money moved, just a placeholder entry in a secret mixing pool.

### 🔥 The Roast
Got a 75 on the privacy_protocol score (that means this address is basically a secret box where you hide your coins, like a hidden sock drawer for crypto). MEDIUM (rule score 75) MEDIUM (rule score 75) The engine flags it because privacy protocols can be a cover for illicit activity, even if nothing actually changed hands.

### 🎯 Verdict & Next Steps
**The activity is flagged as medium risk because it involves a privacy protocol transaction, even though no value was transferred.**

MEDIUM (rule score 75)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 286 days |
| Total Transactions | 1985 |
| Current Balance | 0.019473 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Privacy Pools (0xbow) Entrypoint — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Rule: privacy_protocol (Deposit to Privacy Pools (0xbow) Entrypoint). Evidence: single transaction with zero ETH value, no token transfers, block 26451246, wallet age 286 days, 1985 total tx count, current balance 0.019473 ETH, no days since last activity. The engine assigns a composite score of 75, indicating a moderate risk due to the use of a privacy protocol, despite the lack of monetary transfer.

</details>

---

## Scan Summary

**19 suspicious findings** detected across 19 unique wallets. Highest risk score: **150**.

| | |
|---|---|
| 🔴 CRITICAL | 1 |
| 🟠 HIGH | 2 |
| Wallets flagged | 19 |
| Suspicious value | 100.8751 ETH ($177,773) + $34,381 in stablecoins |
| Blocks scanned | 26451226 — 26451425 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 5 of 19 attempted analyses this run.

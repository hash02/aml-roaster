# 🔥 AML Roaster Report
**2026-11-10 01:23 UTC** · Ethereum Mainnet · ETH $2,126.47
**Blocks:** 26380964 — 26381163 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26380964 to 26381163 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381021-26381160 |

### 💬 What Happened
The wallet made four tiny, identical deposits of 0 ETH to a bridge service that moves funds between blockchains, all in quick succession. It's like someone slipping four identical empty envelopes into a slot to make it look like they sent a single, large package, but in reality, they’re just trying to hide the flow of funds.

### 🔥 The Roast
First off, structuring 70 points for the classic "I’m just making a tiny deposit, not a big one" routine – it's like showing up to a bank with a paper bag of pennies and pretending it's a fortune. The peel_chain_linear 60 points? Yeah, four identical moves in a row – it's the blockchain equivalent of a magician pulling the same card out of a deck over and over. And the bridge_hop 65 points? That’s the grand finale where the funds hop over to a different chain, like a sneaky cat jumping from one rooftop to another. CRITICAL (rule score 195) Instead, we just see a suspiciously choreographed dance.

### 🎯 Verdict & Next Steps
**CRITICAL — the identical zero-value deposits followed by a cross-chain bridge constitute a high-risk structuring and layering activity that warrants urgent review.**

Flag the transaction for manual review, examine the sender’s prior activity and potential source of funds, and consider filing a formal SAR if additional suspicious indicators are confirmed.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1085 days |
| Total Transactions | 213903 |
| Current Balance | 0.830841 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The account performed four identical zero-ETH deposits (Rule: structuring) over a narrow block window, followed by a transfer to Across SpokePool V2 (Rule: bridge_hop). The peel_chain_linear pattern indicates a layering attempt, as the deposits were sequential and identical, suggesting an attempt to obfuscate origin. The wallet has a long history (1085 days, 213,903 txs) but the immediate pattern raises red flags for potential structuring and layering. Further investigation is warranted to determine source and destination intent.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **11** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26380965-26381157 |

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
| Wallet Age | 38 days |
| Total Transactions | 10891 |
| Current Balance | 0.023289 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 11 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 11 sequential similar deposits — layering pattern
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
| **Activity** | **15** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26380970-26381157 |

### 💬 What Happened
The sender sent 15 almost identical tiny ETH payments (each 0.0000 ETH, basically nothing) to a bridge that moves funds between blockchains. It's like a person dropping 15 identical empty envelopes into a mailbox to hide that they were sending a letter, but the letter is invisible. The pattern looks suspicious because it repeats exactly, even though each payment is negligible.

### 🔥 The Roast
Looks like someone tried to smuggle a billion tiny coins through a cross‑chain tunnel. The AML engine gave a 70 on structuring (meaning they’re doing textbook smurfing), 60 on peel_chain_linear (they’re layering the dust into a straight line like a traffic cop’s straight‑ahead sign), and 65 on bridge_hop (they’re hopping across chains like a hopscotch champion). If you think 0.0000 ETH is nothing, just wait until they add a real amount and call it a ‘test’.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

CRITICAL (rule score 195) If further suspicious activity is found, consider filing a SAR and notifying relevant authorities.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 88 days |
| Total Transactions | 28988 |
| Current Balance | 0.548274 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 15 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 15 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction set exhibits multiple red flags: 15 consecutive deposits of 0.0000 ETH trigger the Structuring rule (score 70), indicating possible smurfing. The Peel Chain Linear rule (score 60) is activated due to the linear sequence of identical deposits, suggesting layering. The Bridge Hop rule (score 65) is triggered by the transfer to Across SpokePool V2, a known cross‑chain bridge, which may facilitate layering and obfuscation. The sender’s wallet is 88 days old with 28,988 transactions and an active balance of 0.548274 ETH, and there is no time lag between the last activity and these transactions, increasing suspicion.

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **31** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26380965-26381136 |

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
| Wallet Age | 2796 days |
| Total Transactions | 849597 |
| Current Balance | 12.956931 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 31 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 31 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **12** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26380966-26381097 |

### 💬 What Happened
The sender repeatedly moved the same tiny amount of ETH—exactly 0.0000 ETH—twelve times into a bridge that moves funds between blockchains. It’s like someone dropping the same empty cup into a slot 12 times in a row, trying to hide the fact that they’re using a mixing service to disguise the flow of money.

### 🔥 The Roast
Looks like someone took the "smurfing" manual and literally followed it: 12 identical zero‑ETH deposits (structuring score 70, meaning they’re trying to break up a single transaction into a bunch of invisible ones). Then they added a peel chain (score 60) by sending each one right after the other—think of it as a line of dominoes that all fall the same way. Finally, they hopped across chains via Across SpokePool V2 (bridge_hop score 65), so the money is now on a different blockchain, like moving a package from a courier to a secret drop‑box. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the account for manual review, request source‑of‑funds documentation, and monitor for any further cross‑chain activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 243 days |
| Total Transactions | 17469 |
| Current Balance | 0.091607 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 12 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 12 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction history of wallet 0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427 shows 12 consecutive deposits of 0.0000 ETH to address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2. This pattern triggers the following AML engine rules: [structuring] (score: 70) for identical minimal amounts, [peel_chain_linear] (score: 60) for sequential similar deposits indicating layering, and [bridge_hop] (score: 65) for cross‑chain movement. CRITICAL (rule score 195)

</details>

---

## Finding #6: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381038-26381067 |

### 💬 What Happened
The wallet sent the same 0 ETH three times in a row, like someone trying to drop a zero‑gram parcel into a slot to hide how many times they put it there. The transfers were to a bridge called Across SpokePool V2, which moves crypto from one chain to another, and the sender’s wallet has been very active with almost 30,000 transactions. In plain terms, it’s like someone repeatedly putting empty envelopes through a mail‑drop box that forwards them to a different city, hoping the emptiness will disguise the pattern.

### 🔥 The Roast
First, we’ve got a textbook case of "structuring" (splitting money into many tiny pieces to slip past limits) – except here the pieces are all 0.0000 ETH, so it’s like trying to smuggle a paperweight by putting it in three separate envelopes. Next up, the "peel_chain_linear" rule flags a sequence of similar moves – think of it as peeling an onion, but the onion is made of invisible layers. Finally, the "bridge_hop" rule caught the transfer to Across SpokePool V2, a cross‑chain bridge (imagine a toll bridge that takes your car to a different country). The engine’s score of 195 means it’s as suspicious as a magician who keeps pulling a rabbit out of a hat that never had one.

### 🎯 Verdict & Next Steps
**CRITICAL – The pattern of three identical zero‑value deposits, combined with bridging activity and a high transaction volume, signals potential layering and structuring, warranting immediate review.**

Flag the transaction for manual investigation, request additional transaction context from the wallet owner, and consider enhancing KYC verification for the sender.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 329 days |
| Total Transactions | 29168 |
| Current Balance | 0.197502 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender executed three consecutive ETH transfers of 0.0000 each to Across SpokePool V2, satisfying the structuring rule (Rule ID: structuring) due to identical amounts. The pattern also triggered peel_chain_linear (Rule ID: peel_chain_linear) as a linear peel chain, indicating potential layering. Bridge_hop (Rule ID: bridge_hop) was activated by the use of a cross‑chain bridge. Given the high transaction volume and recent activity, this activity warrants a deeper AML review.

</details>

---

## Finding #7: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x93211e04c224992e8f7dae8ff36cc5d32e11dd6d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26381077-26381077 |

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
| Total Transactions | 4 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #8: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x44c065503967b8af6dd8bd411d69033574f95d46` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26381066-26381066 |

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
| Total Transactions | 4 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #9: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb9376b64647a88a8bdf71b70bb94c761e8a53c8a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26381028-26381028 |

### 💬 What Happened
A brand‑new wallet that had only made a couple of moves just sent a tiny amount of ETH—about 0.0001—to another address. It's like a new kid dropping a single toy into a sandbox that hides where it came from. The amount is almost nothing, but the pattern looks suspicious because the sender is new and the transaction is part of a group of similar small transfers.

### 🔥 The Roast
Looks like this wallet is trying to hide in plain sight—scored a whopping 85 on no_kyc_offramp (meaning it’s a no‑know‑your‑customer exit point, basically a 'no ID' tunnel). And then 70 on sybil_fan_in (so it’s part of a fan‑in crowd that all look like clones, each sending almost the same teeny‑tiny amount). The sender is brand new, barely 0 days old, and has only 2 transactions—like a rookie in a pool of bad actors. This is the kind of move that would make a detective want to pull out a magnifying glass. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, request source‑of‑funds details, and consider a temporary hold pending investigation by the compliance team.

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
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Rule no_kyc_offramp triggered due to deposit to FixedFloat 1 with no KYC verification, indicating a potential off‑ramp to an unregulated exit point. Rule sybil_fan_in flagged because this transaction is one of at least 10 similar deposits (~0.0001 ETH ±30%) from distinct senders, suggesting a Sybil fan‑in pattern. The sender wallet is 0 days old, with only 2 total transactions and a zero balance, which is typical of newly created wallets used for layering. Given the composite score of 155, this activity warrants a suspicious activity report and further investigation.

</details>

---

## Finding #10: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xbf070086ab4959d1159d53a9a74e5816bccbbfe4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26381018-26381018 |

### 💬 What Happened
A brand-new wallet just sent 0.0001 ETH to a FixedFloat address. It's like a fresh email account sending a tiny note to a mailing list that hides the sender's identity. The wallet has only made two transactions in its lifetime, so there's nothing to prove it's legitimate.

### 🔥 The Roast
Looks like someone just tried to sneak a micro‑tip into a FixedFloat, hoping the anonymity of no‑KYC off‑ramp will hide their tracks. 0.0001 ETH? That's the size of a paperclip in crypto terms. The engine gave it a 155 score, which is about as high as a toddler's curiosity level. The no‑KYC off‑ramp rule (meaning the user can deposit and then cash out without any identity verification) and the sybil fan‑in rule (meaning many new wallets are feeding similar amounts into the same address) are both waving red flags. If this was a party, they'd be the two people who keep showing up with the same weird snack.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a new wallet, no‑KYC off‑ramp, and Sybil fan‑in pattern indicates a high risk of illicit behavior.**

Flag the wallet for manual review, trace downstream transactions, and consider adding the address to the watchlist. If the wallet continues to deposit into FixedFloat, investigate the source and possible connection to known mixers.

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
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a 0‑day wallet that has executed only two ETH transfers, both involving an amount of 0.0001 ETH to the FixedFloat 1 address. According to rule [no_kyc_offramp] (deposit to FixedFloat 1 with no KYC off‑ramp), the transaction carries a high risk score of 85. Additionally, rule [sybil_fan_in] identified a Sybil fan‑in pattern, scoring 70, due to multiple new wallets depositing similar small amounts into the same address. These indicators warrant further investigation as potential structuring and anonymity‑facilitated activity.

</details>

---

## Finding #11: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xcaee3222c0a45ae007e990271acb54d5a175e272` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26381009-26381009 |

### 💬 What Happened
The user just dropped a tiny bit of ether (0.0001 ETH) into a service that lets people move money around without showing who they are. It’s like sending a postcard through a mysterious box that hides the sender’s address, and the whole wallet is brand‑new, so there’s no history to check. Because the transfer goes straight to a ‘FixedFloat 1’ service, it looks like an attempt to hide the money’s origin.

### 🔥 The Roast
So this fresh wallet, still smelling like yesterday’s coffee, just decided to play the no‑KYC game and slingshot 0.0001 ETH into FixedFloat 1—no, not a typo, the service literally says ‘FixedFloat 1’ (meaning it’s a fixed‑amount off‑ramp). The AML engine gave it a 155 score, which is like the IRS giving you a tax audit for a 1 cent purchase. Rule no_kyc_offramp (score 85) is basically saying ‘you’re trying to disappear money without identity proof’, and sybil_fan_in (70) means this is one of a bunch of little wallets all sending the same teeny‑tiny amount—think of a swarm of mosquitoes all landing on the same spot. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — The combination of a new, KYC‑free wallet depositing to an off‑ramp service, coupled with a fan‑in Sybil pattern, triggers a high‑risk alert under AML rules.**

Flag this transaction for manual review by the compliance team and request additional context on the source of funds. Consider monitoring the wallet for subsequent activity and cross‑checking against known suspicious addresses.

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
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
This transaction triggers Rule no_kyc_offramp with a score of 85, indicating the movement of funds to a FixedFloat 1 off‑ramp without any KYC verification. Additionally, Rule sybil_fan_in scored 70, reflecting a fan‑in pattern of 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%), suggesting potential Sybil activity. The sender’s wallet is new (age 0 days) with only 2 prior transactions and a zero balance, further raising suspicion of a freshly created wash‑wallet. CRITICAL (rule score 155)

</details>

---

## Finding #12: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x8818c8955f940f39b628d94eac650b01a182e0e1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26380997-26380997 |

### 💬 What Happened
CRITICAL (rule score 155) The sender's address is brand‑new and has no balance after the send, so it's like a one‑night stand with a crypto wallet.

### 🔥 The Roast
Scored 85 on the no_kyc_offramp rule (meaning the address is basically a "no‑know‑your‑customer" dump site) and 70 on sybil_fan_in (meaning this wallet is one of ten similar tiny deposits, like a group of friends each giving a penny to a secret club). The engine is basically saying, "Hey, this looks like a secret Santa where nobody knows who gave what." It's like a secret Santa but with less glitter and more anonymous crypto. If you thought the world of crypto was a simple game of Monopoly, think again – this is the Monopoly board in a black‑market warehouse.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction shows high risk due to no‑KYC off‑ramp and Sybil fan‑in pattern, requiring immediate review.**

Flag the transaction for manual review, investigate downstream recipients, and perform enhanced due diligence on the sender and any linked addresses.

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
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Transaction ID 0x8818c8955f940f39b628d94eac650b01a182e0e1 sent 0.0001 ETH to 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f on block 26380997. The sender wallet is 0 days old, has 2 total transactions, and has a zero balance after the transfer, indicating a potential wash or layering operation. The AML engine produced a composite score of 155, with rule no_kyc_offramp (85) for a deposit to FixedFloat 1 without KYC, and rule sybil_fan_in (70) for fan‑in pattern of similar small deposits. CRITICAL (rule score 155)

</details>

---

## Finding #13: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x16a1e45557abaefad1d02932b8c341a6521b4617` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26380981-26380981 |

### 💬 What Happened
A brand-new wallet (like a fresh account just created this week) sent a tiny amount of ETH—0.0001—to a special address called FixedFloat 1, which acts like a mixing service that hides where the money came from.

### 🔥 The Roast
CRITICAL (rule score 155) The engine gave that move an 85 on the no‑KYC off‑ramp rule (meaning you’re basically saying, 'I’m not going to verify who I am—good luck, regulators!') and a 70 on the sybil fan‑in rule (you’re one of ten new wallets all doing the same tiny trick, like a group of pranksters in a school hallway). With a composite score of 155, the system thinks you’re probably just trying to play hide‑and‑seek with your money.

### 🎯 Verdict & Next Steps
**CRITICAL – the composite score of 155, coupled with a new wallet, no‑KYC off‑ramp, and Sybil fan‑in pattern, warrants immediate human review.**

Flag the transaction for manual compliance review and request additional identity verification for the sender. CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a zero‑day wallet with only two prior transactions and no current balance, indicating a fresh, potentially unverified source. CRITICAL (rule score 155) Additionally, the pattern matches Rule: sybil_fan_in, as the same amount is being sent by 9 other similar new wallets. CRITICAL (rule score 155)

</details>

---

## Finding #14: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf1bdfa6287eb4c03a16b24037c1deada26bf20ba` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26380978-26380978 |

### 💬 What Happened
A brand‑new wallet, with no money in it, just sent 0.0001 ETH to a FixedFloat smart contract. Think of it as dropping a single coin into a vending machine that immediately forwards it to a bank that doesn’t ask who you are. The transaction is tiny, but it’s the kind of move a fresh, anonymous account might make when trying to hide where its money came from.

### 🔥 The Roast
So we’ve got a wallet that’s basically a newborn baby—0 days old and only had two tiny transactions. It tossed a minuscule 0.0001 ETH into a FixedFloat 1 (meaning it’s a no‑KYC off‑ramp, score 85 on the no_kyc_offramp rule, which is like giving your money a free pass to the blockchain without identity verification). And to top it off, it’s part of a fan‑in Sybil pattern (score 70 on sybil_fan_in), where dozens of these newborn wallets are all sending similar, almost identical amounts—like a choir of identical babies all chanting the same tiny coin. If this was a real life party, it would be the kind that keeps everyone guessing who’s actually handing out the money.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of a brand‑new wallet, a no‑KYC off‑ramp destination, and a Sybil fan‑in pattern indicates high risk of illicit activity.**

Flag the transaction for manual review and request additional source‑of‑funds information. Consider placing a hold on the wallet if the pattern of similar low‑value deposits continues.

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
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet with 0 days of age, a total of 2 transactions, and a current balance of 0.000000 ETH, indicating it is newly created and likely used for a short‑lived purpose. The transfer to FixedFloat 1 triggers the no_kyc_offramp rule (score 85), highlighting a potential KYC‑free exit. Additionally, the pattern of similar low‑value deposits from multiple new wallets aligns with the sybil_fan_in rule (score 70), suggesting a possible Sybil or layering scheme. These indicators collectively raise the risk profile of the activity under AML monitoring.

</details>

---

## Finding #15: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x7921e5f811ddf3fd77322823a7a568484843f45c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26380974-26380974 |

### 💬 What Happened
A brand-new wallet (created just now) sent a tiny 0.0001 ETH to a FixedFloat 1 address. Think of it like someone dropping a single marble into a slot that hides the sender's identity. The transaction was so small it probably wouldn't show up in a normal bank check.

### 🔥 The Roast
So we got a brand new wallet that just did a micro‑transfer to a FixedFloat 1 address. That's the kind of move a crypto‑kiddo does when they think 'I'll hide this tiny 0.0001 ETH in a no‑KYC off‑ramp and call it a day.' No KYC? No problem! They’re basically playing hide‑and‑seek with regulators. And because we see a handful of other wallets doing the same exact tiny transfer, it's a classic Sybil fan‑in pattern — like a choir of parrots all singing the same tiny note. The engine gave us a composite score of 155, which is basically a red flag waving like a neon sign.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of a no‑KYC off‑ramp and a Sybil fan‑in pattern with a brand‑new wallet constitutes a high‑risk indicator requiring immediate review.**

Flag this transaction for manual review and investigate the sender’s upstream activity. CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits characteristics consistent with Rule [no_kyc_offramp] (score: 85) due to the deposit to a FixedFloat 1 address, which is identified as a no‑KYC off‑ramp. Additionally, Rule [sybil_fan_in] (score: 70) is triggered by the presence of multiple senders (1 of 10) depositing amounts within ±30% of 0.0001 ETH, indicating a fan‑in Sybil pattern. The sender wallet is brand new (0 days) with only 2 transactions and no current balance, raising concerns of potential layering or structuring. These findings warrant further investigation per AML policy.

</details>

---

## Finding #16: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf0a237475a592bb877c42d064efc7139306e220e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26380969-26380969 |

### 💬 What Happened
Someone just sent 0.0001 ETH from a brand-new wallet to a FixedFloat 1 address. The sender hasn't had any activity before, and the amount is tiny, like a penny in crypto terms. CRITICAL (rule score 155)

### 🔥 The Roast
So, a brand‑new wallet just dropped 0.0001 ETH into a FixedFloat 1 address. That’s basically a micro‑tipping of the blockchain, but with the flavor of a no‑KYC off‑ramp (meaning the money can’t be easily traced back to a real person). And to top it off, it’s part of a fan‑in Sybil pattern (10 or more similar tiny deposits from different addresses, like a bunch of strangers all sending the same tiny pizza tip). Basically, it’s the blockchain version of a “who’s sending the pizza?” mystery.

### 🎯 Verdict & Next Steps
**CRITICAL — This transaction shows a high composite score of 155, no KYC off‑ramp, and Sybil fan‑in pattern.**

Flag the sender wallet for manual compliance review and add it to the watchlist for future activity. CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 10 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Transaction 26380969 exhibits a composite AML score of 155, driven by two high‑risk rules: [no_kyc_offramp] (score 85) indicating a deposit to an off‑ramp lacking KYC, and [sybil_fan_in] (score 70) showing fan‑in Sybil activity with multiple senders depositing similar amounts (~0.000 ETH ± 30%). CRITICAL (rule score 155) CRITICAL (rule score 155) Compliance should consider flagging this wallet for further monitoring.

</details>

---

## Finding #17: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **13** token transfers totaling **$12,964** (694 USDC, 148 USDC, 9,952 USDC, 324 USDC, 592 USDC) |
| **Blocks** | 26380973-26381163 |

### 💬 What Happened
The wallet sent a bunch of stablecoins (like dollars in crypto form) to a smart contract called Across SpokePool V2, splitting the money into 13 separate packets that all ended up in the same place. It's like a bunch of envelopes that are all dropped into the same mailbox, but you can't see who actually put them there. The total amount moved was almost $13,000.

### 🔥 The Roast
So this address decided to play the ultimate game of ‘hide and seek’ with $12,964, sending it in 13 little gifts to a contract that’s basically the crypto version of a secret Santa box (Across SpokePool V2). HIGH (rule score 110) The AML engine gave it a 110, which means it scored high on the stablecoin_mixing rule (meaning the system thinks the sender is using a known pattern to obfuscate money flow). If you’re still wondering, think of it as sending money through a maze of tunnels so the original source gets lost in the labyrinth.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag the transaction set for manual review by AML compliance, and request additional source‑of‑fund information from the sender. HIGH (rule score 110)

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
- **stablecoin_mixing** (+110) — 13 stablecoin transfer(s) to Across SpokePool V2: $12,964 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Suspicious activity detected under rule stablecoin_mixing. The sender address 0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff executed 13 stablecoin transfers totaling $12,964 to the contract address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 (Across SpokePool V2) within block range 26380973-26381163. These transactions are consistent with a known mixing pattern used to obscure transaction provenance. Further investigation is warranted to determine source and destination of funds.

</details>

---

## Finding #18: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x97ccdbea4632140639ad5ea9b944aa034eb15fd4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **23** token transfers totaling **$26,202** (18 USDT, 0 WETH, 84 USDT, 604 USDC, 0 WETH) |
| **Blocks** | 26380977-26381163 |

### 💬 What Happened
A single wallet sent a series of small stablecoin payments into a shared pool that is commonly used to hide where the money came from. Think of it like dropping a bunch of identical envelopes into a shared mailbox so no one can tell who sent which one. The total value was about $26,202 and it all landed in the same smart contract over a few blocks.

### 🔥 The Roast
Looks like the sender tried to play hide-and-seek with their money, dropping 14 stablecoin notes into the Across SpokePool V2 (a.k.a. the crypto version of a dumpster fire). HIGH (rule score 110) 23 tiny transactions for $26,202? That’s like buying a pizza with 23 different coupons and then dumping it into a black hole. If this was a grocery store, we’d call the manager and ask what the heck is going on.

### 🎯 Verdict & Next Steps
**HIGH — the composite score of 110 on the stablecoin_mixing rule indicates a high likelihood of obfuscation of funds.**

Flag this activity for manual review; investigate the sender’s transaction history and potential links to known mixers. Consider placing a temporary hold on the receiver address pending further analysis.

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
- **stablecoin_mixing** (+110) — 14 stablecoin transfer(s) to Across SpokePool V2: $26,202 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The wallet executed 14 stablecoin transfers totaling $26,202 to the Across SpokePool V2 contract, triggering the stablecoin_mixing rule. These transactions occurred within block range 26380977-26381163. HIGH (rule score 110) The pattern warrants further investigation by the compliance team.

</details>

---

## Finding #19: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x9e64d18073cd8ec20e2680124d0551ba1629fa20` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **27** token transfers totaling **$209,127** (3 WETH, 25 WETH, 1 WETH, 25 WETH, 415 USDC) |
| **Blocks** | 26380981-26381161 |

### 💬 What Happened
A single wallet sent over $209,000 in stablecoins to a service called Across SpokePool V2, breaking the money into 27 smaller chunks. This is like someone taking a big envelope of cash, cutting it into pieces, and dropping each piece into a different slot so no one knows the whole amount. The service then shuffles the pieces before sending them to another address.

### 🔥 The Roast
So this address decided to become the world's most enthusiastic coin-flipper. HIGH (rule score 110) The total of $209,127 is not small for a single person—maybe they’re buying a yacht in cryptocurrency? The fact that the wallet has a zero ETH balance and no recent activity is just the icing on this suspicious sundae. HIGH (rule score 110)

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag the transaction for manual compliance review and investigate the source of the funds. Consider adding the wallet to the monitoring watchlist and request further KYC information if available.

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
- **stablecoin_mixing** (+110) — 11 stablecoin transfer(s) to Across SpokePool V2: $208,818 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The wallet 0x9e64d18073cd8ec20e2680124d0551ba1629fa20 transferred 11 stablecoin transactions totaling $208,818 to the Across SpokePool V2 address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 between blocks 26380981 and 26381161. HIGH (rule score 110) HIGH (rule score 110) The wallet’s lack of recent activity and zero ETH balance raise additional concerns about source of funds.

</details>

---

## Finding #20: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5317d95ee02d3c5103cac586db019afa1db67a96` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26381159-26381159 |

### 💬 What Happened
MEDIUM (rule score 85) The sender’s wallet has never been used before (0 days old) and it has zero balance after the transfer, so it looks like a fresh, anonymous drop into a pot that lets people off‑ramp crypto without any identity check.

### 🔥 The Roast
So we have a brand new wallet that’s literally younger than a morning coffee, sending a measly 0.0002 ETH to FixedFloat 1—think of it as dropping a candy into a vending machine that doesn’t ask for your name. The no‑KYC off‑ramp rule (meaning the service doesn’t verify who you are) gave this transaction a hefty 85 score, like a warning light flashing on a car that just hit a pothole. In short, this is the crypto equivalent of a teenager using a burner phone to send a handful of dollars to a friend without anyone knowing who’s who.

### 🎯 Verdict & Next Steps
**MEDIUM – the combination of a new wallet, zero KYC, and a known no‑KYC off‑ramp triggers a moderate suspicion of illicit activity.**

Flag the transaction for manual review, verify the sender’s identity, and consider restricting future transfers from this address until KYC is completed.

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
The transaction involves a newly created address (wallet age 0 days) with minimal activity, sending 0.0002 ETH to FixedFloat 1, a known no‑KYC off‑ramp. MEDIUM (rule score 85) The sender’s wallet balance is zero post‑transaction and no prior KYC verification exists. This pattern meets the AML Engine’s criteria for a medium‑risk flagged activity requiring further human review.

</details>

---

## Finding #21: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x55d22b5432c4ac301d9f41bae5a2705ab524e18e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0939 ETH** ($200) |
| **Blocks** | 26381154-26381154 |

### 💬 What Happened
A brand‑new wallet just sent about $200 worth of ETH straight into a special “FixedFloat 1” address. It’s like dropping a package into a slot that hides who sent it, because the sender’s account has no history and no way to trace who owns it. The whole deal happened in a single block, so it’s a quick, one‑time move.

### 🔥 The Roast
Looks like someone just built a new wallet, grabbed $200, and slipped it into a FixedFloat address that probably turns it into a cryptocurrency version of a secret Santa. The no‑KYC off‑ramp rule (meaning the sender can’t prove who they are) scored a whopping 85, which is basically saying, “We’re not seeing any identity here.” It’s like showing up at a party with a fake ID and a $200 gift card, hoping nobody notices. MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM — The combination of a brand‑new wallet, single large ETH transfer, and no‑KYC off‑ramp suggests elevated risk but no conclusive evidence of wrongdoing.**

Flag the transaction for manual review, verify the destination address’s history, and request additional information on the sender’s source of funds if possible.

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
Suspicious activity detected: A newly created wallet (age 0 days, tx count 1, balance 0) initiated a single ETH transfer of 0.0939 ETH (~$200) to a FixedFloat 1 address within block 26381154. MEDIUM (rule score 85) MEDIUM (rule score 85) Further investigation is warranted.

</details>

---

## Finding #22: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xabae359e326c98a8944c556f218552f6553d54fc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1106 ETH** ($235) |
| **Blocks** | 26381131-26381131 |

### 💬 What Happened
A brand‑new wallet, created just today, sent 0.1106 ETH (about $235) to a FixedFloat address. That’s the only transaction the wallet has ever made, and it now holds zero ETH. Because the wallet is brand new and the funds are moving to a service that lets you cash out without providing identity, it looks suspicious.

### 🔥 The Roast
Score 85 on no_kyc_offramp – that’s like getting a free ride in a limousine but never telling the driver who you are. The sender’s wallet is fresher than a donut on a Sunday morning, and the only thing it’s done is toss a modest sum into a black‑box. It’s like sending a pizza to a pizza place that doesn’t ask for your name or address – the pizza’s going somewhere, but nobody knows where. Good luck figuring out where that pizza is going.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction exhibits characteristics of a new wallet moving funds to a non‑KYC off‑ramp, indicating a moderate risk of layering.**

Verify the ultimate source of the 0.1106 ETH by tracing prior inbound transactions if any, and request KYC information from the recipient service. Flag the account for enhanced monitoring and consider placing a temporary hold pending further investigation.

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
The transaction triggers rule no_kyc_offramp with a composite score of 85. The sender wallet is newly created (0 days old) and has performed a single outbound transfer of 0.1106 ETH to a FixedFloat service that offers a non‑KYC off‑ramp. The lack of KYC and the presence of a fixed‑rate off‑ramp suggest potential layering or obfuscation activity. Further investigation is warranted to determine the ultimate beneficiary and source of funds.

</details>

---

## Finding #23: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa0059a8705fc968cedf1bb5f8c7584a02060e206` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2400 ETH** ($510) |
| **Blocks** | 26381077-26381077 |

### 💬 What Happened
A brand‑new wallet just sent 0.24 ETH (about $510) to a FixedFloat 1 account. It’s like someone dropping a package into a locker that hides who dropped it, with no way to trace the sender’s identity. The transfer was a single, straightforward transaction with no tokens involved.

### 🔥 The Roast
This fresh‑out wallet tried to make a quick deposit into FixedFloat 1, but without any KYC—meaning no identity check (the same as a street vendor selling a mystery product with no license). MEDIUM (rule score 85) Basically, it’s a new wallet showing up out of nowhere, acting like a ghost in a digital alley, and the system is calling out the lack of identity verification. If you’re looking for a good prank, this is the crypto equivalent of a magic trick with no audience.

### 🎯 Verdict & Next Steps
**The activity is medium risk due to the new wallet, no‑KYC deposit to an off‑ramp, and high engine score.**

Flag the transaction for manual review; investigate the source of funds and the identity of the recipient; consider placing a temporary hold pending further information.

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
Under Rule no_kyc_offramp, this transaction is flagged because the sender’s wallet is brand new (0 days old), has only one transaction, and deposited 0.24 ETH into a FixedFloat 1 off‑ramp without providing any customer identification. MEDIUM (rule score 85) The absence of KYC and the use of an off‑ramp service raise concerns about the source and ultimate destination of the funds.

</details>

---

## Finding #24: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x40d3fe91d5bdbd330a60fdd726ca8e714633cf1b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0119 ETH** ($25) |
| **Blocks** | 26381000-26381000 |

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

## Finding #25: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc542b3d9527f5bb977a3b89cbed868df642c19f4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0140 ETH** ($30) |
| **Blocks** | 26380986-26380986 |

### 💬 What Happened
A brand‑new wallet (zero days old, only one transaction) sent a small amount of ETH—about $30—to a service called FixedFloat 1. Think of it like dropping a $30 package into a slot that hides who sent it, because the sender has no identity verification and no history to prove where the money came from.

### 🔥 The Roast
This wallet is so new it hasn't even had a birthday yet (0 days old). It sent 0.014 ETH—just enough to be a tip for a toaster—straight to a no‑KYC off‑ramp, which is like giving a cash machine the keys to a bank vault without asking for your ID. FixedFloat 1 is basically a DeFi laundromat: you drop your coins in, it washes them, and you can pull them out later with a shrug. With a composite score of 85, it's basically shouting, "I’m a clean coin, no one can trace me!"

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review, verify the source of the ETH, and monitor the wallet for additional activity that may indicate layering or integration steps.

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
The transaction involves a newly created wallet (age 0 days, 1 transaction, zero balance) sending 0.0140 ETH ($30) to the address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f, identified by the FixedFloat 1 service. Rule no_kyc_offramp (score: 85) indicates the recipient is a known no‑KYC off‑ramp, creating a high risk of anonymous cash‑out. MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #26: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x474a21f072d3dc15df1263ebb6fefff56e2f7bc5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0140 ETH** ($30) |
| **Blocks** | 26380978-26380978 |

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

## Finding #27: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1c9c078458d7b23f4902f013ef093bd9aa38a735` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$670** (670 USDC) |
| **Blocks** | 26381160-26381160 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $670 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xcfea012e903fa8a5a8b7de025e52caff711b1ba0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **2** token transfers totaling **$884** (884 USDT) |
| **Blocks** | 26380967-26380967 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $884 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc186fa914353c44b2e33ebe05f21846f1048beda` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$485** (485 USDC, 0 WBTC) |
| **Blocks** | 26381001-26381157 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $485 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **7** token transfers totaling **$1,089** (25 USDT, 20 USDC, 646 USDC, 298 USDT, 0 WETH) |
| **Blocks** | 26380977-26381144 |

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
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to Across SpokePool V2: $1,089 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x50cfe7c1938db66a1a6d2e86d36f39fbef3d5c4a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$1,886** (1,886 USDC) |
| **Blocks** | 26381130-26381130 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $1,886 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x69460570c93f9de5e2edbc3052bf10125f0ca22d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$196** (37 USDT, 159 USDT) |
| **Blocks** | 26381070-26381124 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $196 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0038dfb2bbc353daa6ad22cb11ee1d78f41b59cd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$144** (144 USDT, 0 WETH, 0 WETH) |
| **Blocks** | 26381034-26381123 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $144 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9a47f3289794e9bbc6a3c571f6d96ad4e7baed16` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$5** (0 WETH, 5 USDT) |
| **Blocks** | 26381066-26381119 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $5 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x28a4d41776968c1201a807ec51ffb405362b8882` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$650** (600 USDT, 20 USDT, 30 USDC) |
| **Blocks** | 26381058-26381112 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $650 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5308e61baa39228136991bcbf1a1542952398423` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$200** (200 USDC) |
| **Blocks** | 26381061-26381061 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $200 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa81212b5b2a7915e69fa1c35da4d8250a3f9ed3f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$75** (75 USDC) |
| **Blocks** | 26380989-26380989 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $75 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x4af017353ff460e0d7025ee2597d534f318cbb48` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381142-26381142 |

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
| Wallet Age | 34 days |
| Total Transactions | 66 |
| Current Balance | 0.005934 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xc5625cff164806d225bd5858e534e8b3b27d67dc` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0469 ETH** ($100) |
| **Blocks** | 26381134-26381134 |

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
| Wallet Age | 72 days |
| Total Transactions | 10 |
| Current Balance | 0.015294 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x7d7a9857d1e6f49a49c1094b25a57bb5fa86416d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0470 ETH** ($100) |
| **Blocks** | 26381120-26381120 |

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
| Wallet Age | 297 days |
| Total Transactions | 26 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x099dae759f35d3a4d83fa805971377bfc8aaed66` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381120-26381120 |

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
| Wallet Age | 1870 days |
| Total Transactions | 831 |
| Current Balance | 0.005950 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x60b07e3153abf6a40096f19f2d7fc05bce17a861` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381103-26381119 |

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
| Wallet Age | 149 days |
| Total Transactions | 271 |
| Current Balance | 0.000267 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x5ffe3994a6961fc2aa8e2abf736faa93c08d22de` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381118-26381118 |

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
| Total Transactions | 4 |
| Current Balance | 0.000157 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x352690e95d5e47d4ea1c5bc2070456745e4bbc59` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381105-26381105 |

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
| Wallet Age | 270 days |
| Total Transactions | 4098 |
| Current Balance | 0.001509 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x0dc1e92fbcc8413b1341f4c1b1c203c3b1a03d73` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381087-26381087 |

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
| Wallet Age | 371 days |
| Total Transactions | 12819 |
| Current Balance | 0.032356 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xaad5ac0b112ee11d8098b6533fb057eec9ed87ab` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0206 ETH** ($44) |
| **Blocks** | 26381067-26381067 |

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
| Wallet Age | 1165 days |
| Total Transactions | 45 |
| Current Balance | 0.061739 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #47: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xefd9bfa174f19ab9d8283f992d911040df6ee402` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.8695 ETH** ($1,849) |
| **Blocks** | 26381047-26381066 |

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
| Wallet Age | 3530 days |
| Total Transactions | 512 |
| Current Balance | 0.023948 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x8008316e61985599dc62d69716bab3ebe643c0a8` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.7310 ETH** ($1,555) |
| **Blocks** | 26381049-26381049 |

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
| Wallet Age | 208 days |
| Total Transactions | 215 |
| Current Balance | 0.037880 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x769ce45c435bd8be3d2002fd763a52c322185597` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.1453 ETH** ($309) |
| **Blocks** | 26381043-26381047 |

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
| Wallet Age | 17 days |
| Total Transactions | 18 |
| Current Balance | 0.014874 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x86da1280642d2ef80a2d113172bf58bf657ec6d4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381030-26381030 |

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
| Wallet Age | 674 days |
| Total Transactions | 364 |
| Current Balance | 0.002648 ETH |
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
| **Sender** | `0xece1a6e76240bac6a5446ff8a414cf65021719b3` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0235 ETH** ($50) |
| **Blocks** | 26381030-26381030 |

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
| Wallet Age | 1949 days |
| Total Transactions | 67 |
| Current Balance | 0.004317 ETH |
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
| **Sender** | `0x511e6fd8c87e617575e3778ec068fc6fccd47450` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26381015-26381015 |

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
| Wallet Age | 84 days |
| Total Transactions | 1223 |
| Current Balance | 0.009515 ETH |
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
| **Sender** | `0x96fd5a93a5579d14d65bf00756d82ad2d24f03a3` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.8270 ETH** ($1,759) |
| **Blocks** | 26381011-26381011 |

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
| Wallet Age | 90 days |
| Total Transactions | 32 |
| Current Balance | 0.000190 ETH |
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
| **Sender** | `0x24e72485d0631b93e201b4ddf02315f8fda145a4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.4117 ETH** ($875) |
| **Blocks** | 26380984-26380984 |

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
| Wallet Age | 971 days |
| Total Transactions | 130 |
| Current Balance | 0.001130 ETH |
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
| **Sender** | `0xccb822f484e5a21bc4b819292b5cedd3f99aedfb` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($213) |
| **Blocks** | 26380977-26380977 |

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
| Total Transactions | 9 |
| Current Balance | 0.150553 ETH |
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
| **Sender** | `0x1551371b193403e9689d29f4026fa56803fe3f9e` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26380973-26380973 |

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
| Wallet Age | 251 days |
| Total Transactions | 369 |
| Current Balance | 0.013320 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**56 suspicious findings** detected across 56 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 16 |
| 🟠 HIGH | 3 |
| Wallets flagged | 56 |
| Suspicious value | 3.7081 ETH ($7,885) + $254,576 in stablecoins |
| Blocks scanned | 26380964 — 26381163 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 5 of 25 attempted analyses this run.

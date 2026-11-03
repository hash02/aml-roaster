# 🔥 AML Roaster Report
**2026-11-03 00:51 UTC** · Ethereum Mainnet · ETH $2,255.58
**Blocks:** 26330555 — 26330754 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26330555 to 26330754 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **8** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330556-26330751 |

### 💬 What Happened
A wallet that has been active for a month sent eight tiny, identical amounts of ETH—each listed as 0.0000—into a bridge called Across SpokePool V2. Think of it like dropping a handful of coins into a slot machine that hides who actually put them in, but doing it eight times in a row. The total value was zero because the system didn’t record any actual ETH transfer, just the empty placeholders.

### 🔥 The Roast
Score 70 on structuring (that means the wallet is trying to play hide‑and‑seek with the regulators by splitting its moves into the tiniest pieces). Score 60 on peel_chain_linear (so it's layering like a bad onion—cut one thin slice, put it on top of the next, and hope the cops don’t notice). Score 65 on bridge_hop (the wallet hopped across chains like a gossip on a social media platform). Overall, it’s like a toddler trying to cheat a bank by dropping crumbs into a sandbox, but the sandbox is actually a high‑tech bridge.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel_chain_linear, and bridge_hop patterns strongly suggests layering and smurfing typical of illicit activity.**

Flag the transaction for manual review by the compliance team; investigate the source and destination of the funds and monitor the wallet for additional suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 31 days |
| Total Transactions | 8467 |
| Current Balance | 0.022230 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 8 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 8 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender wallet, with 8 identical transfers of 0.0000 ETH, triggered the AML engine’s structuring rule (structuring: evidence of smurfing or layering). The sequential nature of the deposits triggered the peel_chain_linear rule, indicating a layering pattern. Additionally, the transfer to Across SpokePool V2 activated the bridge_hop rule, signifying cross‑chain movement. CRITICAL (rule score 195)

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **16** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330556-26330747 |

### 💬 What Happened
A wallet performed 16 almost identical tiny transfers of 0.0000 ETH to a cross‑chain bridge. It’s like someone repeatedly dropping a nearly invisible coin into a slot to hide the fact that they’re moving something. Even though each transfer looks negligible, the pattern is still suspicious.

### 🔥 The Roast
The engine gave it a 70 on structuring, which is basically the detective saying: "Hey, you’re making a bunch of tiny deposits to avoid detection—classic smurfing." It also scored 60 on peel_chain_linear, meaning the transfers line up like a straight line of breadcrumbs leading to a secret hideout. A 65 on bridge_hop tells us they’re hopping through a bridge, like a hopping monkey trying to escape the law. And all 16 amounts are 0.0000 ETH? That’s like sending a dozen empty envelopes—clearly a red flag. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 195, driven by high structuring, peel_chain_linear, and bridge_hop scores, indicates a high likelihood of illicit layering.**

Flag this transaction for manual review, request source of funds documentation, and monitor the wallet for any additional suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 81 days |
| Total Transactions | 24224 |
| Current Balance | 0.772551 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 16 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 16 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet executed 16 identical deposits of 0.0000 ETH to Across SpokePool V2, triggering the structuring rule (structuring). The linear sequence of transactions aligns with the peel_chain_linear rule, indicating potential layering. The use of a cross‑chain bridge activates the bridge_hop rule. The composite score of 195 warrants further investigation.

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **25** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330605-26330746 |

### 💬 What Happened
A wallet that has been active for almost eight years sent 25 almost identical tiny amounts of ETH (essentially zero) into a cross-chain bridge called Across SpokePool V2, one after the other. It’s like someone filling 25 empty buckets with the same amount of water and dumping them into a black box that moves the money elsewhere.

### 🔥 The Roast
Looks like this address went on a smurf‑party, dropping 25 copies of the same tiny amount into a bridge like a kid dropping identical cookies into a bag. The structuring score of 70 is higher than my coffee consumption, and the peel chain linear score of 60 means it’s a straight line of identical moves. The bridge hop score of 65? Yeah, they just hopped over the bridge like a frog on a trampoline. If this were a game, they'd be winning the ‘most boring transaction sequence’ award.

### 🎯 Verdict & Next Steps
**CRITICAL — composite score of 195 indicates high risk of structuring and layering via a cross‑chain bridge, warranting immediate review.**

Flag the address for further investigation, request source‑of‑funds documentation, and monitor subsequent activity for any related suspicious patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2789 days |
| Total Transactions | 837914 |
| Current Balance | 11.999458 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 25 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 25 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction log shows 25 consecutive ETH transfers of 0.0000 ETH each from 0x07ae8551be970cb1cca11dd7a11f47ae82e70e67 to 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2. Rule [structuring] (identical amounts to avoid detection) scored 70. Rule [peel_chain_linear] (layering pattern with sequential similar deposits) scored 60. Rule [bridge_hop] (cross‑chain bridge usage) scored 65. Composite score 195 exceeds the high‑risk threshold. The sender wallet is 2789 days old, has 837,914 total transactions, and holds 11.999458 ETH. CRITICAL (rule score 195) CRITICAL (rule score 195)

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330585-26330745 |

### 💬 What Happened
The sender made five separate, almost‑empty transfers of ether to a cross‑chain bridge. Think of it as someone dropping five identical envelopes into a slot that hides who sent them – all amounts were the same tiny value, basically zero.

### 🔥 The Roast
Look at those 0.0000 ETH deposits, like a magician pulling empty coins out of a hat. The AML engine gave it a 195, which is higher than the bar you need to climb to become a real crypto gangster. Structuring (smurfing) means splitting funds into tiny, identical packets to dodge detection; peel_chain_linear (layering) is the chain of similar deposits that hide the source; bridge_hop (cross‑chain bridge) is just the fancy way of saying the money hit a bridge to another chain. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 195 and multiple high‑risk pattern matches indicate a high probability of layering or smurfing activity.**

CRITICAL (rule score 195)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 236 days |
| Total Transactions | 15828 |
| Current Balance | 0.083484 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction sequence satisfies multiple AML pattern rules: structuring (smurfing) due to five identical zero‑amount deposits, peel_chain_linear (layering) due to sequential deposits, and bridge_hop (cross‑chain bridge) due to transfer to Across SpokePool V2. Composite score 195 exceeds the high‑risk threshold of 180, indicating significant concern. CRITICAL (rule score 195) This warrants escalation for manual review and source‑of‑funds verification.

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x75a7c0268ca0f40146c0fd38ca2787a0b0d9370c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330643-26330686 |

### 💬 What Happened
A wallet sent three identical, zero‑value ETH deposits to a cross‑chain bridge, like dropping the same empty bottle into a slot machine over and over again—no actual money moved, just the same empty packet each time.

### 🔥 The Roast
The engine gave it a 195, which is like a perfect score for a prankster: structuring 70 (meaning the wallet is doing textbook smurfing—three identical, 0‑ETH “smurfs”), peel_chain_linear 60 (a peel chain is a sneaky way to layer transactions, like peeling an onion one layer at a time), and bridge_hop 65 (the wallet hopped across chains like a kid jumping on a trampoline). In other words, it’s a one‑liner for “I’m just a harmless collector of empty bottles.”

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain, and bridge hop patterns indicates potential layering and obfuscation activity.**

CRITICAL (rule score 195)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 56 days |
| Total Transactions | 5071 |
| Current Balance | 0.021655 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction triggers the STRUCTURING rule (score 70) due to three identical zero‑value deposits, indicating potential smurfing. The PEEL_CHAIN_LINEAR rule (score 60) is satisfied by the sequential, identical deposits, suggesting layering. The BRIDGE_HOP rule (score 65) is triggered by the use of Across SpokePool V2, a cross‑chain bridge, which can facilitate obfuscation. The wallet is 56 days old with 5,071 prior transactions and a current balance of 0.021655 ETH, indicating active use of the address.

</details>

---

## Finding #6: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x76cebd108d4fcfc23021797d29fad23980b0a6f9` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330754-26330754 |

### 💬 What Happened
A brand‑new wallet (like a freshly minted paper money) sent a tiny amount of 0.0001 ETH—about the weight of a paperclip—to a service called FixedFloat 1. The sender had no previous activity and now has no balance left, so it looks like someone dropped a very small package into a slot that hides who actually gave it away.

### 🔥 The Roast
So we’ve got a wallet that’s 0 days old, which is basically a toddler that just learned to walk. It tried to put a paperclip‑sized coin into a FixedFloat 1 box that doesn’t ask for ID (no‑kyc‑offramp, meaning the service lets you off‑ramp without verifying who you are). That’s like trying to sneak a snack into a school cafeteria that has no ID check. The amount is so tiny you could almost mistake it for a typo. Basically, it’s a classic “drop the coin and pretend you’re anonymous” move.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the sender wallet for manual review, request additional identity verification, and monitor subsequent transactions for patterns consistent with mixing or layering.

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
Rule no_kyc_offramp: The sender deposited ETH into FixedFloat 1, an off‑ramp service that does not require KYC verification. The sender wallet is brand new (age 0 days) with only 2 prior transactions and has no remaining balance after this transfer. MEDIUM (rule score 85) The combination of a new wallet, no KYC, and off‑ramp activity warrants further scrutiny per AML policy.

</details>

---

## Finding #7: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb2063bb954cc3998c3fdebd3f8ea227717a85c5f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0150 ETH** ($34) |
| **Blocks** | 26330749-26330749 |

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

## Finding #8: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3f7f67b226035b6a042920edbb86f6955c77206d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330745-26330745 |

### 💬 What Happened
A brand‑new wallet, just created today, sent a tiny amount of ETH (0.0001 ETH, about zero dollars) to a special service called FixedFloat 1. Think of it like dropping a small package into a drop box that hides who actually sent it. The sender’s wallet has only two transactions and no remaining balance, so it looks like a fresh, anonymous user just trying to hide their trail.

### 🔥 The Roast
So this new wallet just decided to play the ‘I’m too cool for KYC’ game and deposited a few grains of ETH into a FixedFloat 1 address. We gave it a whopping 85 on the no‑KYC off‑ramp score (meaning it’s basically a shady deposit that skips identity checks). With only two moves and a zero balance, it’s like a kid who just learned how to throw a coin into a wishing well—purely for the mystery, not the money. MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM risk due to the new wallet depositing to a FixedFloat 1 address without KYC, a pattern associated with potential layering.**

Flag the sender’s wallet and the FixedFloat 1 address for enhanced monitoring, and request additional source‑of‑funds documentation before allowing further deposits.

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
The transaction was initiated by a wallet with 0 days of age and only 2 total transactions, indicating a brand‑new, low‑history account. MEDIUM (rule score 85) This activity triggers RULE_NO_KYC_OFFRAMP and is consistent with RULE_MIXER_USE patterns. MEDIUM (rule score 85)

</details>

---

## Finding #9: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb71c19734461a7b0c0942199e9d2cc3a5b7ced48` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330739-26330739 |

### 💬 What Happened
A brand-new wallet that has never been used before sent a tiny amount of ETH (0.0001) to a FixedFloat 1 address. Think of it like a kid dropping a single candy into a vending machine that then sends it to a random slot; you can't see who gave it or where it's headed.

### 🔥 The Roast
Nice try, new kid on the block! This wallet just dropped 0.0001 ETH into a FixedFloat 1 address, which the engine flagged as a no‑KYC off‑ramp (meaning the money leaves the ecosystem without any identity check). With an age of zero days and only two transactions, it's like a paper‑thin alibi. The composite score is a solid 85 – that's not a polite suggestion, it's a red flag. If you want to keep your money clean, maybe stick to a wallet with a history.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a newly created wallet and a no‑KYC off‑ramp, which elevates the risk without proving wrongdoing.**

Flag the transaction for manual review and consider additional due diligence on the sender and receiver. If the pattern persists, block future transfers to the FixedFloat 1 address.

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
The sender wallet (0xb71c19734461a7b0c0942199e9d2cc3a5b7ced48) is newly created (age 0 days) and has only two transactions, with a current balance of zero after the transfer. The transaction involved 0.0001 ETH sent to a FixedFloat 1 address, which is identified by the AML engine as a no‑KYC off‑ramp (rule no_kyc_offramp). MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #10: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc2270bd858fba1492b6d45623440a77fb7910e5d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0150 ETH** ($34) |
| **Blocks** | 26330737-26330737 |

### 💬 What Happened
A brand-new wallet that has never moved any funds before just sent 0.015 ETH (about $34) to an address that belongs to a service called FixedFloat 1. Think of it as a person dropping a small envelope into a mailbox that has no way to trace who will take it out. The transaction was the only one from that wallet, and the sender's balance went from a tiny amount to zero.

### 🔥 The Roast
So we have a fresh wallet that’s basically a digital newborn, sending a teeny-weeny 0.015 ETH to a FixedFloat 1 address— which is like a magician's hat that makes money disappear without a trace. The no_KYC_offramp rule (meaning the recipient is a service that doesn't ask for identity verification before you can take your money out) scored a whopping 85, so the engine is basically screaming, 'This is a no-identity money drop!' With only one transaction, a zero balance, and no history, you’d think the wallet might as well be a one‑use disposable phone. It's like buying a pizza with a prepaid card and immediately burning the receipt.

### 🎯 Verdict & Next Steps
**MEDIUM — the high composite score and lack of identity verification raise moderate suspicion.**

Flag the transaction for manual review and consider additional due diligence on the FixedFloat 1 address. Monitor for any subsequent outbound transfers from the same wallet.

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
The transaction involves a newly created wallet (age 0 days) that has executed a single outbound transfer of 0.015 ETH to a FixedFloat 1 address, a known no‑KYC off‑ramp service. MEDIUM (rule score 85) The wallet's zero balance post‑transaction and lack of prior activity further support the risk profile. MEDIUM (rule score 85)

</details>

---

## Finding #11: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x7eca79634fa9f66701b682f94f084aa76ca4ee8c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330736-26330736 |

### 💬 What Happened
A brand‑new wallet (it was created today) sent a tiny amount of ETH—just 0.0001—to a special address called FixedFloat 1, which is often used as an off‑ramp where you can move crypto without having to show who you are. It’s like dropping a single coin into a vending machine that doesn’t keep a record of who dropped it. The transaction was very small and happened in a single block, so there’s not much to see beyond that one little move.

### 🔥 The Roast
Looks like this wallet was fresh out of the wallet factory and decided to play hide‑and‑seek with a 0.0001 ETH tip into FixedFloat 1. No KYC off‑ramp rule? MEDIUM (rule score 85) The score of 85 is basically the engine’s way of saying, ‘Hey, this looks like a suspiciously clean‑sweep move.’ If you’re looking for a thrill, you just hit the ‘anonymous’ button with a coin the size of a grain of rice.

### 🎯 Verdict & Next Steps
**MEDIUM – the high composite score of 85 from the no_kyc_offramp rule and the new wallet’s activity pattern indicate a moderate risk that requires human review.**

MEDIUM (rule score 85)

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
The transaction involves a new wallet (age 0 days) with a minimal balance and a single outbound transfer of 0.0001 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f, identified as FixedFloat 1. According to rule no_kyc_offramp, the destination is an off‑ramp where KYC is not required, scoring 85 on the composite risk model. MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #12: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x77b7eec030db8c88a5c1bdb1994610e51f390fed` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330735-26330735 |

### 💬 What Happened
MEDIUM (rule score 85) It's like a new kid dropping a single penny into a secret box that forwards it to a black market without any ID check. The transaction was processed instantly in a single block, leaving no trace of where the money actually ends up.

### 🔥 The Roast
Looks like someone just tried to hide 0.0001 ETH in a crypto cloak‑room. No KYC? Great, because who needs identity verification when you can just pretend your wallet is a newborn? The engine gave it an 85, which is basically saying 'this is a high‑risk party trick, folks!' And let's not forget that the sender is so fresh it's literally 0 days old—like a newborn baby that just learned how to walk and immediately decided to steal a cookie.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review, investigate the destination address (FixedFloat 1) and monitor subsequent activity for further suspicious patterns.

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
The transaction originates from a wallet aged 0 days with only two total transactions and a zero current balance, indicating a freshly created address. MEDIUM (rule score 85) This pattern is flagged as a potential attempt to obscure the source of funds and warrants further investigation. MEDIUM (rule score 85)

</details>

---

## Finding #13: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1fcd94e817ac4ca3b9df3b25b1f3f40262dd4bb0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0250 ETH** ($56) |
| **Blocks** | 26330734-26330734 |

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

## Finding #14: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xaed39e7687d8e00dae95352f286ce53c44eecc5a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0321 ETH** ($72) |
| **Blocks** | 26330732-26330732 |

### 💬 What Happened
MEDIUM (rule score 85) Think of it like dropping a single coin into a box that hides who put it there, and no one knows where the coin came from. The transaction was the wallet's only move and it left the wallet empty again.

### 🔥 The Roast
Score 85 on the no_KYC off‑ramp rule (meaning the money is going to a place that doesn't do ID checks). So basically the sender is playing hide‑and‑seek with a tiny cash stash. One transaction, zero balance, and a brand‑new wallet—like a kid trying to sneak candy into a school cafeteria without a badge. The FixedFloat 1 contract is a fancy way of saying 'we accept your money, but we don't ask for your ID'. MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction triggers a high‑risk rule with no mitigating evidence.**

Flag the wallet for manual review, request source‑of‑funds documentation from the sender if possible, and monitor for additional activity to a regulated exchange.

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
MEDIUM (rule score 85) MEDIUM (rule score 85) MEDIUM (rule score 85) The transaction pattern warrants a review under the 'Unverified Off‑Ramp Activity' and 'New Wallet Suspicion' guidelines.

</details>

---

## Finding #15: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf88a43dd0aede5b9128c249d9aca3df80fa963e7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2640 ETH** ($595) |
| **Blocks** | 26330730-26330730 |

### 💬 What Happened
A brand‑new wallet just sent about 0.264 ETH (roughly $595) to a FixedFloat address. MEDIUM (rule score 85) It’s like dropping a package into a slot that hides who sent it and where it will go next.

### 🔥 The Roast
Scored 85 on the no‑kyc_offramp rule (meaning the sender sent money to a service that doesn’t require you to prove who you are). That’s the same as sending cash through a door that only has a lock you can pick, not a security guard. MEDIUM (rule score 85) It’s like a kid borrowing a car, driving away, and never coming back for the keys.

### 🎯 Verdict & Next Steps
**MEDIUM — high score from the no‑kyc_offramp rule indicates potential risk of unverified source and obfuscation.**

Flag the transaction for manual review, request source‑of‑fund documentation from the sender if possible, and monitor the FixedFloat address for any related activity.

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
The transaction involved a wallet with zero age and a single outgoing transfer of 0.264 ETH to a FixedFloat address. This activity matches the no‑kyc_offramp rule, which flags deposits to off‑ramp services that do not require identity verification. The wallet balance is zero and no prior activity exists, raising concerns about source of funds and potential layering. Further investigation is warranted to confirm the legitimacy of the source and destination.

</details>

---

## Finding #16: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb5bb0313fb5925486524ef9e4dd10eeebdc1d462` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330710-26330710 |

### 💬 What Happened
MEDIUM (rule score 85) It’s like someone dropping a single coin into a hidden box that can then be moved around without anyone knowing where it came from. The sender’s wallet has almost no history, so it’s as if a brand‑new backpack just tossed a coin into a mystery bag.

### 🔥 The Roast
MEDIUM (rule score 85) MEDIUM (rule score 85) The AML engine gave it a score of 85 on the no_KYC_offramp rule (meaning the money can leave the system with zero identity checks). In plain English, this is like a kid who just got a new backpack and immediately drops a coin into a secret pouch; no one knows where it came from or where it’s going. If you’re wondering why it matters, it’s because mixers are the crypto equivalent of a shady pawnshop with no receipts.

### 🎯 Verdict & Next Steps
**MEDIUM — the combination of a brand‑new wallet, low balance, and the no_KYC_offramp rule indicates moderate risk of illicit activity.**

Flag the transaction for manual compliance review. Request additional context on the source of funds and the intended use of the FixedFloat address.

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
Rule no_kyc_offramp (Deposit to FixedFloat 1 with no-KYC off-ramp) was triggered with a composite score of 85. MEDIUM (rule score 85) MEDIUM (rule score 85) The combination of a brand‑new wallet and a no‑KYC off‑ramp address warrants a manual compliance review for potential illicit activity.

</details>

---

## Finding #17: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x654a97d66773b9f34cc89acaba1a4fd0b5468c7d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0066 ETH** ($15) |
| **Blocks** | 26330702-26330702 |

### 💬 What Happened
A brand‑new wallet that has never sent or received any crypto before just sent 0.0066 ETH (about $15) to a service called FixedFloat 1. Think of it like dropping a small parcel into a drop‑box that doesn't keep track of who mailed it or what the parcel contains.

### 🔥 The Roast
This new wallet is so fresh it still has its birth certificate. It sent money to FixedFloat 1, which is basically a fancy vending machine that accepts coins but never asks for ID. The AML engine gave it an 85 on the "no KYC off‑ramp" rule – basically saying, "Hey, this place is like a speakeasy that doesn't ask who you are." Even though the amount is tiny, the lack of identity verification makes it a suspiciously shiny target for the kind of shady business that prefers to stay anonymous. If you think a $15 tip is harmless, think again – the rule's 85 score is louder than a traffic light at a red‑flag intersection.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the receiver address for monitoring and request additional context from the service provider; consider escalating to a full AML review if subsequent activity shows layering or structuring patterns.

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
The transaction involves a new wallet (age 0 days) with a single outbound transfer of 0.0066 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1). This activity triggers the AML rule "no_kyc_offramp" (Composite Score: 85), indicating a deposit to a service lacking a KYC off‑ramp. MEDIUM (rule score 85) The transaction is flagged for further review under the suspicious activity reporting framework.

</details>

---

## Finding #18: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf45ce2d01017edcd6ca842b6f38a31688969f9bf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0279 ETH** ($63) |
| **Blocks** | 26330701-26330701 |

### 💬 What Happened
MEDIUM (rule score 85) There was only one transaction, and the sender’s balance went to zero right after. No other coins or tokens were involved.

### 🔥 The Roast
MEDIUM (rule score 85) The AML engine gave it a 85 on the no_KYC_offramp rule (meaning it’s a deposit into a place that doesn’t ask for your ID, like a shady pawn shop with no receipts). It’s like showing up at a party with a gift card you just bought, but the host never asks who you are—classic. The 63‑dollar amount is small, but the lack of KYC makes it look suspicious, like a kid buying a chocolate bar and immediately swapping it for a bag of candy in a back‑alley market. Good luck finding the real owner of that wallet—it's probably a new user or a bot that thinks “new” means “untraceable.”

### 🎯 Verdict & Next Steps
**MEDIUM – the transaction triggers a high‑risk rule (no_kyc_offramp) but involves only a single, small transfer, so the overall risk is moderate.**

Flag the wallet for manual review, trace its activity for additional transfers, and cross‑reference with known suspicious addresses or patterns before considering any enforcement action.

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
The transaction involves a newly created wallet (age 0 days) that performed a single outbound transfer of 0.0279 ETH to an address identified as a FixedFloat 1 off‑ramp. According to AML rule [no_kyc_offramp], deposits to off‑ramp services without KYC verification are flagged as high risk; the composite score of 85 reflects this. The wallet has no prior activity and zero balance after the transfer, indicating a possible attempt to move funds without proper identity verification. MEDIUM (rule score 85)

</details>

---

## Finding #19: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x15950e52cfd0ef77590b79b429c47a890d5820a1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0611 ETH** ($138) |
| **Blocks** | 26330693-26330693 |

### 💬 What Happened
A brand new wallet (like a freshly opened bank account) sent 0.0611 ETH (about $138) to a FixedFloat 1 address. This is like dropping a package into a slot that hides who sent it, because there's no record of who owns the sending wallet. The transaction was a single ETH transfer with no other tokens involved.

### 🔥 The Roast
This fresh wallet just tried to off‑ramp with no KYC, scoring a whopping 85 on the no_kyc_offramp rule (meaning the sender has no identity verification before sending money). It's like trying to sneak into a club with a fake ID that no one will recognize. MEDIUM (rule score 85) If this was a real person, they'd need a passport, not just a digital address. Looks like a classic "newbie with no identity" trying to hide their cash trail.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review. Verify the source of funds and consider freezing the balance if further suspicious activity is identified.

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
Rule no_kyc_offramp triggered with a score of 85 for the sender wallet 0x15950e52cfd0ef77590b79b429c47a890d5820a1. The wallet has 0 days of age, only one transaction, and zero current balance, indicating a fresh, unverified source of funds. MEDIUM (rule score 85) Recommend a manual review of the transaction and source of funds.

</details>

---

## Finding #20: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xcdfea7649a397072258edd8245aae09772447438` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($226) |
| **Blocks** | 26330689-26330689 |

### 💬 What Happened
A brand-new wallet just sent 0.1 ETH (about $226) to a service called FixedFloat 1. It’s like dropping a package into a locker that hides who sent it, because the sender’s wallet is brand new and has no prior history. The transaction was a single, straightforward transfer with no extra tokens or steps.

### 🔥 The Roast
Looks like someone just opened a fresh wallet and decided to play the ‘who’s this? game’ by sending 0.1 ETH to FixedFloat 1. That’s the classic new‑wallet, no‑KYC, off‑ramp combo – the AML engine is basically shouting, ‘I see you!’ with a score of 85. If you think 0.1 ETH is a lot, remember that’s about the price of a decent coffee. This pattern is the blockchain equivalent of a shady tip jar: no ID, no exit, just a quick cash‑out. (FixedFloat 1 is a type of off‑ramp service that lets users convert crypto to fiat without KYC, so it’s a known risk zone.)

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction triggers a high‑risk KYC evasion pattern but does not constitute proven wrongdoing.**

Flag the transaction for manual review and consider additional due diligence on the receiver and the nature of FixedFloat 1. Monitor for subsequent activity from the same wallet or related addresses.

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
Transaction involves a newly created wallet (0 days old, only 1 transaction) sending 0.1 ETH to FixedFloat 1. The AML engine flagged the activity under rule no_kyc_offramp with a composite score of 85, indicating a high likelihood of KYC evasion via an off‑ramp service. The lack of prior activity and the immediate transfer to a non‑KYC service meet the criteria for suspicious behavior under AML guidelines. MEDIUM (rule score 85)

</details>

---

## Finding #21: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc8ebe399d4f1d9734cfdf7228cc0f4049cefe0dd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2300 ETH** ($519) |
| **Blocks** | 26330680-26330680 |

### 💬 What Happened
A brand-new wallet sent 0.23 ETH (about $519) to a service that lets you move crypto without showing any ID. Think of it like a fresh customer dropping a package into a dropbox that doesn't ask for their name or address.

### 🔥 The Roast
So this brand-new wallet decided to play hide-and-seek with 0.23 ETH. No KYC? That's like inviting a stranger to your party and then handing them a VIP pass. The engine gave it an 85, which is basically the red flag emoji at a speedway. They used FixedFloat 1, a place that says "no ID, just send it". Looks like someone is trying to turn their cash into a "no ID" smoothie.

### 🎯 Verdict & Next Steps
**MEDIUM - Lack of KYC on the off‑ramp and a brand‑new wallet with a single high‑value transfer warrants moderate concern.**

Flag this transaction for manual review and verify the source and intended destination of the funds. Consider placing a temporary hold until additional information is obtained.

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
Rule no_kyc_offramp triggered with a score of 85. Evidence includes a sender wallet age of 0 days, a single transaction, a zero balance after the send, and a destination to FixedFloat 1, an off‑ramp that does not require KYC. MEDIUM (rule score 85) Further review is warranted.

</details>

---

## Finding #22: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8870a3d80e2b2788d176580f5d96318537aadb6e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330662-26330662 |

### 💬 What Happened
MEDIUM (rule score 85) The transaction happened in a single block, and the sender wallet had no previous history (it was created the same day). Essentially, it's like a freshly opened envelope that immediately drops a very small package into a mixing bowl that scrambles who the sender is.

### 🔥 The Roast
So, the wallet is basically the crypto equivalent of a kid who just got a new backpack and decides to hide a handful of candy in a secret compartment. The transfer to FixedFloat 1 is a no-KYC off-ramp (meaning the service doesn't ask for your ID, which is like giving a tip to a bartender who never asks for your name). 0.0001 ETH is so tiny that it's about the same as the tip you'd leave for a good joke, yet the wallet is trying to play hide-and-seek with the blockchain. MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review, monitor the wallet for additional activity, and consider escalating to the compliance team for deeper investigation.

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
The sender wallet 0x8870a3d80e2b2788d176580f5d96318537aadb6e is newly created (age 0 days) and has executed only two transactions, one of which is a 0.0001 ETH transfer to FixedFloat 1. MEDIUM (rule score 85) MEDIUM (rule score 85) Further investigation is warranted to assess potential layering or obfuscation activity.

</details>

---

## Finding #23: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xed5e11859cd1e7b91bf26402bdd4481231f3b764` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0700 ETH** ($158) |
| **Blocks** | 26330635-26330635 |

### 💬 What Happened
MEDIUM (rule score 85) The sender had no prior activity and the wallet balance dropped to zero, like opening a bank account and immediately dropping the money into a secret vault that hides who sent it.

### 🔥 The Roast
MEDIUM (rule score 85) No KYC, no off‑ramp, basically like dropping your cash into a black hole that doesn’t ask for ID. The engine gave it a 85 on no_kyc_offramp—high score, high suspicion. If you want to keep your money safe, maybe stay away from mixers that look like a mystery box from a thrift store.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

MEDIUM (rule score 85) Consider monitoring the wallet for future activity and request additional documentation if the sender is identified as a user.

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
The sender address (0xed5e11859cd1e7b91bf26402bdd4481231f3b764) was created on the same day as the transaction, with a zero balance prior to sending 0.0700 ETH to the recipient address (0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f). This transaction falls under rule no_kyc_offramp, scoring 85, indicating a high probability of an off‑ramp that lacks KYC verification. MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #24: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x9ca219b60bcc066406bcbaf43a3ab8392e9d22a2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330629-26330629 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of Ethereum (0.0001 ETH, basically zero dollars) to a service called FixedFloat 1. Think of it like dropping a handful of pennies into a vending machine that has no way to trace who gave them.

### 🔥 The Roast
Score 85 on no‑KYC off‑ramp (meaning this is the kind of wallet that wants to hide its identity like a kid in a hide‑and‑seek game). The sender's wallet was brand new (0 days old), had only two transactions, and now has zero balance—like someone who just got a new phone, sent a tiny tip, and then disappeared. MEDIUM (rule score 85) This is like putting your pizza delivery bag into a locker that doesn't log who dropped it in.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the wallet for enhanced monitoring. Investigate the source of the 0.0001 ETH and track any subsequent movements through the FixedFloat 1 contract.

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
The transaction involves a wallet with no KYC off‑ramp (Rule: no_kyc_offramp) where a new address (0 days old) transferred 0.0001 ETH to the FixedFloat 1 contract. The wallet has only two prior transactions and no current balance, indicating a potential attempt to obfuscate ownership. MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #25: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x820562007e3d9c47ab71bdd0d0af5e68ff3ccbe5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330628-26330628 |

### 💬 What Happened
A brand‑new wallet (like a freshly delivered pizza box that never left the factory) sent 0.0001 ETH—roughly nothing—to a service called FixedFloat 1, which is known to let people cash out crypto without having to show who they are. The sender had only made two moves ever and now has no funds left in the box, so the whole thing feels like a quick drop‑and‑go trick to hide the money’s trail.

### 🔥 The Roast
So this brand‑new wallet, fresh off the blockchain assembly line, decides to play hide‑and‑seek with 0.0001 ETH (that’s about the price of a cup of coffee, but on a different planet). It slides the tiny coin into a FixedFloat 1 account—no‑KYC off‑ramp, meaning the user never had to prove their identity (like a cashier who doesn’t check your ID before giving you a change). The engine gave it a 85, which is basically saying, “Hey, this looks like a suspicious shortcut, buddy.” If you’re watching the block, you’ll see the sender’s age is 0 days and balance is zero—like a newborn with a full wallet that just emptied it out. Good luck finding the real person behind that address; it’s probably as elusive as a Wi‑Fi signal in a basement.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a brand‑new wallet moving funds to a no‑KYC off‑ramp, which is a recognized pattern of potential anonymity abuse.**

Flag the transaction for manual investigation, confirm source of funds, and consider adding the wallet address to a watchlist for future monitoring.

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
Rule no_kyc_offramp (score: 85) was triggered due to the transfer of ETH from a newly created wallet (age 0 days, 2 total transactions, current balance 0.000000 ETH) to a FixedFloat 1 address, a known off‑ramp that does not require KYC verification. MEDIUM (rule score 85) MEDIUM (rule score 85) The activity should be flagged for manual review and source‑of‑fund verification.

</details>

---

## Finding #26: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xcc05188e9cf4a506c1d82b96373f09e7da73ef88` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0950 ETH** ($214) |
| **Blocks** | 26330625-26330625 |

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
| **Sender** | `0x81e699735d04ee8edc36343ee00dd35510b7a200` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.3000 ETH** ($677) |
| **Blocks** | 26330623-26330623 |

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
| **Sender** | `0x9dabd9552aecfa157c9fcdefaf6ad3a9b8ed53a4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330619-26330619 |

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

## Finding #29: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x845b837679b7dea91e2ea8da4bbf3e39420cc5f5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.4460 ETH** ($1,006) |
| **Blocks** | 26330608-26330608 |

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
| **Sender** | `0xa5c59173f565e4a86fcdee69b83091c42c10372a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330604-26330604 |

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

## Finding #31: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xed1ddeab3a03058f9b39da67198b3a3d343c048e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330601-26330601 |

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

## Finding #32: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5bd5d9d5155dca53313f9fed93c1f51bcd1e8520` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330598-26330598 |

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

## Finding #33: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3dedb08dae1cfb3ce6a994b6c5835c32402b45d0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330595-26330595 |

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

## Finding #34: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa4bbc3105689da434af817a0cf45f0033f9bdb0a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2707 ETH** ($611) |
| **Blocks** | 26330589-26330589 |

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

## Finding #35: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3dd131e5a802cd932506a23b5b9b5587062e3f55` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330573-26330573 |

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

## Finding #36: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb12680c6a086f7fa4b35ed265abfbacb8426529d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330570-26330570 |

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

## Finding #37: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x456e1a87d76ae368c17b9fee0bfc023b95b9a09d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0732 ETH** ($165) |
| **Blocks** | 26330564-26330564 |

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

## Finding #38: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb256c7e216703aa4480e4e95e946809bad75619f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0950 ETH** ($214) |
| **Blocks** | 26330563-26330563 |

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

## Finding #39: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x705848526af7a268e1cda9045f62a815539f17cc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26330562-26330562 |

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

## Finding #40: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x97ccdbea4632140639ad5ea9b944aa034eb15fd4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **17** token transfers totaling **$2,025** (21 USDC, 12 USDC, 1,050 USDC, 18 USDC, 525 USDC) |
| **Blocks** | 26330593-26330754 |

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
- **stablecoin_mixing** (+80) — 16 stablecoin transfer(s) to Across SpokePool V2: $2,025 total (USDT, USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb0be5dbb8653b2e07b16bacd78b4ffbc320592f5` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$399** (399 USDC) |
| **Blocks** | 26330754-26330754 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $399 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x69460570c93f9de5e2edbc3052bf10125f0ca22d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$109** (6 USDT, 102 USDT, 0 WETH) |
| **Blocks** | 26330689-26330754 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $109 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **5** token transfers totaling **$595** (4 USDC, 38 USDT, 1 USDC, 309 USDC, 243 USDC) |
| **Blocks** | 26330613-26330752 |

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
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to Across SpokePool V2: $595 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9e64d18073cd8ec20e2680124d0551ba1629fa20` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **9** token transfers totaling **$3,724** (0 WETH, 0 WETH, 3,721 USDC, 1 WETH, 0 WETH) |
| **Blocks** | 26330557-26330751 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $3,721 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0038dfb2bbc353daa6ad22cb11ee1d78f41b59cd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **7** token transfers totaling **$7,607** (0 WETH, 4,998 USDC, 0 WETH, 0 WETH, 2,609 USDT) |
| **Blocks** | 26330565-26330741 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $7,607 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x28a4d41776968c1201a807ec51ffb405362b8882` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **5** token transfers totaling **$2,095** (23 USDC, 2 USDC, 19 USDT, 1 USDC, 2,049 USDT) |
| **Blocks** | 26330606-26330734 |

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
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to Across SpokePool V2: $2,095 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #47: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xaf6d5de979d8c863d3c52ac7dbf5215773687f69` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$25** (25 USDC) |
| **Blocks** | 26330697-26330697 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $25 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3d2d2538b2dde72ac9f2730afe1799040f08f4f0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDT) |
| **Blocks** | 26330690-26330690 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $0 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9a47f3289794e9bbc6a3c571f6d96ad4e7baed16` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$109** (4 USDC, 105 USDC) |
| **Blocks** | 26330564-26330687 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $109 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xaf1dd9d19cb4d99d53b8aeb314f648f21549674a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$686** (686 USDT) |
| **Blocks** | 26330685-26330685 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $686 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #51: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x60ac95ec1153aa8199751917ede25d0ca49a36e2` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$1,248** (1,248 USDT) |
| **Blocks** | 26330677-26330677 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $1,248 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #52: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc186fa914353c44b2e33ebe05f21846f1048beda` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$592** (591 USDT, 1 WETH, 0 WBTC) |
| **Blocks** | 26330670-26330670 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $591 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #53: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$79** (79 USDC) |
| **Blocks** | 26330661-26330661 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $79 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #54: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x79900badf817654d2008765a92cdd8ba5584bdda` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$3,686** (3,686 USDC) |
| **Blocks** | 26330586-26330586 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $3,686 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #55: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4e6a87c1b56ff19359dce1644c622ef23beee45e` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$48** (48 USDT) |
| **Blocks** | 26330585-26330585 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $48 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #56: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5468d1ab6e50f405e9fb83669c6dac9d1808eaaa` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$501** (501 USDC) |
| **Blocks** | 26330580-26330580 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $501 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #57: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbcba672328338bfa1f525898a96a713ac14763c1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$359** (359 USDC) |
| **Blocks** | 26330570-26330570 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $359 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #58: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x4dc35acebacf540f4d93b683afc57b49094a1cdf` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0995 ETH** ($224) |
| **Blocks** | 26330751-26330751 |

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
| Current Balance | 0.000033 ETH |
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
| **Sender** | `0x8947136dd76ae0ab648878fce79afd51390f570b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330728-26330728 |

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
| Wallet Age | 1356 days |
| Total Transactions | 1236 |
| Current Balance | 0.000068 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #60: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xae549b969dc91b022b8cf1ef2d5d5d2131ac00f7` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0545 ETH** ($123) |
| **Blocks** | 26330721-26330721 |

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
| Wallet Age | 1804 days |
| Total Transactions | 1688 |
| Current Balance | 0.939228 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #61: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x738671901affbc417fa370cf936e461bb5315bd0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **3.0000 ETH** ($6,767) |
| **Blocks** | 26330707-26330707 |

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
| Wallet Age | 2288 days |
| Total Transactions | 3468 |
| Current Balance | 0.648677 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #62: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330706-26330706 |

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
| Wallet Age | 1078 days |
| Total Transactions | 212671 |
| Current Balance | 0.916575 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #63: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xfd826bbc9120e81097da803fecc5e610b6559815` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330706-26330706 |

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
| Wallet Age | 1497 days |
| Total Transactions | 407 |
| Current Balance | 0.000974 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #64: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330697-26330697 |

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
| Wallet Age | 322 days |
| Total Transactions | 28171 |
| Current Balance | 0.199803 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #65: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x0cff7235f24eebdb4d86f82d27a585021d9b5225` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330694-26330694 |

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
| Wallet Age | 1572 days |
| Total Transactions | 40 |
| Current Balance | 8.686768 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #66: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x10828431637fdb33d931b6cc24b6542f27d2de09` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330686-26330686 |

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
| Wallet Age | 1889 days |
| Total Transactions | 1005 |
| Current Balance | 0.004402 ETH |
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
| **Sender** | `0xa3d4d48759238b294ab20338889d3822ffd40063` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330676-26330676 |

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
| Total Transactions | 11 |
| Current Balance | 0.011286 ETH |
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
| **Sender** | `0x2ca3e9ee175f3e21871d0459d44ecd30e7875e6b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330646-26330646 |

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
| Wallet Age | 47 days |
| Total Transactions | 4 |
| Current Balance | 0.008248 ETH |
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
| **Sender** | `0xad511bb19a3225798c3c7f04ac1236651287ca2f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330580-26330646 |

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
| Wallet Age | 1583 days |
| Total Transactions | 5564 |
| Current Balance | 0.004231 ETH |
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
| **Sender** | `0x2d96c21ecd1794431826ce45b6e0ab637f4594fb` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330611-26330639 |

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
| Wallet Age | 3 days |
| Total Transactions | 82 |
| Current Balance | 0.002537 ETH |
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
| **Sender** | `0x511e6fd8c87e617575e3778ec068fc6fccd47450` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330626-26330626 |

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
| Wallet Age | 77 days |
| Total Transactions | 735 |
| Current Balance | 0.004447 ETH |
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
| **Sender** | `0x44e77dbb76c7a4b5391c59b41a5c8d677f102426` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330617-26330617 |

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
| Wallet Age | 27 days |
| Total Transactions | 6 |
| Current Balance | 0.001680 ETH |
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
| **Sender** | `0x200d8ab38930e27b120334c93b962f20d6a4ab78` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0050 ETH** ($11) |
| **Blocks** | 26330606-26330606 |

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
| Wallet Age | 1678 days |
| Total Transactions | 175 |
| Current Balance | 0.077255 ETH |
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
| **Sender** | `0xcdd9902d1d5c59a2936c30cbefc83d3734d0669b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330604-26330604 |

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
| Wallet Age | 354 days |
| Total Transactions | 78 |
| Current Balance | 2.384122 ETH |
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
| **Sender** | `0x9557b1bfde0c5ab8ba53e244d0a2ec6de3102f5d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330590-26330590 |

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
| Wallet Age | 27 days |
| Total Transactions | 62 |
| Current Balance | 0.001738 ETH |
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
| **Sender** | `0x100fea55da1316ba7c624a7e5e86ee9861e3ffb7` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0010 ETH** ($2) |
| **Blocks** | 26330587-26330587 |

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
| Wallet Age | 1813 days |
| Total Transactions | 3325 |
| Current Balance | 0.099929 ETH |
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
| **Sender** | `0xd40f88937d5e774d2bc5a3c9f19b67d979034339` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.1170 ETH** ($264) |
| **Blocks** | 26330573-26330573 |

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
| Current Balance | 0.000114 ETH |
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
| **Sender** | `0xf213b6daec9ad37078a353c5cf3ed51d2591e876` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330567-26330567 |

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
| Current Balance | 0.000074 ETH |
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
| **Sender** | `0x851ee2c974cf792a229b4db4fb08d9065ff598dd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.2650 ETH** ($598) |
| **Blocks** | 26330564-26330564 |

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
| Wallet Age | 204 days |
| Total Transactions | 728 |
| Current Balance | 0.031542 ETH |
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
| **Sender** | `0x3cc14937c8b861a9ea42c5cd5631f1002fbd0bb6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26330562-26330562 |

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
| Wallet Age | 171 days |
| Total Transactions | 3638 |
| Current Balance | 0.007075 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**80 suspicious findings** detected across 80 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 5 |
| 🟠 HIGH | 0 |
| Wallets flagged | 80 |
| Suspicious value | 5.6707 ETH ($12,791) + $23,889 in stablecoins |
| Blocks scanned | 26330555 — 26330754 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 2 of 25 attempted analyses this run.

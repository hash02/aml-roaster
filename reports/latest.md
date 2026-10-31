# 🔥 AML Roaster Report
**2026-10-31 21:24 UTC** · Ethereum Mainnet · ETH $2,252.17
**Blocks:** 26315145 — 26315344 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26315145 to 26315344 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x75a7c0268ca0f40146c0fd38ca2787a0b0d9370c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315192-26315344 |

### 💬 What Happened
Three tiny, identical Ethereum deposits of zero value were sent from a fairly young wallet into a bridge that moves funds between blockchains. It’s like someone dropping three empty envelopes into the same slot in a bank’s vault—nothing shows up, but the pattern looks suspiciously like a smurfing attempt. The wallet has a lot of history and still has a small balance, so the moves might be trying to hide how that money got there.

### 🔥 The Roast
So we have a wallet that’s 54 days old, has done 4,664 transactions, and it’s sending zero‑ETH three times in a row to a bridge. Structuring (the rule that flags identical tiny deposits) gave it a 70, peel_chain_linear (detects a straight‑line chain of similar moves) a 60, and bridge_hop (cross‑chain bridge use) a 65. Basically, it’s like a kid doing the “three‑step dance” at a party—if you see it three times, you know it’s a pattern. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the transaction for manual investigation, request source‑of‑funds documentation, and monitor the account for further suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 54 days |
| Total Transactions | 4664 |
| Current Balance | 0.027987 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender wallet, 54 days old with 4,664 total transactions and a current balance of 0.027987 ETH, performed three consecutive ETH transfers of 0.0000 ETH to 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 on Across SpokePool V2 within blocks 26315192-26315344. The AML engine flagged structuring (identical deposits), peel_chain_linear (sequential layering pattern), and bridge_hop (cross‑chain bridge usage) with scores 70, 60, and 65 respectively, yielding a composite score of 195. This pattern aligns with known layering and structuring red flags under AML regulations.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **7** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315145-26315319 |

### 💬 What Happened
The sender transferred seven identical tiny amounts of ETH (each 0.0000) into the Across SpokePool V2 bridge. Think of it like dropping the same small package into a slot seven times in a row so no one notices the total volume. The total value was $0, but the pattern of the transfers is what raises eyebrows.

### 🔥 The Roast
They’re basically playing a game of hide‑and‑seek with a zero‑value wallet: send the same tiny amount over and over, like a magician pulling an empty card from a deck. Structuring (splitting a transaction into many small ones to dodge thresholds) earned a 70. Peel chain linear (a straight line of identical deposits) got a 60. Bridge hop (using a cross‑chain bridge, a fancy way to move money across networks) added another 65. If this was a comedy show, the punchline would be ‘You can’t hide in plain zero‑eth.’

### 🎯 Verdict & Next Steps
**CRITICAL — The combination of structuring, peel chain linearity, and bridge hop in a short time frame indicates high potential for illicit layering.**

Flag the wallet for enhanced monitoring and request source‑of‑funds documentation. Consider placing a temporary hold on the bridge withdrawals pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 79 days |
| Total Transactions | 23279 |
| Current Balance | 0.802987 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 7 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 7 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction series is flagged under AML Rule 'structuring' (identical small deposits) with a score of 70, indicating potential attempts to evade reporting thresholds. Rule 'peel_chain_linear' (sequential identical deposits) scored 60, suggesting layering activity. Rule 'bridge_hop' (cross‑chain bridge usage) scored 65, raising concerns about cross‑border movement of assets. The pattern of seven zero‑value ETH transfers to Across SpokePool V2, combined with the sender’s high transaction volume and recent activity, warrants further investigation.

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **19** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315147-26315312 |

### 💬 What Happened
A single wallet sent 19 almost‑nothing (0 ETH) payments into a cross‑chain bridge, like a kid trying to sneak a dozen tiny coins through a slot machine without anyone noticing. The sender is very active overall, but all 19 tiny transfers were identical and happened one after the other, making it look like a deliberate attempt to hide the real amount of money moving through the system.

### 🔥 The Roast
Looks like someone’s trying to smuggle a loaf of bread through the customs line by dropping 19 crumbs into a bridge. The AML engine gave it a 70 on structuring (meaning it’s textbook smurfing, like splitting a pizza into 19 slices and handing each out to a different friend). Then it got a 60 on peel_chain_linear – because the deposits were all in a straight line, like a chain of paper clips. Finally a 65 on bridge_hop – the money hopped to Across SpokePool V2, a bridge that shuttles coins between chains. In short, it’s a perfect recipe for a “torture‑the‑wallet” scenario – if you can’t see the amount, you’re still watching the pattern.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of structuring, peel chain linearity, and bridge hop activity creates a high‑risk profile that requires immediate review.**

Flag the wallet for manual review, request additional KYC information from the user, and monitor future activity for any larger value transfers or attempts to conceal the origin of funds.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2787 days |
| Total Transactions | 835799 |
| Current Balance | 13.864661 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 19 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 19 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction sequence triggers the following AML rules: [structuring] (score: 70) – 19 identical zero‑value deposits indicate potential structuring/smurfing. [peel_chain_linear] (score: 60) – the deposits form a linear peel chain, suggesting layering attempts. [bridge_hop] (score: 65) – the use of Across SpokePool V2 indicates cross‑chain activity. CRITICAL (rule score 195)

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **11** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315153-26315307 |

### 💬 What Happened
The sender’s wallet sent 11 identical tiny payments of 0.0000 ETH to a bridge on Across SpokePool V2. It’s like a person dropping the same empty box into a slot repeatedly, trying to hide the pattern of the shipments.

### 🔥 The Roast
Looks like someone tried to smuggle a snack by sending 11 empty packages (structuring = smurfing) all at once, then decided to hop across the bridge (bridge_hop = moving money between chains) just to keep the trail fuzzy. The chain of identical moves is a textbook peel chain (peel_chain_linear = layering with linear steps). If this was a secret recipe, the chef would be a lot more creative than this copy‑and‑paste routine.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction pattern meets multiple high‑risk AML rules indicating potential layering and structuring.**

Flag the wallet for manual compliance review, investigate the source of the funds and the purpose of the bridge usage, and consider adding the address to a watchlist pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 29 days |
| Total Transactions | 7788 |
| Current Balance | 0.018373 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 11 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 11 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The account exhibits a high‑risk pattern: [structuring] score 70 for 11 identical 0.0000 ETH deposits (smurfing); [peel_chain_linear] score 60 indicating a layering peel chain; and [bridge_hop] score 65 for a cross‑chain bridge to Across SpokePool V2. The wallet is only 29 days old, has 7,788 transactions, and holds a small ETH balance, suggesting rapid movement of funds. CRITICAL (rule score 195)

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **10** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315201-26315288 |

### 💬 What Happened
The sender moved 0.0000 ETH ten times to a bridge, each time the same tiny amount. It’s like dropping a packet of invisible letters into a slot that hides who sent it. In plain words, they’re trying to hide their activity by sending identical zero-value transfers through a cross‑chain bridge. The receiver is a special contract on Across SpokePool V2, which acts like a hallway that lets coins hop from one chain to another.

### 🔥 The Roast
Looks like this wallet is playing hide‑and‑seek with the blockchain: 10 identical zero‑value transfers to Across SpokePool V2, which is basically a secret handshake to a cross‑chain bridge. The engine gave it a 195 composite score—think of it as a 195% suspicion level, way above the critical 150% threshold. Structuring (score 70) means they’re smurfing with zeros, peel_chain_linear (score 60) shows a peel chain, and bridge_hop (score 65) indicates they’re hopping across chains. In plain terms: they’re layering empty packets to confuse the system, like sending a letter wrapped in ten identical paper bags.

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 195, exceeding the critical threshold, indicates high‑risk structuring and layering activity involving a cross‑chain bridge.**

Flag the transaction for manual compliance review and consider a deeper investigation into the source of funds. CRITICAL (rule score 195)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 234 days |
| Total Transactions | 15312 |
| Current Balance | 0.092715 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 10 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 10 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction pattern triggers the structuring rule (score 70) due to identical zero‑value deposits, the peel_chain_linear rule (score 60) due to sequential similar deposits, and the bridge_hop rule (score 65) due to use of Across SpokePool V2 cross‑chain bridge. The composite score of 195 exceeds the critical threshold of 150, indicating a high‑risk scenario. The sender wallet is 234 days old with 15,312 prior transactions and a current balance of 0.092715 ETH, showing high activity but no recent balance changes. CRITICAL (rule score 195)

</details>

---

## Finding #6: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315201-26315263 |

### 💬 What Happened
The sender sent three tiny, identical deposits of zero ETH into a bridge that moves funds between blockchains. It’s like dropping three identical empty boxes into a sorting machine to hide who put them there. The activity happened in a short block range, so it looks like someone was trying to layer or smurf the funds.

### 🔥 The Roast
Score 70 on structuring (meaning the deposits are textbook smurfing – three identical, tiny amounts to disguise the real flow). Then a 60 on peel_chain_linear (so the machine did a perfect layering dance). And a 65 on bridge_hop, because the funds jumped to Across SpokePool V2 – a cross‑chain bridge that’s as shady as a tunnel in a city with no lights. In short, it’s a crypto version of a three‑legged dog trying to escape the fence.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of structuring, peel chain linear, and bridge hop flags indicates a high likelihood of layering and obfuscation, warranting immediate human review.**

Flag the account for manual investigation, review any linked addresses, and consider reporting to the AML desk.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 320 days |
| Total Transactions | 27880 |
| Current Balance | 0.199999 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Rule 3: Structuring – evidence: three consecutive transactions of 0.0000 ETH. Rule 4: Peel Chain Linear – evidence: sequential identical deposits indicating layering. Rule 5: Bridge Hop – evidence: transfer to Across SpokePool V2 (a cross‑chain bridge). Additional context: sender wallet age 320 days, 27,880 total transactions, current balance 0.199999 ETH, no inactivity gap. CRITICAL (rule score 195)

</details>

---

## Finding #7: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x511e6fd8c87e617575e3778ec068fc6fccd47450` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315149-26315225 |

### 💬 What Happened
A wallet sent four tiny, identical transfers of 0.0000 ETH to a bridge contract. Think of it like dropping four identical empty envelopes into a mailbox that forwards them to another location. Even though nothing changed hands, the pattern looks like a smurfing attempt to hide the flow of funds.

### 🔥 The Roast
Looks like someone tried to play hide-and-seek with 0 ETH. Structuring hit 70 (means they’re trying to split a single deposit into a bunch of zero‑value pieces so the system thinks nothing's happening). Peel_chain_linear scored 60 (they’re stacking those empty envelopes like a bad IKEA bookshelf). And the bridge hop got 65 (they’re using Across SpokePool V2 like a secret tunnel for a party that never happens). In short, they’re trying to make a mess of the ledger while keeping the balance zero – classic ‘pretend to be a wizard’ move.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Perform a full audit of the wallet’s upstream activity and the counterparties involved, and consider filing a regulatory report if further suspicious activity is uncovered.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 75 days |
| Total Transactions | 578 |
| Current Balance | 0.001330 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender wallet (0x511e6fd8c87e617575e3778ec068fc6fccd47450) performed four sequential identical 0.0000 ETH transfers to the Across SpokePool V2 contract, triggering the following AML engine rules: [structuring] (score 70), [peel_chain_linear] (score 60), and [bridge_hop] (score 65). These rules are designed to detect structuring (smurfing), layering (peel chain), and cross‑chain bridging, respectively. The composite score of 195 exceeds the internal threshold for a critical alert. CRITICAL (rule score 195)

</details>

---

## Finding #8: CRITICAL — Score 190

| | |
|---|---|
| **Sender** | `0xabe56b57236886b63e39c3c72322404f91e2f847` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.9692 ETH** ($6,687) |
| **Blocks** | 26315283-26315283 |

### 💬 What Happened
A brand-new wallet, with no previous history, sent about $6,687 worth of ETH to a service called FixedFloat 1. After the transfer the wallet had zero balance, like someone who just emptied a cash box and left nothing behind.

### 🔥 The Roast
Looks like this wallet was born the same day it made a move—like a toddler who just learned to walk and decides to sprint straight into the nearest candy store. The engine slapped on a 'novel_wallet_dump' (meaning a brand‑new wallet sending a big chunk of funds) and a 'no_kyc_offramp' (meaning the money goes to a place that doesn't ask for ID). The 2.9692 ETH is roughly the price of a small house in some places, but the sender is emptying out and disappearing—classic exit rush. If you’re wondering what FixedFloat 1 is, it’s a crypto service that lets you send ETH without proving who you are, so the engine thinks you’re playing hide‑and‑seek with your money.

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 190, driven by high novelty, lack of KYC, and immediate withdrawal, signals a high risk of illicit activity.**

Flag the transaction for manual review, investigate the source of the sender’s ETH and the purpose of the FixedFloat 1 deposit, and consider adding the address to the watchlist.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 190):
- **novel_wallet_dump** (+65) — Wallet is 0 days old, moving 2.9692 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.9692 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a 0‑day wallet that made a single outgoing transfer of 2.9692 ETH to the off‑ramps service FixedFloat 1, which does not require KYC (no_kyc_offramp). The AML engine assigned high scores: novel_wallet_dump (65) for the new wallet, no_kyc_offramp (85) for the destination, and exit_rush (40) for the immediate depletion of the wallet’s balance. The composite score of 190 exceeds our critical threshold and aligns with known burner wallet patterns used to obfuscate source of funds.

</details>

---

## Finding #9: CRITICAL — Score 190

| | |
|---|---|
| **Sender** | `0xc8a74a18f578077b5c2a96642022a31b17088bfd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.5023 ETH** ($5,635) |
| **Blocks** | 26315280-26315280 |

### 💬 What Happened
A brand‑new wallet, created today, sent all its 2.5 ETH to a FixedFloat address and then had no money left, like someone dropping cash into a slot that hides who sent it and vanishing after the drop.

### 🔥 The Roast
So we got a fresh wallet that just popped up, sent all its dough to FixedFloat 1—like a magician who pulls a coin out of a hat and then vanishes. The engine gave it a 65 on novel_wallet_dump (means it looks like a brand‑new burner wallet). Then a 85 on no_kyc_offramp (the money is going to a service that doesn’t do KYC, so it’s a ‘no‑identity’ off‑ramp). Finally, exit_rush 40 because the wallet is empty after the send, like a quick exit after a heist. In short, this is textbook burner‑and‑run.

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 190, driven by high‑risk patterns of a new burner wallet, no‑KYC off‑ramp, and immediate balance depletion, warrants immediate review.**

CRITICAL (rule score 190)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 190):
- **novel_wallet_dump** (+65) — Wallet is 0 days old, moving 2.5023 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.5023 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Suspicious activity: New wallet (0 days old) with one transaction of 2.5023 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1). The sender’s balance goes to zero immediately after the transfer, indicating a possible ‘exit rush’. The transaction triggers Rule novel_wallet_dump (score 65), Rule no_kyc_offramp (score 85), and Rule exit_rush (score 40). Composite score 190 exceeds internal high‑risk threshold.

</details>

---

## Finding #10: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x25c0344454845dc5a60d56d4f9b369184e256684` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.4448 ETH** ($5,506) |
| **Blocks** | 26315282-26315282 |

### 💬 What Happened
A brand‑new wallet just sent about $5,500 worth of ETH to a service called FixedFloat 1, then went completely empty. It’s like someone dropping a cash bundle into a black‑hole box that instantly hides the sender’s identity and then vanishing.

### 🔥 The Roast
First off, this wallet is brand new—novel_wallet_dump (meaning the wallet has zero history and just dumped a big chunk of ETH in one go) scored 64 points. Then it used no_kyc_offramp (meaning it sent the money to a service that doesn’t require identity verification) and hit 85 points. The exit_rush (wallet balance near zero after moving the money—like a quick getaway) added another 40. In short, it’s a textbook burner wallet with a “no‑KYC” exit strategy. CRITICAL (rule score 189)

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of a brand‑new wallet, large single transfer to a no‑KYC service, and immediate balance depletion triggers a high‑risk flag.**

Flag the transaction for manual review, request source of funds and any associated addresses, and monitor for additional activity that could confirm suspicious intent.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.4448 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.4448 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a high‑risk pattern consistent with Rule [novel_wallet_dump]—a newly created wallet with a single large transfer. Rule [no_kyc_offramp] is triggered by the destination FixedFloat 1, a known off‑ramp that does not require user identification. Rule [exit_rush] is activated by the immediate depletion of the source wallet’s balance to zero after the transfer. These combined indicators warrant a manual compliance review to investigate the source and potential links to illicit activity.

</details>

---

## Finding #11: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xd672e6d362619f31da0e1e5ccc6d78752e910a29` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315344-26315344 |

### 💬 What Happened
A brand-new wallet (just created today) sent a tiny amount of ETH—just 0.0001, like a few pennies—to a service that doesn't do identity checks. The receiver is a so‑called FixedFloat 1 pool, which is basically a locker that hides who the sender is. Because the wallet is new and almost empty, this looks like a small, anonymous drop into a no‑KYC pool.

### 🔥 The Roast
Picture a kid dropping a handful of pennies into a secret no‑ID locker—yeah, that’s what this looks like. The engine gave it 85 points for "no_kyc_offramp" (meaning the receiver doesn't ask for your ID, like a shady club with no membership checks) and 70 for "sybil_fan_in" (so many folks sending the same tiny amount, like a fan club of penny‑punchers). The composite score of 155 is the kind of number you’d see if you tried to score high on a game of Whack‑a‑Mole in the dark. Bottom line: this is a red flag that someone is trying to hide a micro‑transaction in a no‑identity pool, possibly as part of a bigger fan‑club scheme.

### 🎯 Verdict & Next Steps
**CRITICAL — the high composite score with no‑KYC off‑ramp and Sybil fan‑in flags indicates a potentially suspicious micro‑transaction that requires urgent human review.**

Manually investigate the sender’s wallet and any related transactions for a legitimate source; if no valid source is found, file a Suspicious Activity Report (SAR).

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
The transaction (0.0001 ETH, $0) originates from a wallet that is 0 days old, with only 2 total transactions and a current balance of 0.000000 ETH. AML engine flags include: Rule no_kyc_offramp (score 85) indicating a deposit to a service lacking KYC verification; Rule sybil_fan_in (score 70) indicating multiple senders making similar small deposits into the same recipient, suggestive of a Sybil pattern. CRITICAL (rule score 155) CRITICAL (rule score 155)

</details>

---

## Finding #12: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x156b6cbedbb53c30cb110b86a41fbd217495b605` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315342-26315342 |

### 💬 What Happened
A brand‑new wallet just sent a minuscule 0.0001 ETH (worth basically nothing) to a FixedFloat address, which is like dropping a single candy into a school lunch box and then leaving. The wallet was created and used in the same block, so it’s as fresh as a new kid on the playground. There’s no record of any KYC (Know‑Your‑Customer) verification, so we don’t know who owns that wallet.

### 🔥 The Roast
This wallet is so fresh it probably hasn’t even had breakfast yet—new wallet, no KYC, no off‑ramp. Scored a whopping 85 on the no‑KYC off‑ramp rule (meaning it tried to sneak out of the system without showing ID). The 70 points from the sybil_fan_in rule (meaning a bunch of wallets are all sending the same tiny amount, like a swarm of bees dropping honey into the same jar) suggest a Sybil attack, or at least a fan‑in pattern. Basically, it’s the crypto equivalent of a secret club where everyone shares the same weird meme, and the club’s only meeting is a single micro‑transaction. If you think this is normal, check your life choices.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a brand‑new wallet, no KYC, and a Sybil fan‑in pattern with a fixed‑float off‑ramp triggers the highest risk threshold.**

Flag this transaction for manual review, request additional source‑of‑funds evidence, and consider placing the recipient address on a watchlist pending further investigation.

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
Transaction from wallet 0x156b6cbedbb53c30cb110b86a41fbd217495b605 to 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f occurred in block 26315342. The sender wallet is new (age 0 days) and has no prior KYC data. The transaction matches rule no_kyc_offramp (score 85) and rule sybil_fan_in (score 70), indicating a potential Sybil fan‑in pattern and an unverified off‑ramp. Composite score 155 triggers a critical flag.

</details>

---

## Finding #13: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x7063f1a3d1b3c53c77e621839be51904cd1ae541` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315338-26315338 |

### 💬 What Happened
A brand‑new wallet just sent a tiny fraction of a dollar’s worth of ETH into a service that mixes coins, like dropping a single marble into a slot machine that hides who put it in. The sender’s account is only a few hours old, has barely sent any money, and now has no balance left. Because there’s no identity check, it’s basically a one‑way street for anonymous funds.

### 🔥 The Roast
Score 85 on the no_kyc_offramp rule (meaning this wallet deposited into a service that doesn’t ask for ID – like a bouncer who never asks who you are). Then it got a 70 from sybil_fan_in (think 37 people each dropping a penny into the same jar; looks like a Sybil army). In short, it’s like a group of anonymous pranksters all tossing a single cookie into the same giant cookie jar and hoping no one notices who’s behind it.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual compliance review and monitor the wallet for further movements; consider requesting additional identity evidence or blocking future off‑ramp transfers until investigation is complete.

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
The transaction triggered rule no_kyc_offramp with a score of 85 because the sender deposited ETH into FixedFloat 1 without any KYC verification. Additionally, rule sybil_fan_in scored 70 due to the fan‑in pattern of 1 out of 37 similar low‑value deposits, indicating potential Sybil activity. The wallet is newly created (0 days old) and has no current balance, raising concerns about layering or mixing operations. CRITICAL (rule score 155)

</details>

---

## Finding #14: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x0c23bd111e9fe06cfa453a703fe79734901b6214` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315337-26315337 |

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

## Finding #15: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xfe5c52f8db9e319d8d1b662fdce6c6525848f3af` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315336-26315336 |

### 💬 What Happened
A brand‑new wallet, with zero days of history, just sent a tiny amount of ETH (0.0001) to a service called FixedFloat 1. It’s like a new kid dropping a single candy into a vending machine that lets you get money back later, but you never showed your ID at the counter.

### 🔥 The Roast
This wallet is fresher than a morning coffee and just made a 0.0001 ETH drop into FixedFloat 1—no KYC, no ID, just a quick cash‑in. The AML engine gave it 85 points for the no‑KYC off‑ramp rule (meaning the address is basically a one‑way tunnel to cash out without identity checks). Then it got another 70 for the sybil_fan_in rule, because 1 of 37 senders are all putting in the same tiny amount, like a choir of micro‑donors chanting the same song. Score 155, which is basically a red flag taller than a skyscraper. The bot is basically shouting, "I’m all about that anonymous, anonymous life!"

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, verify the sender’s identity and source of funds, and monitor for additional related activity.

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
The transaction involves a newly created wallet (0 days old) sending 0.0001 ETH to FixedFloat 1, an off‑ramp service with no KYC (Rule no_kyc_offramp). The AML engine flagged a sybil fan‑in pattern (Rule sybil_fan_in) due to 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%). CRITICAL (rule score 155) CRITICAL (rule score 155)

</details>

---

## Finding #16: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xdd1b404f5f8a69b56b2ad06039be23d27ea386ba` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315331-26315331 |

### 💬 What Happened
A brand‑new wallet, just created yesterday, sent a minuscule amount of ETH (about 0.0001) to a special address called FixedFloat 1. Think of it like someone dropping a handful of pennies into a slot that hides who sent them. The transfer was tiny and occurred in a single block, so it looks like a quick, almost invisible move.

### 🔥 The Roast
This new wallet is fresher than a bakery loaf—0 days old and only two transactions. The engine gave it an 85 on the no‑KYC off‑ramp rule (meaning it moved money into an address that doesn’t require identity verification), and a 70 on the sybil_fan_in rule (many similar small senders pointing to the same address, like a choir of identical coins). With a composite score of 155, it’s the crypto equivalent of a red‑flagged credit card. Bottom line: this is a “new wallet, no identity, fan‑in pattern” combo that even a detective would flag.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a brand‑new wallet, no‑KYC off‑ramp, and Sybil fan‑in pattern yields a high‑risk assessment that warrants immediate review.**

Flag the transaction for manual review, verify the source of funds and KYC status of any linked entities, and add the wallet to the monitoring list for future activity.

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
The wallet (0xdd1b404f5f8a69b56b2ad06039be23d27ea386ba) was created on the day of the transaction and has only two total transactions, indicating a fresh, low‑activity profile. Rule [no_kyc_offramp] scored 85 because the transfer was to a FixedFloat 1 address that does not enforce KYC, raising concerns about an off‑ramp to fiat. CRITICAL (rule score 155) The composite score of 155 places the transaction in the high‑risk category per AML engine thresholds.

</details>

---

## Finding #17: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x18fb639658c4ff4fb7c3bb99423ded8a050d0a5d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315330-26315330 |

### 💬 What Happened
A brand‑new wallet (just created this month) sent a tiny amount of 0.0001 ETH to a FixedFloat 1 address in the same block, like dropping a single grain of sand into a bucket that hides who put it there.

### 🔥 The Roast
So we’ve got a fresh‑out‑of‑the‑oven wallet that thinks it’s the next big crypto influencer, but it’s actually just a one‑off micro‑transfer to a fixed‑float address (think of it as a vending machine that accepts coins but never gives you a receipt). The engine gave it a whopping 85 for no‑KYC off‑ramp, meaning no identity check before it tried to cash out, and a 70 for Sybil fan‑in, which is basically a bunch of identical little coins arriving at the same destination from a swarm of new wallets. Together that’s a 155 composite score—like a red flag on a tiny paper airplane. This is the kind of pattern that makes regulators go “huh?” and ask, “who’s behind this?”

### 🎯 Verdict & Next Steps
**CRITICAL – The composite score of 155, driven by a new wallet with no KYC off‑ramp and a Sybil fan‑in pattern, indicates a high likelihood of suspicious activity requiring immediate review.**

Flag the sender wallet for manual KYC verification and monitor subsequent transactions to the FixedFloat 1 address for further anomalous activity.

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
The transaction was executed by a wallet with zero days of age and only two prior transactions, indicating a newly created address. The transfer of 0.0001 ETH to a FixedFloat 1 address (Rule: no_kyc_offramp) triggers an off‑ramp without KYC verification. Additionally, the pattern of 37 senders depositing similar amounts (~0.000 ETH ±30%) into the same address (Rule: sybil_fan_in) suggests a Sybil fan‑in activity. CRITICAL (rule score 155)

</details>

---

## Finding #18: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xfe3960ed7b388b06ac198bc91fa176ee0b58fcb3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315325-26315325 |

### 💬 What Happened
A brand‑new wallet just dropped a tiny amount of ETH (0.0001) into a service that turns money into a shape‑changing cloud. It’s like sending a single penny into a vending machine that then hides the source before returning a new coin. No KYC (know‑your‑customer) check was done, so the origin remains anonymous.

### 🔥 The Roast
Looks like a rookie wallet tried to play hide‑and‑seek with 0.0001 ETH. That’s less than the price of a cup of coffee, but it scored a whopping 155 on the AML radar—like getting a perfect score on a test you didn't study for. The engine flagged a no‑KYC off‑ramp (meaning the money vanished into a service that doesn’t ask for ID) and a sybil fan‑in (so 36 other wallets probably sent the same tiny amount, like a choir of people all humming the same off‑beat note). If you’re looking for a clean break, this is the kind of transaction that makes regulators raise an eyebrow faster than a cat spots a laser pointer.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review by the AML team. CRITICAL (rule score 155)

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
The transaction involves a zero‑day wallet that executed a single 0.0001 ETH transfer to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f, an off‑ramp service. The AML engine assigned a composite risk score of 155, with [no_kyc_offramp] (85) indicating the absence of KYC verification for the off‑ramp and [sybil_fan_in] (70) indicating a fan‑in Sybil pattern involving 37 similar senders. This pattern is consistent with potential layering or obfuscation activity. CRITICAL (rule score 155)

</details>

---

## Finding #19: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x71bc31141bd355fdc03e1948c934a6bf08b427ce` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315313-26315313 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (0.0001) to a FixedFloat 1 address. The sender has only made two transactions and has zero balance, so it looks like a fresh account used to hide who’s sending money. It’s like dropping a single grain of sand into a big bucket to hide where it came from.

### 🔥 The Roast
Well looky here, a brand new wallet just decided to play the "I’m an anonymous whisper" game. The engine gave it a whopping 85 on the no‑KYC off‑ramp rule (meaning the money is heading to a place that doesn’t ask for ID). Then it got a 70 on the Sybil fan‑in rule (so 36 other wallets are doing the same 0.0001 ETH trick). In plain English, it’s like a group of teenagers all dropping the same tiny snack into the same trash can to avoid getting caught. If you’re worried about mixers, this is the classic "tornado" playbook. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the sender wallet for manual investigation, monitor subsequent activity for clustering or layering, and consider notifying the receiving FixedFloat 1 address operator if policy allows.

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
The transaction originates from a wallet with zero days of age, two total transactions, and a current balance of 0.000000 ETH. Rule [no_kyc_offramp] was triggered with a score of 85 due to transfer to FixedFloat 1, a known no‑KYC off‑ramp. Rule [sybil_fan_in] scored 70 because the sender is one of 37 wallets sending similar amounts (~0.000 ETH ± 30%) to the same destination, indicating a Sybil fan‑in pattern. CRITICAL (rule score 155)

</details>

---

## Finding #20: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xaf921072f5283cb09001a2ba8c37c8ab684eec13` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315304-26315304 |

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
| **Sender** | `0x021f8d98c8e604da2a4568106a403f68b7c44d02` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315302-26315302 |

### 💬 What Happened
Sender's brand-new wallet (0 days old) sent a tiny amount of ETH, like dropping a single grain of rice into a cup, to a fixed float address. The transaction was the only move from that wallet, and the amount is so small it’s practically invisible on the blockchain.

### 🔥 The Roast
Looks like someone's new wallet is trying to play hide-and-seek with their money. 0 days old and already in the no‑KYC off‑ramp club—like a toddler in a bank vault. The Sybil fan‑in score of 70? That's like a crowded pizza joint where everyone orders the same tiny slice—so we’re suspicious of a coordinated pizza‑party of bots. With an 85 on no‑KYC off‑ramp, this is a classic ‘I don’t know who you are, but I want to move your coin’ scenario.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag this transaction for manual review by compliance. CRITICAL (rule score 155)

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
The transaction originates from a 0‑day wallet that has executed only two transactions and holds no balance, indicating a potential fresh wallet used to funnel funds. The AML engine assigned a high risk score: [no_kyc_offramp] (score: 85) for depositing into a FixedFloat 1 address with no KYC verification, and [sybil_fan_in] (score: 70) for fan‑in activity with 1 of 37 similar senders depositing amounts within ±30% of 0.0001 ETH. CRITICAL (rule score 155)

</details>

---

## Finding #22: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc1b46d976b32cd6fc49438390c10f5f637d30559` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315302-26315302 |

### 💬 What Happened
A brand‑new wallet just sent a tiny fraction of an ETH to a FixedFloat address. It's like dropping a single grain of rice into a slot machine that doesn't show who put it in. The sender's account was created today and hasn't moved any money before.

### 🔥 The Roast
So we got a fresh wallet (0 days old) that just decided to play the ‘I’ll send you a whisper of ETH’ game. No KYC? Sure, because why not let an anonymous newbie cash out at a FixedFloat with no identity check. And guess what, this little 0.0001 ETH was part of a Sybil fan‑in: 1 out of 37 other wallets sending similar amounts—like a choir of tiny coins all humming the same tune. This is basically the crypto equivalent of a group of kids all dumping their spare change into a piggy bank that has no guard. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction meets both no‑KYC off‑ramp and Sybil fan‑in patterns, indicating a high potential for illicit activity.**

Flag the transaction for manual review by compliance. Verify the source of funds and investigate whether the sender is linked to other suspicious activity or known illicit actors.

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
The transaction originates from a newly created wallet (age 0 days, total tx count 2, balance 0 ETH) that sent 0.0001 ETH to FixedFloat address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f. Rule [no_kyc_offramp] is triggered due to the lack of KYC verification on the off‑ramp, scoring 85. Rule [sybil_fan_in] is triggered because the sender is part of a fan‑in pattern with 37 similar senders, scoring 70. The composite score of 155 indicates a high likelihood of suspicious activity requiring review.

</details>

---

## Finding #23: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x715f3e32659311ba14c9d3305555b9245a5ed640` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315294-26315294 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ETH (0.0001) to a service called FixedFloat 1, which is basically a black‑box that takes your money and sends it somewhere else, so no one can easily see where it ends up. The sender had only two transactions and no balance left after this one, so it’s like dropping a single grain of rice into a mystery box that you can’t open. Because the wallet was created on the same day as this transfer, it has zero history to help trace its origin.

### 🔥 The Roast
This is the kind of move that makes our AML engine shout louder than a kid at a candy store. The no‑KYC off‑ramp rule (meaning the wallet can dump crypto into a service that doesn’t ask for identity) scored a whopping 85, and the sybil fan‑in rule (multiple new wallets all sending about the same tiny amount) gave another 70. In plain English, it’s like a bunch of kids all dropping the same tiny Lego block into a mysterious box that nobody knows who owns. The engine’s composite score of 155 says, “We see a red flag!” and 155 is not the number you want in your wallet.

### 🎯 Verdict & Next Steps
**The transaction’s high composite score (155) and the presence of both no‑KYC off‑ramp and Sybil fan‑in patterns render it a critical red flag for potential layering or obfuscation.**

Initiate a manual review of the sender wallet’s broader activity and any downstream recipients. Consider flagging the transaction in the compliance system and monitoring for further similar patterns.

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
The transaction (Block 26315294, amount 0.0001 ETH) from wallet 0x715f3e32659311ba14c9d3305555b9245a5ed640 to FixedFloat 1 triggers Rule [no_kyc_offramp] with a score of 85, indicating a non‑KYC off‑ramp activity. Additionally, Rule [sybil_fan_in] scored 70 due to the pattern of 1 of 37 similar senders depositing comparable amounts, suggesting a Sybil fan‑in structure. The composite score of 155 exceeds the high‑risk threshold, warranting a detailed manual review for potential layering or obfuscation. CRITICAL (rule score 155)

</details>

---

## Finding #24: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x1cf84e56f611e00741bc7305da70284463514f11` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315285-26315285 |

### 💬 What Happened
A brand‑new wallet, just created today, sent a tiny 0.0001 ETH (about a penny in crypto) to a service called FixedFloat 1 that lets people cash out without proving who they are. Think of it as dropping a single dollar into a high‑risk cash‑in machine that doesn't ask for ID. After the send the wallet’s balance is zero, and it’s only made two transactions in total.

### 🔥 The Roast
So we have a fresh‑from‑the‑forge wallet that thinks it’s a secret agent, dropping a micro‑ETH into a no‑KYC casino. The engine flagged it for no_KYC_offramp (meaning no identity check at the exit) and sybil_fan_in (like a spammy fan club sending identical tiny gifts). 0.0001 ETH is the crypto equivalent of a nickel to a million‑dollar slot machine—nice try, but you’re still looking like a newbie who can’t even afford a full cup of coffee. If this was a real person, they'd probably be in a hurry to get their money out before anyone notices they’re playing with a new account. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, request source‑of‑funds documentation, and monitor the wallet for additional suspicious activity before proceeding with any further transfers.

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
The transaction originates from a wallet that is 0 days old, has only 2 total transactions, and holds a zero balance after the transfer, indicating a potentially wash or layering activity. Rule no_kyc_offramp was triggered due to the deposit to FixedFloat 1, which is a known no‑KYC off‑ramp service. Rule sybil_fan_in was also triggered, as this sender is one of 37 addresses sending similar amounts (~0.000 ETH ±30%) to the same destination, a classic Sybil fan‑in pattern. The composite score of 155, with high individual scores for both rules, suggests a high risk of illicit activity. Further investigation is warranted to confirm the source and legitimacy of the funds.

</details>

---

## Finding #25: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xe5e08de2e0aae2a1e2b9d97936f766a13fa267d4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315282-26315282 |

### 💬 What Happened
A brand-new wallet just sent a tiny fraction of an ETH (0.0001, which is basically nothing) to a fixed‑float address that holds a little more than one ETH. The send happened in a single block, with no other coins or tokens involved. It’s like someone dropping a single grain of sand into a container that can hold a whole bucket—hard to track where that grain came from.

### 🔥 The Roast
So we have a brand‑new wallet that just decided to play hide‑and‑seek with a 0.0001 ETH coin. It’s like a kid dropping a single candy into a giant jar and hoping no one notices. The no‑KYC off‑ramp rule gave it a big 85 points—meaning the wallet is basically a black hole where no identity can escape. On top of that, the fan‑in Sybil pattern scored 70, because 37 other wallets are doing the same thing, like a bunch of copycats in a school of fish. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 155, driven by a no‑KYC off‑ramp and a fan‑in Sybil pattern, indicates a high‑risk transaction that requires immediate investigation.**

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
- **sybil_fan_in** (+70) — 1 of 37 senders depositing similar amounts (~0.000 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from wallet 0xe5e08de2e0aae2a1e2b9d97936f766a13fa267d4, which is 0 days old, has made 2 total transactions, and currently holds a balance of 0 ETH. It sent 0.0001 ETH to receiver 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1) in block 26315282. The AML engine flagged this activity under two high‑risk rules: [no_kyc_offramp] (score: 85) indicating a deposit into a non‑KYC off‑ramp, and [sybil_fan_in] (score: 70) indicating a fan‑in Sybil pattern with 1 of 37 senders depositing similar amounts. The composite score of 155 exceeds the critical threshold, warranting manual review.

</details>

---

## Finding #26: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xcc405a8955d146b5b3005eb5b294df9ba503d505` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315280-26315280 |

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
| **Sender** | `0xc5f0958ea52147abc865e6c82b965440a2a70cbf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315277-26315277 |

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
| **Sender** | `0xea01fc3ccc58286a2a4311a1cdc5cb839c723f2a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315271-26315271 |

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
| **Sender** | `0x5b1f313a9c52e622f124fcda656506e110fa4f21` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315266-26315266 |

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
| **Sender** | `0x5bac3193d50141197fe5896c8b7a743e3ea2897a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315261-26315261 |

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
| **Sender** | `0x46e5cee8c6f2a0e6e259288fb866a2cd86223081` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315253-26315253 |

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
| **Sender** | `0x18ac7bda90a1af568e9e9bfd32bdfca3e4beac53` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315249-26315249 |

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
| **Sender** | `0xcfef34e7501ccf0461c8177798d491a15ecc42eb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315241-26315241 |

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
| **Sender** | `0x9d6b263aa0224ecc59240b6bafc761d3e90e3d66` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315228-26315228 |

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
| **Sender** | `0xa41d2a4b2ef82a7cb0ac7a24a9c88821159a5cac` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315227-26315227 |

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
| **Sender** | `0x501534cabc68fe3dbf5dc1d67f32345b1949dcc3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315217-26315217 |

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
| **Sender** | `0x597bf73bb7194e3252ed960dc914e93c19b1ea75` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315205-26315205 |

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
| **Sender** | `0xc8d643b43927128750884cfe9c3a719e432eb9e1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315196-26315196 |

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
| **Sender** | `0x3bf079508474da3b5a078212ad25325561861afa` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315186-26315186 |

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
| **Sender** | `0x4e95f3b4df4e3e16561ac9a821bbcf04079b0776` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315183-26315183 |

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
| **Sender** | `0xbbffad470e2d70ab690b4c91ef6c83d26c0345ca` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315178-26315178 |

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
| **Sender** | `0xe1f3eab7077e0d6f07afc850087992eed2ea24cd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315178-26315178 |

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
| **Sender** | `0xfabf60bfe9e231cfb7aa5fa84bc096087559f1d0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315168-26315168 |

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
| **Sender** | `0x70deb8dcd5ef0bb7d4a41ca7341f38fa9589bcb3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315156-26315156 |

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
| **Sender** | `0x9ca5a20832d47a60bf1ced6eb0e89b7685c02a4e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315156-26315156 |

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
| **Sender** | `0xe03ccf1b2d0eac3cdbdd79cf2197f979ac98d522` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315155-26315155 |

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

## Finding #47: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x98f446f6965953871202e5118a9ac6090cc01832` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26315147-26315147 |

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

## Finding #48: HIGH — Score 115

| | |
|---|---|
| **Sender** | `0x0229325b05fcc9d2a989b6d9f01cf7bff9de3bb2` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0349 ETH** ($79) |
| **Blocks** | 26315233-26315325 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 115.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 115)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 321 days |
| Total Transactions | 16 |
| Current Balance | 0.014992 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 115):
- **structuring** (+50) — 3/3 amounts near round numbers — possible threshold avoidance
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x4c386e1ffc9a65144c7f4f57aa7107e47a68aa4b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$17,000** (17,000 USDC) |
| **Blocks** | 26315338-26315338 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to FixedFloat 1: $17,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **21** token transfers totaling **$28,949** (0 WETH, 30 USDC, 25 USDT, 22,211 USDC, 100 USDC) |
| **Blocks** | 26315149-26315344 |

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
- **stablecoin_mixing** (+110) — 15 stablecoin transfer(s) to Across SpokePool V2: $28,948 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #51: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x29bd8d77db233f8ffb6e4ef95b1f1498f4b71646` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **5** token transfers totaling **$68,461** (1,461 USDT, 8,000 USDT, 8,000 USDT, 31,000 USDT, 20,000 USDT) |
| **Blocks** | 26315169-26315218 |

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
- **stablecoin_mixing** (+110) — 5 stablecoin transfer(s) to Across SpokePool V2: $68,461 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #52: HIGH — Score 105

| | |
|---|---|
| **Sender** | `0x846113540bb12b60c0e852f50d9a5997ce6e7a9b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **9.3233 ETH** ($20,998) |
| **Blocks** | 26315280-26315280 |

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
| Wallet Age | 683 days |
| Total Transactions | 311 |
| Current Balance | 0.005552 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 105):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge
- **exit_rush** (+40) — Wallet balance near zero (0.005552 ETH) after moving 9.3233 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #53: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb508b117cd9fabab284e3571ce6d2a9814101e83` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($225) |
| **Blocks** | 26315344-26315344 |

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
| **Sender** | `0xec6bae8ffd3cfcb1dd512f204da255d3fc29cfcb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0915 ETH** ($206) |
| **Blocks** | 26315323-26315323 |

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
| **Sender** | `0x75dcecd5eaee1780287ab711f158474e0bdee41e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0163 ETH** ($37) |
| **Blocks** | 26315315-26315315 |

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
| **Sender** | `0x43d5cb111c571755d3872f0aad6c6f457ab58b68` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.7553 ETH** ($1,701) |
| **Blocks** | 26315282-26315282 |

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
| **Sender** | `0x15b3706daeeec67aa72e2f171be3c64182444974` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0050 ETH** ($11) |
| **Blocks** | 26315263-26315263 |

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
| **Sender** | `0xc929f370e2a2786def4957d3ae0e314ca34d8562` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26315238-26315238 |

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
| Wallet Age | 1 days |
| Total Transactions | 2 |
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
| **Sender** | `0xe565d898af9838fc38d3145f0473245addc60ff6` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.6200 ETH** ($1,396) |
| **Blocks** | 26315237-26315237 |

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
| **Sender** | `0xe5dbd3368fdb34f32514315b5d3948c45931fb56` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0940 ETH** ($212) |
| **Blocks** | 26315237-26315237 |

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
| **Sender** | `0x3990eba90a394f85d9f1146d51b2bcc8e62fadad` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0300 ETH** ($68) |
| **Blocks** | 26315227-26315227 |

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
| **Sender** | `0x340cc4d71a36f86d41280716ae0306b0abffe142` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0450 ETH** ($101) |
| **Blocks** | 26315226-26315226 |

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
| **Sender** | `0xad2c2353de43ef1d29f2473c52323937aecfe94b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0050 ETH** ($11) |
| **Blocks** | 26315223-26315223 |

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
| **Sender** | `0x5bc05248eae077ebb21134b6238cde028675909f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0164 ETH** ($37) |
| **Blocks** | 26315208-26315208 |

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
| **Sender** | `0x457ebabcd167ad9b9c89a628d163c365fa85406c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0090 ETH** ($20) |
| **Blocks** | 26315184-26315184 |

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
| **Sender** | `0x251e3d71c94c069269867e31224d038c9e06883f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2120 ETH** ($477) |
| **Blocks** | 26315179-26315179 |

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
| **Sender** | `0xe6d1ac3493b581eb8f087b7e18bd14f7d9d0899a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1034 ETH** ($233) |
| **Blocks** | 26315175-26315175 |

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
| **Sender** | `0x6f53ca833e5ad338c01df6f3aa61cde83787c133` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0067 ETH** ($15) |
| **Blocks** | 26315170-26315170 |

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
| **Sender** | `0x74f4bb7dd2aa80f6c2a0db19d812f39b56b27e19` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0067 ETH** ($15) |
| **Blocks** | 26315160-26315160 |

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

## Finding #70: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x311836353a3e8b098b84ef22cf128fa9ffc893d0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$25** (25 USDT) |
| **Blocks** | 26315343-26315343 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $25 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #71: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc2c7272e348761074ae0197f700d8133518446ec` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$18** (18 USDC) |
| **Blocks** | 26315340-26315340 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $18 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #72: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x294e9052f47fcf6dabc8923ed36afdbc3c8be8ed` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$303** (303 USDC) |
| **Blocks** | 26315340-26315340 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $303 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #73: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe76226262c62b9803b0a3be755c872457a9da988` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$16** (16 USDT) |
| **Blocks** | 26315338-26315338 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $16 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #74: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf1d53d5d5fb1950d8ce0f215ec0ded5c8f6e92f8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$26** (26 USDT) |
| **Blocks** | 26315327-26315327 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $26 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #75: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x97ccdbea4632140639ad5ea9b944aa034eb15fd4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **27** token transfers totaling **$6,819** (9 USDC, 2 USDC, 30 USDT, 0 WETH, 52 USDT) |
| **Blocks** | 26315148-26315340 |

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
- **stablecoin_mixing** (+80) — 22 stablecoin transfer(s) to Across SpokePool V2: $6,818 total (USDC, USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #76: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0038dfb2bbc353daa6ad22cb11ee1d78f41b59cd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **9** token transfers totaling **$1,971** (0 WETH, 0 WETH, 1,705 USDC, 0 WETH, 20 USDC) |
| **Blocks** | 26315181-26315339 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $1,971 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #77: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9e64d18073cd8ec20e2680124d0551ba1629fa20` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **8** token transfers totaling **$8,027** (4 WETH, 0 WETH, 0 WETH, 0 WETH, 2 WETH) |
| **Blocks** | 26315211-26315337 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $8,020 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #78: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9a47f3289794e9bbc6a3c571f6d96ad4e7baed16` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** token transfers totaling **$1,480** (274 USDT, 0 WETH, 50 USDT, 15 USDC, 42 USDC) |
| **Blocks** | 26315161-26315329 |

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
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to Across SpokePool V2: $1,480 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #79: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** token transfers totaling **$5,925** (199 USDC, 131 USDT, 4,787 USDC, 808 USDC) |
| **Blocks** | 26315147-26315315 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to Across SpokePool V2: $5,925 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #80: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x28a4d41776968c1201a807ec51ffb405362b8882` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** token transfers totaling **$1,088** (303 USDT, 150 USDC, 21 USDT, 70 USDT, 44 USDT) |
| **Blocks** | 26315162-26315310 |

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
- **stablecoin_mixing** (+80) — 6 stablecoin transfer(s) to Across SpokePool V2: $1,088 total (USDC, USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #81: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3d2d2538b2dde72ac9f2730afe1799040f08f4f0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$304** (50 USDC, 202 USDC, 52 USDC) |
| **Blocks** | 26315145-26315298 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $304 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #82: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3aa884f0d66ab53d185f6b2d7869e0f834d430d5` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$56** (56 USDT) |
| **Blocks** | 26315249-26315249 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $56 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #83: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x69460570c93f9de5e2edbc3052bf10125f0ca22d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$105** (1 USDT, 104 USDT) |
| **Blocks** | 26315187-26315237 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $105 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #84: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8d04cc7e86e687854eb41d9d43512b655b93184b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$6** (6 USDC) |
| **Blocks** | 26315202-26315202 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $6 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #85: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x60ac95ec1153aa8199751917ede25d0ca49a36e2` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$10** (10 USDT) |
| **Blocks** | 26315201-26315201 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $10 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #86: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc186fa914353c44b2e33ebe05f21846f1048beda` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$66** (65 USDT, 1 WETH, 0 WBTC) |
| **Blocks** | 26315189-26315189 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $65 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #87: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd97a2dc5775e551615c264d6db1f237ac86a88e3` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$1,132** (1,132 USDT) |
| **Blocks** | 26315187-26315187 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $1,132 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #88: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x50cfe7c1938db66a1a6d2e86d36f39fbef3d5c4a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$400** (200 USDT, 200 USDT) |
| **Blocks** | 26315149-26315158 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $400 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #89: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x1f80dc8dd0499bbd6d83ae18c5aa5f3b25b40ab6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.4108 ETH** ($925) |
| **Blocks** | 26315335-26315335 |

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
| Wallet Age | 9 days |
| Total Transactions | 140 |
| Current Balance | 0.040961 ETH |
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
| **Sender** | `0x73542226335d3d1217fa9c6e724be6a094136009` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.1013 ETH** ($228) |
| **Blocks** | 26315334-26315334 |

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
| Wallet Age | 164 days |
| Total Transactions | 75 |
| Current Balance | 0.033648 ETH |
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
| **Sender** | `0xddb36428c25f39daf49c8320a3017b685495dd5c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315250-26315333 |

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
| Total Transactions | 25 |
| Current Balance | 0.005741 ETH |
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
| **Sender** | `0x34bfcc9f757cf422dab815aaf52c6faf7ccb863a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315328-26315328 |

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
| Wallet Age | 1780 days |
| Total Transactions | 596 |
| Current Balance | 0.013061 ETH |
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
| **Sender** | `0xf1f3e9a2f596c930eb0efb58cc5f6956eba16f7e` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315327-26315327 |

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
| Wallet Age | 374 days |
| Total Transactions | 61 |
| Current Balance | 0.004240 ETH |
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
| **Sender** | `0x114b8f93d3fc4c73b930c52ccdd4eab783e836f6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0100 ETH** ($23) |
| **Blocks** | 26315199-26315312 |

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
| Wallet Age | 3291 days |
| Total Transactions | 24 |
| Current Balance | 0.018308 ETH |
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
| **Sender** | `0x02436168f8595aaab6498c93f00bbeccbe30e70e` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.5100 ETH** ($1,149) |
| **Blocks** | 26315273-26315273 |

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
| Wallet Age | 646 days |
| Total Transactions | 308 |
| Current Balance | 0.012889 ETH |
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
| **Sender** | `0xb2580c5e3d49f9dc13508bc6cbc312619442c28c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.6800 ETH** ($1,531) |
| **Blocks** | 26315237-26315270 |

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
| Wallet Age | 1361 days |
| Total Transactions | 4918 |
| Current Balance | 0.028820 ETH |
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
| **Sender** | `0x0f2921c204eb605f35cdb65fcbf42b0e7ea16bdd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315268-26315268 |

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
| Wallet Age | 37 days |
| Total Transactions | 12 |
| Current Balance | 0.000131 ETH |
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
| **Sender** | `0xb54ec1f8be3730f6e32102dbddce35b973d66d65` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0155 ETH** ($35) |
| **Blocks** | 26315255-26315267 |

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
| Wallet Age | 183 days |
| Total Transactions | 152 |
| Current Balance | 0.007484 ETH |
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
| **Sender** | `0x80bffee5c265061934b16fdfb1638d8d232061da` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **2.2199 ETH** ($5,000) |
| **Blocks** | 26315267-26315267 |

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
| Wallet Age | 1883 days |
| Total Transactions | 3217 |
| Current Balance | 0.133634 ETH |
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
| **Sender** | `0x8a93c306ba61b43c595dd3cacc85f7a903bc25e7` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315260-26315260 |

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
| Wallet Age | 1580 days |
| Total Transactions | 158 |
| Current Balance | 0.272313 ETH |
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
| **Sender** | `0x825c997af0e4565d691c67000e2aaf87ed7000ce` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.7000 ETH** ($1,577) |
| **Blocks** | 26315241-26315241 |

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
| Wallet Age | 442 days |
| Total Transactions | 609 |
| Current Balance | 1.420338 ETH |
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
| **Sender** | `0x38d37e9a399a36dcb09de22b1830e8b758839cc7` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.1130 ETH** ($254) |
| **Blocks** | 26315239-26315239 |

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
| Wallet Age | 66 days |
| Total Transactions | 41 |
| Current Balance | 0.000298 ETH |
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
| **Sender** | `0x633008f3ec9ec8bb648e5f8b5c268c1f64357de0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0352 ETH** ($79) |
| **Blocks** | 26315200-26315238 |

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
| Wallet Age | 19 days |
| Total Transactions | 18 |
| Current Balance | 0.001957 ETH |
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
| **Sender** | `0xd48ccdbfebb75fb16917f782267ff9a6216aa916` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315234-26315234 |

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
| Wallet Age | 49 days |
| Total Transactions | 1935 |
| Current Balance | 0.013624 ETH |
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
| **Sender** | `0x06010837a3c39e34fb8a9f82c1c5c21b1c921743` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0050 ETH** ($11) |
| **Blocks** | 26315220-26315220 |

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
| Wallet Age | 46 days |
| Total Transactions | 23 |
| Current Balance | 0.000662 ETH |
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
| **Sender** | `0x39f8ab8c02f005d70ac3cee4185254b20058fee0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0100 ETH** ($23) |
| **Blocks** | 26315201-26315201 |

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
| Wallet Age | 663 days |
| Total Transactions | 10 |
| Current Balance | 0.035957 ETH |
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
| **Sender** | `0x3cc14937c8b861a9ea42c5cd5631f1002fbd0bb6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315201-26315201 |

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
| Wallet Age | 168 days |
| Total Transactions | 3608 |
| Current Balance | 0.007374 ETH |
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
| **Sender** | `0x010fb63a6f20ba626bd36a8131980464360975db` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.4440 ETH** ($1,000) |
| **Blocks** | 26315191-26315191 |

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
| Wallet Age | 2013 days |
| Total Transactions | 811 |
| Current Balance | 0.037566 ETH |
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
| **Sender** | `0x3327b00bf7fdfa55ca72256e801d633ca3798a9f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315190-26315190 |

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
| Wallet Age | 57 days |
| Total Transactions | 2342 |
| Current Balance | 0.050482 ETH |
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
| **Sender** | `0x1790c495636690c470d82508d2712c44d92db725` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315190-26315190 |

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
| Wallet Age | 40 days |
| Total Transactions | 26 |
| Current Balance | 0.003890 ETH |
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
| **Sender** | `0x81597a1e84bb55d085446f2e73dbd3d6eeacd73b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0891 ETH** ($201) |
| **Blocks** | 26315159-26315183 |

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
| Wallet Age | 49 days |
| Total Transactions | 190 |
| Current Balance | 0.012878 ETH |
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
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315172-26315175 |

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
| Wallet Age | 1076 days |
| Total Transactions | 212156 |
| Current Balance | 0.933007 ETH |
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
| **Sender** | `0x3de268e2f6e1dea497a7fd78bbfb1302ce4c2a0d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315159-26315159 |

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
| Wallet Age | 130 days |
| Total Transactions | 59 |
| Current Balance | 0.000154 ETH |
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
| **Sender** | `0x2dd5e15c19a1e1c947ff901ab256fb10e98e39f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0012 ETH** ($3) |
| **Blocks** | 26315152-26315158 |

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
| Wallet Age | 155 days |
| Total Transactions | 823 |
| Current Balance | 0.001027 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #115: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xdc06a1af5676c26b4c1e4cf5e73657d2b0412a63` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26315155-26315155 |

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
| Current Balance | 0.000098 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**115 suspicious findings** detected across 115 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 47 |
| 🟠 HIGH | 5 |
| Wallets flagged | 115 |
| Suspicious value | 24.7392 ETH ($55,717) + $142,188 in stablecoins |
| Blocks scanned | 26315145 — 26315344 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 2 of 25 attempted analyses this run.

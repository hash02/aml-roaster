# 🔥 AML Roaster Report
**2026-11-12 23:34 UTC** · Ethereum Mainnet · ETH $2,014.24
**Blocks:** 26401907 — 26402106 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26401907 to 26402106 checked (about 40 min). 5 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 5 addresses attempted, 4 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## ⚠️ Partial Run

This scan reached its 900s time budget and stopped early so a report could still be written. 4 of 8 watched addresses in this batch were scanned. The rest were deferred to the next run: Across SpokePool V2 (`0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5`), LayerZero Endpoint V1 (`0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675`), Wormhole Core Bridge (`0x98f3c9e6e3face36baad05fe09d375ef1464288b`), Across Relayer 1 (intent filler) (`0x428ab2ba90eba0a4be7af34c9ac451ab061ac010`).

---

**Coverage note:** 11 of the findings below were raised while profiling an address whose scan was then cut short by the time budget, so that address counts as deferred above even though it produced findings. Those findings are preliminary: the address keeps its previous scan position, is scanned again on the next run, and its findings are re-derived in full then.

---

## Finding #1: CRITICAL — Score 255

| | |
|---|---|
| **Sender** | `0x42e3702949962192d264604a789c4e0357841a8f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **28.8500 ETH** ($58,111) |
| **Blocks** | 26402077-26402077 |

### 💬 What Happened
A brand‑new wallet, like a freshly opened envelope, suddenly sent out a huge chunk of ETH (about $58,000) to a fixed‑float address that doesn’t require you to show your ID. After the transfer the wallet was empty, so it looks like a quick burner: it made the move and vanished.

### 🔥 The Roast
So this new wallet did the classic “burner‑wallet‑on‑the‑run” dance: it popped up, dumped a fat 28.85 ETH, and then disappeared faster than a magician’s rabbit (novel_wallet_dump, meaning a brand‑new wallet doing a big move). The transfer was hefty (high_value, meaning over $10k in a single shot), and it went straight to a fixed‑float address that doesn’t do KYC (no_kyc_offramp, meaning no identity check). Then it drained itself to zero in a flash (exit_rush, meaning the wallet’s balance hit zero right after the move). In short, it’s like someone just bought a new car, took it for a spin, and then left the keys in the trunk. Nice one, buddy!

### 🎯 Verdict & Next Steps
**CRITICAL — The composite score of 255, driven by a brand‑new wallet, high‑value transfer, no‑KYC off‑ramp, and an exit rush, indicates a high risk of illicit activity.**

CRITICAL (rule score 255) Consider requesting additional source‑of‑funds evidence if the client is identified.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (4 rules, composite score: 255):
- **novel_wallet_dump** (+100) — Wallet is 0 days old, moving 28.8500 ETH — classic burner pattern
- **high_value** (+30) — High-value transfer: 28.8500 ETH ($58,111)
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 28.8500 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involved a 0‑day old sender wallet (novel_wallet_dump) that performed a single high‑value transfer of 28.8500 ETH (~$58,111). The recipient was a FixedFloat 1 address, a known no‑KYC off‑ramp (no_kyc_offramp). Post‑transfer, the sender wallet balance dropped to 0.000000 ETH, indicating a full drain (exit_rush). These patterns collectively trigger high AML risk scoring per our engine. The composite score of 255 exceeds the critical threshold and warrants further investigation.

</details>

---

## Finding #2: CRITICAL — Score 254

| | |
|---|---|
| **Sender** | `0xbdc2a780931d7987b9ee71c8d189c225b841d88e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **20.0000 ETH** ($40,285) |
| **Blocks** | 26402067-26402067 |

### 💬 What Happened
A brand-new wallet sent 20 ETH (about $40,000) to a service called FixedFloat 1 and then vanished, leaving the wallet empty. It’s like dropping a package into a slot that hides who sent it and then walking away with no receipt. The whole thing happened in a single transaction, and the sender had zero balance afterward.

### 🔥 The Roast
This is a textbook burner wallet move: novel_wallet_dump (meaning the wallet is brand‑new and has never moved money before) scored a whopping 99, high_value (a single transfer of $40k) added 30, no_kyc_offramp (the money left through a service with no identity verification) pumped another 85, and exit_rush (the wallet is empty right after the transfer) gave 40. In other words, the sender bought a one‑way ticket to the Dark Side and checked out. If this was a party, the host would have been a very shy, anonymous guy who never shows up again. CRITICAL (rule score 254)

### 🎯 Verdict & Next Steps
**CRITICAL — new wallet, high-value transfer to a non‑KYC off‑ramp with immediate balance drain.**

Flag the transaction for manual compliance review. CRITICAL (rule score 254)

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
- **high_value** (+30) — High-value transfer: 20.0000 ETH ($40,285)
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 20.0000 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a high‑risk pattern consistent with Rule novel_wallet_dump (wallet age 0 days, single transaction, zero balance post‑transfer), Rule high_value (transfer value 20 ETH), Rule no_kyc_offramp (destination FixedFloat 1 is a non‑KYC off‑ramp), and Rule exit_rush (balance drained immediately). The sender’s wallet was created and used in a single transaction, with no subsequent activity, indicating a possible burner wallet scenario. The engine composite score of 254 reflects a high likelihood of suspicious activity. Further investigation is warranted to determine the source and intended use of the transferred funds.

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **24** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26401907-26402106 |

### 💬 What Happened
A single wallet sent 24 tiny transactions of zero ETH to a cross‑chain bridge. Think of it like dropping 24 empty envelopes into a mailbox to hide that you actually sent a letter somewhere else. The sender’s account is active, with a decent balance, but the pattern of identical, almost meaningless transfers looks suspicious.

### 🔥 The Roast
Look at this, 24 identical zero‑ETH deposits—like a kid dropping empty boxes into a vending machine just to keep the cashier busy. The engine flags it as structuring (meaning the user is breaking a single move into many tiny ones to dodge detection), peel_chain_linear (a straight line of peels on a banana, i.e., a layering chain that keeps the money moving in a predictable pattern), and bridge_hop (the money is hopping across chains like a bad magician’s disappearing trick). CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction pattern meets multiple high‑risk AML indicators (structuring, peel chain, bridge hop) suggesting potential layering and obfuscation.**

Flag this address for manual investigation and monitor subsequent activity. CRITICAL (rule score 195)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 91 days |
| Total Transactions | 30593 |
| Current Balance | 0.472635 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 24 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 24 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender wallet (0xfd0aa7548823c40be6dd85682f0342f35dee121a) executed 24 identical zero‑ETH transfers to Across SpokePool V2 (0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5) over blocks 26401907–26402106. Evidence includes a structuring pattern (Rule: structuring, score 70) indicating potential smurfing, a peel chain linearity (Rule: peel_chain_linear, score 60) suggestive of layering, and a bridge hop (Rule: bridge_hop, score 65) indicating cross‑chain movement. The wallet has a high transaction count, is only 91 days old, and remains active with a balance of 0.472635 ETH, further raising suspicion.

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **16** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26401914-26402106 |

### 💬 What Happened
The sender sent 16 tiny packages of zero value into a bridge that moves funds between blockchains, like dropping a handful of empty envelopes into a mail slot that hides who sent them. Each envelope was exactly the same size, so no one could tell them apart. The receiver is a smart contract that forwards the money to another chain, but nothing actually moved because the amount was $0.

### 🔥 The Roast
So this guy decided to play a game of “Who can send the most zero‑eth?” He sent 16 identical packets of nothing into a bridge, which is basically like stuffing 16 empty bottles into a recycling bin that pretends to be a cross‑chain drop‑box. The AML engine gave him a 70 for structuring (because he’s smurfing with zeros), 60 for peel_chain_linear (because it’s a straight‑line chain of empties), and 65 for bridge_hop (because he used Across SpokePool V2 to hop across chains). He’s basically trying to convince regulators he’s doing something fancy, but all he’s doing is moving a bunch of empty envelopes like a bored accountant with a spreadsheet full of zeros.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of identical zero‑value deposits, sequential layering, and bridge hopping satisfies multiple AML rules and warrants immediate investigation.**

Flag this transaction for manual compliance review and cross‑reference the sender’s address against known high‑risk lists. Consider initiating an inquiry into the source of the deposits and the purpose of the bridge hop.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 41 days |
| Total Transactions | 11939 |
| Current Balance | 0.007420 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 16 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 16 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender’s wallet (0x20c58c01cc73da90d5ca4dfb4357228c636422d6) performed 16 consecutive ETH transfers of 0.0000 each to 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2, a known cross‑chain bridge. According to rule [structuring], the identical, low‑value deposits constitute textbook structuring or smurfing. Rule [peel_chain_linear] indicates a peel chain layering pattern due to the sequential similarity. Rule [bridge_hop] flags the use of a bridge to move funds across chains, increasing layering risk. The wallet is only 41 days old, has performed 11,939 transactions, and currently holds 0.007420 ETH, indicating high activity but no recent withdrawals.

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **34** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26401913-26402101 |

### 💬 What Happened
A wallet sent 34 tiny, identical amounts of zero ETH into a bridge contract that moves coins between blockchains. It's like someone dropping the same empty bottle into a slot on a vending machine over and over, making it hard to see where the real money came from. The sender did it right now, with no break between the moves.

### 🔥 The Roast
Looks like this wallet decided to play a game of 'Who can send the smallest amount?' with a bridge that takes ETH from one chain to another. 34 identical 0.0000 ETH transfers? That's not smurfing, that's a math teacher's nightmare. The structuring rule (meaning the pattern of splitting money into tiny pieces) gave it a 70. The peel_chain_linear rule (layering by making a chain of similar moves) gave 60, and the bridge_hop rule (moving coins across chains) gave 65. With a composite score of 195, this guy is basically the blockchain's version of a bad prank call.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual review, cross-reference with internal and external watchlists, and consider placing a temporary hold on future outgoing transfers until a full investigation is completed.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2799 days |
| Total Transactions | 853070 |
| Current Balance | 11.994126 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 34 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 34 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction sequence from 0x07ae8551be970cb1cca11dd7a11f47ae82e70e67 to 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 involved 34 identical 0.0000 ETH transfers within block range 26401913-26402101, indicating a potential structuring activity (Rule: structuring). The sequential pattern of identical deposits suggests a peel chain linear layering attempt (Rule: peel_chain_linear). The use of Across SpokePool V2 indicates a bridge hop across chains (Rule: bridge_hop). The composite AML score of 195 flags this as a high-risk pattern requiring further investigation.

</details>

---

## Finding #6: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **10** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26401970-26402101 |

### 💬 What Happened
The sender sent ten tiny packets of zero value to a bridge address, like someone dropping empty envelopes into a dropbox to hide that they didn't actually send anything.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their money—10 identical 0‑ETH packets, score 70 on structuring (meaning they tried to break up a transaction into smaller, identical parts to avoid detection). The engine also gave a 60 for peel_chain_linear, which is the crypto equivalent of peeling a banana in a straight line to hide the peel. And a 65 on bridge_hop because the packets hopped over to Across SpokePool V2—so basically a cross‑chain bridge to keep the trail fuzzy. Bottom line: they’re trying to make a mess of the audit trail like a kid who’s done a bad prank and left a trail of empty wrappers.

### 🎯 Verdict & Next Steps
**CRITICAL: The transaction pattern meets structuring, peel_chain_linear, and bridge_hop rules, indicating a high risk of layering.**

Flag the account for manual review, request source of funds documentation, and monitor for future suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 246 days |
| Total Transactions | 18188 |
| Current Balance | 0.070545 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 10 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 10 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The account performed 10 consecutive ETH transfers of 0.0000 each to the Across SpokePool V2 contract, satisfying the structuring rule (identical small deposits), the peel_chain_linear rule (sequentially similar transfers), and the bridge_hop rule (cross‑chain bridge usage). The sender wallet is 246 days old with 18,188 prior transactions and a current balance of 0.070545 ETH, indicating an active and experienced user. CRITICAL (rule score 195) CRITICAL (rule score 195)

</details>

---

## Finding #7: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26401954-26402101 |

### 💬 What Happened
The sender sent four identical, zero‑value transactions into a cross‑chain bridge, like dropping four empty envelopes into a mailbox to make it look like a regular mail drop. Even though nothing moved, the pattern of tiny, identical deposits hints at an attempt to disguise the source of funds. The activity happens right before the wallet last used it, so it feels like a quick, sneaky move.

### 🔥 The Roast
Score 70 on structuring (meaning the person is trying to hide the source by breaking up transactions into tiny amounts). Score 60 on peel_chain_linear (the four deposits are like a straight line of smurfing, as if you’re trying to create a chain of breadcrumbs). CRITICAL (rule score 195) Even though the ETH amount is $0, the pattern screams "I’m trying to stay under the radar while still moving something." It’s like putting a bunch of invisible coins into a vault and hoping the security camera doesn’t notice the empty slots.

### 🎯 Verdict & Next Steps
**CRITICAL – The combination of structuring, peel chain, and cross‑chain bridge activity signals a high risk of layering or obfuscation.**

Flag the transaction for manual review, request source of funds documentation, and monitor the receiving address for further suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1088 days |
| Total Transactions | 214529 |
| Current Balance | 0.782123 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet (0xef1ec136931ab5728b0783fd87d109c9d15d31f1) performed four consecutive, identical zero‑ETH deposits (structuring rule) to Across SpokePool V2, forming a peel chain (peel_chain_linear rule) and involving a cross‑chain bridge (bridge_hop rule). The wallet’s high transaction count (214,529) and age (1088 days) raise additional concerns about potential layering and obfuscation. No token transfers were recorded, but the pattern aligns with known suspicious activity for structuring and layering. This activity merits a high composite score of 195 and should be flagged for further review.

</details>

---

## Finding #8: CRITICAL — Score 191

| | |
|---|---|
| **Sender** | `0xf4b6e4727701cc3649d88030decc6da4d9b871aa` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **3.4394 ETH** ($6,928) |
| **Blocks** | 26402104-26402104 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 191.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 191)**

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

**Rules Triggered** (3 rules, composite score: 191):
- **novel_wallet_dump** (+66) — Wallet is 0 days old, moving 3.4394 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 3.4394 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #9: CRITICAL — Score 190

| | |
|---|---|
| **Sender** | `0x70499d83e0d3182a8f156a9e8cfe13537971dad3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.9455 ETH** ($5,933) |
| **Blocks** | 26402033-26402033 |

### 💬 What Happened
A brand‑new crypto address just sent almost $6,000 worth of ETH to a service called FixedFloat 1, then disappeared with no remaining balance. It's like someone drops a suitcase in a hidden slot and then walks away with the cash, leaving no paper trail. The sender had no prior activity and didn't use any KYC (Know‑Your‑Customer) verification, so there's no obvious identity attached.

### 🔥 The Roast
This wallet scored a whopping 65 on novel_wallet_dump, which basically means it’s a brand‑new burner that dumped a big chunk of ETH like a kid with a fresh wallet. No_KYC_Offramp got an 85 because the funds went straight to a FixedFloat 1, which is a no‑identity, no‑passport, no‑KYC off‑ramp — basically a tunnel for the money. Exit_rush scored 40, showing the wallet was empty after the dump, like a magician who pulls all the coins out of the hat and disappears. CRITICAL (rule score 190) If this were a sitcom, the plot twist would be “Where did the money go?”

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits a high‑risk pattern of a newly created wallet moving a large amount to a non‑KYC off‑ramp and immediately draining, indicating a potential attempt to obscure the source of funds.**

Flag the transaction for manual AML review; request additional information on the origin of the ETH and monitor subsequent activity for any further suspicious patterns.

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
- **novel_wallet_dump** (+65) — Wallet is 0 days old, moving 2.9455 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.9455 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction matches the following AML engine rules: [novel_wallet_dump] (score 65) indicating a newly created wallet (age 0 days) used for a large ETH dump; [no_kyc_offramp] (score 85) showing transfer to FixedFloat 1, a known non‑KYC off‑ramp; and [exit_rush] (score 40) reflecting the wallet balance dropping to zero immediately after the transfer. The evidence includes a single outgoing transaction of 2.9455 ETH ($5,933 USD) to the off‑ramp and a post‑transaction balance of 0.000000 ETH. CRITICAL (rule score 190)

</details>

---

## Finding #10: CRITICAL — Score 190

| | |
|---|---|
| **Sender** | `0xe8fdcf4a7220c11f2d44f464ac99d681ecaa0c97` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.5315 ETH** ($5,099) |
| **Blocks** | 26402031-26402031 |

### 💬 What Happened
A brand‑new wallet that had never been used before just sent a single large amount of 2.5315 ETH (about $5,099) to a service called FixedFloat 1. After the send, the wallet had no money left, so it’s like someone who just dropped a big cash envelope into a slot that hides who sent it and immediately walked away.

### 🔥 The Roast
Looks like a brand‑new burner wallet decided to play a game of hide‑and‑seek with a $5K stash. The AML engine gave it a 65 on novel_wallet_dump (meaning it’s a fresh wallet dumping funds like a new kid in school), 85 on no_kyc_offramp (so it’s going to a place that doesn’t ask for ID—think of it as a shady bar that won’t ask who you are), and 40 on exit_rush (the wallet empties in a heartbeat). CRITICAL (rule score 190)

### 🎯 Verdict & Next Steps
**CRITICAL — The composite score of 190 exceeds the high‑risk threshold due to combined burner wallet, no‑KYC off‑ramp, and exit rush patterns.**

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
- **novel_wallet_dump** (+65) — Wallet is 0 days old, moving 2.5315 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.5315 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
This transaction involves a wallet with a 0‑day age and a single outgoing transfer of 2.5315 ETH to FixedFloat 1, after which the wallet balance drops to 0.000000 ETH. The AML engine flagged the pattern under the following rules: [novel_wallet_dump] (score 65) indicating a new wallet dumping funds, [no_kyc_offramp] (score 85) indicating a transfer to a service without KYC, and [exit_rush] (score 40) indicating the wallet was emptied immediately after the transfer. CRITICAL (rule score 190) CRITICAL (rule score 190)

</details>

---

## Finding #11: CRITICAL — Score 190

| | |
|---|---|
| **Sender** | `0xf799f57ef0c6ef6aeddb05ac5e7faa14247cd9c1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.9337 ETH** ($5,909) |
| **Blocks** | 26401956-26401956 |

### 💬 What Happened
A brand‑new wallet (just created today) sent about $5,909 worth of ETH straight into a service that instantly turns crypto into cash without asking for any identity proof. The sender had no money left in the wallet after the move, so it looks like a quick, one‑time drop to hide where the money came from.

### 🔥 The Roast
So we have a fresh burner wallet (novel_wallet_dump score 65) that decided to play hide‑and‑seek with 2.9337 ETH. It dumped the coins into FixedFloat 1 (no_kyc_offramp score 85), the crypto equivalent of a no‑name ATM that never asks for your ID. And then it vanished, leaving the wallet empty (exit_rush score 40). Basically, the wallet is saying, "I’m off the grid, but I’m also not leaving any receipts," which is exactly the kind of thing we flag for a deeper look.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction shows a classic burner wallet pattern with immediate off‑ramp conversion and no KYC, requiring urgent human review.**

Flag the transaction for manual investigation, trace subsequent transfers from the FixedFloat account, and consider adding the sender address to a watchlist for future monitoring.

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
- **novel_wallet_dump** (+65) — Wallet is 0 days old, moving 2.9337 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.9337 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers multiple high‑risk indicators: (novel_wallet_dump) – the wallet is brand new (0 days) and moved a large amount of ETH; (no_kyc_offramp) – the destination is a fixed‑float service that offers instant fiat conversion without KYC; (exit_rush) – the wallet’s balance drops to zero immediately after the transfer. These patterns are consistent with burner wallet usage to obscure the origin of funds. The transaction should be reported under the suspicious activity report template and monitored for downstream movement.

</details>

---

## Finding #12: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x7a5c50b66f91d689250996c2b05328c18d5f3bc4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.0574 ETH** ($4,144) |
| **Blocks** | 26402062-26402062 |

### 💬 What Happened
A brand‑new wallet (created today) sent 2.0574 ETH – about $4,144 – to a service that doesn’t ask for identity verification. After the send, the wallet’s balance is zero, so all the money has disappeared in one go. It’s like a fresh delivery truck dropping off a huge shipment and then vanishing into the night.

### 🔥 The Roast
So this new wallet is basically the crypto equivalent of a disposable phone you get from a shady vendor, drop a huge cash package, and then it’s gone. The engine flagged it as a "novel_wallet_dump" (meaning a brand‑new wallet dumps a big chunk of coins right away) and a "no_kyc_offramp" (the coins hit a place that doesn’t care about who’s sending them). And because it’s gone from 2.0574 ETH to zero in one step, it’s got an "exit_rush" score too – like a cashier who empties the till in a single swipe. All told, the composite score of 189 is like a red flag that says, “Hey, something fishy is happening here!”

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction exhibits a classic burner‑wallet pattern with a high composite score, indicating a high likelihood of illicit fund movement.**

Flag the wallet and transaction for manual AML review; investigate the source of the 2.0574 ETH and monitor for additional activity from the same address or related accounts.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.0574 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.0574 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet with a 0‑day age and a single outgoing transfer of 2.0574 ETH to a FixedFloat 1 address, which is a known no‑KYC off‑ramp service. According to rule [novel_wallet_dump], the wallet’s age and immediate large transfer constitute a high‑risk pattern. Rule [no_kyc_offramp] indicates that the destination does not perform identity verification, increasing the risk of illicit movement. Rule [exit_rush] confirms the wallet was drained to zero balance after the transfer, completing the typical burner‑wallet cycle. These indicators collectively warrant a high‑risk assessment and require further investigation.

</details>

---

## Finding #13: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0xed5b44e2c4d8864cc39669c6fdd7d42aad58ecd9` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.3621 ETH** ($4,758) |
| **Blocks** | 26401935-26401935 |

### 💬 What Happened
A brand‑new wallet, which was just created and has never held any money before, sent about 2.36 ETH (roughly $4,800) to a service called FixedFloat 1. Think of it like someone dropping a large pizza into a new, anonymous box with no way to trace who ordered it.

### 🔥 The Roast
Looks like a classic burner wallet: 0 days old, one transaction, and all the dough (ETH) gone in a single hit. The engine gave it a 64 for novel_wallet_dump (meaning the wallet is brand new and is dumping funds like a teenager dumping cash in a party), a 85 for no_kyc_offramp (no‑KYC off‑ramp, so the money is moving to a place that doesn’t ask who you are), and a 40 for exit_rush (wallet balance is zero after the move, like a magician pulling the money out of a hat and never looking back). The total score of 189? That’s not just a coincidence, it’s a warning light on a car that’s about to crash.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction matches multiple high‑risk patterns including a brand‑new wallet dumping 2.3621 ETH to a no‑KYC off‑ramp, raising immediate concern.**

Flag for manual review by the compliance team. Investigate the source address, check for any known associations, and consider requesting additional information or a chain analysis.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.3621 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.3621 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a high‑risk profile: [novel_wallet_dump] (wallet age 0 days, single large transfer), [no_kyc_offramp] (transfer to FixedFloat 1, a known no‑KYC off‑ramp), and [exit_rush] (immediate balance depletion). The composite score of 189 exceeds the internal threshold for high‑risk activity. This pattern is consistent with burner wallet usage designed to obscure the origin of funds. Flag for compliance review.

</details>

---

## Finding #14: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x9e3852320ea0fd9ecf416868a16b38443313b5d0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.2703 ETH** ($4,573) |
| **Blocks** | 26401933-26401933 |

### 💬 What Happened
A brand‑new wallet just sent 2.27 ETH (about $4,573) to a service called FixedFloat 1. The sender’s account was empty before the transfer and stays empty afterward, like dropping a big package into a slot that hides who sent it. This is a classic pattern used when people want to move money quickly without leaving a trace.

### 🔥 The Roast
This brand‑new wallet is 0 days old—like a newborn with no history—yet it already moved 2.27 ETH, which is like sending a full‑size pizza in one go. The engine gave it a 64 for 'novel_wallet_dump', meaning the wallet just dumped money without a past. Then a 85 for 'no_kyc_offramp', because the money went to FixedFloat 1, a service that doesn’t ask for ID—like a shady bar that only accepts cash. Finally, a 40 for 'exit_rush', because the balance went from full to zero instantly—like a magician who pulls a rabbit out of a hat and never puts it back.

### 🎯 Verdict & Next Steps
**CRITICAL: The transaction demonstrates a new wallet dump to a non‑KYC off‑ramp with an instant zero balance, matching high‑risk AML patterns.**

Flag the transaction for further investigation and request additional information about the source of funds. Consider monitoring related addresses for repeat activity and report to compliance if suspicious patterns persist.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.2703 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.2703 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created wallet (age 0 days) that transferred 2.2703 ETH to FixedFloat 1, a non‑KYC off‑ramp service. According to rule novel_wallet_dump, the wallet’s one‑time movement of 2.2703 ETH constitutes a high‑risk pattern of a burner wallet. CRITICAL (rule score 189) Rule exit_rush confirms that the sender’s balance dropped to zero immediately after the transfer, indicating a potential exit strategy.

</details>

---

## Finding #15: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0xb8d6d96f95626d6b56c239035cfe995c13bb2566` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9552 ETH** ($3,938) |
| **Blocks** | 26402057-26402057 |

### 💬 What Happened
A brand‑new wallet, just created yesterday, sent about 1.9552 ETH (roughly $3,938) to a service called FixedFloat 1. After the transfer, the wallet’s balance dropped to zero, meaning all the ETH was moved out in one go. It’s like dropping a package into a slot that hides who sent it and then leaving the slot empty afterward.

### 🔥 The Roast
This wallet is brand‑new—zero days old, like a freshly opened bottle of wine that never saw the light of day—yet it moved almost $4,000 in one transaction. The engine called it a “novel_wallet_dump” (meaning the wallet has no history and dumps a large sum), which is the crypto equivalent of a cash‑in‑the‑bank teller with a suspiciously empty wallet. CRITICAL (rule score 188) Finally, the “exit_rush” score (wallet drained to zero right after the dump) shows the classic “I’m out of here” move. Bottom line: it’s like a magician who pulls a rabbit out of a hat and immediately throws the hat away—no one knows where the rabbit came from, and it’s gone in a flash.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 188)**

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9552 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9552 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet that is 0 days old with only one transaction, indicating a new burner wallet. Rule novel_wallet_dump (score: 63) flagged the large transfer from a wallet with no prior activity. Rule no_kyc_offramp (score: 85) identified the destination as FixedFloat 1, a platform that does not perform KYC on off‑ramp users. Rule exit_rush (score: 40) noted the wallet’s balance dropped to zero immediately after the transfer, suggesting a full drainage of funds. CRITICAL (rule score 188)

</details>

---

## Finding #16: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x143d6048a3b4a623a15caf5157a0e5a10a5c8cd2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9709 ETH** ($3,970) |
| **Blocks** | 26401908-26401908 |

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9709 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9709 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #17: CRITICAL — Score 187

| | |
|---|---|
| **Sender** | `0x33eeb97ddce037df33c70219eb9dbdc626d25e20` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.0700 ETH** ($2,155) |
| **Blocks** | 26402091-26402091 |

### 💬 What Happened
A brand-new wallet just sent 1.07 ETH to a service called FixedFloat 1, then disappeared with no balance left. It's like dropping a package into a slot that hides who sent it, only to find the package gone and no receipt. The sender had never been used before and now has zero money left.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with 1.07 ETH, but the only thing they hid was the wallet age—0 days, like a newborn baby. The engine gave this a 62 on [novel_wallet_dump] (meaning the wallet is brand new and dumping funds), 85 on [no_kyc_offramp] (meaning the money is going to a place that doesn't ask for identity, basically a no‑KYC off‑ramp), and 40 on [exit_rush] (meaning the funds were drained in one go). This is the kind of pattern that makes regulators go "uh‑uh, that looks fishy." If you thought this was a clean transaction, think again—it's a textbook burner wallet move.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of a brand-new wallet, a single large ETH transfer to a no‑KYC off‑ramp, and immediate balance drain signals a high‑risk burner‑wallet pattern requiring immediate review.**

Flag this transaction for manual investigation, verify the legitimacy of the destination service, and monitor the receiver address for further suspicious activity. Consider cross‑checking with known burner wallet lists and apply enhanced due‑diligence procedures.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 187):
- **novel_wallet_dump** (+62) — Wallet is 0 days old, moving 1.0700 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.0700 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The account 0x33eeb97ddce037df33c70219eb9dbdc626d25e20 exhibits the following suspicious indicators: (1) [novel_wallet_dump] – wallet age 0 days with a single outgoing transaction of 1.0700 ETH, (2) [no_kyc_offramp] – the transfer destination is FixedFloat 1, a known no‑KYC off‑ramp service, and (3) [exit_rush] – the sender’s balance is 0.000000 ETH immediately after the transfer, indicating complete fund drain. CRITICAL (rule score 187) CRITICAL (rule score 187)

</details>

---

## Finding #18: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xedf9bd7803a618f1ed805faa2582286f845e96a4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26402100-26402100 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #19: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x1f39e7c1820be3748af6ba14dd775da4c7e4b351` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($1) |
| **Blocks** | 26402098-26402098 |

### 💬 What Happened
A brand-new wallet (like a freshly opened bank account) sent a tiny amount of ETH, about $1, to a FixedFloat 1 address, which is known to let people move crypto without verification. The sender’s address only had two transactions and was created today, meaning there's no history to trace.

### 🔥 The Roast
Looks like this newbie wallet tried to slip through a KYC checkpoint with a one‑off $1 drop. The engine gave it an 85 for [no_kyc_offramp] (meaning the address accepts deposits but doesn’t let you withdraw without ID), and a 70 for [sybil_fan_in] (think of a fan club where everyone buys the same souvenir). It’s basically a group of kids passing a note in class—everyone’s copying each other, and the teacher is raising an eyebrow. CRITICAL (rule score 155) So, it’s like a secret club that only knows how to stash money, not how to get it out.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag this transaction for manual review by the compliance team; consider conducting a deeper investigation of the FixedFloat 1 address and the associated network activity. CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet with zero days of age, two prior transactions, and a zero balance, indicating a newly created, unverified address. Rule [no_kyc_offramp] was triggered with a score of 85 due to the deposit to a FixedFloat 1 address that provides a no‑KYC off‑ramp. Rule [sybil_fan_in] scored 70, indicating a fan‑in Sybil pattern where 1 of 17 senders are depositing similar amounts (~0.001 ETH ± 30%). CRITICAL (rule score 155)

</details>

---

## Finding #20: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x70becb087bff0eadb733e86e5377f00a665ff848` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($1) |
| **Blocks** | 26402093-26402093 |

### 💬 What Happened
A brand‑new wallet that has never sent anything before just dropped about $1 worth of ETH into a special smart‑contract address that is known to hide where the money goes. Think of it like a mystery box that takes your money and then hands it out to a bunch of strangers, making it hard to see who actually got the cash.

### 🔥 The Roast
So we have a fresh‑from‑the‑oven wallet with zero KYC that decided to play hide‑and‑seek with $1. CRITICAL (rule score 155) Basically, it’s the blockchain’s version of a suspicious group of kids all dropping identical coins into the same secret jar. CRITICAL (rule score 155) CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
This transaction triggers the following AML rules: [no_kyc_offramp] – the sender’s wallet is 0 days old, has no KYC, and is sending ETH to a FixedFloat contract, a known off‑ramp destination; [sybil_fan_in] – the sender is one of 17 wallets depositing similar amounts (~0.001 ETH ± 30%) to the same contract, indicating a potential Sybil pattern. CRITICAL (rule score 155) CRITICAL (rule score 155)

</details>

---

## Finding #21: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x2ff952ef0c9f57e8615976da52f4b02d025d02fe` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($1) |
| **Blocks** | 26402088-26402088 |

### 💬 What Happened
A brand‑new wallet just dropped a tiny amount of ETH (about $1) into a service called FixedFloat 1, which acts like a vending machine that mixes coins so it’s hard to trace who sent it. The sender had only two transactions and no money left in the account, so it looks like a quick, anonymous transfer. In plain terms, it’s like someone slipping a $1 bill into a slot that hides who handed it to the machine.

### 🔥 The Roast
Looks like a brand‑new wallet tried to play hide‑and‑seek with a $1 coin and slipped it into FixedFloat 1, a mix‑and‑match service that’s basically a crypto blender. The engine gave it an 85 on the no‑KYC off‑ramp (meaning the wallet never asked to cash out with identity checks) and a 70 on the sybil fan‑in pattern (so it’s one of 17 similar wallets sending the same tiny amount). CRITICAL (rule score 155) CRITICAL (rule score 155) CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of a brand‑new wallet with no KYC off‑ramp and a sybil fan‑in pattern indicates high risk for anonymous mixing activity.**

CRITICAL (rule score 155) Request additional transaction history or KYC data from the sender’s wallet if available, and monitor for subsequent related activity.

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a zero‑day wallet (0 days old) with a total transaction count of 2 and a current balance of 0.000000 ETH, indicating no ongoing activity. Rule [no_kyc_offramp] was triggered (score: 85) due to the deposit to FixedFloat 1, a known no‑KYC off‑ramp service. Rule [sybil_fan_in] was also triggered (score: 70), as the wallet is one of 17 senders depositing a similar amount (~0.001 ETH ± 30%) to the same receiver, suggesting a fan‑in Sybil pattern. CRITICAL (rule score 155)

</details>

---

## Finding #22: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb5bf78ecea93e68a7e473480e7338622785f720c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($1) |
| **Blocks** | 26402083-26402083 |

### 💬 What Happened
A brand‑new wallet, with no prior history, sent about $1 worth of ETH to a FixedFloat 1 address. The sender is basically a fresh anonymous drop, and the amount is tiny, like putting a single candy into a vending machine that hides who bought it. Because the wallet has never been used before and there’s no identity check, it looks like a quick, stealthy move.

### 🔥 The Roast
This is like a new kid in school who just dropped a $1 pizza into the cafeteria trash can and nobody knows who it came from. The wallet is brand new, no KYC (no identity verification), and it’s part of a fan‑in Sybil pattern – 1 of 17 identical wallets all doing the same thing. The engine gave it a 85 on the no‑KYC off‑ramp rule (meaning the recipient is basically a black hole for identity) and a 70 on Sybil fan‑in, so the composite is a whopping 155. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction’s composite score of 155 indicates high risk due to no‑KYC off‑ramp and Sybil fan‑in patterns.**

Flag for manual review by the AML team; request source‑of‑funds details if possible and monitor subsequent activity for additional suspicious patterns.

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a sender wallet aged 0 days with only 2 prior transactions and a balance of 0 ETH, indicating a fresh, potentially anonymous source. The wallet deposited 0.0007 ETH ($1) into a FixedFloat 1 address, a known no‑KYC off‑ramp (rule [no_kyc_offramp]), and belongs to a cluster of 17 similar wallets each sending amounts within 30% of 0.001 ETH (rule [sybil_fan_in]). CRITICAL (rule score 155) CRITICAL (rule score 155)

</details>

---

## Finding #23: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xb0e1c6d84adf0b5c05dc34aad4f0653c50172a36` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26402082-26402082 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ETH—about a dollar—to a service that forwards money to other people without requiring identity checks. Imagine someone dropping a $1 bill into a slot that instantly sends it to a random stranger; you can’t tell who it came from or who it goes to.

### 🔥 The Roast
This wallet is fresher than a pizza crust—0 days old and already making a move. The transaction is a textbook “no‑kyc off‑ramp” (meaning the money goes to a service that doesn’t ask for ID) and scored a solid 85 points. Add in the sybil fan‑in (several wallets sending almost the same amount to the same place) and the engine flags it as a “fan‑in Sybil pattern” – like a choir of copy‑cats humming the same $1 tune. Bottom line: a composite score of 155 turns this into a red‑flag that deserves a human detective’s attention.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a fresh no‑KYC off‑ramp and a fan‑in Sybil pattern indicates a high likelihood of illicit layering.**

Flag the transaction for manual review, investigate the source wallet’s activity and the destination service’s compliance posture, and consider placing a hold or reporting to the AML team.

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created wallet (age 0 days) that performed 2 total transactions and currently holds zero balance, indicating rapid movement of funds. The transfer to FixedFloat 1, an off‑ramp service with no KYC, triggered rule [no_kyc_offramp] with a score of 85. Additionally, the amount of 0.0006 ETH falls within a 30% range of 0.001 ETH, and 1 of 17 similar senders were identified, activating rule [sybil_fan_in] with a score of 70. These patterns collectively produce a composite risk score of 155, exceeding the critical threshold for further review.

</details>

---

## Finding #24: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xed01eafe0db9dfe293ddd1448257f1006e763758` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($1) |
| **Blocks** | 26402080-26402080 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #25: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x2d8e991e9add1a7987cad53521ae1c6c15577496` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26402080-26402080 |

### 💬 What Happened
A brand-new wallet just dropped a tiny bundle of 0.0006 ETH (about $1) into a service called FixedFloat 1, which is like handing your money to a friend who promises to give you cash back later, but you never see their face. The sender has only made two transactions ever and has zero balance now, so it’s basically a fresh account doing a single move. CRITICAL (rule score 155)

### 🔥 The Roast
So, we’ve got a newborn wallet that’s already tried to off‑load its $1 to a no‑KYC service (scored 85 on the no_KYC_offramp rule, meaning no ID required to cash out). The same little amount shows up in 1 of 17 similar deposits—sybil_fan_in score 70—so it’s basically the crypto equivalent of a group of teenagers all sending money to the same anonymous charity. If you think this is a harmless tip, just remember: even a single $1 can be a key to a bigger scam. The wallet is so new, it’s like a teenager who just got a credit card and is already making purchases—easy target for bad actors.

### 🎯 Verdict & Next Steps
**CRITICAL – The combination of a brand‑new wallet, a no‑KYC off‑ramp deposit, and fan‑in Sybil pattern indicates a high‑risk activity that requires immediate human review.**

Flag the transaction for manual investigation, request source‑of‑funds information from the sender, and monitor any related addresses for further suspicious activity.

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction was executed by a wallet that is 0 days old, with only 2 total transactions and a current balance of 0.000000 ETH. It deposited 0.0006 ETH to the FixedFloat 1 address, triggering the [no_kyc_offramp] rule (score 85) indicating an off‑ramp with no identity verification. Additionally, the pattern matches 1 of 17 similar senders depositing ~0.001 ETH ±30%, activating the [sybil_fan_in] rule (score 70) for a fan‑in Sybil pattern. CRITICAL (rule score 155)

</details>

---

## Finding #26: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x8bad95c6e6139171d7eac843d4b6b3a0131960f3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26402066-26402066 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa02083af824061177d8eea94e7cd33813a3ae8c5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26402064-26402064 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc4553abec5a2b0e1f21622fb30c640236281b81b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26402063-26402063 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x614dade404559315505ce1c6e46f44bd68129ad1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26402060-26402060 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xba842d2139f45a28dd1e914baeda81d1c32fdec7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($1) |
| **Blocks** | 26402037-26402037 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x39a498264a7b6774d4b742eaff756293d0e0a4ca` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26401954-26401954 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x3907121926177ffaf05bd39ffae053156d758e9e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26401942-26401942 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf6e62f97fc09c41e23f615ac5b0fa4cafe988c5b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26401938-26401938 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xeb3bd5e603683a934c04d7d3cf2fac02d0ad5ab3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26401936-26401936 |

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
- **sybil_fan_in** (+70) — 1 of 17 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xe6c5de9e6e0b78d1e211318b579fb61bab1ed810` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0597 ETH** ($120) |
| **Blocks** | 26402103-26402103 |

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

## Finding #36: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x39221ef4c791ba25f637bcfa17f16c7e5c3cb1d5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0009 ETH** ($2) |
| **Blocks** | 26402102-26402102 |

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
| **Sender** | `0xc9e085d8e6677b5b1dee5f9b85ab0c8f02afb15a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402096-26402096 |

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

## Finding #38: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc237afdfef35d2a71511390ccbda9719038c193d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402093-26402093 |

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

## Finding #39: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x47b1affcf5e9da4f3f8716e2ea7dd068071a4851` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402087-26402087 |

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

## Finding #40: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5f6d33bf7202eac36278441c6b9d3d19269513b1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402081-26402081 |

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

## Finding #41: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xec5c59d4e5f3f8ea1ae3d07af2430ed117fa2c5a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402073-26402073 |

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

## Finding #42: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xab348814dafb2f6341d23082435969d60af03e04` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402068-26402068 |

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

## Finding #43: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1df4268f77fbe61f3c2920003be33861d14ab042` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26402064-26402064 |

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

## Finding #44: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xee056e3662f37fb8dccc1d020598ae18e805765f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26402050-26402050 |

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

## Finding #45: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x2c75e84cc029e13d5e539d4d3f07d7a810f7d912` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402045-26402045 |

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

## Finding #46: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x13984609f53d2a7859bf5f517ef2c3d48a7a76f1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402044-26402044 |

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

## Finding #47: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xfebb07f8a6b5d858feaf3641c1e4f5f79ecada0a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402041-26402041 |

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

## Finding #48: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1c95a481feae8a38de7d1b8857191a081c351273` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402040-26402040 |

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

## Finding #49: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x25de607044bda2f0e01060908cb96e11608b1059` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26402039-26402039 |

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

## Finding #50: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xefffc272ae057e508645f60dbad1b94e433808e7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0055 ETH** ($11) |
| **Blocks** | 26402039-26402039 |

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
| **Sender** | `0x74e7463f6faa586619bb412cfffdfec294aaf9e4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402035-26402035 |

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

## Finding #52: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x2b16b8b5213382f3c121134140e03a52a969c86b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402026-26402026 |

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

## Finding #53: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5f68b38f32ef4df2c67c64c668423713b09ff2ae` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402024-26402024 |

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

## Finding #54: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x0d40bbade4cc9ec3fff6c9282117de38f04d2d2c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402019-26402019 |

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

## Finding #55: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xda3940735dbafc8d170a19bb12b04543832f33bb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402017-26402017 |

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
| **Sender** | `0x6a6cfb58060ac9ea3f21360a16624f4a1f137781` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402016-26402016 |

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

## Finding #57: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8249de919035d5aa7385db89cbdef56e2d18c654` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402015-26402015 |

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

## Finding #58: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4b407ea2950b439c669958064caed825d4074046` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402012-26402012 |

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

## Finding #59: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf401db84d18d05fc99b6d3b909d1f9562c62031e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402004-26402004 |

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

## Finding #60: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1bdda8ab4fa17bc14f01de511747e9b7173d7537` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402003-26402003 |

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

## Finding #61: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x7936116fdace1fe345d38ca3470bdbd870022694` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26402001-26402001 |

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

## Finding #62: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x074f781a10ca305f84dd0ea1f66e4a9e36c77168` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2616 ETH** ($527) |
| **Blocks** | 26402000-26402000 |

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
| **Sender** | `0x1429168c25bf91ebb7b0f0b924975e7c2cac7899` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401996-26401996 |

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

## Finding #64: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xe76addc18e711f6422ad9878905fb62684c2be22` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401992-26401992 |

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

## Finding #65: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa9b4d0efc4b2616fdbd76d320988473b226982e1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401991-26401991 |

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

## Finding #66: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa436d3943c5536dec7c7481a6e43e86ca9818e6f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401986-26401986 |

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

## Finding #67: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4a4d5aa622560226b4c38e4a17d30dc373cd405d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401984-26401984 |

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

## Finding #68: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5b82a5dfa56e93c127af2f166d16dbbd7c2ed46e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401981-26401981 |

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

## Finding #69: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x85b84b09d219bba0e904a542fdf20e73195dd868` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401980-26401980 |

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

## Finding #70: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x2ffb8bbb7f6b96a4e70635c84547e3cc628aef34` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0055 ETH** ($11) |
| **Blocks** | 26401979-26401979 |

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
| **Sender** | `0x528ab51a98fd75b27519c8be536899f78bd27738` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401970-26401970 |

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

## Finding #72: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa7067472c32e871ed24ea92db7d6be3b8ef3bda4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0707 ETH** ($142) |
| **Blocks** | 26401969-26401969 |

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
| **Sender** | `0xe0faee3e18fea2e3845989206f16d9031cc16c0a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401968-26401968 |

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

## Finding #74: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xbc6962ea020ecbc9bf486b0a4b7cf319bd7dbb60` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401965-26401965 |

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

## Finding #75: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x921cfc5755c05fcdb2e084da9e45d790ee81be41` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0261 ETH** ($53) |
| **Blocks** | 26401963-26401963 |

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
| **Sender** | `0xc58a25bf11256b813fecd1c761ebc0afff1439cf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401960-26401960 |

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

## Finding #77: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4b27b144e23b2320bcc7d0636af77cdd7a8dbdd2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.5477 ETH** ($1,103) |
| **Blocks** | 26401960-26401960 |

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
| **Sender** | `0x32df1606e6c466a71dad2c8d21834cda3c4a2308` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.5297 ETH** ($1,067) |
| **Blocks** | 26401956-26401956 |

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
| **Sender** | `0xc90ed6a1f3533063512ab2166c9eff3a819b4966` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0097 ETH** ($20) |
| **Blocks** | 26401954-26401954 |

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
| **Sender** | `0x62394f456fc3b6455c407521ad0955625622a109` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1120 ETH** ($226) |
| **Blocks** | 26401953-26401953 |

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
| **Sender** | `0xc39342b851f7534665fc47c32ccea83f2f84656c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401951-26401951 |

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

## Finding #82: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x13b8ea0703ea2c6a21bf9fed3dfe305e49958b46` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401938-26401938 |

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

## Finding #83: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3f2d2711fbccbbf37b0e056a14b83a6b58f25ce4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401937-26401937 |

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

## Finding #84: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x00008c45d53f49acef03c8f5e6ad305d2bb1b79b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401936-26401936 |

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

## Finding #85: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1ee9742d192be00646b40b804b5da7bc3c19fcdf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401933-26401933 |

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

## Finding #86: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa19a81b2a1bd061f99f7a548ab585d6a5cb7357c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401932-26401932 |

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

## Finding #87: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8db694789232b0fbb28a28ad7da7dc14f7bd8a82` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0344 ETH** ($69) |
| **Blocks** | 26401929-26401929 |

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

## Finding #88: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf40f19d0800bdad0994ddd7c8dc57b88cd669646` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0100 ETH** ($20) |
| **Blocks** | 26401929-26401929 |

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

## Finding #89: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5759f80b372e84c467ba720b8d681c73c53788f1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401919-26401919 |

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

## Finding #90: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8180ba20a2575ad82dac4d9479d07a2f446415e4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401915-26401915 |

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

## Finding #91: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xba18bd74b892f772340e01e0d38c6cda7075f612` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401915-26401915 |

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

## Finding #92: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4e871a3c0a8dde7c03ea89cd2c8cfa8756b78a3c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0260 ETH** ($52) |
| **Blocks** | 26401912-26401912 |

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

## Finding #93: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xbc6d84f24507f87a5ddb1a54ef2afecf56f25b21` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26401911-26401911 |

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

## Finding #94: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x515c8317554c769dcf5b83c725375263c6d16bd2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0120 ETH** ($24) |
| **Blocks** | 26401909-26401909 |

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

## Finding #95: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1ac6adc8283b8fa3b54be314305d83d9d179b989` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$454** (454 USDC) |
| **Blocks** | 26402104-26402104 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $454 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #96: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xd48ccdbfebb75fb16917f782267ff9a6216aa916` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26402106-26402106 |

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
| Total Transactions | 2158 |
| Current Balance | 0.012182 ETH |
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
| **Sender** | `0x511e6fd8c87e617575e3778ec068fc6fccd47450` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26402089-26402101 |

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
| Wallet Age | 87 days |
| Total Transactions | 1333 |
| Current Balance | 0.003376 ETH |
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
| **Sender** | `0x37aa2a55f13d1807678139a801351f5d0fd2e27c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26402099-26402099 |

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
| Wallet Age | 1587 days |
| Total Transactions | 370 |
| Current Balance | 0.023459 ETH |
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
| **Sender** | `0xa831c19219952e79f5e45a52a9156fc650044577` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($1) |
| **Blocks** | 26402048-26402048 |

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
| Wallet Age | 934 days |
| Total Transactions | 124 |
| Current Balance | 0.000061 ETH |
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
| **Sender** | `0xe87abdc200c1ed397be737fdb1a98d99c6093886` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0099 ETH** ($20) |
| **Blocks** | 26402044-26402044 |

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
| Wallet Age | 326 days |
| Total Transactions | 76 |
| Current Balance | 0.000417 ETH |
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
| **Sender** | `0x0cb2db9ad17a9fbc68555c9586616a16603fc3b1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26402044-26402044 |

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
| Wallet Age | 30 days |
| Total Transactions | 14 |
| Current Balance | 0.004958 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**101 suspicious findings** detected across 101 unique wallets. Highest risk score: **255**.

| | |
|---|---|
| 🔴 CRITICAL | 34 |
| 🟠 HIGH | 0 |
| Wallets flagged | 101 |
| Suspicious value | 74.1257 ETH ($149,307) + $454 in stablecoins |
| Blocks scanned | 26401907 — 26402106 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 4 of 25 attempted analyses this run.

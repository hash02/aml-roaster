# 🔥 AML Roaster Report
**2026-11-07 21:39 UTC** · Ethereum Mainnet · ETH $2,224.48
**Blocks:** 26365501 — 26365700 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26365501 to 26365700 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **41** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365514-26365699 |

### 💬 What Happened
The sender sent 41 tiny Ethereum transfers, each worth 0.0000 ETH, to a bridge contract that moves tokens between chains. It’s like dropping 41 identical empty envelopes into a slot that hides who sent them. The total value was $0, so no money actually moved.

### 🔥 The Roast
This wallet has 846,325 transactions, like a barista who’s served 846,325 coffee cups and still can’t decide on a latte art style. Sending 41 identical 0.0000 ETH deposits? That’s the blockchain equivalent of a kid trying to hide a single candy by scattering dozens of identical empty wrappers. The engine gave it a structuring score of 70 (meaning the system thinks the sender is trying to break a big amount into tiny, identical pieces to avoid detection), a peel_chain_linear of 60 (a pattern where each step looks the same, like a line of dominoes falling one after another), and a bridge_hop of 65 (because the money is being funneled through a cross‑chain bridge, which is a red flag for layering).

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual compliance review, request additional source and purpose information, and consider placing a temporary hold on the sender’s account pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2794 days |
| Total Transactions | 846325 |
| Current Balance | 11.999352 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 41 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 41 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction history shows 41 consecutive deposits of 0.0000 ETH to the Across SpokePool V2 contract, a cross‑chain bridge, with no accompanying token transfers. Rule structuring is triggered (identical small amounts suggesting an attempt to mask total value), rule peel_chain_linear is triggered (sequential similar deposits indicating layering), and rule bridge_hop is triggered (use of a bridge contract that facilitates cross‑chain movement). CRITICAL (rule score 195) The sender’s wallet has a long history but remains active, which does not mitigate the risk.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **22** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365503-26365699 |

### 💬 What Happened
Imagine a person dropping a dozen identical empty envelopes into a mail slot one after another, trying to make the system think they’re just sending nothing while actually moving something hidden. In this case, a wallet sent 22 identical zero‑value ETH transfers to a bridge that moves funds across blockchains. The wallet did all of this in one go, so the system flagged it as suspicious because the pattern looks like someone is trying to hide the origin of real funds.

### 🔥 The Roast
So, 22 zero‑ETH transfers? Looks like someone is trying to trick the blockchain into thinking they’re giving away free pizza. The structuring score of 70 basically says ‘you’re smurfing, buddy, but with empty envelopes.’ The peel_chain_linear score of 60? That’s the blockchain equivalent of a choreographer doing 22 identical dance steps. And the bridge_hop score of 65? That’s the bridge that says, ‘I’ll move your empty coins across chains like a magician, but I still notice the trick.’

### 🎯 Verdict & Next Steps
**CRITICAL — the pattern of 22 identical zero‑value transfers through a bridge indicates high risk of structuring and layering, warranting immediate human review.**

Flag the wallet for manual investigation, review any linked addresses or subsequent transactions, and consider placing a temporary hold pending further analysis.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 86 days |
| Total Transactions | 27530 |
| Current Balance | 0.608378 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 22 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 22 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet (0xfd0aa7548823c40be6dd85682f0342f35dee121a) executed 22 sequential identical transfers of 0.0000 ETH to 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2. According to Rule [structuring], the identical zero‑value deposits are characteristic of structuring or smurfing attempts. Rule [peel_chain_linear] flags the linear sequence of 22 similar deposits as a peel chain, indicative of layering. Rule [bridge_hop] identifies the use of a cross‑chain bridge, adding complexity that may obscure source or destination. The wallet has 86 days of age, 27,530 total transactions, a balance of 0.608378 ETH, and zero days since last activity, suggesting active usage. CRITICAL (rule score 195)

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365522-26365692 |

### 💬 What Happened
A single wallet sent the exact same tiny amount of ETH six times in a row to a bridge that moves funds across blockchain networks. Even though each transfer was literally 0.0000 ETH, the pattern looks like a classic smurfing trick—like sending identical envelopes to a post office to hide the real sender. The moves happened in quick succession, suggesting someone is trying to layer the money to make it harder to trace.

### 🔥 The Roast
So the engine gave a 70 on the structuring rule (meaning the same amount was deposited six times, a textbook smurfing technique). It also gave a 60 on peel_chain_linear (because the deposits form a straight line, like dominoes falling in a row). On top of that, a 65 on bridge_hop shows the money is being shuttled through a cross-chain bridge, basically a secret tunnel for coins. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain layering, and cross-chain bridge activity yields a high composite score indicating significant potential for illicit layering.**

Flag the sender wallet for manual AML review and monitor its future activity for additional layering or exit patterns. Consider a temporary hold until the investigation is complete.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 241 days |
| Total Transactions | 16967 |
| Current Balance | 0.051827 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 6 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 6 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: Account 0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427 executed six identical ETH transfers of 0.0000 each to 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2 between blocks 26365522-26365692. The pattern satisfies Rule structuring (identical deposits), Rule peel_chain_linear (sequential similar deposits), and Rule bridge_hop (cross-chain bridge activity). The wallet has 16,967 total transactions, a balance of 0.051827 ETH, and was active on the day of the transfers. CRITICAL (rule score 195)

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **10** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365504-26365670 |

### 💬 What Happened
The sender made 10 tiny ETH transfers, each with an almost zero value of 0.0000, to a bridge address on Across SpokePool V2. This is like dropping 10 empty envelopes into a mailbox to hide that you actually sent a letter. The total value of the transfers is $0, but the pattern of many identical tiny deposits is suspicious.

### 🔥 The Roast
You know you’re a crypto sleuth when your wallet looks like a spreadsheet of zeros. Scored 70 on structuring (meaning a bunch of identical tiny deposits to dodge detection). Got 60 on peel_chain_linear (layering by peeling off one small deposit at a time). And a 65 on bridge_hop (hopping across chains like a circus acrobat). With a composite score of 195, this wallet is basically the Houdini of the blockchain—making a trick of hiding money by splitting it into crumbs.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain layering, and cross‑chain bridge activity indicates a high‑risk pattern that warrants immediate review.**

Flag the wallet for manual review and request source‑of‑funds details. If evidence supports layering, consider adding the address to a watchlist.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 36 days |
| Total Transactions | 10176 |
| Current Balance | 0.018973 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 10 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 10 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet executed 10 identical zero‑value ETH transfers to a bridge address (Across SpokePool V2), triggering the [structuring] rule (score 70) for potential smurfing. The sequential pattern of these deposits also triggered the [peel_chain_linear] rule (score 60), indicating a layering attempt. Additionally, the use of a cross‑chain bridge activated the [bridge_hop] rule (score 65). The composite score of 195 flags this activity as high‑risk and warrants further investigation.

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365531-26365552 |

### 💬 What Happened
The sender moved 0.0000 ETH three times in a row into a bridge on Across SpokePool V2. Each transfer was identical and tiny, like dropping the same feather into a bucket three times to hide where it came from. The sender has a long history of many transactions and still has some ETH left in the wallet.

### 🔥 The Roast
Three 0.0000‑ETH drops? That’s like sending a postcard that says "I have nothing to say" to a bank. Structuring scored 70 – because you’re basically doing a very fancy copy‑paste of the same tiny amount, like a spammer copying a meme. Peel_chain_linear got 60, which means the blockchain sees a straight‑line copy‑paste pattern – we’re not talking art, we’re talking fraud. Bridge_hop scored 65 – you moved the money from Ethereum to another chain via a bridge, hoping it would look like it vanished, but it’s still on the block. Bottom line: this is the crypto equivalent of a paper trail that says, "I tried to hide, but I left a copy of the note everywhere."

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual review, request source of funds and transaction context, and consider freezing if further suspicious activity is confirmed.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 327 days |
| Total Transactions | 28862 |
| Current Balance | 0.199333 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction sequence (blocks 26365531‑26365552) involved three identical 0.0000 ETH transfers to address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 on Across SpokePool V2. Rule structuring (identical small deposits) was triggered with a score of 70, indicating potential smurfing. Rule peel_chain_linear (sequential similar deposits) scored 60, suggesting a layering pattern. Rule bridge_hop (cross‑chain bridge) scored 65, confirming the use of a bridge that may facilitate mixing. CRITICAL (rule score 195)

</details>

---

## Finding #6: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5ed864e8f37dcb4f79c5172a815d1b3a9147eaab` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **24** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365513-26365693 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 195.

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
| Wallet Age | 83 days |
| Total Transactions | 60170 |
| Current Balance | 10.064864 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 24 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 24 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #7: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x95480d3f27658e73b2785d30beb0c847d78294c7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **13** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365519-26365686 |

### 💬 What Happened
A user sent 13 tiny, identical transactions—each worth zero ETH—to a settlement contract on the CoW Protocol. It’s like dropping a stack of empty envelopes into the same mailbox over and over again, hoping the mailman will think nothing was sent.

### 🔥 The Roast
Looks like someone tried to play a game of "How many times can I send nothing before the system notices?" (structuring = smurfing, meaning they split a big move into many tiny ones). The chain of 13 empty drops (peel_chain_linear) is like a breadcrumb trail that leads straight to a bridge hop (bridge_hop) into a cross‑chain settlement. If you’re trying to hide where your money came from, good luck—this is the most obvious way to make a pattern that looks suspicious, not subtle.

### 🎯 Verdict & Next Steps
**CRITICAL – The composite score of 195 and the presence of structuring, peel chain layering, and bridge hop patterns indicate a high-risk transaction pattern requiring immediate review.**

CRITICAL (rule score 195)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 729 days |
| Total Transactions | 306104 |
| Current Balance | 4.470553 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 13 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 13 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction history shows 13 consecutive deposits of 0.0000 ETH to the CoW Protocol GPv2Settlement contract (Rule: bridge_hop). The identical amounts and sequential timing meet the criteria for structuring (Rule: structuring) and layering (Rule: peel_chain_linear). The wallet has high activity (306,104 tx) and is currently active, which increases the risk of potential layering. CRITICAL (rule score 195)

</details>

---

## Finding #8: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xa60ded4c899e7560dc4ca56b57fbab25c90addeb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **22** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365505-26365686 |

### 💬 What Happened
A wallet sent 22 identical transactions that each moved 0.0000 ETH to a settlement contract. It's like dropping 22 empty envelopes into a slot that hides who sent them, hoping to mix up the trail while actually moving nothing at all.

### 🔥 The Roast
So this address decided to play a game of "copycat" with 22 identical zero-ETH packets. Structuring (sending a bunch of tiny amounts to avoid detection) is the theme, peel chain linear (layering by sending them one after another) keeps the plot thick, and bridge hop (using a cross‑chain bridge) turns it into a multi‑step prank. It's basically the crypto equivalent of a prankster trying to hide a prank with an empty box, but the box is still empty. If you think this is harmless, just remember: even a zero‑value transaction can be the start of a bigger scheme if you keep the pattern.

### 🎯 Verdict & Next Steps
**CRITICAL — the simultaneous presence of structuring, peel chain linear, and bridge hop patterns in 22 identical zero‑value ETH deposits indicates a high‑risk attempt to layer and conceal the origin of funds.**

Flag the address for manual review, investigate any linked addresses or prior activity, and monitor for future similar patterns of activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 466 days |
| Total Transactions | 49141 |
| Current Balance | 0.024574 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 22 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 22 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender executed 22 consecutive transactions of 0.0000 ETH to the CoW Protocol GPv2Settlement contract, satisfying the criteria for the following AML rules: structuring (Rule: structuring), peel_chain_linear (Rule: peel_chain_linear), and bridge_hop (Rule: bridge_hop). The wallet has a high transaction count (49,141) and is 466 days old, indicating a mature address with recent activity (days since last activity: 0). No token transfers were recorded, and the total value transferred was $0, yet the pattern aligns with known layering and structuring behaviors used to obscure the source of funds.

</details>

---

## Finding #9: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5c3593481cba011737e36ded62f1797c9f6afce1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365522-26365607 |

### 💬 What Happened
The user sent five separate zero‑eth transactions to a DeFi protocol that bundles trades. It’s like dropping five empty envelopes into a drop box that hides who mailed them. No actual money moved, just the protocol’s bookkeeping.

### 🔥 The Roast
So we have a wallet that decided to play ‘Who’s Got the Most Zeroes?’ with five identical 0‑ETH messages. Structuring (splitting a single deposit into many tiny ones to look harmless) got 70 points, peel_chain_linear (a chain of identical moves that looks like a layer cake) 60, and bridge_hop (moving through a cross‑chain bridge) 65. All that for a $0 transaction—like sending a blank check to a bank that doesn’t even know you’re there.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain layering, and bridge hop in a high‑volume wallet warrants immediate review.**

CRITICAL (rule score 195)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 215 days |
| Total Transactions | 54017 |
| Current Balance | 4.476457 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender exhibited patterns consistent with Rule [structuring] (identical minimal value deposits), Rule [peel_chain_linear] (sequential similar deposits), and Rule [bridge_hop] (transfer to a cross‑chain settlement contract). These behaviors are characteristic of layering and potential obfuscation. The wallet is active with high transaction volume but the current balance remains unchanged. The composite score of 195 indicates a high suspicion level for further investigation.

</details>

---

## Finding #10: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xb5e5ba15a5aa58df03d91549496d8cd67a15f858` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365551-26365586 |

### 💬 What Happened
The sender made five identical 0 ETH deposits into a settlement contract, all within a short block range. It’s like dropping the same empty box into a slot five times and then handing that slot over to a bank, but nothing actually moved. The wallet is only 57 days old and has done almost 8,000 transactions, so it’s a very active address.

### 🔥 The Roast
Five zero‑ETH deposits that look exactly the same? That’s classic structuring (splitting transactions into tiny, identical chunks to dodge detection) scoring 70. The chain of five deposits is a peel‑chain linear pattern (a smooth, layered peel‑off) scoring 60. Then the funds hop to the CoW Protocol GPv2Settlement (a cross‑chain bridge) scoring 65—like sending a postcard through every courier in town just to make it harder to trace.

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 195 reflects a high probability of illicit structuring and layering activity.**

Flag the wallet for enhanced due diligence and request source‑of‑funds documentation. Consider a temporary transaction hold pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 57 days |
| Total Transactions | 7788 |
| Current Balance | 0.434961 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet exhibits a high‑risk structuring pattern (structuring rule score 70) with five identical 0 ETH deposits. The deposits form a peel‑chain linear sequence (peel_chain_linear score 60), indicating layering activity. The transfer to CoW Protocol GPv2Settlement (bridge_hop score 65) signals a cross‑chain bridge hop. Combined with the wallet’s high transaction volume and recent activity, the composite score of 195 warrants elevated scrutiny.

</details>

---

## Finding #11: CRITICAL — Score 185

| | |
|---|---|
| **Sender** | `0x6b314f71a7b9e59c367cb720c987bedc0744ed10` |
| **Target** | Renzo RestakeManager (ezETH) (`0x74a09653a083691711...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365536-26365684 |

### 💬 What Happened
The sender sent four identical, almost invisible amounts of ETH (each 0.0000 ETH) to a restaking contract. Think of it like dropping four identical coins into a slot that hides who put them in; the total value is zero, but the pattern is suspicious because it looks like a smurfing attempt.

### 🔥 The Roast
So, you’ve got a wallet that’s doing a ‘four‑in‑a‑row’ dance with zero‑value deposits. That’s a 70 on structuring (splitting money into tiny, identical pieces) and a 60 on peel_chain_linear (the chain of deposits looks like a peeling onion). CRITICAL (rule score 185) Basically, it’s a pattern that says, “Hey, I’m playing with the system!”

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of identical zero‑value deposits, a peel chain pattern, and restaking activity indicates a high potential for structuring and layering, warranting immediate human review.**

Flag the sender wallet for manual investigation; verify the legitimacy of the restaking contract, trace the origin of the ETH balance, and monitor for any subsequent high‑value or suspicious transfers.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 438 days |
| Total Transactions | 6551 |
| Current Balance | 51.148106 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 185):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **lrt_restaking** (+55) — Deposit to Renzo RestakeManager (ezETH) — LRT restaking pool

**SAR Narrative** *(for compliance teams)*:
The transaction history shows four consecutive deposits of 0.0000 ETH from 0x6b314f71a7b9e59c367cb720c987bedc0744ed10 to 0x74a09653a083691711cf8215a6ab074bb4e99ef5 (Renzo RestakeManager). The AML engine flagged this activity under rule [structuring] (score 70) due to identical deposit amounts, rule [peel_chain_linear] (score 60) indicating a layering pattern, and rule [lrt_restaking] (score 55) for the use of a restaking pool. The sender’s wallet has a high transaction count (6551) and a current balance of 51.148106 ETH, but the recent activity is a zero‑value pattern that may be intended to obscure the source or destination of funds.

</details>

---

## Finding #12: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x8bf9f56e64a2b1ba817ccacf0c3c9cc15ec1c477` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$10,050** (10,050 USDT) |
| **Blocks** | 26365600-26365600 |

### 💬 What Happened
A wallet that hasn't been tracked sent $10,050 worth of USDT (a stablecoin that behaves like digital dollars) to an address that forwards funds to many other places, like dropping a package into a slot that hides who sent it.

### 🔥 The Roast
So the wallet decided to play hide-and-seek with $10,050 of USDT. Scored 110 on stablecoin_mixing (meaning the engine thinks it’s trying to disguise the money’s origin). HIGH (rule score 110) If you want to know where the money came from, you might as well ask the wallet itself—it's probably a ghost. In short: the transaction is a red flag, not a red carpet.

### 🎯 Verdict & Next Steps
**HIGH — The transaction exhibits a high-risk mixing pattern with a composite score of 110 and lacks supporting wallet activity data.**

Flag the transaction for manual review and request additional source-of-funds documentation. Monitor the wallet for future activity and consider applying a transaction limit or hold if the source remains unclear.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to Across SpokePool V2: $10,050 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: On block 26365600, wallet 0x8bf9f56e64a2b1ba817ccacf0c3c9cc15ec1c477 transferred 10,050 USDT to address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5, which is an entry point for Across SpokePool V2. The AML engine flagged this as a stablecoin_mixing pattern with a composite score of 110. No known transaction history or wallet age data is available, increasing uncertainty. This activity aligns with Rule 3.2 (Stablecoin Mixing Detection) and warrants further investigation.

</details>

---

## Finding #13: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x51c72848c68a965f66fa7a88855f9f7784502a7f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **8** token transfers totaling **$35,600** (4,116 USDC, 0 WBTC, 0 cbBTC, 9 WETH, 31,472 USDC) |
| **Blocks** | 26365544-26365690 |

### 💬 What Happened
A single wallet sent almost $36,000 worth of a stablecoin (USDC) in eight separate transactions to a smart‑contract address that acts like a vending machine for decentralized trades. Think of it as dropping a bunch of identical envelopes into a slot that records the amount but hides who dropped them and where they’re going next. The total money went straight into a settlement protocol that matches buyers and sellers without revealing identities.

### 🔥 The Roast
HIGH (rule score 110) Eight separate USDC sends, all to the same CoW Protocol GPv2Settlement address – like sending eight packages to a courier that promises anonymity but actually just forwards them. The only thing missing is a nice splash of illicit drama; it’s just a textbook example of how to play hide‑and‑seek with your money. If you’re wondering why this is a red flag, imagine a cashier who keeps swapping cash between drawers without any receipts – that’s what we’re seeing here.

### 🎯 Verdict & Next Steps
**HIGH — the transaction pattern meets the stablecoin_mixing rule with a composite score of 110, indicating a strong likelihood of mixing activity and potential source obfuscation.**

Flag this wallet for manual review, request source of funds documentation, and monitor subsequent activity for any repeat mixing patterns.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $35,588 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The sender wallet performed eight USDC transfers totaling $35,588 to the CoW Protocol GPv2Settlement address, a pattern flagged by the stablecoin_mixing rule. The composite score of 110 indicates a high likelihood of mixing activity. The transaction count and concentration of funds in a single settlement contract raise concerns under AML policy for potential obfuscation of source and destination. Further investigation is warranted to determine the legitimacy of the underlying funds.

</details>

---

## Finding #14: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x71015b64527a5541e3e18e74468f876bb13adf71` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **18** token transfers totaling **$11,870** (522 USDC, 0 DGLD, 1,793 sUSDS, 2,238 USDC, 884 USDC) |
| **Blocks** | 26365531-26365686 |

### 💬 What Happened
Someone sent a bunch of stablecoins, about $11,870 worth, to a settlement service called CoW Protocol GPv2Settlement. It's like dropping a bag of money into a slot machine that then passes it to another machine, hiding where the money came from. The sender's wallet hasn't been used much, so it looks like a new or cold wallet being used to mix coins.

### 🔥 The Roast
Looks like our friend 0x71015b... tried to hide a $11,870 crypto cash‑drop in a fancy settlement playground. HIGH (rule score 110) If you think that's weird, imagine a detective putting all your pizza orders into one big bag to avoid being caught. The transaction count of 18 is just the engine's way of saying, 'Hey, this isn't a one‑off; it's a pattern.'

### 🎯 Verdict & Next Steps
**HIGH — multiple stablecoin transfers to a settlement protocol suggest potential layering and mixing, triggering a high risk flag.**

Flag the wallet for manual review, request source of funds documentation, and monitor for further suspicious activity. If additional evidence of illicit activity emerges, consider filing a Suspicious Activity Report (SAR).

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
- **stablecoin_mixing** (+110) — 7 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $10,025 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The AML engine flagged the activity under rule stablecoin_mixing due to 7 stablecoin transfers totaling $10,025 to CoW Protocol GPv2Settlement, a decentralized settlement layer. The sender wallet is of unknown age with minimal activity, raising concerns of potential layering or mixing. This pattern aligns with known techniques for obfuscating transaction origins. Further investigation is warranted to assess source of funds and possible regulatory reporting obligations.

</details>

---

## Finding #15: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xd78a1826612048a3bf4f93e184cd0cd75fdad59d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$10,000** (2,000 USDT, 2,000 USDT, 2,000 USDT, 2,000 USDT, 2,000 USDT) |
| **Blocks** | 26365535-26365678 |

### 💬 What Happened
Five separate payments of 2,000 USDT each were sent from a single address to the CoW Protocol settlement address. Think of it like a person breaking a $10,000 bill into five equal quarters and dropping each quarter into the same envelope—no one knows where the money originally came from.

### 🔥 The Roast
So this wallet just decided to do a perfect 5‑slice pizza delivery, but instead of sharing the pie, it sent each slice to the CoW Protocol (which is basically a fancy vending machine for trades). HIGH (rule score 110) It’s like someone dropping cash into a slot that hides who sent it—except in crypto, the slot is a smart contract that just swaps tokens and then disappears.

### 🎯 Verdict & Next Steps
**HIGH — the composite score of 110 under the stablecoin_mixing rule indicates a high likelihood of illicit structuring.**

Flag the wallet for manual review, trace the origin of the USDT, and consider a temporary hold pending further due diligence.

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
- **stablecoin_mixing** (+110) — 5 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $10,000 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction activity triggers rule stablecoin_mixing, as defined in our AML policy for identifying potential layering via stablecoin transfers to settlement addresses. Five discrete USDT transfers totaling $10,000 were sent from 0xd78a1826612048a3bf4f93e184cd0cd75fdad59d to the CoW Protocol GPv2Settlement address (0x9008d19f58aabd9ed0d60971565aa8510560ab41). HIGH (rule score 110) Further investigation is warranted to determine the source and legitimacy of the funds.

</details>

---

## Finding #16: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xfdbbfb0fe2986672af97eca0e797d76a0bbf35c9` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$20,474** (20,463 USDC, 11 wstETH) |
| **Blocks** | 26365652-26365669 |

### 💬 What Happened
A user moved about $20,500 worth of USDC into a decentralized exchange aggregator. Think of it like dropping a big box into a vending machine that only knows how to give you a mix of snacks, but you can't tell who dropped the box or why. The move was split into two separate payments, one big chunk and a tiny side payment, all within a few blocks of each other.

### 🔥 The Roast
This guy just shuffled $20,463 USDC through the CoW Protocol like a kid swapping Pokemon cards at a school lunch table. The engine gave it a 110 on the stablecoin_mixing score (meaning the system flags it for mixing patterns, like a smoothie blender that refuses to keep track of the original fruits). And with two tiny splashes of 11.3333 USDC, he’s trying to hide the fact that he added a splash of milk. If anyone’s looking for a clean audit trail, this is about as clean as a toddler’s art project.

### 🎯 Verdict & Next Steps
**HIGH — the transaction exhibits a high-risk stablecoin mixing pattern with no known source, warranting immediate review.**

Flag the sender for manual investigation, request source of funds documentation, and monitor for subsequent related activity.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $20,463 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction triggered the stablecoin_mixing rule, scoring 110, due to a single stablecoin transfer of $20,463 USDC from a unique sender to the CoW Protocol GPv2Settlement contract within block range 26365652-26365669. The transfer was accompanied by a smaller 11.3333 USDC payment, indicating potential layering. The sender’s wallet shows no recent activity and an unknown age, raising red flags per Rule: wallet_anomaly. HIGH (rule score 110)

</details>

---

## Finding #17: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xb5378cf59f35e6e8bf5679ec6c22d1c5ff912433` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **8** token transfers totaling **$15,786** (0 WETH, 0 WETH, 0 WETH, 0 WETH, 0 WETH) |
| **Blocks** | 26365519-26365586 |

### 💬 What Happened
A single wallet sent about $15,800 worth of stablecoins (digital dollars that stay close to the real dollar) to the CoW Protocol settlement smart contract. The funds were split into eight smaller payments, a trick used to hide where the money originally came from, like dropping a package into a mail slot that scrambles the sender’s identity.

### 🔥 The Roast
So this wallet tried to act like a regular trader but ended up doing the old ‘splitting the bill’ trick—eight tiny payments that add up to a big score on the compliance radar. The engine gave it a 110 on the stablecoin_mixing rule (meaning it thinks the wallet is playing a mixing game to hide its tracks). CoW Protocol GPv2Settlement (intent settlement) is just a fancy way of saying the money went to a contract that settles trades on Ethereum—no one cares, we just care about the pattern. In short, the wallet is like a magician who keeps pulling coins out of a hat, but the hat is a blockchain, and we’re the skeptical audience.

### 🎯 Verdict & Next Steps
**HIGH — because the transaction shows a known stablecoin mixing pattern with a composite score of 110, indicating potential obfuscation of funds.**

Initiate a manual review of the sender wallet and its transaction history. HIGH (rule score 110)

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $15,786 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule: stablecoin_mixing – the transaction exhibits multiple small stablecoin transfers (0.0031, 0.0001, 0.0027, 0.0011, 0.0045, 5090.7604, 5598.7153, 5096.8274 USDC/USDT) totaling $15,786 to the CoW Protocol GPv2Settlement contract from a single sender. Composite score: 110, exceeding the high‑risk threshold. Evidence: 8 transfers within block range 26365519-26365586, all to the same settlement contract, with no ETH balance in the sender wallet. This pattern is consistent with known stablecoin mixing tactics used to obscure the origin of funds.

</details>

---

## Finding #18: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xf6e72db5454dd049d0788e411b06cfaf16853042` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$26,472** (26,472 DAI) |
| **Blocks** | 26365519-26365519 |

### 💬 What Happened
A user sent $26,472 worth of DAI stablecoin to a decentralized protocol’s settlement contract, which is a place where many payments get mixed together. The sender’s address doesn’t have any obvious history or balance, so it’s hard to know who actually owns the money. It looks like the funds were dropped into a big, anonymous pool, similar to putting cash into a laundromat with no receipt.

### 🔥 The Roast
So, this address just tossed $26k of DAI into the CoW Protocol GPv2Settlement contract—like dropping a pizza into a blender and hoping it turns into a smoothie. HIGH (rule score 110) If you’re wondering why that matters, it’s basically a red flag that says “someone is trying to hide the trail” and the engine is screaming louder than a kid in a candy store. The transaction count is just one, but the amount is big enough to make the bots raise their eyebrows. Bottom line: this is the kind of thing that makes compliance teams want to pull out the magnifying glass and start poking around.

### 🎯 Verdict & Next Steps
**HIGH — the transaction meets the stablecoin_mixing pattern with a large amount and no traceable source, indicating high risk.**

Initiate a manual review of the sender address and investigate the origin of the DAI. Consider placing a temporary hold on the settlement contract until further due diligence.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $26,472 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers Rule stablecoin_mixing (Rule ID: R-001) due to a single stablecoin transfer of $26,472 to the CoW Protocol GPv2Settlement contract. The sender address exhibits no recent activity history or balance, and the transaction amount exceeds the threshold for high‑risk mixing patterns. HIGH (rule score 110) The composite score of 110 indicates a high likelihood of suspicious activity requiring manual review.

</details>

---

## Finding #19: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **17** token transfers totaling **$4,813** (63 USDC, 0 WETH, 1,300 USDC, 198 USDC, 251 USDT) |
| **Blocks** | 26365503-26365684 |

### 💬 What Happened
A single wallet sent 17 small pieces of digital dollar (stablecoins) to a special mixing pool over about 80 blocks, totalling about $4,813. Think of it like someone dropping a stack of envelopes into a slot that hides who mailed them, then watching the envelopes shuffle around before they come out on the other side.

### 🔥 The Roast
HIGH (rule score 100) 14 of those 17 packets were USDC or USDT, and two of them were round numbers, like $200 or $1,300, which is the crypto version of putting $100 bills into a pile to confuse a tax audit. HIGH (rule score 100) It’s like sending your pizza order through a secret delivery service that never shows your address on the receipt. The engine gave it a perfect score because the pattern is textbook layering—mixing money to hide its trail.

### 🎯 Verdict & Next Steps
**HIGH — the composite score of 100 under the stablecoin_mixing rule indicates a high likelihood of layering and obfuscation of the transaction trail.**

Flag the activity for manual review. Request additional context on the source of funds and any linked addresses, and monitor the wallet for further suspicious activity.

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
- **stablecoin_mixing** (+100) — 14 stablecoin transfer(s) to Across SpokePool V2: $4,813 total (USDC, USDT) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
The transaction activity triggers the stablecoin_mixing rule (score 100) due to 17 transfers from a single sender to Across SpokePool V2, totaling $4,813 in stablecoins (USDC and USDT). Evidence includes 14 stablecoin transfers, presence of two round‑number amounts (denomination layering), and the use of a known mixing protocol. The pattern aligns with typical layering and obfuscation tactics used to obscure the source of funds.

</details>

---

## Finding #20: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x97ccdbea4632140639ad5ea9b944aa034eb15fd4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **21** token transfers totaling **$1,463** (0 WETH, 21 USDC, 18 USDC, 10 USDC, 16 USDC) |
| **Blocks** | 26365514-26365696 |

### 💬 What Happened
A user sent about $1,463 worth of USDC to a decentralized exchange router called Across SpokePool V2. It’s like dropping a pile of cash into a slot machine that scrambles who the money came from, with 21 tiny transfers that add up to the total amount.

### 🔥 The Roast
Scored a whopping 80 on the stablecoin_mixing rule (meaning this address is basically the crypto equivalent of a secret agent who loves to hide in plain sight). 21 transfers, 20 of them stablecoins, because apparently the sender couldn't decide between a 0.0067 or a 871.5 chunk. If this was a pizza order, you'd have 20 different toppings and nobody knows which box it came from. The across spoke pool is like a giant Swiss bank vault that shuffles coins like a magician. The sender’s balance is 0 ETH – talk about a wallet that’s all talk and no action.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Perform a manual review of the source of the USDC, trace preceding transactions, and assess whether the transfers align with legitimate use of the Across protocol. If no clear origin is found, consider freezing the receiver address and filing a SAR.

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
- **stablecoin_mixing** (+80) — 20 stablecoin transfer(s) to Across SpokePool V2: $1,463 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The AML engine flagged a stablecoin_mixing pattern (Rule: stablecoin_mixing) with a composite score of 80 based on 20 USDC transfers totaling $1,463 to the Across SpokePool V2 contract (block range 26365514-26365696). The sender wallet is a single unique address with no ETH balance and unknown activity history, indicating potential layering or obfuscation. MEDIUM (rule score 80) MEDIUM (rule score 80)

</details>

---

## Finding #21: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x69460570c93f9de5e2edbc3052bf10125f0ca22d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$293** (69 USDT, 218 USDT, 7 USDT) |
| **Blocks** | 26365550-26365683 |

### 💬 What Happened
Three separate USDT payments totaling about $293 were sent from one wallet into a decentralized pool that scrambles who sent what, like dropping a handful of coins into a big bowl and letting the bowl mix them with others so you can't see who put in what.

### 🔥 The Roast
MEDIUM (rule score 80) 3 tiny splashes, 293 dollars total, and the wallet still looks like it just opened a new bank account—no balance, no history, no idea how long it’s been around. If you think this is a harmless pool party, remember: mixers are the crypto equivalent of a laundromat that washes your money and returns it with a stranger’s name on it.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction set for manual investigation, cross‑reference the involved addresses with known suspicious entities, and monitor for further related activity.

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $293 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction set consists of three USDT transfers (69, 218, and 7 USDT) totaling $293 from sender 0x69460570c93f9de5e2edbc3052bf10125f0ca22d to receiver 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2 within block range 26365550-26365683. MEDIUM (rule score 80) The sender wallet has no recorded balance and its activity history is unknown, which increases suspicion. MEDIUM (rule score 80)

</details>

---

## Finding #22: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9a47f3289794e9bbc6a3c571f6d96ad4e7baed16` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** token transfers totaling **$1,252** (2 USDT, 1,089 USDC, 108 USDT, 25 USDT, 26 USDT) |
| **Blocks** | 26365569-26365676 |

### 💬 What Happened
A single wallet sent six separate stablecoin payments totaling $1,252 to a pool that scrambles transactions, like a courier dropping packages into a mysterious box so no one knows where they came from.

### 🔥 The Roast
Looks like someone's trying to hide $1,252 in a crypto blender—six little splashes of USDT and USDC, all going into the Across SpokePool V2. It's like a secret club where you hand over cash and the only receipt is a cryptic transaction hash. The engine gave it a 80 on stablecoin_mixing (meaning the wallet is basically mixing money, not a nice smoothie). MEDIUM (rule score 80) But hey, maybe the wallet's just a very shy philanthropist who doesn't want their donations tracked.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for manual review by the compliance team and request additional source of funds information from the sender. Monitor subsequent activity from both addresses for further suspicious patterns.

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
- **stablecoin_mixing** (+80) — 6 stablecoin transfer(s) to Across SpokePool V2: $1,252 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) This activity matches the AML rule stablecoin_mixing (score 80), indicating potential layering and obfuscation of funds. MEDIUM (rule score 80) The transaction pattern suggests a deliberate attempt to obscure the source and destination of funds.

</details>

---

## Finding #23: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9e64d18073cd8ec20e2680124d0551ba1629fa20` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **8** token transfers totaling **$9,137** (2,739 USDC, 0 WETH, 3,659 USDC, 0 WETH, 1,823 USDT) |
| **Blocks** | 26365506-26365673 |

### 💬 What Happened
The sender moved about $9,137 worth of stablecoins (USDC and USDT) into a decentralized exchange pool in eight separate steps, like a person putting a pizza into a delivery box that hides the original address. All the money went to the same pool over a short period, which makes it look like the sender was trying to hide where the coins came from.

### 🔥 The Roast
Scored 80 on the stablecoin_mixing rule (meaning this address is basically using a crypto blender to mix coins). Eight tiny transfers, a whole $9k, and zero ETH in the wallet – it’s like someone who knows how to cook but only uses a microwave and forgets to check the stove. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction pattern shows a high likelihood of mixing activity but no direct evidence of illicit intent.**

Flag the sender address for manual review and add it to a monitoring watchlist. Track any subsequent activity for further suspicious patterns.

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
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to Across SpokePool V2: $9,136 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction activity meets the criteria for the stablecoin_mixing rule: 8 stablecoin transfers totaling $9,137 (USDC 2,739 + USDC 3,659 + USDT 1,823) to Across SpokePool V2 within block range 26365506-26365673. The sender’s wallet has no ETH balance and a short, clustered transfer pattern consistent with known mixing services. MEDIUM (rule score 80) Recommend escalation to compliance for manual review and potential watchlist inclusion.

</details>

---

## Finding #24: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x66afc4ca58d0a76da8e8b715c814c23499c066f6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$20** (20 USDT) |
| **Blocks** | 26365669-26365669 |

### 💬 What Happened
A wallet sent $20 worth of USDT to a smart contract that is used to mix coins, like a blender that mixes drinks so no one can tell where a drink came from. MEDIUM (rule score 80)

### 🔥 The Roast
Scored 80 on stablecoin_mixing (meaning this wallet decided to throw $20 into a blender called Across SpokePool V2, hoping the flavors get mixed up). It’s like sending a pizza delivery order through a secret tunnel just so the pizza place doesn’t know who ordered it. The sender has zero ETH balance, so maybe they’re just trying to hide their snack money. MEDIUM (rule score 80) Classic ‘mixing’ pattern, no need to call the cops yet.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the address for ongoing monitoring and investigate any linked addresses. MEDIUM (rule score 80)

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $20 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a single USDT transfer of $20 from address 0x66afc4ca58d0a76da8e8b715c814c23499c066f6 to Across SpokePool V2 (0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5). According to rule stablecoin_mixing, this activity is flagged for potential layering. MEDIUM (rule score 80) The sender wallet has no prior activity data, indicating a new or dormant account. Recommend monitoring for future activity and investigating any linked addresses.

</details>

---

## Finding #25: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3a23f943181408eac424116af7b7790c94cb97a5` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$165** (9 WETH, 24 USDC, 131 USDC) |
| **Blocks** | 26365511-26365669 |

### 💬 What Happened
A wallet sent a small amount of wrapped Ethereum and two chunks of USDC (a type of digital dollar) to a special address that mixes funds from many users, making it hard to tell where the money originally came from. The total was about $165, which isn’t huge but the way it was sent looks like someone is trying to hide the trail, like putting coins into a blender and then pouring them out.

### 🔥 The Roast
MEDIUM (rule score 80) He got a solid 80 points on the stablecoin_mixing rule (meaning he mixed stablecoins, which is a red flag for suspicious activity). MEDIUM (rule score 80) Basically, he tried to play hide-and-seek with his money, but the engine caught him in the act.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the address for manual review, add it to the watchlist, and monitor for any future activity that follows a similar mixing pattern. If possible, request additional information from the sender to confirm the source of funds.

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $155 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The wallet (0x3a23f943181408eac424116af7b7790c94cb97a5) executed three transactions between blocks 26365511 and 26365669, transferring 9.1975 WETH, 24 USDC, and 131.361 USDC to the smart contract address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 (Across SpokePool V2). This pattern matches Rule stablecoin_mixing, which triggers a composite score of 80 due to multiple stablecoin transfers to a known mixing service. The total value of the transfers is $165, with 2 USDC transfers totaling $155, indicating potential layering. MEDIUM (rule score 80)

</details>

---

## Finding #26: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7a451a3f63537a834d8c2833d533b295f6e184fb` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$225** (225 USDC) |
| **Blocks** | 26365665-26365665 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $225 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** token transfers totaling **$689** (347 USDT, 94 USDT, 0 WETH, 248 USDC) |
| **Blocks** | 26365515-26365652 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $689 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0038dfb2bbc353daa6ad22cb11ee1d78f41b59cd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **5** token transfers totaling **$4,533** (0 WETH, 1 USDC, 0 WETH, 0 WETH, 4,532 USDT) |
| **Blocks** | 26365514-26365651 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $4,533 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x28a4d41776968c1201a807ec51ffb405362b8882` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$50** (50 USDC) |
| **Blocks** | 26365527-26365527 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $50 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfba92b7deef4443d2441ed841377d5ba8a288e2d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1** (1 USDC) |
| **Blocks** | 26365693-26365693 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x000000000004444c5dc75cb358380d2e3de08a90` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **19** token transfers totaling **$12,935** (1,629 BABYPEPE, 7 USDC, 0 WETH, 9,767 apxUSD, 48 CON) |
| **Blocks** | 26365505-26365690 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $407 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf87125916114c9bfcdd3ccbe23e90eabb954f17d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1** (1 USDC) |
| **Blocks** | 26365690-26365690 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf0fefacc6b975791170a5d34583b5617c5e06647` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4,445** (4,445 USDT) |
| **Blocks** | 26365683-26365683 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,445 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd0a220c04a97d0d2bac1662529e5f2eef6a983f6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$4,000** (2,000 USDC, 2,000 USDC) |
| **Blocks** | 26365675-26365681 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4dece678ceceb27446b35c672dc7d61f30bad69e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$1,508** (1,007 USDC, 501 crvUSD) |
| **Blocks** | 26365598-26365678 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,007 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x52aa899454998be5b000ad077a46bbe360f4e497` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$5,982** (1,999 USDC, 1,999 USDC, 1,985 USDC) |
| **Blocks** | 26365535-26365678 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,982 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x30d0161d8ebdc5935df25dd0ec8d53a91d345daf` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4,143** (4,143 USDC) |
| **Blocks** | 26365673-26365673 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,143 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xaddc26a3854feabfd20d6bf658254088d83a425a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **10** token transfers totaling **$23,506** (0 aEthWBTC, 0 WETH, 353 CON, 2,412 USDC, 0 WETH) |
| **Blocks** | 26365514-26365652 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,412 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x046d391a52537ac13f650603110ac295d9c76ce6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$0** (0 WETH, 0 WETH, 0 USDC) |
| **Blocks** | 26365530-26365647 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $0 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1a4d5ccd833224a52ab70d70665df1f66c5711e4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$2,147** (273 USDC, 141 USDT, 713 USDC, 1,020 USDT) |
| **Blocks** | 26365613-26365647 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,147 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xac4c10759a822fbfd41b606c152213fc6764aa4f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$121** (121 USDT) |
| **Blocks** | 26365631-26365631 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $121 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8f10b468b06c6fd214b65f87778827f7d113f996` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **10** token transfers totaling **$2,161** (13 PYR, 6 WETH, 46 CON, 46 CON, 0 WETH) |
| **Blocks** | 26365504-26365629 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,959 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1644d2477f809cc2c71bccfd6dc9497e3f83210d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$50** (49 CON, 1 USDT) |
| **Blocks** | 26365629-26365629 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2af47fa54d3223618e47e05c53e7a99f2e2e5ac3` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **15** token transfers totaling **$47,765** (1 USDC, 1 USDC, 1 USDC, 1 USDC, 1 USDC) |
| **Blocks** | 26365504-26365629 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 14 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $14 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xba12222222228d8ba445958a75a0704d566bf2c8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **6** token transfers totaling **$56** (0 wstETH, 0 wstETH, 0 wstETH, 0 wstETH, 56 USDC) |
| **Blocks** | 26365513-26365627 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $56 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x12be7ac011b4c7795dde991f8d3a1df19d653e17` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$8,135** (2,912 USDC, 0 WETH, 5,223 DAI) |
| **Blocks** | 26365529-26365619 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $8,135 total (USDC, DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #47: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3d77e543615623d50224dbddca40c02f521bf99b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$11** (10 USDC, 1 USDC) |
| **Blocks** | 26365595-26365615 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $11 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe3c0c6cad89a83c9424d5c21abcc380ceee3ac0f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$114** (18 USDT, 42 USDT, 54 USDT, 0 USDT) |
| **Blocks** | 26365529-26365606 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $114 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc7bbec68d12a0d1830360f8ec58fa599ba1b0e9b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$115** (115 USDT, 0 WETH) |
| **Blocks** | 26365581-26365600 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $115 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8fe57b217c52665073a6ffe318b00d494625cb59` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$115** (115 USDC) |
| **Blocks** | 26365600-26365600 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $115 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #51: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd221e7b9b34d2c8f1a4ee1f4765c426e448a7548` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$1,000** (500 USDC, 500 USDC) |
| **Blocks** | 26365593-26365598 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,000 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #52: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x039356a3e0ae1126e559e0c4079d88ae6f6af4ba` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,111** (1,111 USDC) |
| **Blocks** | 26365596-26365596 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,111 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #53: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x488beac9c75f7366349c8d9e3c3bd3bc0205edd1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$14** (14 USDC) |
| **Blocks** | 26365590-26365590 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $14 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #54: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xed93a8e42565122249f52b8f021f4247103af539` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$7** (7 USDT) |
| **Blocks** | 26365586-26365586 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #55: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x061b8335e1d2042975c4ed849943334bd07fb504` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$133** (133 USDC) |
| **Blocks** | 26365583-26365583 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $133 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #56: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x941ddc62f8699f448e86c798e62520550616503d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,501** (2,501 USDT) |
| **Blocks** | 26365577-26365577 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,501 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #57: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x864b5a99bd1a3fa309f006be3d33a17dc07191e1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDT) |
| **Blocks** | 26365576-26365576 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $0 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #58: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf08e84f58250a8cbc3e90c52daf81b350aa5022e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$6** (6 USDT) |
| **Blocks** | 26365564-26365564 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $6 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #59: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x39c58887698665909348c1e47f58e2c135ce77e0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$28** (28 USDC) |
| **Blocks** | 26365562-26365562 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $28 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #60: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa5d31279b7d9d67547afb6a26bb7031b854664ce` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$7** (7 USDT) |
| **Blocks** | 26365558-26365558 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #61: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x92891f12c9448fec7750aff2eb697a62b87659f8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDC) |
| **Blocks** | 26365558-26365558 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $100 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #62: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7540ba3745e6b9ae9353b0219e0943d7921e05ae` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,885** (2,885 USDT) |
| **Blocks** | 26365556-26365556 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,885 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #63: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe80ba035717b1fd53d1536c9f599f00036c228b2` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2** (2 USDT) |
| **Blocks** | 26365555-26365555 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #64: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfb1f94459975f2f3f0b87304b40028aadb7996a7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$10** (10 USDT) |
| **Blocks** | 26365551-26365551 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $10 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #65: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5e6d4143311e7362af62d4096c76a7ffcb56d772` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$405** (405 USDC) |
| **Blocks** | 26365548-26365548 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $405 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #66: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x41ef7a29b30585730b6a69212664000887c7b827` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$3,000** (3,000 USDC) |
| **Blocks** | 26365544-26365544 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #67: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x79612b0bfe41cbc402e120a73c313536bdc945d5` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,986** (1,986 USDT) |
| **Blocks** | 26365535-26365535 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,986 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #68: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1a6a47f4080eaa48ee66aaa8893c3ae9edd0553d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$814** (814 USDT, 0 WETH) |
| **Blocks** | 26365521-26365534 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $814 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #69: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8d7e857451f6f0c5176fe22534f8a817593b6585` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$813** (813 USDC) |
| **Blocks** | 26365534-26365534 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $813 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #70: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x13394005c1012e708fce1eb974f1130fdc73a5ce` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$101** (101 USDC) |
| **Blocks** | 26365530-26365530 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $101 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #71: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x112294dd9e89232081e9d500fe0caa7f87264dbd` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDT) |
| **Blocks** | 26365530-26365530 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $0 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #72: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x30b66394b12d79f85e159eca485daa0c43e49750` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5,223** (5,223 USDC) |
| **Blocks** | 26365529-26365529 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,223 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #73: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x14cf6d2fe3e1b326114b07d22a6f6bb59e346c67` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$750** (750 USDC) |
| **Blocks** | 26365528-26365528 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $750 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #74: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x18d1b124044e028511875cfdb380c240f6f87035` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$751** (751 USDT) |
| **Blocks** | 26365528-26365528 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $751 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #75: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3d1e14bf95b5e174193fa78f01f18a4252a7bc86` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$146** (146 USDT) |
| **Blocks** | 26365521-26365521 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $146 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #76: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8b2833425d751c1fbfb5c6d43d209ff9b366439e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$7,064** (7,064 USDC) |
| **Blocks** | 26365519-26365519 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7,064 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #77: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe9c19e5bd10e5096519fe1d2a9d783f79b8211da` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$8,667** (8,667 USDC) |
| **Blocks** | 26365519-26365519 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $8,667 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #78: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5ac8ffc2ff6e27c5f253ccc66d2b6a32f4e485f4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDT) |
| **Blocks** | 26365505-26365505 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $100 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #79: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x2d96c21ecd1794431826ce45b6e0ab637f4594fb` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365639-26365687 |

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
| Wallet Age | 8 days |
| Total Transactions | 294 |
| Current Balance | 0.003538 ETH |
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
| **Sender** | `0x93b603240fdaad95971aafcbdc1bfaeae8eb2e45` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0043 ETH** ($10) |
| **Blocks** | 26365664-26365684 |

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
| Wallet Age | 1241 days |
| Total Transactions | 182 |
| Current Balance | 0.004170 ETH |
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
| **Sender** | `0x0f80c4e51981932777b6d418ddc38d384e2ae9e7` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365645-26365678 |

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
| Total Transactions | 16 |
| Current Balance | 0.021643 ETH |
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
| **Sender** | `0xd28c4fcc1925c4565074f263416260f7f1760229` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365638-26365638 |

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
| Total Transactions | 1028 |
| Current Balance | 0.000172 ETH |
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
| **Sender** | `0x472689239dfc0f51732e79388b9c4d454d9f2233` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0967 ETH** ($215) |
| **Blocks** | 26365611-26365611 |

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
| Wallet Age | 1266 days |
| Total Transactions | 322 |
| Current Balance | 0.000219 ETH |
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
| **Sender** | `0x12bed481414a0aff7a6f51f8104e584fffcb8772` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365606-26365606 |

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
| Wallet Age | 185 days |
| Total Transactions | 74 |
| Current Balance | 0.002074 ETH |
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
| **Sender** | `0xf5126b003c3abb51022050966aff94784d1fffe8` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0067 ETH** ($15) |
| **Blocks** | 26365601-26365601 |

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
| Wallet Age | 233 days |
| Total Transactions | 85 |
| Current Balance | 0.003564 ETH |
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
| **Sender** | `0xa8955b61a36d6c7747e78bf9dd0217ab9916199a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0160 ETH** ($36) |
| **Blocks** | 26365592-26365592 |

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
| Wallet Age | 52 days |
| Total Transactions | 19 |
| Current Balance | 0.000774 ETH |
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
| **Sender** | `0x24e72485d0631b93e201b4ddf02315f8fda145a4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0010 ETH** ($2) |
| **Blocks** | 26365580-26365580 |

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
| Wallet Age | 969 days |
| Total Transactions | 126 |
| Current Balance | 0.000035 ETH |
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
| **Sender** | `0xc7d231806a22294c7d94ad8d650a4a8fea7525fe` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0070 ETH** ($16) |
| **Blocks** | 26365555-26365555 |

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
| Wallet Age | 680 days |
| Total Transactions | 62 |
| Current Balance | 0.001070 ETH |
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
| **Sender** | `0x63d3a2576ef7d0c394a4f44f27b1cd08df820235` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.1250 ETH** ($278) |
| **Blocks** | 26365535-26365535 |

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
| Wallet Age | 50 days |
| Total Transactions | 3 |
| Current Balance | 0.000078 ETH |
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
| **Sender** | `0x1fa584e0dabee05c063985979d416911538c4430` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.2969 ETH** ($660) |
| **Blocks** | 26365532-26365532 |

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
| Wallet Age | 1749 days |
| Total Transactions | 292 |
| Current Balance | 0.014990 ETH |
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
| **Sender** | `0xb6fcf1020833243c8a51721bda1f2429654a21b1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0020 ETH** ($4) |
| **Blocks** | 26365528-26365528 |

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
| Wallet Age | 43 days |
| Total Transactions | 742 |
| Current Balance | 0.002994 ETH |
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
| **Sender** | `0x36025e751e7b6599152da9cc2b38a5c4225b450e` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365504-26365517 |

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
| Total Transactions | 123 |
| Current Balance | 0.000975 ETH |
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
| **Sender** | `0x15ff511a210e135b1a1a1e3df10bcbe9b25f0884` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0030 ETH** ($7) |
| **Blocks** | 26365514-26365514 |

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
| Wallet Age | 421 days |
| Total Transactions | 128 |
| Current Balance | 0.000669 ETH |
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
| **Sender** | `0xfe07906f5659cf70204d52c402516c2010c4641b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0015 ETH** ($3) |
| **Blocks** | 26365503-26365503 |

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
| Current Balance | 0.000036 ETH |
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
| **Sender** | `0xa7780b8ad864a28b4f894cf4f6ba7dbda7862970` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365503-26365503 |

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
| Wallet Age | 1130 days |
| Total Transactions | 249 |
| Current Balance | 0.002362 ETH |
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
| **Sender** | `0xb1ca4a18aff443656f407fa8be3533ff27dde911` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365683-26365683 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 65.

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
| Total Transactions | 21562 |
| Current Balance | 0.637391 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #97: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xf3a3ab25347de13b6955868a88c4b25da6007a1f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365631-26365631 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 65.

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
| Wallet Age | 4 days |
| Total Transactions | 134 |
| Current Balance | 0.034527 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #98: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa883710b6dbf008a1cc25722c54583e35884a209` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365530-26365629 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 65.

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
| Wallet Age | 858 days |
| Total Transactions | 25504 |
| Current Balance | 0.497135 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #99: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x664eeb033d68e13d2ad6933a496a62ce9a3060be` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365602-26365602 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 65.

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
| Wallet Age | 311 days |
| Total Transactions | 10459 |
| Current Balance | 0.125217 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #100: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa7842153fde380a864726d0e91f14f6ffab7d46c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26365521-26365534 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 65.

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
| Wallet Age | 523 days |
| Total Transactions | 21925 |
| Current Balance | 0.897540 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**100 suspicious findings** detected across 100 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 11 |
| 🟠 HIGH | 8 |
| Wallets flagged | 100 |
| Suspicious value | 0.5602 ETH ($1,246) + $307,831 in stablecoins |
| Blocks scanned | 26365501 — 26365700 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 1 of 25 attempted analyses this run.

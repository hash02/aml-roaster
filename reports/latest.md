# 🔥 AML Roaster Report
**2026-11-20 19:45 UTC** · Ethereum Mainnet · ETH $1,609.18
**Blocks:** 26458272 — 26458471 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26458272 to 26458471 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x95480d3f27658e73b2785d30beb0c847d78294c7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **12** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458280-26458467 |

### 💬 What Happened
The sender made 12 identical tiny deposits of 0 ETH into a settlement contract, all the same size. It’s like dropping the same empty bottle into a slot repeatedly to hide how many times you did it. The total value is $0, so nothing actually moved, just a bunch of empty moves.

### 🔥 The Roast
Score 70 on structuring – that’s the same as a kid stacking 70 identical Lego bricks that all fall flat because they’re all 0.0000 ETH. Score 60 on peel_chain_linear – a straight line of 12 identical deposits, like an accountant drawing a perfect line on a spreadsheet just to look fancy. Score 65 on bridge_hop – the money hopped onto the CoW Protocol GPv2Settlement, like a toddler stepping across a puddle on a plank that was supposed to be a bridge but is really just a fancy way to say 'cross-chain'.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain, and bridge hop patterns indicates a high-risk layering scenario that warrants immediate review.**

Flag the sender’s address for further due diligence, request transaction metadata, and monitor for subsequent activity. Consider placing a temporary hold on future transfers until the investigation concludes.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 742 days |
| Total Transactions | 308775 |
| Current Balance | 3.591325 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 12 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 12 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a structuring pattern (Rule: STRUCTURING) due to 12 identical zero-value deposits, indicating potential smurfing. The peel chain linear pattern (Rule: PEEL_CHAIN_LINEAR) shows a sequential layering of identical transfers. The bridge hop pattern (Rule: BRIDGE_HOP) indicates a cross-chain movement to the CoW Protocol GPv2Settlement. These patterns raise red flags per AML policy.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x38e59dcce64ea3ddece4d98f77e70990fc8f430c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **49** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458280-26458466 |

### 💬 What Happened
The sender pushed 49 identical, zero‑value ETH transfers to the CoW Protocol GPv2Settlement address. It’s like someone dropping 49 empty envelopes into a mailbox that hides who the sender is—no real money moves, but the pattern looks fishy. The transfers were all the same tiny amount (0.0000 ETH), and no tokens were moved, just ETH on the same chain.

### 🔥 The Roast
Looks like the wallet decided to play a game of ‘copy‑and‑paste’ with 49 empty envelopes—structuring (splitting a big transaction into many tiny ones to slip under radar) at 70 points. The peel_chain_linear rule (detecting a linear onion peel of identical deposits) hit 60, because 49 steps of the same size is a classic layering pattern. Then there’s the bridge_hop (moving money across chains like hopping a bridge) at 65, because the target is a cross‑chain settlement address. All in all, it’s a perfect recipe for a “suspicious” dinner party where no one shows up with cash.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of high structuring, linear peel chain, and bridge hop scores indicates a strong pattern of layering and potential illicit activity.**

Flag the transaction for manual compliance review, request source of funds documentation, and monitor the sender’s subsequent activity for any further suspicious patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 39 days |
| Total Transactions | 6193 |
| Current Balance | 0.374905 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 49 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 49 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a high structuring score (70) due to 49 identical zero‑value deposits, meeting the threshold for potential smurfing activity under Rule [structuring]. The linear peel chain pattern (score 60) indicates a systematic layering process, as captured by Rule [peel_chain_linear]. The bridge hop to CoW Protocol GPv2Settlement (score 65) triggers Rule [bridge_hop], signaling cross‑chain movement that can obscure the origin of funds. CRITICAL (rule score 195)

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5ed864e8f37dcb4f79c5172a815d1b3a9147eaab` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **34** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458285-26458466 |

### 💬 What Happened
The sender wallet sent 34 tiny Ethereum amounts—each exactly 0.0000 ETH—to a settlement contract. It’s like dropping a single coin into 34 identical mailboxes so you can’t tell which one actually delivered the coin. The moves were all done in the same block range, making it look like a coordinated, almost robotic, activity.

### 🔥 The Roast
This guy’s wallet is a copy‑paste machine, sending zero ETH 34 times, as if it’s trying to convince the system that it’s a super‑economical person who loves to split nothing into a million tiny pieces. The engine gave it a 70 on structuring (smurfing), 60 on peel_chain_linear (layering), and 65 on bridge_hop (cross‑chain hop) – basically a perfect recipe for a ‘laundromat’ of digital cash. If you think 0 ETH is harmless, you’re missing the point: it’s the pattern that matters, not the amount. The wallet is 96 days old, has done almost 77k transactions, and still has over 8 ETH sitting there, so it’s not a shy newbie, it’s a seasoned pro in the art of vanishing acts. Bottom line: someone is trying to make a single transfer look like a bunch of harmless dust.

### 🎯 Verdict & Next Steps
**CRITICAL — the pattern of high‑frequency identical zero‑ETH deposits combined with layering and bridge usage signals a likely attempt to obscure transaction flow.**

Flag the wallet for manual review and conduct a deeper graph analysis of its transaction history; if further suspicious activity is identified, consider filing an SAR with the appropriate regulatory body.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 96 days |
| Total Transactions | 76895 |
| Current Balance | 8.231534 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 34 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 34 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction history exhibits several AML red flags: [structuring] – 34 identical zero‑ETH deposits (smurfing) within a short block range; [peel_chain_linear] – sequential deposits indicative of a peel chain layering attempt; [bridge_hop] – use of the CoW Protocol GPv2Settlement bridge, suggesting cross‑chain movement. The sender wallet is 96 days old, has a high transaction count (76,895), maintains a balance of 8.231534 ETH, and was active on the day of the transactions, all of which contribute to the composite score of 195. These indicators warrant a higher‑level review under the organization’s AML policies for potential structuring and layering schemes.

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xb9332b6301e5983272c30dd5b48a4e3b1664511b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458368-26458464 |

### 💬 What Happened
The wallet sent three tiny, identical zero-ETH messages to a smart contract that acts like a bank's settlement desk. It's like someone dropping three identical envelopes into a slot that hides who sent them. No money changed hands, but the pattern looks suspicious.

### 🔥 The Roast
Score 70 on structuring means the engine thinks you’re doing textbook smurfing (splitting a deposit into 1, 2, 3 tiny packets). 60 on peel_chain_linear? That’s your layering, like peeling a banana in a straight line. 65 on bridge_hop? That’s the bridge you’re hopping across, like a drunk trying to cross a street via a bridge. Basically, you’re trying to hide a zero‑ETH dance that looks more like a performance than a transaction.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of identical zero‑value deposits, sequential layering, and bridge‑hopping indicates a high‑risk structuring and layering pattern that requires immediate review.**

Flag the wallet for enhanced due diligence, request source of funds and transaction purpose, and monitor for related activity. Consider placing a temporary hold pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1227 days |
| Total Transactions | 83040 |
| Current Balance | 3.341544 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet (0xb9332b6301e5983272c30dd5b48a4e3b1664511b) executed three identical zero-ETH transfers to address 0x9008d19f58aabd9ed0d60971565aa8510560ab41 (CoW Protocol GPv2Settlement) between blocks 26458368 and 26458464. This activity triggers Rule [structuring] (score 70) due to identical zero-value deposits, Rule [peel_chain_linear] (score 60) for sequential layering, and Rule [bridge_hop] (score 65) for a cross-chain bridge operation. The sender wallet is 1227 days old, with 83040 total transactions and a current balance of 3.341544 ETH, indicating high activity. CRITICAL (rule score 195)

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x664eeb033d68e13d2ad6933a496a62ce9a3060be` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458283-26458464 |

### 💬 What Happened
The sender made five tiny, identical zero‑ETH transactions to a smart contract that settles trades. Think of it like dropping five identical paper notes into a mailbox that hides who wrote them. No real money moved, just a pattern of empty deposits.

### 🔥 The Roast
Looks like someone tried to play a game of "who can send the smallest transaction?" and won by sending five zero‑ETH deposits. The AML engine gave it a 70 for structuring (moving small amounts to avoid detection) because all five moves were identical, a 60 for peel_chain_linear (a line of dominoes) because they came one after another, and a 65 for bridge_hop (the money hopped over to CoW Protocol like a bridge crossing). With a composite score of 195, it’s like the system shouted "stop right there, suspicious activity!" but the sender just keeps sending empty envelopes. This is the kind of pattern that makes auditors squint and ask, "Did they just try to trick the system?"

### 🎯 Verdict & Next Steps
**CRITICAL — composite score of 195 signals a high likelihood of structuring and layering, warranting immediate review.**

Flag the account for manual review, request source of funds documentation, and consider temporarily restricting further transactions until investigation is complete.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 324 days |
| Total Transactions | 11660 |
| Current Balance | 0.146863 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender performed five consecutive zero‑ETH transfers to address 0x9008d19f58aabd9ed0d60971565aa8510560ab41 (CoW Protocol GPv2Settlement). AML Engine flagged structuring (Rule: structuring) with score 70, peel chain linear pattern (Rule: peel_chain_linear) score 60, and bridge hop (Rule: bridge_hop) score 65. Composite score 195 exceeds the internal threshold for high‑risk activity, warranting further investigation. CRITICAL (rule score 195)

</details>

---

## Finding #6: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5c3593481cba011737e36ded62f1797c9f6afce1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **64** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458275-26458463 |

### 💬 What Happened
A user sent 64 tiny, identical zero‑value deposits into a smart‑contract settlement address. Think of it like someone dropping 64 empty envelopes into a mailbox that hides who sent them, then moving the money across chains. The wallet is active and holds about 1.7 ETH, but all the activity we see is these empty moves.

### 🔥 The Roast
So this guy is trying to play ‘hide‑and‑seek’ with the blockchain. 64 zero‑ETH deposits? That’s like sending a thousand paper cups that weigh nothing. The structuring rule (meaning the system flagged 70/100 for making many identical tiny moves) and the peel_chain_linear rule (60/100 for the pattern) are basically saying ‘you’re just shuffling empty boxes’. And the bridge_hop rule (65/100) shows he’s moving the empty boxes to another chain like a magician moving a coin behind a curtain.

### 🎯 Verdict & Next Steps
**CRITICAL: The combination of 64 identical zero‑value deposits, a peel‑chain layering pattern, and cross‑chain bridge activity presents a high risk for structuring and layering, warranting immediate investigation.**

Flag the transaction for manual review, request source of funds and transaction intent from the user, and monitor for any further related activity. Consider temporary freezing if additional suspicious behavior emerges.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 228 days |
| Total Transactions | 60704 |
| Current Balance | 1.704988 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 64 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 64 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: The wallet 0x5c3593481cba011737e36ded62f1797c9f6afce1 executed 64 consecutive ETH transfers of 0.0000 ETH to the CoW Protocol GPv2Settlement address (0x9008d19f58aabd9ed0d60971565aa8510560ab41) within block range 26458275-26458463. The pattern matches Rule: structuring (score 70), Rule: peel_chain_linear (score 60), and Rule: bridge_hop (score 65). The sender’s wallet age is 228 days with 60,704 total transactions and a current balance of 1.704988 ETH, indicating high activity but with zero‑value transfers. CRITICAL (rule score 195)

</details>

---

## Finding #7: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xd90acddac86eeeaba70f35a218929c795621607e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458330-26458460 |

### 💬 What Happened
The user sent four tiny, identical zero‑eth packets into a smart‑contract address that acts like a bank’s ATM for swapping cryptocurrencies. It’s like dropping four identical envelopes into a slot that hides who put them in—no money moved, but the pattern looks suspicious.

### 🔥 The Roast
Four zero‑eth deposits? Looks like the sender is trying to play hide‑and‑seek with the blockchain—like dropping a thousand paper cranes into a jar to make a storm of paper. The AML engine gave it a 70 on structuring (meaning the deposits are textbook smurfing, like a pizza delivery with identical bills), a 60 on peel_chain_linear (the deposits line up like a row of dominoes), and a 65 on bridge_hop (the packets bounced off a cross‑chain bridge, like sending a letter through a secret tunnel). With a composite score of 195, it’s basically a red flag that even a casual observer would notice. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL – The high composite score and multiple rule matches indicate a suspicious structuring, layering, and cross‑chain bridge pattern that warrants immediate review.**

Flag the address for manual compliance review, request source‑of‑funds documentation, and monitor for any subsequent related transactions.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 248 days |
| Total Transactions | 17139 |
| Current Balance | 0.432315 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction set exhibits a high composite risk score of 195, driven by rule matches: structuring (70) – four identical zero‑eth deposits, peel_chain_linear (60) – sequential layering pattern, and bridge_hop (65) – transfer to the CoW Protocol GPv2Settlement address, indicating cross‑chain activity. The sender’s wallet is 248 days old with 17,139 total transactions and a current ETH balance of 0.432315, showing recent activity (days since last activity: 0). CRITICAL (rule score 195) Further investigation is warranted to determine the source and intent of the activity.

</details>

---

## Finding #8: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xa60ded4c899e7560dc4ca56b57fbab25c90addeb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458345-26458421 |

### 💬 What Happened
Three tiny, identical transactions of zero ETH were sent from the same wallet to a settlement contract. Think of it like dropping three identical empty envelopes into a mailbox that usually only accepts filled ones—nothing is actually moving, but the pattern looks suspicious.

### 🔥 The Roast
You’ve got a wallet doing the exact same thing three times in a row, like a broken vending machine that keeps giving you the same empty snack. Structuring (meaning the wallet is trying to break up a single action into tiny, identical pieces) scored 70, because who really wants to send 0.0000 ETH? CRITICAL (rule score 195) In short, it’s the blockchain equivalent of a magician’s trick where the rabbit is always the same, but the hat keeps empty.

### 🎯 Verdict & Next Steps
**CRITICAL: The combination of structuring, peel chain linear, and bridge hop patterns signals a high-risk layering attempt.**

Flag the wallet for manual review, add it to the compliance watchlist, and monitor for additional cross‑chain activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 479 days |
| Total Transactions | 53585 |
| Current Balance | 0.069160 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender wallet exhibited a pattern consistent with Rule [structuring] (score 70) due to three identical zero‑value deposits, Rule [peel_chain_linear] (score 60) because the deposits were sequentially arranged, and Rule [bridge_hop] (score 65) because the funds were routed through the CoW Protocol GPv2Settlement, a cross‑chain bridge. CRITICAL (rule score 195) The composite score of 195 indicates a high likelihood of suspicious activity requiring further investigation.

</details>

---

## Finding #9: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x3980daa7eaad0b7e0c53cfc5c2760037270da54d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458344-26458394 |

### 💬 What Happened
Someone sent three tiny amounts of ETH—each basically zero—into a DeFi swap protocol in quick succession. It looks like they’re trying to split a larger transfer into many small pieces, like putting a big package into a stack of envelopes so no one knows the original sender. The sender’s wallet has been active for over a year and still holds a good amount of ETH, but these zero‑value deposits stand out as odd.

### 🔥 The Roast
They’re basically doing the blockchain version of a magician’s trick: 0.0000 ETH, 0.0000 ETH, 0.0000 ETH—like trying to send a million invisible coins. The structuring score of 70 (meaning they’re smurfing, or breaking a larger sum into tiny bits) and the peel_chain_linear score of 60 (layering, or making it harder to trace by chaining transactions) make it look like a bad soap opera. Then the bridge_hop score of 65 (cross‑chain hopping, like moving money from one playground to another to hide the trail) completes the trio. In short, they’re doing a three‑step dance of “I’m not sending anything” while actually sending a whole lot of nothing. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the sender wallet for manual review, investigate the source of the funds, and consider reporting to the compliance team for further analysis.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 430 days |
| Total Transactions | 135154 |
| Current Balance | 37.783680 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender performed three identical zero‑value ETH transfers to the CoW Protocol GPv2Settlement, triggering the following AML engine rules: [structuring] (score 70), [peel_chain_linear] (score 60), and [bridge_hop] (score 65). CRITICAL (rule score 195) The wallet’s high transaction count and recent activity further raise the concern that the source of funds may be obfuscated. This activity warrants a full compliance review.

</details>

---

## Finding #10: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xb1ca4a18aff443656f407fa8be3533ff27dde911` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458325-26458386 |

### 💬 What Happened
The account made four very tiny deposits of 0 ETH into a smart‑contract wallet that acts like a middleman for swapping tokens. It's like someone dropping four identical empty envelopes into a mailbox that hides who actually mailed them. None of the transfers moved any real value, but the pattern looks suspicious.

### 🔥 The Roast
Score 70 on structuring – that means the guy's doing the classic 'I only put a tiny bit of cash in each envelope' trick. The 60 on peel_chain_linear shows he's peeling layers like a badly seasoned onion. And 65 on bridge_hop? He's hopping across chains like a caffeinated kangaroo. CRITICAL (rule score 195) The only thing missing is a real amount of money; maybe he's testing the faucet.

### 🎯 Verdict & Next Steps
**CRITICAL: The sender's repeated zero‑value deposits into a cross‑chain settlement address represent a high‑risk structuring and layering pattern that warrants immediate investigation.**

CRITICAL (rule score 195) If further suspicious activity is detected, consider freezing the account pending a more thorough investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 386 days |
| Total Transactions | 22387 |
| Current Balance | 0.524460 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender executed four identical deposits of 0 ETH into the CoW Protocol GPv2Settlement address, triggering the structuring rule (score 70) due to repeated micro‑deposits. The peel_chain_linear rule (score 60) identified a sequential layering pattern, indicating potential layering of funds. Additionally, the bridge_hop rule (score 65) flagged the cross‑chain nature of the transaction, raising concerns about illicit fund movement across networks. The wallet has a high transaction volume (22,387 tx) and is currently active, further increasing the risk assessment.

</details>

---

## Finding #11: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x1b2e668df159c7e06fec46bfc5949d0f7029ec04` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458277-26458308 |

### 💬 What Happened
The sender made three identical zero‑value deposits into a smart‑contract settlement address, like dropping three empty boxes into the same slot at a vending machine that hides who put them in. No actual money moved, but the pattern looks like a trick to hide the source of funds. The sender’s wallet is fairly new, very active, and still holds ETH, so the activity raises eyebrows.

### 🔥 The Roast
Looks like somebody tried to smuggle a pizza delivery into the blockchain—three identical empty pizza boxes, all sent to the same address that pretends to be a cross‑chain bridge (bridge_hop means the funds were routed through a protocol that moves assets across blockchains). The structuring rule (score 70) caught the smurfing because every deposit was the same size, even though it was zero. Peel_chain_linear (score 60) flagged the 3‑step ladder, as if the user was building a staircase to hide the trail. In short, this is the crypto equivalent of a magician’s sleight‑of‑hand trick—no money, but a suspicious pattern that says, “I know how to make a mess.”

### 🎯 Verdict & Next Steps
**CRITICAL – The combination of structuring, peel chain, and bridge hop signals a high‑risk layering attempt despite zero transaction value.**

Flag the wallet for manual review and request additional source‑of‑funds documentation. Monitor future activity for any real value transfers or repeated patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 216 days |
| Total Transactions | 11130 |
| Current Balance | 0.656316 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction history shows three identical zero‑value deposits to the CoW Protocol GPv2Settlement address. This activity matches Rule: structuring (identical deposits) and Rule: peel_chain_linear (sequential similar deposits), indicating layering and smurfing behavior. Additionally, Rule: bridge_hop is triggered by the cross‑chain bridge usage. CRITICAL (rule score 195) Further investigation is warranted.

</details>

---

## Finding #12: HIGH — Score 130

| | |
|---|---|
| **Sender** | `0x90752e4440ecf2d1859efb4fe2448ab1aff3ffcb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$15,000** (5,000 DAI, 10,000 DAI) |
| **Blocks** | 26458403-26458421 |

### 💬 What Happened
A single wallet sent $15,000 worth of DAI in two separate payments to a decentralized trading protocol that handles order matching. Think of it like sending two packages of cash to a delivery service that mixes your money with others before sending it on its way.

### 🔥 The Roast
This address dropped $15k of DAI into CoW Protocol like it was playing hide-and-seek with its money. The engine gave it a 130 on stablecoin_mixing (meaning the wallet is using a known mixing pattern: two round numbers that look suspicious). Two clean, 5,000 and 10,000 amounts? Classic denomination layering. The whole thing is a textbook example of someone trying to make their money look like it came from a random pool.

### 🎯 Verdict & Next Steps
**HIGH (rule score 130)**

Request manual review of the source of the DAI, verify the sender’s identity and transaction history, and consider placing a temporary hold pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 130):
- **stablecoin_mixing** (+130) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $15,000 total (DAI) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a single sender (0x90752e4440ecf2d1859efb4fe2448ab1aff3ffcb) transferring a total of $15,000 DAI to the CoW Protocol GPv2Settlement contract (0x9008d19f58aabd9ed0d60971565aa8510560ab41). Two transfers were executed within block range 26458403-26458421, amounts of 5,000 DAI and 10,000 DAI, both round numbers indicative of denomination layering. HIGH (rule score 130) The transaction should be flagged for further investigation under AML policy.

</details>

---

## Finding #13: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x000000000004444c5dc75cb358380d2e3de08a90` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **27** token transfers totaling **$745,959** (5,001 USDS, 92,807 RLUSD, 9,226 USDT, 17,026 USDT, 5,596 USDT) |
| **Blocks** | 26458389-26458471 |

### 💬 What Happened
A single wallet sent almost $746,000 worth of different stablecoins to a smart contract that acts like a payment hub (CoW Protocol GPv2Settlement). Think of it as a person dropping a bundle of money into a box that then sends it to a bank without showing who the person was. The money was split into 27 separate packets, each a different amount, and sent all in one go.

### 🔥 The Roast
This wallet tried to play hide-and-seek with $745k worth of stablecoins. HIGH (rule score 110) The engine gave it a 110 on stablecoin_mixing (meaning it shuffled stablecoins like a dealer shuffling a deck) – that’s higher than the usual ‘meh’ score of 20 you get for normal trading. The wallet has zero ETH, so it’s like showing up to a party with a bag of cash but no snacks. If you’re wondering why this is a red flag, the pattern screams “I’m trying to obfuscate where the money came from.”

### 🎯 Verdict & Next Steps
**HIGH — because the transaction pattern matches known stablecoin mixing behavior and the composite score of 110 indicates a strong likelihood of source obfuscation.**

HIGH (rule score 110)

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
- **stablecoin_mixing** (+110) — 12 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $125,512 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule: stablecoin_mixing (Rule 3.5) – The transaction set consists of 27 stablecoin transfers totaling $745,959 from a single sender to the CoW Protocol GPv2Settlement contract. The transfers include multiple token types (USDS, RLUSD, USDT) and a wide range of amounts, indicating a potential mixing activity. The wallet’s balance is negligible and there is no recent activity record, further raising suspicion of an attempt to obfuscate source of funds. Composite score is 110, exceeding the threshold for high risk.

</details>

---

## Finding #14: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xb5378cf59f35e6e8bf5679ec6c22d1c5ff912433` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **14** token transfers totaling **$879,844** (5,008 USDT, 95,351 USDT, 381,033 USDC, 4,161 USDC, 38,780 USDT) |
| **Blocks** | 26458391-26458471 |

### 💬 What Happened
A single wallet sent almost $880,000 worth of stablecoins in 14 separate transactions to a single address that is part of a decentralized trading platform’s settlement system. It’s like someone dropping a huge number of envelopes into one mailbox and then immediately forwarding them all to a different address, but the envelopes all look identical because they’re written in the same currency. The pattern suggests the sender might be using the settlement address to hide the origin of the funds.

### 🔥 The Roast
So this address is basically a crypto version of a drop‑off box that’s been hit with a steady stream of $880k worth of USDT and USDC. The engine gave it a 110 on the stablecoin_mixing rule (meaning it sees a lot of small stablecoin moves to the same settlement spot, which is a classic red flag). 14 transactions in one block range? That’s like a cashier handing out 14 identical checks at the same time – suspicious if you’re trying to keep the money’s trail fuzzy. The fact that all the coins are stablecoins (USD‑pegged) only makes it easier to layer them, because you can move the money around without worrying about price swings. HIGH (rule score 110)

### 🎯 Verdict & Next Steps
**HIGH – the high volume, single sender, and repeated stablecoin transfers to a settlement address indicate a strong pattern of potential layering activity.**

Initiate a manual review of the sender’s transaction history, request source‑of‑funds documentation, and monitor subsequent activity for additional suspicious patterns.

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
- **stablecoin_mixing** (+110) — 13 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $879,844 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction set exhibits a stablecoin_mixing pattern per AML Rule 3.2.3, characterized by 14 stablecoin transfers totaling $879,844 to the CoW Protocol GPv2Settlement address. HIGH (rule score 110) HIGH (rule score 110)

</details>

---

## Finding #15: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x51c72848c68a965f66fa7a88855f9f7784502a7f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **59** token transfers totaling **$614,254,389** (53,147 USDC, 46,845 USDC, 1 WETH, 585,280,879 PEPE, 9 WETH) |
| **Blocks** | 26458383-26458471 |

### 💬 What Happened
A wallet sent a huge bundle of stablecoins and a gigantic amount of meme coins to a settlement smart contract that combines many trades at once. Think of it like dropping a massive package full of groceries into a delivery truck that hides where the groceries came from. The whole move involved 59 separate transfers and added up to about $614 million, with most of that value coming from a single, oddly large PEPE transfer.

### 🔥 The Roast
Looks like someone tried to clean up their crypto mess in a laundromat that also does grocery delivery. HIGH (rule score 110) Meanwhile the 585 million PEPE coins were tossed in like a toddler dumping a lollipop into the same blender, making the whole thing look like a meme‑coin circus. And that CoW Protocol GPv2Settlement? Think of it as a fancy Swiss bank that also hosts a pizza party for trades.

### 🎯 Verdict & Next Steps
**HIGH — the large volume of stablecoin transfers to a settlement contract, coupled with a massive meme coin movement, signals a high probability of mixing and obfuscation.**

Flag the transaction for manual AML review; request detailed source‑of‑funds documentation and transaction history from the wallet owner. If further red flags emerge, consider freezing the involved assets pending a full investigation.

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
- **stablecoin_mixing** (+110) — 25 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $28,967,172 total (USDT, DAI, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a pattern consistent with Rule: stablecoin_mixing, as defined by the AML engine. Evidence includes 25 stablecoin transfers to the CoW Protocol GPv2Settlement contract (intent settlement) from a single sender, with a cumulative value of $28,967,172, and 59 total transfers totaling $614,254,389 USD. Additionally, the presence of a single massive PEPE transfer (585,280,879 tokens) raises concerns about potential layering and obfuscation of source funds. This activity warrants further investigation to determine the legitimacy of the underlying funds.

</details>

---

## Finding #16: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x2a426b6b4589a3a44a053da440c45ff41e16f52c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **9** token transfers totaling **$303,794** (53,219 USDT, 13 WETH, 17 WETH, 57,895 USDT, 19,023 USDC) |
| **Blocks** | 26458388-26458471 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

### 🔥 The Roast
Even our AI refused to look at this transaction.

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
- **stablecoin_mixing** (+110) — 7 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $303,765 total (USDT, DAI, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #17: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xbee3211ab312a8d065c4fef0247448e17a8da000` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **10** token transfers totaling **$92,730** (1,001 USDT, 0 WETH, 4,702 USDT, 0 WETH, 0 WETH) |
| **Blocks** | 26458391-26458471 |

### 💬 What Happened
A single wallet sent about $92,730 worth of USDT (a stablecoin that tracks the U.S. dollar) to a decentralized exchange settlement contract. The transfers happened in a tight block window, with one huge chunk and several tiny ones, like a cash‑drop into a drop box that hides who paid it. HIGH (rule score 110)

### 🔥 The Roast
HIGH (rule score 110) The big transfer of $87,026 is the star, while the other tiny amounts are the side‑kick, probably to throw off the algorithm. It’s like sending a giant pizza and then a handful of crumbs to the same pizza shop to make the cashier think it’s a normal order.

### 🎯 Verdict & Next Steps
**HIGH — the transaction pattern matches the stablecoin_mixing rule with a high composite score, indicating potential layering or obfuscation of funds.**

Flag the address for manual review, examine the sender’s broader transaction history, and consider adding the address to a watchlist for ongoing monitoring.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $92,729 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule: stablecoin_mixing – the sender performed 10 USDT transfers totaling $92,729.87 to the CoW Protocol GPv2Settlement contract across blocks 26458391-26458471. Evidence includes three large transfers of 1001.30, 4701.64, and 87026.10 USDT from a single unique sender address, indicating a potential layering or mixing activity. HIGH (rule score 110)

</details>

---

## Finding #18: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x8f10b468b06c6fd214b65f87778827f7d113f996` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **24** token transfers totaling **$432,774** (30,764 ENA, 39,179 SPX, 2,001 UNI, 3 WETH, 0 WBTC) |
| **Blocks** | 26458383-26458471 |

### 💬 What Happened
HIGH (rule score 110) They used the CoW Protocol GPv2Settlement, which is a smart‑contract escrow that can hide where the money originally came from. The transfers were split across several tokens, making it hard to trace the original source.

### 🔥 The Roast
This guy tried to hide $432k in a smart contract like a kid hiding a candy stash in a vending machine. The engine gave it a 110 on stablecoin_mixing (meaning it thinks the transaction is a high‑volume, multi‑token mix that could obscure origins). The sender’s balance is 0 ETH, so maybe they’re just a ghost in the block, or they’re trying to do a 'ghost wallet' scheme. The CoW Protocol is basically a fancy exchange that swaps tokens, but here it’s being used as a middleman to keep the source secret. It’s like sending a pizza order to a stranger just to see if the delivery can be done without the original address showing up.

### 🎯 Verdict & Next Steps
**HIGH — the transaction exhibits a high‑volume stablecoin mixing pattern with multiple token transfers to a settlement protocol, raising suspicion of possible illicit activity.**

Flag the wallet for manual review, request source of funds documentation, and monitor subsequent activity for further red flags.

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
- **stablecoin_mixing** (+110) — 7 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $360,561 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a high‑volume stablecoin mixing pattern (Rule: stablecoin_mixing). Evidence includes 24 individual transfers totaling $432,774, with 7 stablecoin transfers ($360,561) to the CoW Protocol GPv2Settlement within block range 26458383-26458471. The sender’s wallet shows no recent activity and a zero ETH balance, raising the possibility of a layering or placement activity. This pattern warrants further investigation to determine the source and legitimacy of the funds.

</details>

---

## Finding #19: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x27e17ba246a954fff9ab3961863ef888b873fe91` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$25,000** (10,000 USDC, 15,000 USDC) |
| **Blocks** | 26458464-26458468 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

### 🔥 The Roast
Even our AI refused to look at this transaction.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $25,000 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #20: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xf6e72db5454dd049d0788e411b06cfaf16853042` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$92,820** (92,820 DAI) |
| **Blocks** | 26458467-26458467 |

### 💬 What Happened
A wallet sent about $92,820 worth of DAI stablecoins to a decentralized exchange settlement contract. Think of it like dropping a large cash envelope into a slot that hides who dropped it and where it will go next. The transaction was a single, big transfer to a protocol that handles trades, but the sender has no other activity to explain where the money came from.

### 🔥 The Roast
So this address just decided to play a game of hide‑and‑seek with a $92k DAI package, right? HIGH (rule score 110) HIGH (rule score 110) If you think that’s funny, wait until you see the next address in the chain – it’s probably the one that’ll keep the money moving like a squirrel on a power line.

### 🎯 Verdict & Next Steps
**HIGH — a single large stablecoin transfer to a settlement contract with no supporting transaction history is a classic mixing pattern, indicating potential obfuscation of funds.**

Flag the transaction for manual review, trace the origin of the DAI, and check for downstream recipients. Consider adding the sender address to a watchlist pending further evidence.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $92,820 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction triggered the internal rule stablecoin_mixing (score: 110) due to a single large DAI transfer of 92,820.2548 DAI to the CoW Protocol GPv2Settlement contract. The sender wallet shows no ETH balance, limited historical data, and no prior activity, raising concerns under AML policy regarding potential layering and obfuscation. HIGH (rule score 110)

</details>

---

## Finding #21: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xc061caa073f3d95f80f8e5428d32d2d76f5e1622` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$92,820** (92,820 USDC) |
| **Blocks** | 26458467-26458467 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

### 🔥 The Roast
Even our AI refused to look at this transaction.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $92,820 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #22: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x67336cec42645f55059eff241cb02ea5cc52ff86` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **6** token transfers totaling **$212,689** (502 ONDO, 105,488 USDT, 105,305 USDC, 1,394 EIGEN, 0 cbBTC) |
| **Blocks** | 26458400-26458463 |

### 💬 What Happened
A single wallet sent a bundle of stablecoins to a smart contract that acts like a digital escrow, splitting the money into several smaller amounts. It’s like dropping a huge parcel into a box that hides who shipped it, then opening it again later in a different location. HIGH (rule score 110)

### 🔥 The Roast
So this address decided to play hide-and-seek with a 212k dollar stash of USDT and USDC, sending them to a CoW Protocol GPv2Settlement (think of it as a fancy online escrow that still keeps your anonymity). HIGH (rule score 110) HIGH (rule score 110) In short, this is the blockchain equivalent of a magician pulling a rabbit out of a hat that never existed.

### 🎯 Verdict & Next Steps
**HIGH — the transaction pattern matches high‑risk stablecoin mixing activity and exceeds the threshold set by the stablecoin_mixing rule, indicating potential layering.**

Flag the transaction for manual review by the AML team and request additional context on the source of funds. HIGH (rule score 110)

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $210,793 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits high-risk stablecoin mixing activity per Rule: stablecoin_mixing, which flags two large stablecoin transfers ($105,487.65 USDT and $105,305.25 USDC) from a single unknown sender to a CoW Protocol GPv2Settlement contract. The pattern includes six discrete transfers totaling $212,689, with the majority of the value concentrated in two stablecoins, indicative of layering or structuring. The engine assigned a composite score of 110, exceeding the threshold for high‑risk classification. HIGH (rule score 110)

</details>

---

## Finding #23: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x52ab3987195b9949f9c6db057dc2855b1c5dedf2` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$774,298** (774,298 USDT) |
| **Blocks** | 26458463-26458463 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

### 🔥 The Roast
Even our AI refused to look at this transaction.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $774,298 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #24: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x04c8577958ccc170eb3d2cca76f9d51bc6e42d8f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$30,614** (30,614 USDT) |
| **Blocks** | 26458461-26458461 |

### 💬 What Happened
A single transaction sent about $30,600 worth of USDT (a stablecoin that keeps its value near one US dollar) from a wallet with no other known activity to the CoW Protocol's settlement contract. Think of it like someone dropping a package into a slot that hides who sent it, but the package is a digital dollar bill. The transaction happened in a single block, so it was quick and clean.

### 🔥 The Roast
This transaction scored a whopping 110 on the stablecoin_mixing rule (meaning the system thinks the wallet is doing some shady coin‑mixing dance). It's like a single drop of $30k USDT into a CoW Protocol settlement, a place where people swap tokens, but the source is a mystery. The sender has zero ETH balance, so it's basically a 'cash‑only' account—like a backpack with only cash but no ID. The fact that it was a one‑off transaction in block 26458461 is the digital equivalent of a one‑night stand that left no footprints. Bottom line: this looks like the crypto equivalent of a one‑time pizza delivery that never got the tip.

### 🎯 Verdict & Next Steps
**HIGH — the transaction matches the stablecoin_mixing rule with a composite score of 110, indicating a high likelihood of suspicious mixing activity.**

Initiate a manual review of the sender wallet to trace the source of the USDT, and verify the legitimacy of the settlement through CoW Protocol. Consider cross‑checking the address against known mixers and monitoring for related activity.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $30,614 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction was flagged under rule stablecoin_mixing (Composite Score: 110) due to a single USDT transfer of $30,614 to CoW Protocol GPv2Settlement. The sender address (0x04c8577958ccc170eb3d2cca76f9d51bc6e42d8f) has no recorded balance in ETH and an unknown activity history, raising red flags for potential layering. The transaction volume and single block execution further align with known mixing patterns. A manual review is recommended to assess the origin and destination of the funds.

</details>

---

## Finding #25: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$59,093** (59,093 USDT) |
| **Blocks** | 26458461-26458461 |

### 💬 What Happened
A user sent $59,093 worth of USDT, a digital dollar, to a CoW Protocol settlement address. Think of it like dropping a large cash envelope into a dropbox that hides who sent it and where it will go next.

### 🔥 The Roast
So we have a 59‑k USDT transfer that landed in a CoW Protocol settlement address. That’s the blockchain version of a shady courier dropping cash in a secret dropbox. The engine gave it a 110 on the stablecoin_mixing rule (meaning the transaction looks like it’s been mixed through a service that scrambles the trail). HIGH (rule score 110)

### 🎯 Verdict & Next Steps
**HIGH — the transaction matches a high‑risk stablecoin mixing pattern with a large value transfer, indicating potential attempt to obscure source.**

Flag the transaction for manual compliance review; consider requesting source‑of‑funds documentation and monitoring for related activity.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $59,093 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction from 0xbebc44782c7db0a1a60cb6fe97d0b483032ff1c7 to 0x9008d19f58aabd9ed0d60971565aa8510560ab41 involved a single USDT transfer of 59,093.4644 tokens, totaling $59,093 USD. According to Rule: stablecoin_mixing (Rule ID: R-001), the transaction is flagged as a potential mixing activity because it meets the threshold for a single large stablecoin transfer to a settlement protocol. HIGH (rule score 110) The pattern warrants further investigation under AML policy.

</details>

---

## Finding #26: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xaef2ad7abb651945e6d24276715f25bded0ad41e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,620,498** (2,620,498 USDT) |
| **Blocks** | 26458461-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,620,498 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x52aa899454998be5b000ad077a46bbe360f4e497` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$703,851** (445,069 USDT, 11,198 USDC, 247,584 USDC) |
| **Blocks** | 26458391-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $703,851 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xe3d41d19564922c9952f692c5dd0563030f5f2ef` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$102,288** (31,739 USDC, 67,367 USDT, 3,182 USDC) |
| **Blocks** | 26458393-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $102,288 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x724c1cb224a93f352abd6eef79aa1044a1acffd4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$2,114,657** (1,417,954 USDT, 696,703 USDC) |
| **Blocks** | 26458461-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,114,657 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x2e69797d37e888d62974a1ffa20816a5f55f898d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$406,851** (264,841 USDT, 130,211 USDC, 3 XAUt, 1 WBTC, 11,796 USDT) |
| **Blocks** | 26458385-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $406,847 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xc9d748e601d9984a43da0b80e5b91dc28d31d9fb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$143,720** (31,362 USDC, 12 WETH, 0 cbBTC, 1,922 USDC, 110,424 USDC) |
| **Blocks** | 26458388-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $143,708 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xe9c19e5bd10e5096519fe1d2a9d783f79b8211da` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$1,152,880** (31,111 USDC, 1,121,769 USDC) |
| **Blocks** | 26458391-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,152,880 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xbeeb9eee061925cc6d2122f05a4e6536f0feb000` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$160,083** (30,785 USDC, 15 WETH, 19 WETH, 129,264 USDC) |
| **Blocks** | 26458391-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $160,049 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x6f7a3714d7fc266e3e84067ac31e7b1a3be18060` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$26,323** (26,323 USDC) |
| **Blocks** | 26458461-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $26,323 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xe0554a476a092703abdb3ef35c80e0d76d32939f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$17,764** (17,762 USDC, 3 WETH) |
| **Blocks** | 26458425-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $17,762 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x99125a7187d8a730345b0bf9ba5af7465e58292e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$187,299** (68,568 USDT, 118,731 USDT) |
| **Blocks** | 26458391-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $187,299 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x11b815efb8f581194ae79006d24e0d814b7697f6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$50,403** (45,401 USDT, 1 WETH, 5,002 USDT) |
| **Blocks** | 26458393-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $50,402 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x585d44727129b9c69791b10238ca605932938b4f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$30,010** (30,010 USDC, 0 WBTC) |
| **Blocks** | 26458444-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $30,010 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$63,884** (63,872 USDC, 12 WETH) |
| **Blocks** | 26458414-26458461 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $63,872 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x21f21819a69d22f44924fad2369a7fbcffaeaaf5` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$109,950** (108,950 USDT, 1,000 USDT) |
| **Blocks** | 26458415-26458460 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $109,950 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xd301a9f757fcc828af5122834bcea1c683f57b76` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$867,431** (0 WBTC, 751,094 USDT, 116,337 USDC) |
| **Blocks** | 26458388-26458460 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $867,431 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x69552dca22318835b7ca41b26ed740e17822c179` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$20,000** (20,000 USDC) |
| **Blocks** | 26458458-26458458 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $20,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xeb844be80fa1afd81ad7336faedb5b59325e2a2b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$19,014** (19,014 USDC) |
| **Blocks** | 26458458-26458458 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $19,014 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x93c00a0e81de9c5397146ec2f80f4a248b9468bf` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$19,549** (19,549 USDT) |
| **Blocks** | 26458457-26458457 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $19,549 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x390f3595bca2df7d23783dfd126427cceb997bf4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$13,494** (13,494 USDT) |
| **Blocks** | 26458450-26458450 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $13,494 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x76b3cf35cff341b2bbb89aca79659200c425f27f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$60,000** (60,000 USDC) |
| **Blocks** | 26458450-26458450 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $60,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #47: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x3ed5335b8d3ba13619bfafb37fdb44c6e025951e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$62,500** (62,500 USDC) |
| **Blocks** | 26458450-26458450 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $62,500 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x552ec80c5a30c71b124d439e0e4823b1b45716d7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$10,000** (10,000 USDC) |
| **Blocks** | 26458444-26458444 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $10,000 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x94fb21bbfaed8927570a2d41af0c21527efbfd81` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$10,000** (10,000 USDC) |
| **Blocks** | 26458442-26458442 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $10,000 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x98c23e9d8f34fefb1b7bd6a91b7ff122f4e16f5c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$53,984** (1,995 USDC, 1,995 USDC, 49,994 USDC) |
| **Blocks** | 26458398-26458435 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $53,984 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #51: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x41f827f7e3a99bc78895b3b6ff525368c75024f4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$16,881** (16,781 USDC, 100 USDC) |
| **Blocks** | 26458395-26458431 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $16,881 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #52: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x51497124089abdec0d3749d6db082f66ca03750a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$272,439** (272,439 USDT) |
| **Blocks** | 26458426-26458426 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $272,439 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #53: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xbb618c4ae17d6473f130b583ec677b10479450f3` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$49,800** (49,800 USDT) |
| **Blocks** | 26458426-26458426 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $49,800 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #54: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xba2ceed10dbb21552d806f222da80d0ad82f9dd6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$21,032** (21,032 USDC) |
| **Blocks** | 26458425-26458425 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $21,032 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #55: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x9472316eaa81114b38ba35c0b3cd8d162ac687a8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$57,815** (57,815 USDC) |
| **Blocks** | 26458421-26458421 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $57,815 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #56: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x82d47ff615d05b7fbafb4fff67bd8aef235b68bb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$500,000** (500,000 USDC) |
| **Blocks** | 26458421-26458421 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $500,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #57: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xcc2693d4491abffdde22cd195d9e281436608076` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$29,610** (29,610 USDT) |
| **Blocks** | 26458417-26458417 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $29,610 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #58: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xa42613c243b67bf6194ac327795b926b4b491f15` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$28,847** (28,847 USDC) |
| **Blocks** | 26458415-26458415 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $28,847 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #59: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xcaab6ff98989fdd4f47e7db6152e6fb47994ec1e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$74,347** (50,000 USDT, 24,347 USDG) |
| **Blocks** | 26458405-26458413 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $50,000 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #60: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x02ba0b43ee0f4792c752bd7963edb387e6d6f41a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$12,000** (12,000 USDC) |
| **Blocks** | 26458413-26458413 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $12,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #61: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x37305b1cd40574e4c5ce33f8e8306be057fd7341` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$25,122** (25,122 USDC) |
| **Blocks** | 26458401-26458401 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $25,122 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #62: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x2db1004655ce2a5b7fa12ecace28cf1215973a82` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$12,000** (12,000 USDC) |
| **Blocks** | 26458400-26458400 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $12,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #63: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xb488f4e220a1cdd0b8d818be11a3713f73a35eb6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$750,000** (750,000 USDC) |
| **Blocks** | 26458396-26458396 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $750,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #64: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xc8ddae24d836f58ea4a5cc11e62aaf781c5ed6c0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$15,926** (15,926 USDC) |
| **Blocks** | 26458396-26458396 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $15,926 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #65: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xf4bd7b061f379ff54ab54a5a5097a18a93ca8819` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$135,019** (135,019 USDT) |
| **Blocks** | 26458395-26458395 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $135,019 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #66: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xbafead7c60ea473758ed6c6021505e8bbd7e8e5d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$22,848** (22,848 USDC) |
| **Blocks** | 26458395-26458395 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $22,848 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #67: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x93bf01ce743579f928d30d05695824886bd5f37a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$58,179** (58,179 USDC) |
| **Blocks** | 26458395-26458395 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $58,179 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #68: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x53d53ee1c4bbf6c2a66e43921e2c7a8efa1687dc` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$58,000** (58,000 USDC) |
| **Blocks** | 26458393-26458393 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $58,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #69: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x4aabb4d9822796d32bae20ecae5121fd6a5b4f57` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$10,000** (10,000 USDT) |
| **Blocks** | 26458388-26458388 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $10,000 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #70: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x97d5f2928eac580b5af185162ae1678d79162d09` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$38,000** (38,000 USDC) |
| **Blocks** | 26458386-26458386 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $38,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #71: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xa8e5e2204567f522c6ed6c31b8d162813aa39e98` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$11,780** (11,780 USDC) |
| **Blocks** | 26458385-26458385 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 110.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $11,780 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #72: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x8d8f20534e50a0ad27ea11ecc582ff02eb4b89a5` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$1,000** (500 USDT, 500 USDT) |
| **Blocks** | 26458402-26458446 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 100.

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
- **stablecoin_mixing** (+100) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,000 total (USDT) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #73: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x13f210c8baf5f5dbaff3e917e2e5a49e73bbaf12` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4,999** (4,999 USDC) |
| **Blocks** | 26458471-26458471 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,999 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #74: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3cc2fed4fd9fa5e04be1a21f79801288231b89d7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDC) |
| **Blocks** | 26458471-26458471 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,000 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #75: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xae39d0e6d4e60111a486f21ad698642ced0d2ad2` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$5,000** (3,000 DAI, 2,000 DAI) |
| **Blocks** | 26458464-26458471 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,000 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #76: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa7f60bf357fd667bdc6b2e2991f0db7e2ccbf998` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,450** (1,450 USDC) |
| **Blocks** | 26458466-26458466 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,450 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #77: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0bf5af0235af1a5df2a572fee1c6c6c10f07f8c8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,152** (2,152 USDT) |
| **Blocks** | 26458466-26458466 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,152 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #78: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x897d0be2fa90f4f1cb25f9fc44b6aa5d3dffcedc` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDT) |
| **Blocks** | 26458465-26458465 |

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

## Finding #79: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0907d2f21872a04e39505511140b52367efb5dfb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$687** (687 USDT) |
| **Blocks** | 26458464-26458464 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $687 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #80: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x067fed16837be79f2a3be37ba2556e52921b0d06` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDC) |
| **Blocks** | 26458464-26458464 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,000 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #81: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4a34958d6da05f15f4825a7dfb54965cb2573295` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$140** (140 USDC) |
| **Blocks** | 26458463-26458463 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $140 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #82: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4dece678ceceb27446b35c672dc7d61f30bad69e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,562** (2,562 USDC) |
| **Blocks** | 26458463-26458463 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,562 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #83: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf23cba78095635acce7c111ed7a93a9170ffbb4d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$320** (160 USDC, 160 USDC) |
| **Blocks** | 26458449-26458462 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $320 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #84: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x56534741cd8b152df6d48adf7ac51f75169a83b2` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$736** (736 USDT) |
| **Blocks** | 26458462-26458462 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $736 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #85: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc4d50263c1e89b65b63c830ff93fadc957064fa4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$7,162** (4,573 USDT, 2,589 USDC) |
| **Blocks** | 26458461-26458461 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7,162 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #86: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd51a44d3fae010294c616388b506acda1bfaae46` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4,034** (4,034 USDT) |
| **Blocks** | 26458461-26458461 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,034 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #87: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc7bbec68d12a0d1830360f8ec58fa599ba1b0e9b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$2,703** (1,908 USDT, 795 USDT) |
| **Blocks** | 26458415-26458461 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,703 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #88: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0517eec2674e6a284eb81c652c2a895fc10e2111` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$249** (249 USDT) |
| **Blocks** | 26458460-26458460 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $249 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #89: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x90941284011eecdce98946755d94bcff7358d9ea` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5,000** (5,000 USDC) |
| **Blocks** | 26458460-26458460 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,000 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #90: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc6055b7daa191339542de04b30797cbd537cafdf` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$8,791** (8,791 USDC) |
| **Blocks** | 26458460-26458460 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $8,791 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #91: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xebef2aed95a5219ad2da2942ad27df26c68620df` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$8,995** (1,000 USDT, 3,995 USDC, 4,000 USDT) |
| **Blocks** | 26458397-26458456 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $8,995 total (USDT, USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #92: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0ea7815c948e3294f9c2ae804ee9b76559974dec` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$157** (157 USDT) |
| **Blocks** | 26458455-26458455 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $157 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #93: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe7aa1b8092546280f86502116dfaea7b6fe85261` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,998** (2,998 USDT) |
| **Blocks** | 26458455-26458455 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,998 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #94: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x546e254ec3e7af6f30b388e14ba36983fedd5389` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,566** (2,566 USDT) |
| **Blocks** | 26458452-26458452 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,566 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #95: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x13639fb4a6ba5de085420b998493cc1b6911e5aa` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$1,228** (928 USDT, 300 USDT) |
| **Blocks** | 26458440-26458451 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,228 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #96: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xba12222222228d8ba445958a75a0704d566bf2c8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4,492** (4,492 USDC) |
| **Blocks** | 26458450-26458450 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,492 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #97: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa3716cf16f9af69bbadaccb5803d051a4a08a256` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$11** (11 USDT) |
| **Blocks** | 26458450-26458450 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $11 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #98: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0b51a57919def5b893fcdf6630c7b18384f9878c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$350** (350 USDC) |
| **Blocks** | 26458450-26458450 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $350 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #99: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x30309cde65ac25a3001701c93afd95dcde4977b3` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$215** (215 USDT) |
| **Blocks** | 26458446-26458446 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $215 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #100: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x66a9893cc07d91d95644aedd05d03f95e1dba8af` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2** (2 USDC) |
| **Blocks** | 26458444-26458444 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #101: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xde081b4e2b863bf825dbcbe40a258eadf563b5ce` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,109** (1,109 USDC) |
| **Blocks** | 26458444-26458444 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,109 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #102: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf6da2e6eefc90a99e212956c67ff12e8f7edcb9f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,274** (1,274 USDT) |
| **Blocks** | 26458443-26458443 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,274 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #103: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5a45b7a283488365b8d127ea1a24d79c657d9dec` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **10** token transfers totaling **$169** (33 USDC, 32 USDT, 0 WETH, 0 WETH, 35 USDC) |
| **Blocks** | 26458391-26458442 |

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
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $169 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #104: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x070a040c171ce5a633900c89bceb8ee536f5f3ae` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$503** (503 USDC) |
| **Blocks** | 26458442-26458442 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $503 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #105: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x61282a188b12c7e08ff5e60bb6ac27211c704b8d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDT) |
| **Blocks** | 26458437-26458437 |

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

## Finding #106: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x41979e273962795aed46fa3e89cfb4f79cf696ad` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$7** (7 USDC) |
| **Blocks** | 26458436-26458436 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #107: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc483134f2403dcd837764d0eb1eef929c50fea17` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDT) |
| **Blocks** | 26458433-26458433 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,000 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #108: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6984304cf41b884d84f47453079ce400f033f0b4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$123** (123 USDT) |
| **Blocks** | 26458433-26458433 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $123 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #109: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf5ca27927ffb16bd8c870dcb49750146cce8217c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5** (5 USDC) |
| **Blocks** | 26458431-26458431 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #110: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0563db7e00e78e576b3bb397c3a4d094f3f80f9c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$3,300** (3,300 USDC) |
| **Blocks** | 26458431-26458431 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,300 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #111: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x25ed652355e89d1b7a877359fdde0a8ca4205a19` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4,500** (4,500 USDC) |
| **Blocks** | 26458431-26458431 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,500 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #112: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa5d79f9ae4204c47c7b38edd879b1f17789fc027` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$900** (900 USDC) |
| **Blocks** | 26458426-26458426 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $900 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #113: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0217efb296892022cc5ea0e2d925c89237620bea` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,645** (1,645 USDC) |
| **Blocks** | 26458426-26458426 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,645 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #114: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7eb4c07fea81097f737221118fe823c2a7004235` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4,000** (4,000 DAI) |
| **Blocks** | 26458424-26458424 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,000 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #115: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb645f7bd757751f5c1352690a8e8ebe4a56d7d18` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$8,800** (8,800 USDC) |
| **Blocks** | 26458424-26458424 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $8,800 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #116: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x23878914efe38d27c4d67ab83ed1b93a74d4086a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$995** (995 USDT) |
| **Blocks** | 26458421-26458421 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $995 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #117: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x51cc6be6809c135d65934b94f5105aea922a98f6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$106** (106 USDT) |
| **Blocks** | 26458421-26458421 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $106 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #118: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x73a6584bd6dc010b6ce4c416877ea6aa04a4d804` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$3,204** (3,204 USDT) |
| **Blocks** | 26458419-26458419 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,204 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #119: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbc746fb9250d999bc0132c9eab63cbeee637ecef` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$11** (11 USDC, 0 WBTC) |
| **Blocks** | 26458399-26458419 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $11 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #120: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc8e091023aa3e3a7413fec0d9e75039c65688628` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$7** (7 USDC) |
| **Blocks** | 26458418-26458418 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #121: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x28cef21c87817dbfcb200d3a243b797d24903e81` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$175** (175 USDT) |
| **Blocks** | 26458418-26458418 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $175 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #122: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8d4dbe6dfcd42015e58d8856109f579f27e76a31` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$700** (700 USDC) |
| **Blocks** | 26458418-26458418 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $700 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #123: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5b07a604e3cc9ecb3628e17eab1f3ee0f232020c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDT) |
| **Blocks** | 26458417-26458417 |

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

## Finding #124: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe40f64d9926c5c514a0cba558a7543152925e9ba` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,332** (1,332 USDC) |
| **Blocks** | 26458417-26458417 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,332 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #125: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd809f63cf4314348aa57787d013ca4e585627a07` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,999** (1,999 USDC) |
| **Blocks** | 26458415-26458415 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,999 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #126: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xed87a50635ab6f76d534b710c12f84723d64ada9` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDC) |
| **Blocks** | 26458415-26458415 |

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

## Finding #127: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb51995191d035f5f7e9b1546abca772c8ad76a91` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,150** (1,150 USDC) |
| **Blocks** | 26458413-26458413 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,150 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #128: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xec682d5fe3f2e4fc61b8bbf00389320e9c0d9b55` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$184** (184 USDC) |
| **Blocks** | 26458412-26458412 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $184 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #129: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x021cdfbc8223f3b20a893b71932eaed8b5e8d9d0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5,429** (5,429 USDC) |
| **Blocks** | 26458411-26458411 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,429 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #130: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7ccbcd97b7fcf790d934f913139040f060f5b0b9` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$5,727** (2,727 USDC, 3,000 USDC) |
| **Blocks** | 26458393-26458411 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,727 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #131: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x81aee07f99be78d88881fa6d98feff7555113635` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$460** (460 USDC) |
| **Blocks** | 26458409-26458409 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $460 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #132: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x92c50388db5b5180ba56c67b022d63a19e539e72` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$755** (755 USDT) |
| **Blocks** | 26458409-26458409 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $755 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #133: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb6a01409cfb3ba3d51f02b51cc902e0a4e768dc7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$62** (62 USDT) |
| **Blocks** | 26458409-26458409 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $62 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #134: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9fa97b718c0b6fcfe1e9762a1e2db9092498dde2` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5,000** (5,000 USDT) |
| **Blocks** | 26458409-26458409 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,000 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #135: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x00000000000014aa86c5d3c41765bb24e11bd701` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$57** (20 USDC, 37 USDC) |
| **Blocks** | 26458390-26458407 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $57 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #136: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd815865628a2f0faa45e9cc27a7c2e132a9d1fbc` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$57** (57 USDC) |
| **Blocks** | 26458405-26458405 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $57 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #137: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbef105dfb5b8a95286bb25b02312b86885d7a277` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$226,742** (38 USDC, 226,704 SLAP) |
| **Blocks** | 26458390-26458404 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $38 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #138: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf584617637c2bf5b6a826adf213f7beb9b76b29a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5** (5 USDT) |
| **Blocks** | 26458403-26458403 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #139: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7d7c7922d50836a524d074b76652edce145fa0c8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,598** (1,598 USDC) |
| **Blocks** | 26458402-26458402 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,598 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #140: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x084d5d21e57a339aad0865648470908938725b1f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$189** (189 USDT) |
| **Blocks** | 26458402-26458402 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $189 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #141: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xeb88dc728ae4e13bd622b3cc7bcc854b8ef0c9af` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$165** (165 DAI) |
| **Blocks** | 26458401-26458401 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $165 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #142: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8ad599c3a0ff1de082011efddc58f1908eb6e6d8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$8,998** (8,998 USDC) |
| **Blocks** | 26458401-26458401 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $8,998 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #143: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x847a305740e7101150789f3c377c7e295c17dd7a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDC) |
| **Blocks** | 26458400-26458400 |

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

## Finding #144: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe80ec0cdcf63032b771654b91a2ec0e22d6401af` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,600** (1,600 USDT) |
| **Blocks** | 26458399-26458399 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,600 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #145: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3ada35c2e20744900b829ae6201699a35ac376cc` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDT) |
| **Blocks** | 26458396-26458396 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $100 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #146: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x60594a405d53811d3bc4766596efd80fd545a270` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$362** (362 DAI) |
| **Blocks** | 26458396-26458396 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $362 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #147: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x10e1fe923c5e5483053d601b214778dd30495249` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$67** (67 USDC) |
| **Blocks** | 26458394-26458394 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $67 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #148: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xaddc26a3854feabfd20d6bf658254088d83a425a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$546** (10 WETH, 536 USDT) |
| **Blocks** | 26458388-26458394 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $536 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #149: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6ef3f6b58b01562f09aa0e05fb7b61144b57679d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$56** (56 USDC) |
| **Blocks** | 26458394-26458394 |

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

## Finding #150: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe5151036877a35b6ef82be88d33d8bba0cb54171` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$14** (14 USDT) |
| **Blocks** | 26458391-26458391 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $14 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #151: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2f9e0e8fc0f8ab51ad969bea488e8b09f3e10962` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$305** (305 USDT) |
| **Blocks** | 26458389-26458389 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $305 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #152: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3416cf6c708da44db2624d63ea0aaef7113527c6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,359** (2,359 USDT) |
| **Blocks** | 26458389-26458389 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,359 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #153: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xeb83eab9bc5b955f4e4f7720cd7888c811cdddca` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$99** (99 USDT) |
| **Blocks** | 26458388-26458388 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $99 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #154: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd4229b73705b37559ed827913692ef0723dd107b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$3,000** (3,000 DAI) |
| **Blocks** | 26458388-26458388 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,000 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #155: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5303e2581e81b4d0886fc6c227d6b29d87f153df` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,885** (2,885 USDT) |
| **Blocks** | 26458388-26458388 |

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

## Finding #156: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc2940861b6e11b05a71941a5ef6697a1c95ce98c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$718** (718 USDT) |
| **Blocks** | 26458387-26458387 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $718 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #157: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x47f155b16ef180ae6b240f031f01fbb927dcc605` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDT) |
| **Blocks** | 26458383-26458383 |

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

## Finding #158: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x388b0fe6638d83d88e488f9005a20e50bf9289c3` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$9,575** (9,575 USDC) |
| **Blocks** | 26458383-26458383 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $9,575 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #159: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xc81d54ed36d6600ca8d9cd22c23b82afe9c67229` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458465-26458465 |

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
| Wallet Age | 671 days |
| Total Transactions | 94 |
| Current Balance | 0.006172 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #160: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x4c5213672f972ae8e3d39d7e3e83d47d39e2f739` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458288-26458460 |

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
| Wallet Age | 240 days |
| Total Transactions | 22826 |
| Current Balance | 0.011558 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #161: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa7842153fde380a864726d0e91f14f6ffab7d46c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458310-26458395 |

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
| Wallet Age | 536 days |
| Total Transactions | 26095 |
| Current Balance | 1.131482 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #162: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa883710b6dbf008a1cc25722c54583e35884a209` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458322-26458393 |

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
| Wallet Age | 871 days |
| Total Transactions | 29157 |
| Current Balance | 0.598810 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #163: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xdf61b3accc23b83b57fd3050e42d1dfd360d20c9` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458374-26458374 |

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
| Wallet Age | 11 days |
| Total Transactions | 27 |
| Current Balance | 0.338919 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #164: LOW — Score 55

| | |
|---|---|
| **Sender** | `0xe37ef305844d71d67b75b2c364b70a802fec9e5d` |
| **Target** | EtherFi Liquidity Pool (eETH) (`0x308861a430be4cce55...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26458366-26458366 |

### 💬 What Happened
A wallet was caught interacting with EtherFi Liquidity Pool (eETH). Our engine flagged it at score 55.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**LOW (rule score 55)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 181 days |
| Total Transactions | 777 |
| Current Balance | 206.209543 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 55):
- **lrt_restaking** (+55) — Deposit to EtherFi Liquidity Pool (eETH) — LRT restaking pool

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**164 suspicious findings** detected across 164 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 11 |
| 🟠 HIGH | 61 |
| Wallets flagged | 164 |
| Suspicious value | 0.0000 ETH ($0) + $629,622,430 in stablecoins |
| Blocks scanned | 26458272 — 26458471 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 4 of 25 attempted analyses this run.

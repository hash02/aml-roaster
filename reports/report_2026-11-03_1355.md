# 🔥 AML Roaster Report
**2026-11-03 13:50 UTC** · Ethereum Mainnet · ETH $2,291.52
**Blocks:** 26334473 — 26334672 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26334473 to 26334672 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5ed864e8f37dcb4f79c5172a815d1b3a9147eaab` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **22** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334497-26334669 |

### 💬 What Happened
The wallet sent 22 separate tiny deposits of 0 ETH to a settlement contract. Think of it like dropping 22 identical empty envelopes into a mailbox; you can see the pattern but no cash is actually moving. The total value was zero, so it looks like a test or a glitch, not a real transfer of funds.

### 🔥 The Roast
Got a 70 on structuring (smurfing), 60 on peel_chain_linear (layering), 65 on bridge_hop (cross-chain bridge). 22 identical 0 ETH deposits? That's like a magician making 22 rabbits appear out of a hat, but the hat is empty. The wallet is 79 days old but already sent 55k transactions—like a fast‑food drive‑thru that never actually orders. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual investigation, request source of funds documentation, and monitor subsequent activity for further structuring or layering. Consider placing a temporary hold if additional red flags emerge.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 79 days |
| Total Transactions | 55031 |
| Current Balance | 3.917409 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 22 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 22 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Rule [structuring] triggered with score 70 due to 22 identical 0 ETH deposits, indicating possible smurfing. Rule [peel_chain_linear] triggered with score 60 indicating a peel chain layering pattern. Rule [bridge_hop] triggered with score 65 due to deposit to CoW Protocol GPv2Settlement, a cross‑chain bridge. CRITICAL (rule score 195)

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xb1ca4a18aff443656f407fa8be3533ff27dde911` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334479-26334666 |

### 💬 What Happened
The sender’s wallet sent five identical, zero‑value messages to a smart‑contract that acts like a cross‑border post office. It’s like dropping five empty envelopes into a slot that hides who sent them, then handing them off to a courier that forwards them to another country. No real money moved, but the pattern is suspicious.

### 🔥 The Roast
Score 70 on structuring? That’s just a fancy way of saying the user is trying to hide their tracks by sending five identical zero‑ETH packets—like a magician pulling a rabbit out of a hat, but the rabbit is invisible. The peel_chain_linear score of 60? Think of it as a domino effect, each fall is a tiny, identical drop that keeps the chain going. And a bridge_hop score of 65? That’s the user hopping from one network to another, like a bad tourist using a free shuttle to get from the airport to the hotel. Bottom line: it’s a textbook case of “if you can’t be seen, you’re probably trying to be seen elsewhere.”

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual review, request source‑of‑funds documentation, and monitor subsequent activity for additional layering or conversion into other assets.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 369 days |
| Total Transactions | 21416 |
| Current Balance | 0.656427 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet performed five sequential, identical zero‑ETH deposits (Rule: structuring) indicative of smurfing attempts to obscure the source of funds. The pattern aligns with a peel chain (Rule: peel_chain_linear) where each transaction mimics the previous, forming a layering sequence. Additionally, the deposits were routed to the CoW Protocol GPv2Settlement contract, a cross‑chain bridge (Rule: bridge_hop), further complicating traceability. Given the wallet’s high activity (21,416 txs) and recent activity, these combined patterns warrant heightened scrutiny.

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x664eeb033d68e13d2ad6933a496a62ce9a3060be` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **8** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334541-26334664 |

### 💬 What Happened
The wallet sent eight almost‑identical tiny amounts of ETH (each showing 0.0000, effectively the smallest possible amount) to a smart‑contract address that handles settlement for a decentralized exchange. It's like dropping eight identical envelopes into a slot that hides who sent them, all in one block range. No real money changed hands, but the pattern looks suspiciously like a classic 'smurfing' or structuring attempt.

### 🔥 The Roast
Score 195? That's higher than my gym membership. The engine flagged structuring (70) because eight identical 0.0000 ETH deposits are like a cashier who keeps giving customers the same change in a vending machine. Peel_chain_linear (60) says the deposits were in a straight line, so the wallet is basically playing a game of 'follow the leader' with its own money. Bridge_hop (65) points out the target is a cross‑chain bridge, which is the crypto equivalent of a shady travel agent. Bottom line: this wallet is trying to hide its tracks like a cat that thinks it’s a ninja, but the engine isn’t buying it.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual investigation, review any associated counterparties or downstream addresses, and consider adding the address to a watchlist pending further evidence.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 307 days |
| Total Transactions | 10220 |
| Current Balance | 0.218254 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 8 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 8 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Rule structuring: The sender performed eight identical ETH transfers of 0.0000 each, a textbook example of structuring to avoid detection thresholds. Rule peel_chain_linear: The transfers are sequentially ordered, indicating a peel chain layering pattern. Rule bridge_hop: The destination is CoW Protocol GPv2Settlement, a known cross‑chain bridge, suggesting an attempt to move funds through multiple layers. Evidence: transaction count 8, identical amounts, block range 26334541-26334664, zero token transfers. The composite score of 195 indicates a high suspicion level.

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x38e59dcce64ea3ddece4d98f77e70990fc8f430c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **13** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334480-26334663 |

### 💬 What Happened
The user sent 13 identical tiny amounts of ETH (each 0.0000 ETH) to a smart contract that handles trade settlements. It's like dropping 13 identical coins into a slot machine that hides who sent them. The total value is zero, so the transaction looks like a way to hide the flow of funds.

### 🔥 The Roast
Score 70 on structuring? That's like someone trying to buy a loaf of bread by splitting it into 13 crumbs. The engine caught a peel chain (score 60) — think of it as a chain of identical tiny moves that look like a dance but are really just a smurfing routine. And with a bridge hop score of 65, the funds are hopping from one place to another, like a squirrel that can't decide which tree to stash its nuts in. This pattern is a red flag for potential layering and structuring, and it's not a good look for anyone trying to keep their money hidden.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain, and bridge hop with a composite score of 195 indicates a high likelihood of illicit layering activities.**

Flag the wallet for manual review, trace the source of the 13 deposits, and request transaction history and any associated off-chain identifiers. Consider placing a temporary hold or monitoring for additional suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 22 days |
| Total Transactions | 1473 |
| Current Balance | 0.385910 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 13 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 13 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits characteristics of structuring (Rule: structuring) as 13 identical deposits of 0.0000 ETH were made, indicating an attempt to avoid detection thresholds. The pattern also matches the peel_chain_linear rule, showing a sequence of 13 similar deposits typical of layering. Additionally, the bridge_hop rule is triggered by the transfer to CoW Protocol GPv2Settlement, suggesting cross-chain movement that may obscure origin. The composite score of 195 indicates high risk, warranting further investigation.

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x1b2e668df159c7e06fec46bfc5949d0f7029ec04` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334490-26334659 |

### 💬 What Happened
CRITICAL (rule score 195) It’s like dropping five empty envelopes into a slot that records the drop time but not the sender’s address. The pattern of identical, sequential deposits is suspicious, even though nothing changed hands.

### 🔥 The Roast
You tried to hide your money by sending five zero‑ETH packets, like a magician who says ‘poof!’ and nothing appears. That structuring (Rule: structuring, meaning identical deposits that look like smurfing) got a 70 score. The peel_chain_linear (Rule: peel_chain_linear, like peeling an onion in straight layers) gave 60, and the bridge_hop (Rule: bridge_hop, a cross‑chain bridge that’s basically a fancy tunnel) gave 65. Combined, your composite score of 195 is enough to make regulators say ‘hold on, we need to investigate.’

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 195, exceeding the high‑risk threshold, indicates potential structuring and layering that warrants immediate review.**

Flag the transaction for manual compliance review; investigate the sender’s broader transaction history and source of funds, and consider placing the wallet on a watchlist pending additional evidence.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 199 days |
| Total Transactions | 10360 |
| Current Balance | 0.474404 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender wallet executed five identical zero‑ETH deposits to the CoW Protocol GPv2Settlement contract, triggering the structuring rule (identical amounts), the peel_chain_linear rule (sequential pattern), and the bridge_hop rule (cross‑chain bridge target). These patterns are consistent with layering and smurfing activity. With a composite score of 195, the transaction exceeds the high‑risk threshold and should be flagged for further investigation. The wallet’s history—10360 total transactions, 199 days old, current balance 0.474 ETH, and no inactivity—adds to the risk assessment.

</details>

---

## Finding #6: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5c3593481cba011737e36ded62f1797c9f6afce1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **15** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334487-26334658 |

### 💬 What Happened
This is like someone dropping 15 identical envelopes into a mailbox, each with nothing in them, all going to the same address that acts like a sorting hub for crypto trades. The sender’s wallet has been active for about 7 months and still holds a little ETH, but those 15 zero‑value deposits look suspiciously like a pattern to hide how much money is being moved.

### 🔥 The Roast
Score 195—like getting an A when everyone else got a C. The engine says you’re smurfing (sending many tiny amounts) even though they’re all zero ETH, so it’s a classic “I’m not sending anything, but I’m still hiding the pattern” trick. The peel_chain_linear rule (60) caught your 15‑step chain, because even zero ETH can be a breadcrumb trail. The bridge_hop rule (65) flags the CoW Protocol settlement as a cross‑chain hop, because you’re moving through a bridge even if it’s just a zero‑cash hop. Basically, you’re playing crypto hide‑and‑seek with a zero‑cash budget, and the engine isn’t buying it.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, linear peel chain, and bridge hop activity in a high‑volume wallet with recent activity triggers a high‑risk flag.**

Flag the wallet for manual review, request source of funds and transaction purpose, and monitor for any subsequent high‑value transfers or connections to known mixers.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 210 days |
| Total Transactions | 50861 |
| Current Balance | 1.049490 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 15 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 15 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet performed 15 identical zero‑value deposits to 0x9008d19f58aabd9ed0d60971565aa8510560ab41 (CoW Protocol GPv2Settlement) between blocks 26334487 and 26334658. Rule [structuring] (score 70) identified the textbook smurfing pattern of identical small deposits. Rule [peel_chain_linear] (score 60) detected a sequential peel chain of 15 steps, indicating layering intent. Rule [bridge_hop] (score 65) flagged the cross‑chain bridge activity to the settlement contract. The wallet’s age (210 days), high transaction count (50861), and current balance (1.049490 ETH) provide context for the potential misuse.

</details>

---

## Finding #7: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xb5e5ba15a5aa58df03d91549496d8cd67a15f858` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **9** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334484-26334623 |

### 💬 What Happened
A single wallet sent nine identical zero‑value ETH transfers to the CoW Protocol settlement contract. Think of it as dropping nine identical empty envelopes into a slot—no money changes hands, but the pattern looks like someone is trying to hide the fact that they're moving something around. The wallet has been active for 53 days and has sent thousands of transactions before, so the activity looks like a deliberate attempt to layer and structure moves.

### 🔥 The Roast
Looks like someone tried to do a crypto version of a paper trail—nine zero‑value drops to a settlement contract, like a magician pulling identical rabbits out of a hat. The engine gave a 70 on structuring (splitting moves into tiny bits to dodge eyes), 60 on peel_chain_linear (the chain of identical moves), and 65 on bridge_hop (cross‑chain hop to the CoW Protocol). It’s basically a “copy‑paste” bot that thinks it’s a stealthy ninja, but we see the pattern: 9 identical, 0 ETH, 0 value—classic smurfing. If this was a real money trail, it would be the blockchain’s version of a “buy one, get one free” scam. Good luck hiding that, buddy.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for detailed human review, request source‑of‑funds documentation, and monitor for further cross‑chain activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 53 days |
| Total Transactions | 7002 |
| Current Balance | 0.503559 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 9 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 9 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The subject wallet performed nine consecutive ETH transfers of 0.0000 ETH to the CoW Protocol GPv2Settlement contract (Rule: structuring). This pattern meets the criteria for structuring (identical, minimal amounts) and peel_chain_linear (sequential similar deposits), indicating layering activity (Rule: peel_chain_linear). CRITICAL (rule score 195) CRITICAL (rule score 195)

</details>

---

## Finding #8: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x95480d3f27658e73b2785d30beb0c847d78294c7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334584-26334613 |

### 💬 What Happened
The sender made three tiny, identical ETH transfers to a CoW Protocol settlement address, all of them worth zero dollars in stablecoin value. It’s like dropping three identical envelopes into a mailbox that doesn’t reveal who sent them, making it hard to trace the origin.

### 🔥 The Roast
Looks like this wallet is playing a game of "Smurf the Money"—three deposits of 0.0000 ETH each, because who needs a real number when you can just copy‑paste the same zero? The engine gave it a 70 on structuring (that’s the rule that flags identical deposits as smurfing) and a 60 on peel_chain_linear (layering, because why not keep the pattern going?). On top of that, a 65 on bridge_hop for hopping onto the CoW Protocol settlement, like a bad magician pulling a rabbit out of a hat that’s actually a bridge. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Initiate a full transaction trail review, request additional KYC information from the sender, and monitor for related activity across the wallet’s transaction history.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 725 days |
| Total Transactions | 305083 |
| Current Balance | 4.797079 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 195) Specifically, the engine identified a structuring pattern (Rule: structuring) with a score of 70 due to three identical 0.0000 ETH deposits, a peel chain linear pattern (Rule: peel_chain_linear) with a score of 60 indicating layering, and a bridge hop (Rule: bridge_hop) with a score of 65 reflecting cross‑chain activity via the CoW Protocol GPv2Settlement. These patterns warrant further investigation per AML policy.

</details>

---

## Finding #9: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xa60ded4c899e7560dc4ca56b57fbab25c90addeb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334515-26334565 |

### 💬 What Happened
A wallet sent five tiny, identical zero‑value packets to a smart contract that handles trade settlements. None of those packets actually carried any money, but the pattern looks like someone is trying to hide how they moved a larger amount in separate steps. Think of it as dropping a series of empty envelopes into a mailbox to disguise the fact that you’re sending a real letter elsewhere.

### 🔥 The Roast
Five identical 0.0000 ETH deposits? Because why send one chunk when you can send five empty packets and pretend it’s a puzzle? The engine gave it a composite score of 195, basically the crypto world’s 10/10 on the ‘I’m hiding something’ scale. The "structuring" rule (breaking up a transaction into smaller pieces to avoid detection) scored 70, "peel_chain_linear" (a chain of similar moves that look like a peeling onion) hit 60, and "bridge_hop" (moving money across chains like a hopscotch champion) got 65. CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the transaction for manual review by AML analysts. Verify the source of the underlying assets and assess whether the sender’s activity aligns with known legitimate usage of the CoW Protocol.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 462 days |
| Total Transactions | 47369 |
| Current Balance | 0.018757 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The subject wallet performed five identical zero‑value deposits (0.0000 ETH each) to the CoW Protocol GPv2Settlement contract, generating a composite AML score of 195. Rule evidence includes a structuring score of 70 (indicative of smurfing), a peel_chain_linear score of 60 (suggesting a peel‑chain layering pattern), and a bridge_hop score of 65 (cross‑chain bridge activity). CRITICAL (rule score 195) CRITICAL (rule score 195)

</details>

---

## Finding #10: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x2e69797d37e888d62974a1ffa20816a5f55f898d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **12** token transfers totaling **$194,698** (100 USDC, 5,000 CRV, 5,000 CRV, 5,000 CRV, 2,459 USDT) |
| **Blocks** | 26334479-26334669 |

### 💬 What Happened
A wallet sent 12 separate stablecoin payments totalling about $195,000 to a settlement address used by the CoW Protocol. The transfers included a mix of USDC and USDT, with several round‑number amounts that look like they were intentionally layered. Basically, it’s like someone tried to hide their cash flow by moving it through a series of small, identical envelopes that all end up at the same post office.

### 🔥 The Roast
Looks like this guy thought the CoW Protocol was a magic trick, but it turned out to be just a fancy vending machine that spits out a bunch of identical coins. He sent 7 stablecoin transfers, all round numbers, so if you’re looking for the real price of the pizza, you’re out of luck. The engine flagged it as stablecoin_mixing (meaning the wallet is using a pattern that resembles mixing money, like putting different coins in a blender). The score of 110 says the system thinks it’s a pretty good mix, and it’s probably not his first time doing the salsa dance with stablecoins.

### 🎯 Verdict & Next Steps
**HIGH — the pattern matches the stablecoin_mixing rule with a composite score of 110 and multiple round‑number transfers indicative of layering.**

HIGH (rule score 110) Consider initiating a follow‑up investigation to confirm the legitimacy of the funds.

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
- **stablecoin_mixing** (+110) — 7 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $169,698 total (USDT, USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
The transaction set triggered the stablecoin_mixing rule with a composite score of 110, indicating high suspicion. Evidence includes 12 separate transfers to a CoW Protocol GPv2Settlement address, 7 of which are stablecoin transfers totaling $169,698 (USDT, USDC). The pattern shows denomination layering with multiple round-number amounts (e.g., 5,000 and 10,000 equivalents), a single unique sender, and no obvious source of funds. This aligns with Rule SR-03: Stablecoin Mixing Detection.

</details>

---

## Finding #11: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x5018be882dcce5e3f2f3b0913ae2096b9b3fb61f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$437,753** (39,792 USDC, 198,972 USDC, 198,989 USDC) |
| **Blocks** | 26334579-26334669 |

### 💬 What Happened
A single wallet sent three big chunks of USDC—like a person dropping three giant envelopes into a bank box—into the CoW Protocol settlement contract. The total is about $437,753, all in one go, and the sender hasn't moved anything else before or after.

### 🔥 The Roast
HIGH (rule score 110) He sent three separate envelopes, each bigger than a house, but all ending up in the same mysterious vault. Looks like he was trying to hide his money in plain sight—just a little less ‘tornado cash’ and a lot more ‘who’s that guy?’

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag the sender’s address for detailed human review, investigate the origin of the funds, and consider monitoring any related addresses for further suspicious activity.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $437,753 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction sequence triggers the stablecoin_mixing rule (score: 110) due to three USDC transfers totaling $437,753 to the CoW Protocol GPv2Settlement contract. The sender’s wallet shows no prior activity or balance, indicating a possible attempt to obscure the source of funds. HIGH (rule score 110)

</details>

---

## Finding #12: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x440888714a6afed60ff44e9975a96e6a36f7fac4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **12** token transfers totaling **$17,827** (1,325 USDC, 1,322 USDC, 1,323 USDC, 1,977 USDC, 1,327 USDC) |
| **Blocks** | 26334537-26334666 |

### 💬 What Happened
The wallet sent 12 separate USDC (a digital dollar) payments totalling $17,827 to a smart contract that acts like a dropbox for settling trades. Each payment was a chunk of the total, kind of like sending 12 envelopes to a courier that scrambles who sent them. The recipient is a protocol that bundles these payments together, making it hard to track the original source.

### 🔥 The Roast
HIGH (rule score 110) The engine flagged it with a stablecoin_mixing score of 110 (meaning the pattern matches known mixing behavior). 12 tiny USDC transfers instead of one big one? That's like sending 12 pizza slices instead of one whole pizza to confuse the delivery guy. If you thought this was a secret club, the rule says 'no, it's just a fancy way to break up the trail'.

### 🎯 Verdict & Next Steps
**HIGH — 12 stablecoin transfers totalling $17,827 to a settlement protocol indicate potential layering and mixing activity.**

Flag the transaction for manual AML review and investigate the sender and receiver addresses for additional related activity.

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
- **stablecoin_mixing** (+110) — 12 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $17,827 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction record shows 12 distinct USDC transfers from address 0x440888714a6afed60ff44e9975a96e6a36f7fac4 to CoW Protocol GPv2Settlement (intent settlement) totaling $17,827. This activity aligns with rule stablecoin_mixing, which identifies potential layering or mixing of stablecoin funds. Evidence includes the multiple small transfers (USDC amounts ranging from ~$1,322 to ~$1,980) and the single unique sender. The pattern raises suspicion of obfuscation of source or destination funds.

</details>

---

## Finding #13: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x67336cec42645f55059eff241cb02ea5cc52ff86` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **12** token transfers totaling **$352,612** (1,259 SYRUP, 512 ONDO, 116 PENDLE, 525 USDC, 5,154 USDT) |
| **Blocks** | 26334530-26334662 |

### 💬 What Happened
A single wallet sent almost $353,000 in stablecoins (digital dollars that keep the same value) to a smart contract that acts like a trade‑settlement box. The transfers were split into 12 smaller packets and all collected in one place that hides who originally owned them. It's like someone sending a bunch of envelopes to a drop‑box that then forwards them to a secret address, making it hard to trace the source.

### 🔥 The Roast
HIGH (rule score 110) The total hit $350k, which is a big enough party that even the AML engine raised its eyebrows. And the receiver was CoW Protocol GPv2Settlement (think of it as a fancy Swiss bank that settles trades across many exchanges in one go). If you think this is a normal day at the office, you might want to check the coffee machine first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag the transaction for manual review by the AML compliance team. HIGH (rule score 110)

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
- **stablecoin_mixing** (+110) — 9 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $350,726 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The AML engine flagged this activity under rule stablecoin_mixing with a composite score of 110. Evidence includes nine stablecoin transfers totaling $350,726 to the CoW Protocol GPv2Settlement contract from a single sender. The pattern is consistent with layering techniques used to obscure the provenance of funds. HIGH (rule score 110)

</details>

---

## Finding #14: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x1644d2477f809cc2c71bccfd6dc9497e3f83210d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **14** token transfers totaling **$3,189,328,708** (3,189,115,015 AYYLIEN, 5,147 USDC, 45,044 USDC, 26,764 USDT, 30,690 USDC) |
| **Blocks** | 26334530-26334650 |

### 💬 What Happened
A mysterious wallet sent more than $3.1 billion in stablecoins to a smart‑contract address that acts like a cashier’s desk for a DeFi exchange. The sender broke the big transfer into 14 smaller payments, as if you were dropping a huge pizza in 14 tiny boxes to hide who ordered it. The moves look like an attempt to make the money trail look messy and hard to follow.

### 🔥 The Roast
So this guy thought he could hide a $3‑billion pizza order in 14 tiny boxes. HIGH (rule score 110) The CoW Protocol GPv2Settlement contract is basically a high‑speed swap shop, not a bank, but the engine still treats it like a suspicious laundromat. If you’re wondering why this matters, 110 is like getting a red flag from the IRS after a quick tax audit. Bottom line: this wallet is playing hide‑and‑seek with the block explorer.

### 🎯 Verdict & Next Steps
**HIGH, because the large volume and multiple small transfers to a settlement contract suggest a high risk of source obfuscation.**

Flag the wallet for manual review, request source verification and KYC data from the sender, and monitor for related downstream transactions.

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
- **stablecoin_mixing** (+110) — 10 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $213,692 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The account 0x1644d2477f809cc2c71bccfd6dc9497e3f83210d executed 14 stablecoin transfers totaling $3,189,328,708 to the CoW Protocol GPv2Settlement contract (Rule: stablecoin_mixing). The pattern of multiple small transfers to a single settlement contract indicates potential mixing activity, raising concerns about source transparency (Rule: Source_Transparency_Concerns). The transaction volume exceeds typical market activity for a single wallet and aligns with known high‑risk patterns (Rule: High_Value_Transfers). HIGH (rule score 110)

</details>

---

## Finding #15: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x000000000004444c5dc75cb358380d2e3de08a90` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **12** token transfers totaling **$243,781** (144,901 SNAP, 42,464 SNAP, 1,367 SP, 17,762 USDT, 592 EURC) |
| **Blocks** | 26334497-26334650 |

### 💬 What Happened
A single wallet sent about $244,000 worth of stablecoins to a settlement smart contract on the CoW Protocol, but it broke the money into 12 smaller chunks. It's like someone splitting a huge pizza into many slices before putting them in different boxes to make it harder to see where the pizza originally came from.

### 🔥 The Roast
This wallet got a whopping 110 on the stablecoin_mixing score (meaning it’s acting like a crypto‑mixing service, shuffling coins to hide their origin). 12 tiny transfers, 6 of them stablecoins, all heading to a settlement contract that’s basically a digital escrow. The pattern is so obvious it could give a detective a headache – it’s like watching a magician keep moving the same coin around the table in different spots. If you’re hoping to keep this money clean, you’re basically doing the same thing a thief does: hide the trail and hope nobody notices the sleight of hand.

### 🎯 Verdict & Next Steps
**HIGH, due to the structured splitting of a large stablecoin sum across multiple transfers into a settlement contract, indicating potential layering.**

Flag the sender for manual AML review, investigate the source of the stablecoins, and monitor future activity for continued mixing patterns.

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
- **stablecoin_mixing** (+110) — 6 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $54,019 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule: stablecoin_mixing (Rule 3.1) – The sender performed 12 transfers totaling $243,781 in stablecoins to the CoW Protocol GPv2Settlement contract. Six of these transfers involved USDT or USDC, indicating a structured attempt to obfuscate the source of funds. The transaction pattern, combined with the large aggregate value, triggers a high‑risk flag for potential layering activity.

</details>

---

## Finding #16: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x064a804e338083693b8efb4a7f440de608a72a3a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$1,498,632** (499,964 USDG, 998,668 USDC) |
| **Blocks** | 26334500-26334641 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $998,668 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #17: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x82d47ff615d05b7fbafb4fff67bd8aef235b68bb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$500,000** (500,000 USDC) |
| **Blocks** | 26334641-26334641 |

### 💬 What Happened
A single transfer of $500,000 worth of USDC (a stablecoin that behaves like digital cash) was sent to the CoW Protocol GPv2Settlement address. It's like sending a giant envelope of money through a post office that doesn't keep a record of who mailed it. The transaction happened in one block, with no other moves from the sender.

### 🔥 The Roast
Looks like someone decided to play the "Where's Waldo?" game with $500k in USDC. They slid the coins through the CoW Protocol GPv2Settlement (a fancy name for a decentralized exchange settlement layer, basically a place where trades are finalized) like a magician pulling a rabbit out of a hat. The AML engine gave it a 110, which is like the red flag on a traffic light: stop and investigate. HIGH (rule score 110) Either way, it's a big move that deserves a closer look.

### 🎯 Verdict & Next Steps
**HIGH — the transaction triggers the stablecoin_mixing rule with a composite score of 110, indicating a high likelihood of source obfuscation.**

Open a SAR and request additional source-of-funds documentation from the sender. Consider placing a temporary hold on the wallet until further information is verified.

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
The transaction involves a single stablecoin (USDC) transfer of $500,000 to the CoW Protocol GPv2Settlement address. HIGH (rule score 110) The sender’s wallet has no publicly available activity history, and no balance in ETH, raising additional concerns about source transparency. This pattern meets the threshold for a suspicious activity report and requires further investigation per AML compliance guidelines.

</details>

---

## Finding #18: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x52aa899454998be5b000ad077a46bbe360f4e497` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **8** token transfers totaling **$1,569,192** (2,795 sUSDai, 1,300,021 USDC, 81,672 USDC, 8,815 USDC, 48 wstETH) |
| **Blocks** | 26334497-26334640 |

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
- **stablecoin_mixing** (+110) — 5 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,566,349 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #19: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x36dcdcef3f7b57ec83b830b75761fd497e4d8edc` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$37,758** (37,115 USDC, 0 WBTC, 0 WETH, 641 USDC, 1 XAUt) |
| **Blocks** | 26334478-26334634 |

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $37,757 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #20: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x0efccbb9e2c09ea29551879bd9da32362b32fc89` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$37,167** (37,167 USDT) |
| **Blocks** | 26334634-26334634 |

### 💬 What Happened
A wallet sent about $37,000 worth of a stablecoin (USDT) to a smart contract that handles trades on a decentralized exchange. It's like dropping a package into a dropbox that automatically shuffles it before sending it to the next person, hiding who actually sent the money.

### 🔥 The Roast
HIGH (rule score 110) 110 points? That’s like getting a red flag on a radar for a speedster. The wallet is practically a ghost—no balance, no history, like a person who only shows up to pay rent and then vanishes. HIGH (rule score 110) 0x0efccbb9e2c09ea29551879bd9da32362b32fc89 has all the right moves to keep regulators on their toes.

### 🎯 Verdict & Next Steps
**HIGH — The transaction triggered the stablecoin_mixing rule with a composite score of 110, indicating suspicious mixing activity that requires further investigation.**

Flag the transaction for manual review by the compliance team and request additional context on the sender’s intent, including any linked wallets or prior activity. Consider placing a temporary hold on related funds if the investigation cannot be completed promptly.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $37,167 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a single stablecoin (USDT) transfer of $37,167 from address 0x0efccbb9e2c09ea29551879bd9da32362b32fc89 to CoW Protocol GPv2Settlement (intent settlement) address 0x9008d19f58aabd9ed0d60971565aa8510560ab41. According to rule stablecoin_mixing, this pattern indicates potential mixing activity, as the sender’s funds are routed through a protocol that facilitates token swaps and could obscure origin. The composite score of 110 exceeds the threshold for high-risk monitoring. HIGH (rule score 110)

</details>

---

## Finding #21: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x0cef320d0c5793ade37964e2661a033771e53cd5` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **12** token transfers totaling **$36,300,078** (9,737 TILT, 3,431 USDS, 2,034 USDC, 200 USDC, 356 USDT) |
| **Blocks** | 26334484-26334621 |

### 💬 What Happened
A single crypto wallet sent a huge pile of stablecoins—about $36 million worth—to a decentralized trading protocol, but the money was split into many tiny packets before hitting the market, like dropping a package into a slot that hides who sent it.

### 🔥 The Roast
So this wallet tried to play hide‑and‑seek with $36 million, sending a few dozen tiny coins to CoW Protocol like it was a crypto version of a paper‑clip scavenger hunt. The biggest single transfer was 31,851,979 USDC, which is a lot of change for a vending machine that only sells Bitcoin. The stablecoin_mixing rule gave it a 110, which is basically the same as a traffic light that says ‘red’ and ‘stop’. HIGH (rule score 110)

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag the wallet for manual review by compliance, focusing on the 12 stablecoin transfers and their settlement to CoW Protocol. Cross‑check the sender’s source of funds and any downstream recipients for further red flags.

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
- **stablecoin_mixing** (+110) — 5 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $15,181 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction record shows 12 stablecoin movements totaling $36,300,078, with 5 individual transfers (USDT, USDC) totalling $15,181 to the CoW Protocol GPv2Settlement contract (Rule: stablecoin_mixing). HIGH (rule score 110) The composite score of 110 triggers a high‑risk flag under the stablecoin_mixing rule, indicating potential layering of funds. HIGH (rule score 110)

</details>

---

## Finding #22: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x51c72848c68a965f66fa7a88855f9f7784502a7f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **23** token transfers totaling **$3,011,010** (5,000 CRV, 1,032 LIT, 0 PAXG, 5,000 CRV, 0 PAXG) |
| **Blocks** | 26334487-26334618 |

### 💬 What Happened
A single wallet sent a total of $3,011,010 worth of stablecoins to a smart contract that handles token swaps, but the sender broke the money into 23 tiny payments. It’s like a person dropping a huge package into a slot that hides who actually paid for it, and then sending many small envelopes to make it look like several people were involved. The transfers were all from the same address, so the system flags it as a potential mixing activity.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their crypto. They sent $3,011,010 worth of stablecoins in 23 tiny packages to a swap contract, hoping the smart contract would act like a secret Santa and hide the source. HIGH (rule score 110) They probably thought the contract would erase their tracks, but the engine says otherwise. HIGH (rule score 110)

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag the transaction for manual compliance review and request transaction origin details. Cross‑reference with AML watchlists and consider additional due‑diligence such as KYC if available.

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
- **stablecoin_mixing** (+110) — 11 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,990,841 total (USDT, USDC, DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The account 0x51c72848c68a965f66fa7a88855f9f7784502a7f performed 23 stablecoin transfers totaling $3,011,010 to the CoW Protocol GPv2Settlement contract (intent settlement) within blocks 26334487‑26334618. HIGH (rule score 110) HIGH (rule score 110) HIGH (rule score 110)

</details>

---

## Finding #23: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x8b2833425d751c1fbfb5c6d43d209ff9b366439e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$79,380** (1 WETH, 79,379 USDT) |
| **Blocks** | 26334584-26334613 |

### 💬 What Happened
A user sent a large amount of USDT, a digital dollar, to a smart contract that swaps tokens. The transfer also included a tiny amount of wrapped Ether (WETH), a token that represents ETH inside the Ethereum network. Think of it as sending a big envelope of dollars into a box that can change them into other currencies, but the box hides where the money originally came from.

### 🔥 The Roast
Scored a whopping 110 on stablecoin_mixing (meaning this looks like a classic attempt to hide the trail by moving USDT through a swap contract). The sender’s balance is zero ETH, like a person with no cash on hand but still trying to buy a fancy car. HIGH (rule score 110) 0.5764 WETH is just a sprinkle of ETH, like a pinch of salt in a giant pot of soup. If you’re looking for a clean transaction, this is the opposite of it.

### 🎯 Verdict & Next Steps
**HIGH — the composite score of 110 under the stablecoin_mixing rule signals a high probability of suspicious stablecoin mixing activity, warranting immediate human review.**

Flag the transaction for manual review by compliance staff. Investigate the sender’s prior activity, assess potential link to known mixers, and consider a temporary hold pending further analysis.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $79,379 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Transaction 0x8b2833425d751c1fbfb5c6d43d209ff9b366439e to 0x9008d19f58aabd9ed0d60971565aa8510560ab41 involves two token transfers: 0.5764 WETH and 79379.3272 USDT, totaling $79,380. The transfer occurs within blocks 26334584-26334613 and is recorded as a single intent settlement on the CoW Protocol GPv2Settlement contract. The AML engine assigned a composite score of 110 under the rule stablecoin_mixing, indicating a high likelihood of stablecoin mixing activity. HIGH (rule score 110)

</details>

---

## Finding #24: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xbc41acbaf1c69803eaf8e5f6b14be0f466e6b0fe` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **7** token transfers totaling **$19,149** (0 WETH, 10,014 USDT, 6 WETH, 4,912 USDC, 0 WETH) |
| **Blocks** | 26334484-26334606 |

### 💬 What Happened
A wallet sent seven separate chunks of stablecoin to a smart contract that settles trades. Think of it like dropping a bunch of envelopes into a mailbox that immediately reshuffles them, so you can’t tell who originally put them in. The total amount was about $19,149, split into tiny pieces and a few big ones, all ending up in the same settlement contract.

### 🔥 The Roast
So this address tried to play hide-and-seek with its money, sending 3 separate stablecoin batches to the CoW Protocol GPv2Settlement (that’s the smart contract that just swaps tokens for you). HIGH (rule score 110) Basically, it’s like someone tried to mix a cocktail of cash and then pour it into a vending machine that doesn’t remember who bought the drink. The fact that the wallet’s balance is zero ETH and we don’t know its age just adds to the mystery, like a ghost in the machine.

### 🎯 Verdict & Next Steps
**HIGH — the transaction pattern matches the stablecoin_mixing rule with a composite score of 110 indicating significant risk of anonymized transfer.**

Flag the transaction for manual review, investigate the source of the stablecoins, and monitor the wallet for additional related activity.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $19,143 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a high-risk pattern under the stablecoin_mixing rule (score 110). Evidence includes three stablecoin transfers totaling $19,143 to the CoW Protocol GPv2Settlement (intent settlement) from a single unique sender, with individual amounts of 10,014.0526 USDT, 4,912.2711 USDC, and 6.2373 WETH. The sender’s wallet shows no recent activity and an unknown age, raising concerns about potential layering and obfuscation of funds.

</details>

---

## Finding #25: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x6d59c8564ca00abefa1970c49d68c0b7bc23f8ed` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$10,001** (10,001 USDC) |
| **Blocks** | 26334603-26334603 |

### 💬 What Happened
A wallet sent just over $10,000 worth of USDC (a stablecoin that’s like a digital version of the U.S. dollar) to a smart‑contract address that’s part of the CoW Protocol, which is used to settle trades. Think of it as dropping a $10,000 bill into a slot that hides who you’re sending it to and why. The transaction happened in a single block and there’s no other activity from that wallet that we can see.

### 🔥 The Roast
So we’ve got a one‑liner: 10,001 USDC to a CoW Protocol settlement. That’s like sending a secret pizza order to a delivery person who never says your name. The AML engine gave it a 110 on stablecoin_mixing (meaning the system flagged it as a classic “mix‑and‑melt” pattern) and the engine thinks this is a potential red flag. If you’re looking for drama, the wallet has zero ETH balance and we have no idea how old it is – it’s like a mystery box with no receipt. HIGH (rule score 110)

### 🎯 Verdict & Next Steps
**HIGH — the transaction matches a high‑risk stablecoin mixing pattern with a single large transfer and no supporting wallet activity.**

Flag the transaction for manual review; investigate the source of funds for the sender and assess whether additional monitoring or reporting is required.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $10,001 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction from address 0x6d59c8564ca00abefa1970c49d68c0b7bc23f8ed to address 0x9008d19f58aabd9ed0d60971565aa8510560ab41 involved a single stablecoin transfer of 10,001 USDC, executed in block 26334603. HIGH (rule score 110) The lack of additional wallet activity and the high value transfer further support the pattern risk. HIGH (rule score 110)

</details>

---

## Finding #26: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x732deffe1c555c22303c5e9709c3a3aa293351b4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$14,381** (14,381 USDT) |
| **Blocks** | 26334602-26334602 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $14,381 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xe1baeb65617cad39d23d5d80c50ae3d734ba6fdc` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$15,488** (7,739 USDC, 7,749 USDT) |
| **Blocks** | 26334589-26334598 |

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $15,488 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xf6e72db5454dd049d0788e411b06cfaf16853042` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$3,715,642** (750 DAI, 1,809,812 DAI, 610,872 DAI, 596,198 DAI, 698,010 DAI) |
| **Blocks** | 26334580-26334587 |

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
- **stablecoin_mixing** (+110) — 5 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,715,642 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xc9d748e601d9984a43da0b80e5b91dc28d31d9fb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$62,417** (62,417 USDT) |
| **Blocks** | 26334584-26334584 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $62,417 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xe3d41d19564922c9952f692c5dd0563030f5f2ef` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$277,682** (277,682 USDT) |
| **Blocks** | 26334584-26334584 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $277,682 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xd42c6931f2b77afbec84fc43c38e8fbe493e355b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$441,233** (441,233 USDT) |
| **Blocks** | 26334584-26334584 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $441,233 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x36cd75f8d0dcb4574013568f7a560ee03a2fd195` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$209,000** (10,000 USDC, 199,000 fxUSD) |
| **Blocks** | 26334579-26334584 |

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

## Finding #33: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xc4d50263c1e89b65b63c830ff93fadc957064fa4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$81,769** (78,412 USDC, 2,119 USDC, 1,238 USDT) |
| **Blocks** | 26334566-26334583 |

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $81,769 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x4dece678ceceb27446b35c672dc7d61f30bad69e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$24,974** (24,974 USDC) |
| **Blocks** | 26334545-26334545 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $24,974 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xd1dd6d99c5fb5d31ff52eacce5046c7158859e85` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000,000** (1,000,000 USDT) |
| **Blocks** | 26334500-26334500 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,000,000 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x390f3595bca2df7d23783dfd126427cceb997bf4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$22,275** (22,275 USDT) |
| **Blocks** | 26334498-26334498 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $22,275 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x949e734f9e45637942340cb1f20924797ab1dccc` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$125,985** (125,985 USDC) |
| **Blocks** | 26334497-26334497 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $125,985 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x40c5a066175440cf577b80431d0ac8936212caa9` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$95,000** (95,000 USDT) |
| **Blocks** | 26334479-26334479 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $95,000 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbee3211ab312a8d065c4fef0247448e17a8da000` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **8** token transfers totaling **$3,855** (200 USDT, 542 WOO, 1,001 USDT, 999 USDC, 15 USDT) |
| **Blocks** | 26334530-26334669 |

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
- **stablecoin_mixing** (+80) — 6 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,313 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc42fbc8285d2edead6e9092e7240cbc35fba584d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$200** (200 USDC) |
| **Blocks** | 26334669-26334669 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $200 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9b57e03b4f45a27ef908935eebcde061e0c928c8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$400** (200 USDC, 200 USDC) |
| **Blocks** | 26334658-26334662 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $400 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7a50a89550c4b142d1df57ec47b9cb3386d852da` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$1,374,196** (17 USDT, 0 WETH, 1,366,861 PEPE, 0 WETH, 7,317 XPR) |
| **Blocks** | 26334490-26334659 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $17 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8f10b468b06c6fd214b65f87778827f7d113f996` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **8** token transfers totaling **$13,676** (200 USDC, 9 WETH, 0 WETH, 37 KAG, 7,741 USDC) |
| **Blocks** | 26334537-26334659 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $8,492 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6d8f4021637c0754fb19368f427f13d1ce369dc3` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$229** (229 USDT) |
| **Blocks** | 26334656-26334656 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $229 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe0554a476a092703abdb3ef35c80e0d76d32939f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$9,561** (0 WETH, 3,000 USDC, 502 USDC, 5,053 USDC, 1,007 USDC) |
| **Blocks** | 26334515-26334650 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $9,561 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf51a6ced17c2286e37dad1599a89d9ea23060022` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$500** (500 USDC) |
| **Blocks** | 26334650-26334650 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $500 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #47: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x37305b1cd40574e4c5ce33f8e8306be057fd7341` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$1,094** (204 USDC, 890 USDC) |
| **Blocks** | 26334515-26334642 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,094 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xcf9c5eed4ea71277c13a46c4b0e13dcd2164a5b2` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$204** (204 DAI) |
| **Blocks** | 26334642-26334642 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $204 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd83b87dce3ca0b7019493f6f29d6cb2f5d486b11` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$26** (26 USDC) |
| **Blocks** | 26334642-26334642 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $26 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x51f4de6a9d2d1dcec42ef72460d02fe276058f75` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$3,135** (3,135 USDT) |
| **Blocks** | 26334640-26334640 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,135 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #51: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3416cf6c708da44db2624d63ea0aaef7113527c6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$700** (700 USDT) |
| **Blocks** | 26334635-26334635 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $700 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #52: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xae02e59549594a63db0d5d281f2c79f4b417aa65` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$701** (701 USDC) |
| **Blocks** | 26334635-26334635 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $701 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #53: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x66581d83a0f5725bc6c537f554332028d7bec23a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDC) |
| **Blocks** | 26334628-26334628 |

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

## Finding #54: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x57ec49e27fa6c4f8986919f8422ea861fd32114d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDC) |
| **Blocks** | 26334626-26334626 |

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

## Finding #55: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf0fbe3039198627d5e37233f05db1df657a67489` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDT) |
| **Blocks** | 26334622-26334622 |

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

## Finding #56: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd2a342008f8954d2488767db8fa244a6886a1193` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$3,341** (3,341 USDC) |
| **Blocks** | 26334614-26334614 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,341 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #57: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbedebcbf28bfe6d0013b54dacf311389c70590b5` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDC) |
| **Blocks** | 26334607-26334607 |

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

## Finding #58: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7bb6f683d6defd7d82c6f4198fed7073160ca848` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$492** (0 USDC, 492 USDC, 0 WETH) |
| **Blocks** | 26334591-26334606 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $492 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #59: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd37a59b4740a28ab97d79ea0bfc5b74afaa25f8f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$17** (17 USDT) |
| **Blocks** | 26334604-26334604 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $17 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #60: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xde87718fd060c137853ee01f957199edd4872b52` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$9,999** (9,999 USDC) |
| **Blocks** | 26334598-26334598 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $9,999 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #61: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1f77528c1a66ba2dcbdeaf6cf471323333e91c9b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$664** (664 USDC) |
| **Blocks** | 26334596-26334596 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $664 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #62: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x177460bb5b0dad2a1810c678138d40395813b85c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$90** (90 USDC) |
| **Blocks** | 26334596-26334596 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $90 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #63: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9add4030f682fc0de069aab11ed1e0a9c81e0e0c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5** (5 USDC) |
| **Blocks** | 26334595-26334595 |

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

## Finding #64: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x585d44727129b9c69791b10238ca605932938b4f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$2,029** (0 WETH, 2,029 USDT) |
| **Blocks** | 26334584-26334594 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,029 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #65: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x51840edc34be8f0a391cbb180a213facf22ccd74` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4** (4 USDT) |
| **Blocks** | 26334594-26334594 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #66: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x93bf01ce743579f928d30d05695824886bd5f37a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$751** (751 USDC) |
| **Blocks** | 26334587-26334587 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $751 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #67: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4f493b7de8aac7d55f71853688b1f7c8f0243c85` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,026** (2,026 USDC) |
| **Blocks** | 26334584-26334584 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,026 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #68: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2a356443fee07703266066c6bb1b11b82d8246ad` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$875** (875 USDC) |
| **Blocks** | 26334582-26334582 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $875 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #69: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x30b66394b12d79f85e159eca485daa0c43e49750` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5,212** (5,212 DAI) |
| **Blocks** | 26334579-26334579 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,212 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #70: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7592b2cccb62c02f0977dd3ad51137888c272bc1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5,459** (5,459 DAI) |
| **Blocks** | 26334579-26334579 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,459 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #71: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xdda2ad366ca14d586d5e4429839f257132729e99` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,236** (1,236 USDC) |
| **Blocks** | 26334566-26334566 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,236 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #72: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xdc382cdf2a25790f535a518ec26958c227e9dcf2` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$760** (260 USDC, 500 USDC) |
| **Blocks** | 26334535-26334565 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $760 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #73: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb9f71287b1c9cc08d351c8f107201e4064f78ac5` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$9,363** (9,363 USDC) |
| **Blocks** | 26334563-26334563 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $9,363 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #74: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1402f3e3565d661d0c53e533ba66b2c318c13040` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$31,781,723** (31,780,573 REST, 150 USDC, 1,000 USDC) |
| **Blocks** | 26334526-26334563 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,150 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #75: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xcd9f6a970ec2a2f61a9d89d3937ffdb15e24b97c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4** (4 USDT) |
| **Blocks** | 26334562-26334562 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #76: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x93314425248b61295b8d9c45a56cf8114c27c4aa` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDT) |
| **Blocks** | 26334559-26334559 |

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

## Finding #77: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6dd9a81ce10b092486979f957328828e3fe9e057` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$33** (33 USDT) |
| **Blocks** | 26334556-26334556 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $33 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #78: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd51a44d3fae010294c616388b506acda1bfaae46` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,726** (1,726 USDT) |
| **Blocks** | 26334555-26334555 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,726 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #79: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe7ddc11fbef0ecff7658f2b92d4885cde7da7fa0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$90** (90 USDT) |
| **Blocks** | 26334539-26334539 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $90 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #80: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7dadb53b972fb9f30b4a4918d1a226453e0f33ed` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$550** (550 USDC) |
| **Blocks** | 26334537-26334537 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $550 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #81: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbfab494d6311432ed86ee88779acd7b4838920b7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$11** (11 USDT) |
| **Blocks** | 26334534-26334534 |

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

## Finding #82: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x435e2b2b07dd14eca1c560e4a6efe18cfeb1d6da` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDC) |
| **Blocks** | 26334531-26334531 |

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

## Finding #83: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x14d7aab5b4bca6a02e52ac22520b033bf35f4091` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$249** (149 USDT, 100 USDT) |
| **Blocks** | 26334515-26334523 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $249 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #84: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x70d4696abc39c3cc5dd90659b5ea8a4ce7919ae9` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$200** (200 USDT) |
| **Blocks** | 26334518-26334518 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $200 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #85: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x10596455cb369a38165b8562fd90bc2360f19b9b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$890** (890 DAI) |
| **Blocks** | 26334515-26334515 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $890 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #86: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x05ca1e9dd929337230faffbec471c78318172620` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$20** (20 USDC) |
| **Blocks** | 26334512-26334512 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $20 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #87: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x04571c32a4e1c5f39bc3a238cb95b215058c432c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$500** (500 USDC) |
| **Blocks** | 26334506-26334506 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $500 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #88: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x715e60106943eab8133540ffd78ddb0414d8694a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$4,000** (4,000 USDC) |
| **Blocks** | 26334506-26334506 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #89: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x11b815efb8f581194ae79006d24e0d814b7697f6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$109** (109 USDT) |
| **Blocks** | 26334502-26334502 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $109 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #90: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4e62e4916be5d847af5d2c3079992ccae78be53a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDT) |
| **Blocks** | 26334493-26334493 |

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

## Finding #91: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5a69e335ad608a067060bea4705387be33fe7552` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$14** (14 USDC) |
| **Blocks** | 26334490-26334490 |

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

## Finding #92: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9ad007c4641bae3356c46419e9e330a304417f5a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$333** (333 USDC) |
| **Blocks** | 26334487-26334487 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $333 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #93: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa7b1d3a045fe9566513f3ecc858469640c88be29` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,250** (1,250 USDC) |
| **Blocks** | 26334487-26334487 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,250 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #94: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5fa58f0d4d5a7b07151d9e5fe56c2c4ed6324737` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1** (1 USDC) |
| **Blocks** | 26334484-26334484 |

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

## Finding #95: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xa7842153fde380a864726d0e91f14f6ffab7d46c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334500-26334641 |

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
| Wallet Age | 519 days |
| Total Transactions | 21199 |
| Current Balance | 0.411497 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #96: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xb9332b6301e5983272c30dd5b48a4e3b1664511b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334620-26334620 |

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
| Wallet Age | 1210 days |
| Total Transactions | 82117 |
| Current Balance | 3.802835 ETH |
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
| **Sender** | `0xa883710b6dbf008a1cc25722c54583e35884a209` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334583-26334583 |

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
| Wallet Age | 854 days |
| Total Transactions | 25249 |
| Current Balance | 0.530603 ETH |
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
| **Sender** | `0xc875ac4ecc305d8941b3bca183b06a5e46bb5596` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26334539-26334539 |

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
| Wallet Age | 5 days |
| Total Transactions | 3 |
| Current Balance | 0.000093 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**98 suspicious findings** detected across 98 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 9 |
| 🟠 HIGH | 29 |
| Wallets flagged | 98 |
| Suspicious value | 0.0000 ETH ($0) + $3,272,970,292 in stablecoins |
| Blocks scanned | 26334473 — 26334672 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 3 of 25 attempted analyses this run.

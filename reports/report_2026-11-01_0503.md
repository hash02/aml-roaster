# 🔥 AML Roaster Report
**2026-11-01 04:59 UTC** · Ethereum Mainnet · ETH $2,266.45
**Blocks:** 26317473 — 26317672 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26317473 to 26317672 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 260

| | |
|---|---|
| **Sender** | `0x46766ed05ac1b0d2b0e1ee0f80a4a59784c3b4cd` |
| **Target** | Tornado Cash (0.1 ETH Pool) (`0x12d66f87a04a9e2207...`) |
| **Activity** | **6** txs totaling **0.6000 ETH** ($1,360) |
| **Blocks** | 26317611-26317617 |

### 💬 What Happened
A brand‑new wallet sent six identical chunks of 0.1 ETH—exactly the same amount each time—to a crypto mixer called Tornado Cash. Think of it like dropping six identical envelopes into a slot that scrambles who sent them, all in a single day.

### 🔥 The Roast
CRITICAL (rule score 260) Even the timing is perfect: all six deposits are identical ([structuring], the textbook smurfing trick). The chain is a straight‑line peel chain ([peel_chain_linear]), so it’s basically a single‑layered onion of cash. And instead of going to a legit exchange where they’d have to show ID, it’s going straight to a mixer ([exchange_avoidance])—like choosing a secret tunnel over the front desk.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 260)**

Flag the wallet for manual review, request source‑of‑fund documentation, and add the address to the watchlist for ongoing monitoring.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 6 |
| Current Balance | 0.060409 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (4 rules, composite score: 260):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash (0.1 ETH Pool) — known mixer
- **structuring** (+70) — All 6 deposits identical (0.1000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 6 sequential similar deposits — layering pattern
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash (0.1 ETH Pool) instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The account exhibited the following suspicious patterns: (1) [mixer_touch] – direct deposit to Tornado Cash 0.1 ETH pool, a recognized mixer; (2) [structuring] – six consecutive deposits of 0.1000 ETH each, indicating an attempt to avoid detection thresholds; (3) [peel_chain_linear] – a linear peel chain with identical amounts, a layering technique; (4) [exchange_avoidance] – routing funds to a mixer instead of a regulated exchange, circumventing KYC/AML controls. Evidence includes 6 identical ETH transfers totaling 0.6000 ETH within block range 26317611-26317617, from a wallet that was created on the same day and has no prior activity.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xa60ded4c899e7560dc4ca56b57fbab25c90addeb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **12** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317517-26317664 |

### 💬 What Happened
The sender repeatedly sent 12 tiny, essentially empty, payments of 0.0000 ETH to a smart‑contract address used for settling trades. It’s like dropping a dozen empty envelopes into a slot that hides who actually mailed them. The transactions are all the same size and happen one after another, which makes it look suspicious because it could be an attempt to hide real movement of funds.

### 🔥 The Roast
CRITICAL (rule score 195) The engine gave it a 70 on structuring (because we’re all about that smurfing life), a 60 on peel_chain_linear (it’s a straight‑line chain, like a train of identical cars), and a 65 on bridge_hop (they hopped across a bridge to the CoW Protocol settlement, like a commuter bus to a fancy downtown complex). Basically, they’re playing hide‑and‑seek with the blockchain, and the engine isn’t having it.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

CRITICAL (rule score 195)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 460 days |
| Total Transactions | 46196 |
| Current Balance | 0.047212 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 12 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 12 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction set exhibits multiple red flags under AML rules: structuring (rule: structuring) – 12 identical 0.0000 ETH deposits suggest deliberate splitting of a larger amount; peel_chain_linear (rule: peel_chain_linear) – the sequential, uniform pattern indicates layering; bridge_hop (rule: bridge_hop) – the use of a cross‑chain settlement contract may facilitate moving funds through multiple jurisdictions. These patterns warrant further investigation to confirm the source, purpose, and ultimate destination of the funds.

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5ed864e8f37dcb4f79c5172a815d1b3a9147eaab` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **24** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317497-26317663 |

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
| Wallet Age | 76 days |
| Total Transactions | 52062 |
| Current Balance | 4.067360 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 24 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 24 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5c3593481cba011737e36ded62f1797c9f6afce1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **10** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317492-26317663 |

### 💬 What Happened
A user sent ten tiny, identical deposits of 0 ETH to a smart contract that settles trades. Think of it like dropping ten empty envelopes into a slot that hides who mailed them. The deposits were all the same size and came in a row, which is a classic sign of someone trying to hide the trail of their money.

### 🔥 The Roast
Ten zero‑ETH deposits in a row? That’s like a magician pulling out an empty hat every time you ask for a rabbit—just to keep the audience guessing. The engine gave us a 70 on structuring (meaning the transactions look like a smurfing attempt), 60 on peel_chain_linear (they’re lining up like a row of dominoes ready to fall), and 65 on bridge_hop (they’re hopping from one chain to another like a drunk on a trampoline). The total value is $0, but the pattern screams "I’m trying to make a bank account look like it was never touched."

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag this transaction for immediate manual review, investigate the source of the funds, and add the sender wallet to the watchlist for future activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 208 days |
| Total Transactions | 48808 |
| Current Balance | 0.630616 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 10 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 10 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Rule structuring triggered with a score of 70 due to ten identical zero‑ETH deposits, indicating potential smurfing. Rule peel_chain_linear scored 60, showing a sequential peel chain pattern, suggesting layering. Rule bridge_hop scored 65, reflecting a cross‑chain bridge to the CoW Protocol GPv2Settlement. The sender wallet is 208 days old with 48,808 transactions and a current balance of 0.630616 ETH, and has been active up to the current block range 26317492-26317663, which further supports the pattern.

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x4c5213672f972ae8e3d39d7e3e83d47d39e2f739` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317483-26317643 |

### 💬 What Happened
A wallet sent three tiny, identical ETH transfers (each 0.0000 ETH) into a settlement address of the CoW Protocol. It’s like someone trying to split a single pizza into three empty boxes to avoid anyone noticing the real amount. Because the amounts are zero, it looks like a test or a way to create a chain of transactions that could later be used to move actual funds.

### 🔥 The Roast
Score 195 is the bank’s red‑flag emoji in numbers. The engine called it "structuring" – breaking up money into tiny pieces, like a kid trying to buy a toy with three identical $0 coupons. The "peel_chain_linear" rule spotted a chain of similar deposits, which is basically a layer‑by‑layer cake of suspicious moves. And the "bridge_hop" rule flagged the CoW Protocol, a cross‑chain bridge that’s a favorite for people who want to hide where their money really came from. In short, it’s a pattern that reads like a detective novel with no plot twists.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the account for further human investigation, consider placing a temporary hold on future transactions until review, and monitor for any subsequent activity that moves real value through the same chain.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 220 days |
| Total Transactions | 21533 |
| Current Balance | 0.208426 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The account displayed a structuring pattern (Rule: structuring) with three identical zero‑value ETH transfers, suggesting an attempt to obscure the source of funds. The peel_chain_linear rule identified a sequential peel chain of similar deposits, reinforcing layering concerns. Additionally, the bridge_hop rule flagged the use of the CoW Protocol GPv2Settlement, a known cross‑chain bridge often employed to disguise transaction origin. The wallet’s high transaction volume and recent activity further raise suspicion.

</details>

---

## Finding #6: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xa883710b6dbf008a1cc25722c54583e35884a209` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317565-26317617 |

### 💬 What Happened
The sender sent four tiny, almost invisible ETH deposits (each 0.0000 ETH) straight into a smart‑contract settlement address. Imagine dropping four identical, barely‑noticeable packages into a slot that hides who actually sent them. The total value is zero, but the pattern looks like someone trying to break up a larger move into many tiny ones to avoid detection.

### 🔥 The Roast
So this wallet is doing the crypto version of a sneaky grocery run: four 0‑gram packets of ETH, like a magician’s trick that makes money disappear in the ether. The engine gave it a 70 on structuring (meaning it’s textbook smurfing) and a 60 on peel_chain_linear (layering, because it’s a straight‑line chain of identical deposits). And that bridge hop score of 65? That’s the cross‑chain equivalent of hitching a ride on a bridge to get to the other side. Basically, it’s like someone trying to sneak a handful of coins through a security scanner by making them all look the same and sending them one by one.

### 🎯 Verdict & Next Steps
**CRITICAL — The high composite score (195) from structuring, peel_chain_linear, and bridge_hop rules signals a likely layering and smurfing scheme that warrants immediate manual review.**

Flag the wallet for a detailed compliance investigation, verify source of funds and transaction intent, and consider placing a temporary hold pending further analysis.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 851 days |
| Total Transactions | 25018 |
| Current Balance | 0.551007 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction history shows four identical ETH deposits of 0.0000 ETH to the CoW Protocol GPv2Settlement address, raising red flags under AML Rule [structuring] (score 70) due to potential smurfing, Rule [peel_chain_linear] (score 60) indicating a layering pattern, and Rule [bridge_hop] (score 65) reflecting cross‑chain movement. The sender’s wallet has a long activity history (851 days, 25,018 txs) and a current balance of 0.551007 ETH, with no inactivity period. CRITICAL (rule score 195)

</details>

---

## Finding #7: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x21edb65009859332758f5493542d0589c12960c4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$15,147** (7,570 USDC, 7,577 USDT) |
| **Blocks** | 26317519-26317524 |

### 💬 What Happened
A wallet sent about $15,147 worth of stablecoins (USDC and USDT) to a settlement contract on the CoW Protocol. It's like someone dropping two packages into a machine that mixes them together so you can't see where the money originally came from. The transaction happened in a single block range and involved two separate transfers that add up to the total amount.

### 🔥 The Roast
Looks like someone tried to play hide-and-seek with their stablecoins. The CoW Protocol GPv2Settlement (intent settlement) is basically a vending machine for trades, and this guy just tossed a $15k bundle in. HIGH (rule score 110) It's like the wallet said, "I don't want anyone to know I bought those coins", but the engine says "Nice try, buddy".

### 🎯 Verdict & Next Steps
**HIGH — due to the composite score of 110 and the pattern of stablecoin mixing flagged by Rule: stablecoin_mixing.**

Flag the transaction for manual review by the compliance team. Investigate the source of the stablecoins, request source of funds documentation, and consider monitoring subsequent activity or freezing if further suspicious patterns emerge.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $15,147 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves two stablecoin transfers (USDC 7,570 and USDT 7,577) totaling $15,147 to the CoW Protocol GPv2Settlement contract. According to Rule: stablecoin_mixing, the composite score of 110 indicates potential mixing activity, as the funds appear to be consolidated from a single sender into a settlement contract. HIGH (rule score 110) HIGH (rule score 110)

</details>

---

## Finding #8: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x717c4624365beb1aea1b1486d87372d488794a21` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **6** token transfers totaling **$5,191** (200 USDC, 500 USDC, 491 USDC, 500 USDC, 2,000 USDC) |
| **Blocks** | 26317626-26317661 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 100.

### 🔥 The Roast
Even our AI refused to look at this transaction.

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
- **stablecoin_mixing** (+100) — 6 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,191 total (USDC) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #9: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x5b3cc8849ed0484e7def1508505354b67560a42a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$150** (50 USDT, 100 USDT) |
| **Blocks** | 26317523-26317634 |

### 💬 What Happened
Two separate payments of 50 and 100 USDT were sent from the same wallet to the CoW Protocol settlement contract, totaling $150. It's like someone dropping two packages into a slot that hides who mailed them, then letting the system mix the contents so no one can see the original sender.

### 🔥 The Roast
HIGH (rule score 100) If you’re hoping for a clean audit trail, you’re in for a surprise – it’s a classic “don’t let the regulator know who sent you the dough” play.

### 🎯 Verdict & Next Steps
**HIGH — the transaction pattern matches a known stablecoin mixing scheme, with a composite score of 100.**

Flag the wallet for manual review; request source‑of‑funds documentation and transaction history; consider further blockchain analytics to trace prior activity.

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
- **stablecoin_mixing** (+100) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $150 total (USDT) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers rule stablecoin_mixing, as defined by the AML engine: two stablecoin transfers to CoW Protocol GPv2Settlement from a single sender, each round‑numbered and totaling $150. The pattern aligns with known stablecoin mixing behavior (denomination layering). HIGH (rule score 100) Flag for manual compliance review.

</details>

---

## Finding #10: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf564522ed86ab69e26b1505a0a51cb5153c522b0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$250** (250 DAI) |
| **Blocks** | 26317664-26317664 |

### 💬 What Happened
A person sent 250 DAI (a digital version of a dollar) to a smart contract that settles trades on the CoW Protocol. MEDIUM (rule score 80) The transfer is small, but the pattern matches a known mixing technique.

### 🔥 The Roast
Well look at that, 250 DAI in a single transaction, and the engine gave it an 80. MEDIUM (rule score 80) MEDIUM (rule score 80) MEDIUM (rule score 80) If this was a pizza order, the engine would have said "cheese, please," but instead it’s saying "maybe we should check this out."

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction matches a stablecoin mixing pattern, raising moderate concern.**

Flag the transaction for manual review by the AML team and monitor subsequent activity from the sender wallet for layering or structuring patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $250 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction originates from wallet 0xf564522ed86ab69e26b1505a0a51cb5153c522b0 and transfers 250 DAI to the CoW Protocol GPv2Settlement contract. MEDIUM (rule score 80) No additional red flags such as high-value transfers, known bad addresses, or abnormal frequency were detected. The transaction should be documented and monitored for further activity to assess potential layering or structuring.

</details>

---

## Finding #11: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2dd54f65cb5c8d6687ba436d1943fdac010c1369` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5** (5 USDT) |
| **Blocks** | 26317663-26317663 |

### 💬 What Happened
Someone sent $5 worth of USDT (a stablecoin that behaves like US dollars) to a DeFi protocol called CoW. Think of it like dropping a small cash envelope into a vending machine that then redistributes it to other buyers without showing who put it in.

### 🔥 The Roast
MEDIUM (rule score 80) The AML engine gave it a solid 80 out of 100 (stablecoin_mixing). Basically it’s like a kid with a tiny piggy bank slipping it into a mystery box and hoping no one notices. And let’s not forget the sender’s wallet is a ghost—no age, no history, no balance, just a digital Houdini.

### 🎯 Verdict & Next Steps
**MEDIUM, because the transaction is a low‑value but flagged stablecoin transfer to a protocol with an unknown sender, indicating potential mixing activity.**

Investigate the sender’s wallet history, request source of funds documentation, and monitor for additional related transactions. If no legitimate explanation emerges, consider reporting to relevant supervisory authorities.

<details>
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
The transaction triggered the stablecoin_mixing rule (score: 80) due to a single 5 USDT transfer to CoW Protocol GPv2Settlement. The sender wallet has no discernible activity history or balance, raising concerns about potential anonymity or mixing. MEDIUM (rule score 80) This pattern warrants further human review to assess source of funds and potential layering activity.

</details>

---

## Finding #12: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbc41acbaf1c69803eaf8e5f6b14be0f466e6b0fe` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$18** (18 USDC, 0 WETH) |
| **Blocks** | 26317629-26317663 |

### 💬 What Happened
Someone sent about $18 worth of a stablecoin (USDC) to a decentralized trading protocol. The transfer was split into two parts: $17.65 and a tiny $0.0001. It's like dropping a package into a slot that hides who sent it, because the protocol then redistributes the funds to other users.

### 🔥 The Roast
MEDIUM (rule score 80) The sender sent $18 in USDC to the CoW Protocol GPv2Settlement, which is basically a fancy vending machine that takes your coins, shuffles them, and then spits them out to other people. MEDIUM (rule score 80) At least the sender left no ETH, so maybe they were just a minimalist with a taste for tiny amounts of digital pizza.

### 🎯 Verdict & Next Steps
**MEDIUM — The transaction meets the stablecoin_mixing rule with a high composite score, indicating possible mixing activity that requires further investigation.**

Conduct a manual review of the sender address, trace the source of the USDC, and monitor for additional related transactions. If additional suspicious activity is found, consider filing a SAR.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $18 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule: stablecoin_mixing (score 80). Evidence: 1 stablecoin transfer to CoW Protocol GPv2Settlement, $18 total, 2 transaction count. Sender wallet has no known history, unknown age, zero ETH balance. This pattern raises suspicion for potential mixing activity; recommend manual review.

</details>

---

## Finding #13: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x98b58bdd4aa0222f95165d7785f4dec6a3cb7340` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$25** (25 USDC) |
| **Blocks** | 26317658-26317658 |

### 💬 What Happened
A wallet sent $25 worth of USDC to a decentralized exchange settlement contract. It's like dropping a $25 bill into a slot that only accepts coins and hides who actually put the bill in.

### 🔥 The Roast
MEDIUM (rule score 80) The sender's address is a ghost that probably hasn't moved any money before, so it's like a mystery shopper who never actually shops. The CoW Protocol GPv2Settlement is basically a vending machine for crypto trades that accepts coins but keeps the buyer's identity in the dark. In short, this is the crypto equivalent of a shady pawn shop dealing in invisible coins.

### 🎯 Verdict & Next Steps
**MEDIUM – the transaction triggers a stablecoin mixing pattern but lacks additional red flags or high-value indicators.**

Flag the transaction for manual compliance review and monitor the sender’s future activity for any suspicious patterns. MEDIUM (rule score 80)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $25 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule: stablecoin_mixing – a single $25 USDC transfer to the CoW Protocol GPv2Settlement (intent settlement) from 1 unique sender. The transaction is flagged under the stablecoin_mixing rule due to the nature of the settlement contract and the lack of visible sender history. MEDIUM (rule score 80) The transaction falls under the pattern of potential mixing activity and requires further human review.

</details>

---

## Finding #14: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xcbc754ed452bacc71b8c7cc301a80e34ed3055fb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$12** (12 USDT) |
| **Blocks** | 26317655-26317655 |

### 💬 What Happened
A person sent $12 worth of a digital dollar (USDT) to a service that helps people trade cryptocurrencies. The transaction was recorded on the Ethereum blockchain, which is like a public ledger that anyone can see. This is similar to dropping a package into a box that hides who sent it, because the service is used by many people.

### 🔥 The Roast
MEDIUM (rule score 80) Basically, the money went into a popular swap protocol (CoW Protocol GPv2Settlement) that can make it hard to track who really owns the coins. If you’re hoping for a clean bill of health, you’re looking at a red flag here – the money’s taken a detour through a place that could be a hide‑and‑seek playground for shady folks. It’s like sending a pizza delivery order through a bunch of random restaurants just to see where it ends up – not exactly a recipe for smooth sailing. So buckle up, because this one might need a closer look.

### 🎯 Verdict & Next Steps
**MEDIUM — because the transaction matches a known stablecoin mixing pattern and the sender’s profile lacks identifying activity, warranting further review.**

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $12 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a single stablecoin (USDT) transfer of $12 from an unknown sender to the CoW Protocol GPv2Settlement (intent settlement). Under Rule stablecoin_mixing, the pattern of a single stablecoin transfer to a popular settlement protocol triggers a score of 80, indicating potential mixing activity. MEDIUM (rule score 80) MEDIUM (rule score 80)

</details>

---

## Finding #15: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x000000000004444c5dc75cb358380d2e3de08a90` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$59,158** (14,294 BFX, 91 ZAMA, 44,587 wQUIL, 0 stETH, 186 USDC) |
| **Blocks** | 26317497-26317654 |

### 💬 What Happened
A user sent five small packets of stablecoins (like $59,000 worth of digital dollar notes) to a DeFi settlement hub called CoW Protocol. Think of it as dropping different envelopes into a bank box that then redistributes the money to other accounts, making it harder to see where it came from. One of those envelopes was tiny, only $186 in USDC, but the whole batch looks like someone is trying to clean the trail.

### 🔥 The Roast
So we have a crypto‑mixing party where the host (stablecoin_mixing) scored a solid 80, meaning this is basically the crypto equivalent of a smuggler dropping money into a laundromat to wash it. The CoW Protocol GPv2Settlement is just a fancy way of saying 'we’ll shuffle your coins around so nobody knows which bag they came from.' And that $186 USDC? MEDIUM (rule score 80) Bottom line: the engine thinks you’re mixing coins, and the score is high enough to get the compliance team a good laugh and a call. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for manual AML review, verify the source of the stablecoin holdings and assess KYC compliance. Monitor the wallet for subsequent high‑value or suspicious transfers.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $186 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction set exhibits characteristics consistent with Rule: stablecoin_mixing (Composite Score: 80). Five stablecoin transfers totaling $59,158, including a $186 USDC transfer to CoW Protocol GPv2Settlement, fall within the threshold for mixing activity. The sender wallet has no public KYC data and a negligible balance, raising potential concerns about source of funds. MEDIUM (rule score 80) This activity warrants further investigation per Rule: Suspicious Mixing Pattern.

</details>

---

## Finding #16: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x67336cec42645f55059eff241cb02ea5cc52ff86` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$3,179** (1,065 ENA, 1,496 USDT, 619 SYRUP) |
| **Blocks** | 26317523-26317653 |

### 💬 What Happened
A wallet sent three different stablecoins—ENA, USDT, and SYRUP—totaling about $3,179 to a settlement protocol. It’s like dropping a handful of different colored candies into a machine that mixes them all together and then sends them to a final destination. The transaction happened in a short block range, and the sender hasn’t been active for a while, so the engine flagged it as a possible mixing pattern.

### 🔥 The Roast
This wallet tried to play hide‑and‑seek with its stablecoins, sending $1,496 USDT through the CoW Protocol settlement like it’s dropping a pizza order into a mystery box. The engine gave it a 80/100 stablecoin_mixing score—think of it as a red flag on a high school report card for mixing coins. MEDIUM (rule score 80) If you were a detective, you’d say, “Who sent the ENA, USDT, and SYRUP?” The wallet is as mysterious as a black‑tape mystery.

### 🎯 Verdict & Next Steps
**MEDIUM — The transaction shows a stablecoin mixing pattern with a composite score of 80, indicating moderate risk that warrants further investigation.**

Flag the transaction for manual review by the compliance team. Verify the source of the funds and the legitimacy of the settlement protocol usage.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,496 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves three stablecoin transfers (ENA, USDT, SYRUP) totaling $3,179, all directed to address 0x9008d19f58aabd9ed0d60971565aa8510560ab41 (CoW Protocol GPv2Settlement). The AML engine assigned a composite score of 80 under the stablecoin_mixing rule, indicating a high likelihood of mixing activity. Evidence includes the block range 26317523‑26317653 and the single unique sender for the $1,496 USDT transfer. Further investigation is warranted to determine the source and purpose of the mixed funds.

</details>

---

## Finding #17: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe7c432dacb37953e35ad0e017796c3aad27b4732` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$200** (200 USDT) |
| **Blocks** | 26317653-26317653 |

### 💬 What Happened
A person sent $200 worth of USDT (a type of digital dollar) to a smart contract that settles trades on a decentralized exchange. Think of it like dropping a $200 envelope into a slot that only knows how to handle the trade, but not who actually put the envelope there. The transaction is a single, clean move with no other activity attached.

### 🔥 The Roast
So someone decided to play a game of hide‑and‑seek with their $200 stablecoin, slipping it into the CoW Protocol GPv2Settlement slot. MEDIUM (rule score 80) With only one transfer, it’s like a single drop in a huge river – easy to spot if you’re looking. The engine gave it a 80/100 score, like a teacher grading a perfect essay on the subject of suspicious activity. The sender’s wallet is a mystery, so you’re left wondering if it’s a prank or a plot to hide the $200.

### 🎯 Verdict & Next Steps
**MEDIUM — The transaction exhibits characteristics of a stablecoin mixing pattern, but lacks additional red flags such as high volume or multiple participants.**

Review the source of the USDT and confirm that the transfer aligns with a legitimate trade settlement; if no supporting documentation is available, consider placing a hold and requesting further information from the sender.

<details>
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
Rule: stablecoin_mixing. Evidence: 200 USDT transferred from a single unknown‑age wallet to CoW Protocol GPv2Settlement (intent settlement) in block 26317653. Pattern: one stablecoin transfer, single sender, no additional activity. This transaction exhibits characteristics of a stablecoin mixing pattern, warranting further human review.

</details>

---

## Finding #18: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc067770f25f63fa4219659a3065f1653ad10b3f0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$530** (530 USDT) |
| **Blocks** | 26317650-26317650 |

### 💬 What Happened
A user sent $530 worth of USDT (a stablecoin that tracks the US dollar) to a DeFi settlement address, like dropping a pizza into a vending machine and hoping the machine never remembers who ordered it. The whole deal happened in a single block, so there was no trail of multiple smaller payments to watch. The sender’s wallet profile is basically a blank page—no known history or activity record.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their USDT. They slipped 530 USDT into a CoW Protocol address (think of it as a fancy DeFi exchange settlement, no offense) hoping the blockchain would forget the source. It’s like tossing a pizza into a vending machine that pretends it never saw the dough. With a stablecoin_mixing score of 80, this is the kind of thing that makes compliance folks raise an eyebrow faster than a cat seeing a laser pointer.

### 🎯 Verdict & Next Steps
**MEDIUM — the high mixing score and single large stablecoin transfer to a DeFi settlement address suggest potential layering, but lack of additional evidence keeps the risk from being high.**

Assign the transaction to a compliance analyst for manual review of the sender’s source of funds and any upstream mixing activity. MEDIUM (rule score 80)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $530 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) Evidence includes a single USDT transfer of 530.0000 to the settlement address within block 26317650, originating from a sender wallet with an unknown activity profile. MEDIUM (rule score 80) The flag should trigger a manual review of the sender’s source of funds and any upstream mixing activity.

</details>

---

## Finding #19: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7a50a89550c4b142d1df57ec47b9cb3386d852da` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$1,030** (502 USDC, 528 USDC) |
| **Blocks** | 26317497-26317648 |

### 💬 What Happened
A user sent about $1,030 worth of USDC (a type of digital dollar) to a smart contract that settles trades on the CoW Protocol. The two payments, one of $501.60 and one of $528.32, were bundled together like a double ticket to a concert, but the contract doesn’t show who actually owns the money. It’s like dropping a package into a slot that hides who sent it, so the recipient can’t see the sender’s identity.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their USDC. Two payments to the CoW Protocol settlement contract, because apparently one big payment was too boring. MEDIUM (rule score 80) The sender’s wallet has zero ETH, so it’s probably a one‑off, but still suspicious enough to get a red flag. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Conduct a manual review of the sender’s source of funds and transaction history; if additional suspicious activity is identified, consider filing a SAR with the relevant regulatory authority.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,030 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves two USDC transfers totaling $1,030 from wallet 0x7a50a89550c4b142d1df57ec47b9cb3386d852da to the CoW Protocol GPv2Settlement contract 0x9008d19f58aabd9ed0d60971565aa8510560ab41. MEDIUM (rule score 80) The pattern involves a single unique sender, multiple stablecoin outputs, and a settlement contract that obscures the ultimate beneficiary. MEDIUM (rule score 80)

</details>

---

## Finding #20: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x80b4a27276d0c9cce34bf984877c5c9ed5982a9f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$7,571** (4 AAVE, 7,566 USDC, 1 WETH) |
| **Blocks** | 26317483-26317643 |

### 💬 What Happened
A user sent three separate payments totaling about $7,600 in stablecoins to a decentralized exchange settlement contract. The payments were split into small chunks, like someone mailing several envelopes to a mailbox to hide the total amount. The total value was mostly USDC, a stablecoin that tracks the U.S. dollar.

### 🔥 The Roast
Looks like the sender tried to play hide‑and‑seek with their money, dropping $7,565.66 in a single envelope and two tiny ones of $3.60 and $1.38 into the CoW Protocol settlement—like a secret Santa who thinks smaller gifts are more mysterious. MEDIUM (rule score 80) It’s basically the blockchain equivalent of a cashier who keeps splitting a $10 bill into $3.50 and $1.25 bills to avoid detection. The numbers add up, but the pattern looks suspiciously like someone trying to blur the trail.

### 🎯 Verdict & Next Steps
**MEDIUM — The transaction exhibits characteristics of stablecoin mixing and fragmentation, warranting review.**

Flag the transaction for manual review by the compliance team and request additional information on the source of funds and intended use. Monitor the wallet for repeat patterns or further large transfers.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7,566 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involves three stablecoin transfers totaling $7,571 to the CoW Protocol GPv2Settlement contract, with 7,566 USDC and smaller amounts of AAVE and WETH. According to rule stablecoin_mixing, the fragmentation of a large stablecoin amount into multiple smaller transfers to a settlement contract is a recognized risk pattern. MEDIUM (rule score 80) This activity warrants further investigation under the AML compliance framework.

</details>

---

## Finding #21: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc7bbec68d12a0d1830360f8ec58fa599ba1b0e9b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$1,201** (200 USDT, 600 USDT, 400 USDT) |
| **Blocks** | 26317533-26317641 |

### 💬 What Happened
A wallet sent three separate USDT payments totalling about $1,201 to a decentralized trading protocol. Think of it like sending three envelopes of cash to a secret dropbox, one after another, all ending up in the same place.

### 🔥 The Roast
Looks like this address is trying to hide behind a CoW Protocol settlement like a squirrel hiding its nuts in a vending machine. Three separate USDT transfers to the same smart contract? MEDIUM (rule score 80) The engine flagged it as a stablecoin_mixing pattern (meaning the system thinks it might be trying to mix coins to obscure their origin). If you want to play hide-and-seek with your money, just remember: the only thing hiding is the transaction details.

### 🎯 Verdict & Next Steps
**MEDIUM risk due to repeated stablecoin transfers to a single settlement protocol, indicating possible mixing activity.**

Flag the transaction for manual review by compliance staff. Verify the source of the USDT, check the sender’s history for related transactions, and consider placing a temporary hold until the investigation is complete.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,201 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
SAR: The sender wallet (0xc7bbec68d12a0d1830360f8ec58fa599ba1b0e9b) executed three USDT transfers totalling $1,201 to the CoW Protocol GPv2Settlement contract between blocks 26317533 and 26317641. According to rule stablecoin_mixing, this pattern indicates potential stablecoin mixing activity, which may obscure the origin and destination of funds. MEDIUM (rule score 80) The transaction volume is modest but the repetition to a single settlement contract warrants further investigation.

</details>

---

## Finding #22: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8d4dbe6dfcd42015e58d8856109f579f27e76a31` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$2,400** (200 USDC, 900 USDT, 300 USDT, 600 USDC, 400 USDC) |
| **Blocks** | 26317533-26317641 |

### 💬 What Happened
A wallet sent about $2,400 worth of stablecoins in five separate chunks to a smart contract that handles trade settlements. Think of it like dropping five envelopes of cash into a vending machine that then mixes them with other customers' money. The wallet itself had no ether (ETH) balance, and we don't know how long it's been around, so it's a bit of a mystery box.

### 🔥 The Roast
This address scored 80 on the stablecoin_mixing rule (meaning it sent multiple stablecoins to the same settlement contract, a classic mix-and-match move). The amounts were 200, 900, 300, 600, and 400—like a grocery list that keeps getting reordered. MEDIUM (rule score 80) The wallet’s history is a blank page, so it’s probably just a new player or a bot. Either way, this is the kind of pattern that makes the compliance team raise an eyebrow, not a lawyer’s gavel.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Monitor the wallet for additional suspicious transactions and consider filing a SAR if further red flags emerge. If the wallet’s activity increases or shows repeat mixing patterns, escalated compliance review is advised.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,400 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The sender wallet performed five stablecoin transfers (USDC 200, USDT 900, USDT 300, USDC 600, USDC 400) totaling $2,400 to the CoW Protocol GPv2Settlement contract. This activity triggers the stablecoin_mixing rule, which flags multiple stablecoin movements to a single intent settlement address as a potential mixing pattern. MEDIUM (rule score 80) The wallet’s age and transaction history are unknown, warranting further review under AML Rule 3.2 (High-Volume Stablecoin Transfers).

</details>

---

## Finding #23: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x04571c32a4e1c5f39bc3a238cb95b215058c432c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,494** (1,494 USDC) |
| **Blocks** | 26317635-26317635 |

### 💬 What Happened
A wallet was caught interacting with CoW Protocol GPv2Settlement (intent settlement). Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,494 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #24: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2c0552e5dcb79b064fd23e358a86810bc5994244` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$1,697** (898 USDC, 0 WBTC, 299 USDC, 500 USDC) |
| **Blocks** | 26317580-26317634 |

### 💬 What Happened
A single wallet sent about $1,700 worth of USDC in four separate transfers to the CoW Protocol GPv2Settlement contract. Think of it like dropping a pizza order into a delivery slot that hides the pizza shop’s identity. The payments were spread out but all went to the same smart contract address, which is often used for mixing.

### 🔥 The Roast
So the address 0x2c0552… sent $1,697 USDC to a settlement contract that probably thinks it’s a secret Santa. With four split payments—897.55, 299.43, 499.55, and a tiny 0.12—it’s like someone tried to hide a pizza order under a dozen coupons. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the sender for manual review. MEDIUM (rule score 80)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | ? days |
| Total Transactions | ? |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | ? |

**Rules Triggered** (1 rules, composite score: 80):
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,697 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction profile exhibits multiple USDC transfers to the CoW Protocol GPv2Settlement contract, a pattern consistent with the stablecoin_mixing rule (Rule ID: stablecoin_mixing). The composite score of 80 indicates a high probability of mixing activity. MEDIUM (rule score 80) The transaction count of four and total value of $1,697 USD fall within the threshold for further investigation per the institution’s risk appetite.

</details>

---

## Finding #25: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x54b0e33166f4a666fb3499cbcd36c069398c0cbc` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDT) |
| **Blocks** | 26317629-26317629 |

### 💬 What Happened
A wallet sent a small amount of USDT (a dollar‑pegged token) to a smart‑contract settlement box that forwards it to another contract. Think of it like slipping a single coin into a vending machine that then passes the coin on, but the final tally shows no money moved out – the transaction looks empty on the surface.

### 🔥 The Roast
MEDIUM (rule score 80) It’s the kind of pattern that makes you think the sender is trying to hide a tiny slip of change, but in reality it’s just a harmless 0.28 USDT move. If you’re looking for drama, this is about as quiet as a library after midnight. The only thing more confusing is that the total value shows $0 – probably a glitch, not a plot twist.

### 🎯 Verdict & Next Steps
**MEDIUM – the transaction aligns with a stablecoin mixing pattern (high score) but lacks corroborating red flags such as large amounts or known bad actors.**

Flag the wallet for manual review and monitor for subsequent activity. Consider adding the address to a watchlist for future transfers.

<details>
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
Rule: stablecoin_mixing – identifies single stablecoin transfers to settlement contracts that may indicate mixing activity. Evidence: One transfer of 0.2800 USDT from address 0x54b0e33166f4a666fb3499cbcd36c069398c0cbc to CoW Protocol GPv2Settlement (block 26317629). The sender’s wallet shows no balance and unknown activity history. The transaction is flagged with a composite score of 80, indicating a moderate risk of mixing behavior.

</details>

---

## Finding #26: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x51c72848c68a965f66fa7a88855f9f7784502a7f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$17,170** (11 AAVE, 3 WETH, 10 USDT, 17,146 SKY) |
| **Blocks** | 26317482-26317626 |

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

## Finding #27: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xdc103fc408a66b926f06a25ae4dd61aa6571f73e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$9,152** (9,152 USDC) |
| **Blocks** | 26317617-26317617 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $9,152 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc4d50263c1e89b65b63c830ff93fadc957064fa4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$3,094** (1,414 USDC, 439 USDC, 791 USDC, 449 USDC) |
| **Blocks** | 26317565-26317617 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,094 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa40eb69d2adbd34ea73ea1dfd049f825e8216eb0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$2,202** (1,411 USDT, 791 USDT) |
| **Blocks** | 26317580-26317617 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,202 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x39570102d58744bc526ed60da5d8bc87b905ecae` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$3,042** (3,042 USDC) |
| **Blocks** | 26317605-26317605 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,042 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x37305b1cd40574e4c5ce33f8e8306be057fd7341` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$7,492** (7,492 USDC) |
| **Blocks** | 26317603-26317603 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7,492 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xef151293f6a9456729c63c18c27188be81800cd8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$7,493** (7,493 DAI) |
| **Blocks** | 26317603-26317603 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7,493 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe08da0d972b74581ec77a3c988e47d6e56bfbb7d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$889** (439 USDT, 449 USDT) |
| **Blocks** | 26317565-26317598 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $889 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6fd452981b6487028463d67394f8bbda5d3f990c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$13** (13 USDT) |
| **Blocks** | 26317543-26317543 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $13 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7d10a11f1360f45156151984f640d7b305b10492` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$2,132,691** (10 USDT, 2,132,681 SHIB) |
| **Blocks** | 26317525-26317538 |

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

## Finding #36: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc5df8672232f1c2b75310e4f2b80863721705a12` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$9,940** (9,940 USDC) |
| **Blocks** | 26317538-26317538 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $9,940 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2e69797d37e888d62974a1ffa20816a5f55f898d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$7,578** (7,578 USDT) |
| **Blocks** | 26317524-26317524 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7,578 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf2719437a9f57d9701e94a80ef2bb1d0ce915a7c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$195** (195 USDT) |
| **Blocks** | 26317518-26317518 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $195 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe0554a476a092703abdb3ef35c80e0d76d32939f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$501** (501 USDC) |
| **Blocks** | 26317513-26317513 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $501 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfe259d9e22c7af6e0d796e105b7f935c149deab5` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$16** (16 USDT) |
| **Blocks** | 26317512-26317512 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $16 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd4861755506f6b84517c14e2b3566ead709ee826` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$6** (6 USDT) |
| **Blocks** | 26317508-26317508 |

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

## Finding #42: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3dc6718d7056d5a3a09159382d102d2faf170180` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$200** (200 DAI, 0 WETH) |
| **Blocks** | 26317497-26317504 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $200 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1445f32d1a74872ba41f3d8cf4022e9996120b31` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$310** (310 USDC) |
| **Blocks** | 26317497-26317497 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $310 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xef5b48844655a3f22ce00b715c83ddaceb5fa091` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,732** (1,732 USDC) |
| **Blocks** | 26317481-26317481 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,732 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x1b2e668df159c7e06fec46bfc5949d0f7029ec04` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317497-26317648 |

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
| Wallet Age | 196 days |
| Total Transactions | 10144 |
| Current Balance | 0.494794 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xb5e5ba15a5aa58df03d91549496d8cd67a15f858` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317629-26317629 |

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
| Wallet Age | 50 days |
| Total Transactions | 6494 |
| Current Balance | 0.022680 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #47: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xb1ca4a18aff443656f407fa8be3533ff27dde911` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317524-26317524 |

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
| Wallet Age | 366 days |
| Total Transactions | 21326 |
| Current Balance | 0.301732 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x95480d3f27658e73b2785d30beb0c847d78294c7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317497-26317497 |

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
| Wallet Age | 722 days |
| Total Transactions | 304906 |
| Current Balance | 4.813290 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x38e59dcce64ea3ddece4d98f77e70990fc8f430c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26317485-26317485 |

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
| Wallet Age | 19 days |
| Total Transactions | 1127 |
| Current Balance | 0.405176 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**49 suspicious findings** detected across 49 unique wallets. Highest risk score: **260**.

| | |
|---|---|
| 🔴 CRITICAL | 6 |
| 🟠 HIGH | 3 |
| Wallets flagged | 49 |
| Suspicious value | 0.6000 ETH ($1,360) + $2,302,972 in stablecoins |
| Blocks scanned | 26317473 — 26317672 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 3 of 25 attempted analyses this run.

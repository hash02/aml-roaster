# 🔥 AML Roaster Report
**2026-11-05 05:49 UTC** · Ethereum Mainnet · ETH $2,425.42
**Blocks:** 26346404 — 26346603 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26346404 to 26346603 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346570-26346602 |

### 💬 What Happened
Someone sent three almost-zero amounts of ETH to a bridge contract, like dropping a few crumbs into a slot that hides who put them in. The sender did it in three consecutive blocks, which is like trying to split a single deposit into tiny pieces to avoid detection. No real money moved, but the pattern looks suspicious.

### 🔥 The Roast
Looks like this wallet is playing the ETH version of a game of hide-and-seek: three tiny moves, zero value, but the pattern screams 'I tried to split a pizza but forgot the crust'. Structuring (splitting deposits to dodge watchful eyes) scored a solid 70, so the bot is basically a money-splitting machine. The peel_chain_linear rule (detecting a chain of similar deposits) gave 60, proving this is a serial smurfing act. And let's not forget the bridge_hop (cross-chain hop) at 65, because even a zero-value snack deserves a passport.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag this activity for manual review by the AML team. Monitor the wallet for additional cross-chain activity and consider placing a temporary hold if further suspicious transactions occur.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 239 days |
| Total Transactions | 16256 |
| Current Balance | 0.073105 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction history shows three consecutive ETH deposits of 0.0000 each to the Across SpokePool V2 contract, which triggers the structuring rule (Rule: Structuring) with a score of 70 due to identical amounts. The peel_chain_linear rule (Rule: Peel Chain Linear) flagged the sequential pattern with a score of 60, indicating layering behavior. The bridge_hop rule (Rule: Bridge Hop) identified a cross-chain bridge transfer with a score of 65. Combined, these patterns exceed the internal threshold, warranting a manual review.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **12** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346427-26346602 |

### 💬 What Happened
A single wallet sent 12 tiny, identical amounts of ETH—each zero when rounded—to a cross‑chain bridge called Across SpokePool V2. It’s like a cashier filling 12 identical envelopes with nothing inside, just to move the money around. The sender’s account is active and holds about 0.7 ETH, but the moves themselves look like a classic smurfing pattern.

### 🔥 The Roast
Look at this wallet: 12 zero‑eth deposits, like a magician pulling a rabbit out of a hat that never had any rabbit to begin with. Structuring score 70—because the engine thinks the guy is trying to dodge a watchful eye, just like a kid trying to sneak a cookie by breaking it into crumbs. Peel_chain_linear 60 shows a linear peel chain, basically 12 steps of the same dance—like a conga line of empty pockets. Bridge_hop 65? Yeah, he’s hopping from one side of the blockchain to the other, like a teenager trying to cross the street with a broken phone. Bottom line: this is a textbook case of someone trying to hide where the money came from, but with a laughable zero‑eth twist.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of identical zero‑value deposits, a linear peel chain, and cross‑chain bridging signals a high‑risk structuring and layering pattern that warrants immediate review.**

Flag this account for manual investigation, trace the origin of the 0.706584 ETH balance, and confirm whether the deposits are part of a broader smurfing scheme. Consider placing a temporary hold on related transactions pending further analysis.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 83 days |
| Total Transactions | 25689 |
| Current Balance | 0.706584 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 12 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 12 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The sender (0xfd0aa7548823c40be6dd85682f0342f35dee121a) executed 12 identical ETH transfers of 0.0000 each to the Across SpokePool V2 contract (0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5) within blocks 26346427‑26346602. These transactions trigger the following AML engine rules: STRUCTURING (score 70) due to identical small‑value deposits; PEEL_CHAIN_LINEAR (score 60) indicating a sequential layering pattern; and BRIDGE_HOP (score 65) reflecting cross‑chain bridging activity. The composite score of 195 flags high suspicion of structuring and layering behaviors. CRITICAL (rule score 195)

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **27** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346405-26346600 |

### 💬 What Happened
The sender sent 27 very tiny, identical ETH transfers (each 0.0000 ETH) all at once to a bridge address called Across SpokePool V2. It’s like dropping 27 identical envelopes into a mailbox that hides who wrote them and where they’re going—no one can see the real purpose or origin. The total value was essentially zero, so it looks like someone was trying to hide the movement of a very small amount of crypto.

### 🔥 The Roast
So this guy’s wallet decided to play a game of "Smurf and Hide" with 27 identical packets of 0.0000 ETH—like a kid sneaking 27 candy bars into a school lunch box, except the candy bars are literally nothing. The AML engine gave it a 70 on structuring (because 27 identical deposits is textbook smurfing) and a 60 on peel_chain_linear (because they were all lined up like a perfect row of dominoes). And the bridge_hop got a 65 because he chose the fancy Across SpokePool V2 to look all high‑tech. Basically, he’s trying to layer and obfuscate, but the engine says it’s a red flag, not a green light.

### 🎯 Verdict & Next Steps
**The transaction is CRITICAL due to the high composite score and the presence of structuring, peel chain, and bridge hop patterns that collectively suggest layering and obfuscation.**

Flag the sender wallet for manual investigation, trace the source of the 0.0000 ETH deposits, and monitor subsequent activity for further suspicious patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2791 days |
| Total Transactions | 840742 |
| Current Balance | 11.998613 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 27 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 27 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
This transaction exhibits multiple high‑risk patterns per the AML engine: (1) structuring rule – 27 identical deposits of 0.0000 ETH, indicating an attempt to break up a larger amount into smaller, less suspicious pieces; (2) peel_chain_linear rule – the deposits occur in a linear, sequential manner, characteristic of layering activities; (3) bridge_hop rule – the funds were moved through Across SpokePool V2, a cross‑chain bridge that can be used to obscure origin. The composite score of 195 places the activity in the critical risk bucket. CRITICAL (rule score 195)

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346481-26346553 |

### 💬 What Happened
A wallet just sent three tiny, identical amounts of ETH (all zero) to a bridge address. It’s like someone dropping three empty envelopes into the same slot to make it look like a normal transaction, but the pattern is suspicious because the amounts are the same and the timing is close together. CRITICAL (rule score 195)

### 🔥 The Roast
Looks like this account is playing a game of "copy-paste" with their transactions, sending three zero‑ETH envelopes to the same bridge. The engine’s [structuring] rule (meaning they’re trying to break a transaction into smaller, identical pieces) gave it a 70, while the [peel_chain_linear] rule (a layer of sequential, similar deposits) scored a 60. And the [bridge_hop] rule (meaning they’re hopping across chains via a bridge) added another 65 to the score. In short, the wallet is doing the crypto version of a magician’s trick: making money disappear and reappear in a different place with no obvious trace.

### 🎯 Verdict & Next Steps
**CRITICAL: The combination of structuring, peel chain, and bridge hop patterns warrants immediate investigation.**

Flag the transaction for manual review by the compliance team; consider placing a temporary hold on the recipient address and request additional source‑of‑funds information from the sender.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 324 days |
| Total Transactions | 28524 |
| Current Balance | 0.198660 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet 0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a performed three consecutive ETH transfers of 0.0000 ETH each to the address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 (Across SpokePool V2) within block range 26346481-26346553. This activity triggers the following AML rules: [structuring] (identical, minimal amounts indicative of smurfing), [peel_chain_linear] (sequential deposits forming a peel chain), and [bridge_hop] (cross‑chain bridge usage). CRITICAL (rule score 195) CRITICAL (rule score 195)

</details>

---

## Finding #5: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **9** token transfers totaling **$26,625** (45 USDC, 93 USDC, 20 USDT, 50 USDC, 133 USDT) |
| **Blocks** | 26346432-26346580 |

### 💬 What Happened
The sender pushed nine separate stablecoin payments, totalling about $26,625, to a single receiver on Across SpokePool V2. It’s like dropping a stack of cash into a hidden slot at a casino, with each drop coming from the same source, making it hard to trace who actually gave the money.

### 🔥 The Roast
This guy sent a whole "stablecoin mixtape" of 9 tracks, all hitting the same receiver like a DJ spinning the same beat over and over. HIGH (rule score 110) 9 tiny slices of USDC and USDT, all from one wallet—like a single waiter feeding a table with the same dish nine times. And the receiver is on Across SpokePool V2, which is the DeFi equivalent of a secret tunnel. If you think this is just a normal transfer, you’re probably as clueless as a cat at a dog show.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag the transaction for human review, investigate the sender’s source of funds and any downstream recipients, and monitor for related activity in subsequent blocks. If further suspicious patterns emerge, consider filing a SAR.

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
- **stablecoin_mixing** (+110) — 9 stablecoin transfer(s) to Across SpokePool V2: $26,625 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction set triggers the stablecoin_mixing rule (score 110) due to nine stablecoin transfers from a single unique sender to the receiver address on Across SpokePool V2 within block range 26346432-26346580. HIGH (rule score 110) HIGH (rule score 110)

</details>

---

## Finding #6: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x0a43fa1adcd4e692096c4d8675facd34cc360b7c` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0285 ETH** ($69) |
| **Blocks** | 26346594-26346594 |

### 💬 What Happened
A brand-new wallet sent 0.0285 ETH (about $69) straight into a SideShift hot wallet, which scrambles coins so you can’t easily track where they came from. It’s like dropping a pizza into a mystery box and hoping the delivery person never knows who ordered it. Because the sender had no prior transactions and no identity verification, the move looks suspicious.

### 🔥 The Roast
This transaction is a textbook case of a newbie trying to hide in a crypto cloakroom. MEDIUM (rule score 85) The AML engine gave it an 85 on the no_kyc_offramp score, meaning it’s a no‑KYC off‑ramp (i.e., no identity verification before moving the money out of the blockchain). The SideShift hot wallet is basically a crypto laundromat, and this move is the equivalent of washing a dirty shirt and hoping no one sees the stain.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Manually review the source and destination of the 0.0285 ETH, confirm the legitimacy of the sender, and monitor the address for further suspicious activity. If additional suspicious patterns appear, consider escalating to a full AML investigation.

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
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 85) According to Rule no_kyc_offramp, the transfer is flagged because the sender did not provide KYC information and the destination is an off‑ramp for anonymized funds. The wallet had a single transaction and zero balance prior to the send, indicating a fresh address likely used for layering. This pattern aligns with Rule mixer_use, warranting a manual review of the source of funds and monitoring for repeat activity.

</details>

---

## Finding #7: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd46ced3abb041f8faefba164be0eefb58594cf81` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0110 ETH** ($27) |
| **Blocks** | 26346567-26346567 |

### 💬 What Happened
A brand-new wallet just dropped 0.011 ETH (about $27) into a service called FixedFloat 1. Think of it like dropping a small package into a slot machine that hides who sent it and where it ends up. The sender had no prior transactions and no balance, so it’s like a newcomer with a brand-new wallet that’s never used before.

### 🔥 The Roast
Score 85 on the no‑KYC‑offramp rule (meaning the sender can move money without proving who they are). That’s basically the crypto equivalent of a shady alley bar that doesn’t ask for ID. The wallet is brand new and empty—like a fresh‑minted coin that’s never been touched. MEDIUM (rule score 85) If you’re wondering why we’re flagging it, it’s because we’re not sure if the money is coming from a clean source or a shady one.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

MEDIUM (rule score 85) If no additional red flags appear, consider filing a low‑priority SAR.

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
Suspicious Activity Report: A newly created wallet (0 days old) with no prior transactions sent 0.0110 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1). The transaction occurred in block 26346567 with a total value of $27 USD. Rule cited: no_kyc_offramp – the transfer was made to an off‑ramp that does not require identity verification. The wallet’s balance post‑transaction is zero, indicating an immediate outflow. MEDIUM (rule score 85)

</details>

---

## Finding #8: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x77a2fff175b5a94070ef41c6569e3415064dce10` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2920 ETH** ($708) |
| **Blocks** | 26346564-26346564 |

### 💬 What Happened
A brand-new wallet, created today, sent 0.2920 ETH (about $708) to a single address called FixedFloat 1. The sender had never moved any money before and now has zero balance, like a new kid dropping a note into a mailbox that hides who wrote it. The transaction is the only one in the block, so there's nothing to compare it to.

### 🔥 The Roast
MEDIUM (rule score 85) The no_kyc_offramp rule (meaning the transaction went to a service that lets people cash out without identity verification) scored a whopping 85. It's like sending money through a black hole that doesn't ask for your ID—perfect for anyone who likes to keep their financial fingerprints on the down low.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review by compliance staff, verify source of funds, and monitor the receiving address for subsequent activity.

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
The transaction originates from a 0‑day wallet with a single outbound transfer of 0.2920 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f, classified as FixedFloat 1. The wallet exhibits no KYC verification and has no prior activity, triggering rule no_kyc_offramp with a composite score of 85. MEDIUM (rule score 85) Further human review is warranted to assess the source of funds and destination intent.

</details>

---

## Finding #9: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x777d33eab592d0e38c89f08d12ebf92f3699b793` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346558-26346558 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of Ethereum (0.0001 ETH, about zero dollars) to a service called FixedFloat 1. It’s like dropping a single coin into a slot machine that then shuffles it so you can’t see where it came from.

### 🔥 The Roast
This fresh wallet, 0 days old, is playing the ‘I’m too cool for KYC’ game by sending a blip of ETH to a service that normally wants you to show ID. The no_kyc_offramp rule (meaning the wallet tried to cash out without any identity verification) blew up louder than a toddler on a sugar high. It’s basically a digital tip for a shady barista that says, ‘I left my ship in the harbor, no one knows I’m here.’

### 🎯 Verdict & Next Steps
**MEDIUM — The transaction originates from a brand‑new wallet with no KYC off‑ramp activity, triggering the no_kyc_offramp rule, indicating potential layering risk.**

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
The transaction originates from a new wallet (age 0 days) with minimal activity (2 total transactions) and no current balance, indicating a potential layering attempt. MEDIUM (rule score 85) MEDIUM (rule score 85) The transaction involves a single ETH transfer to FixedFloat 1, a service known to facilitate fiat conversion and therefore a potential exit point for illicit funds.

</details>

---

## Finding #10: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa3abbfec5350da26a0a54de9a757bcd4fda1c085` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0150 ETH** ($36) |
| **Blocks** | 26346533-26346533 |

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

## Finding #11: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x9af073e1ba20d3f00862c95d3b6b4559eaf1fa71` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2920 ETH** ($708) |
| **Blocks** | 26346529-26346529 |

### 💬 What Happened
A brand-new wallet sent 0.292 ETH (about $708) to a service that lets you cash out without any identity check. Think of it like dropping a fresh package into a locker that instantly gives you cash, but the locker never asks for a receipt. The sender had no prior activity and now has zero balance after sending.

### 🔥 The Roast
This wallet is fresher than a morning coffee—0 days old, 1 transaction, and zero balance left. It just shoved 0.292 ETH into FixedFloat 1, a platform that lets you off‑ramp without a KYC check (Rule no_kyc_offramp). Basically, it's the crypto equivalent of a door that opens to the street but no one knows who you are. The engine flagged it with an 85 score—so it’s not a ghost, it’s a potential red flag.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a new wallet and a no‑KYC off‑ramp service, which are typical indicators of layering or anonymity exploitation, but no direct evidence of illicit activity.**

Flag the wallet for enhanced monitoring and request additional context from the platform about the source of funds. If further suspicious patterns emerge, consider filing a SAR.

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
On block 26346529, wallet 0x9af073e1ba20d3f00862c95d3b6b4559eaf1fa71, which has zero days of age and only one transaction, transferred 0.292 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1). This activity satisfies Rule no_kyc_offramp, indicating an off‑ramp transfer to a service that does not perform identity verification. MEDIUM (rule score 85) The composite score of 85 triggers a medium‑risk review for potential layering or anonymity exploitation.

</details>

---

## Finding #12: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x41b491a844effccfd43b61037308d3194e62b891` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0868 ETH** ($211) |
| **Blocks** | 26346503-26346503 |

### 💬 What Happened
A brand‑new wallet, which had been created just moments ago and had no money in it, sent about 0.0868 ETH (roughly $211) to another address that looks like a place where people can turn crypto into cash. It’s like someone just got a new wallet and dropped a small cash bundle into a dropbox that doesn’t ask for ID or proof of where the money came from.

### 🔥 The Roast
Looks like a fresh‑minted wallet decided to play hide‑and‑seek with regulators. The address had zero balance before the send, so it’s like borrowing from the void. The transaction was a single ETH transfer to a FixedFloat 1 address, which is basically a known off‑ramp that doesn’t do KYC. The AML engine gave it a score of 85 on the rule [no_kyc_offramp]—which is the same rule that flags when a wallet with no identity verification sends funds to a place that can easily convert them to fiat. In short, it’s a classic ‘new wallet to exchange’ pattern that’s got compliance waving a red flag.

### 🎯 Verdict & Next Steps
**MEDIUM — The new wallet with no KYC sending ETH to an off‑ramp‑like address triggers a high composite score of 85, indicating moderate risk.**

Flag the transaction for manual review and place the sender address on a watchlist for future monitoring; consider requesting source‑of‑funds information if possible.

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
Transaction involves a newly created wallet (0 days old) with no prior activity, sending 0.0868 ETH (≈$211) to a FixedFloat 1 address. The AML engine identified the pattern "no_kyc_offramp" with a composite score of 85, indicating potential risk of an unverified off‑ramp. The sender wallet’s zero balance before the transaction and lack of KYC documentation further raise suspicion of possible illicit activity. Compliance should review the transaction and monitor subsequent activity for additional suspicious patterns.

</details>

---

## Finding #13: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xed51429c81529374c668b8f3ff8f29ab7ed5f186` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0825 ETH** ($200) |
| **Blocks** | 26346498-26346498 |

### 💬 What Happened
A brand‑new wallet just sent 0.0825 ETH (about $200) to a FixedFloat service that lets users move money without KYC. Think of it like dropping a mysterious parcel into a machine that forwards it to an unknown recipient, making it hard to trace where the money came from. The whole thing happened in a single block, so there was no time for anyone to intervene.

### 🔥 The Roast
So we have a 0‑day‑old wallet, like a newborn baby that just learned to walk, sending a tidy 0.0825 ETH to a FixedFloat address. That’s a classic no‑KYC off‑ramp (meaning the service doesn’t ask for your ID before letting you cash out). The AML engine gave it an 85/100 because it’s basically saying, "Hey, this is a suspicious move because people love to hide their money in a place that doesn’t ask for passports." It’s like putting a pizza in a bag and sliding it into a black‑market delivery van. If you’re wondering why the engine is shouting, it’s because the wallet was brand new and the transaction was a single shot to an anonymous service.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a new wallet sending funds to a no‑KYC off‑ramp, meeting the no_kyc_offramp rule with a high score, indicating moderate risk of anonymity usage.**

Flag the transaction for manual review. MEDIUM (rule score 85)

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
The transaction involves a new wallet (wallet age 0 days) sending 0.0825 ETH to a FixedFloat address, which falls under the no_kyc_offramp rule, scoring 85. This pattern is indicative of potential layering or anonymity usage. The lack of KYC and the single transaction to a known service designed for off‑ramp anonymity trigger a flag per AML policy. Further investigation is required to confirm source of funds and intended destination.

</details>

---

## Finding #14: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf39cc9921b21febcc6572d48f1de9be957b0bfcc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0612 ETH** ($148) |
| **Blocks** | 26346497-26346497 |

### 💬 What Happened
A brand-new wallet just sent 0.0612 ETH to a FixedFloat 1 address, which is like dropping a package into a slot that hides who sent it. The sender had no previous history and this was its only transaction. MEDIUM (rule score 85)

### 🔥 The Roast
MEDIUM (rule score 85) The AML engine gave it a whopping 85 on the no_kyc_offramp rule (meaning there’s no identity verification on the receiving side), which is higher than the score you'd get for a bad pizza order. MEDIUM (rule score 85) But hey, at least we know the kid has a new address and hasn't used the old one yet!

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review and add the sender wallet to a watchlist. Monitor for additional activity and consider further due diligence if more transactions occur.

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
MEDIUM (rule score 85) The AML engine flagged the activity under rule no_kyc_offramp, scoring 85, indicating a high likelihood of an unverified off‑ramp. MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #15: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x643290675cffd6f190e6af504c024ec404ce55dc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0050 ETH** ($12) |
| **Blocks** | 26346494-26346494 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (about $12) to a service called FixedFloat 1, which is like dropping a small parcel into a mysterious box that can turn it into something else without asking who you are. The sender's account was created today and had no previous history, so it's a brand-new, no‑history wallet. There was only this single transaction, and the sender had no ETH left after sending it.

### 🔥 The Roast
Looks like someone just opened a fresh wallet, put a couple of coins in, and sent it straight to FixedFloat 1—like a kid giving a pizza slice to a friend and hoping the friend will hide it in a secret stash. Scored 85 on the no_kyc_offramp rule (meaning they sent crypto to a service that lets you convert it without proving identity), so it's as suspicious as a magician who never shows the trick. The wallet has zero balance now, which is classic 'no leftovers' strategy to avoid leaving a paper trail. Bottom line: it's a textbook example of a 'new wallet, no KYC, off‑ramp' scenario—like a sneaky spy dropping a message into a black‑mail box.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a newly created wallet depositing a modest amount into a non‑KYC off‑ramp, raising potential structuring and anonymity concerns.**

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
The transaction originates from a wallet that was created on the same day as the transfer and has a single outgoing transaction of 0.005 ETH. The destination is FixedFloat 1, a service identified in the AML database as an off‑ramp with no KYC (rule: no_kyc_offramp). The sender wallet has no prior activity and a zero balance post‑transfer, indicating a possible structuring attempt to obscure the source. This activity warrants a manual review under the 'No KYC Off‑Ramp' policy.

</details>

---

## Finding #16: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x881e00548993f07e8349a86db08a4c91e39d2625` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2828 ETH** ($686) |
| **Blocks** | 26346494-26346494 |

### 💬 What Happened
A brand‑new wallet (created just today) sent about 0.28 ETH (roughly $686) to a service that doesn’t ask for identity verification. Think of it like dropping a package into a slot that hides who shipped it. No other transfers or history—just a single, clean‑looking move.

### 🔥 The Roast
Scored a whopping 85 on the no‑KYC off‑ramp rule (meaning the money went to a place that doesn’t require you to show a driver's license). This is basically like paying cash to a shady bar that never asks for your ID. The wallet was brand new and had zero balance before the move—classic "I’m just a ghost" style. No tokens, no mixers, just straight‑up ETH to the void. If you’re hoping to avoid scrutiny, try not to use the same wallet for every transaction.

### 🎯 Verdict & Next Steps
**MEDIUM — new wallet, single transaction to a non‑KYC platform suggests possible layering but lacks corroborating red flags.**

Flag the wallet for manual review, request source of funds documentation, and monitor for subsequent activity to see if the funds are moved to another address or mixed.

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
The transaction involves a wallet with zero age, single activity, and zero pre‑transaction balance, which triggers Rule no_kyc_offramp (score 85). The transfer of 0.2828 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1) meets the criteria for a deposit to a non‑KYC off‑ramp. No token transfers or additional suspicious patterns are present. This activity warrants further scrutiny under the AML framework.

</details>

---

## Finding #17: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x36344ab20851467b5dcf5a931c8b678c57ace268` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346486-26346486 |

### 💬 What Happened
A brand-new wallet, created just today, sent 0.0001 ETH (about a few cents) to an address that is known to let people withdraw crypto without providing identity verification. Think of it as a new kid dropping a tiny note into a public mailbox that everyone can read, but no one knows who wrote it.

### 🔥 The Roast
So we have a fresh wallet that’s 0 days old and only ever did two transactions—one of them a micro‑payment to a no‑KYC off‑ramp. The engine gave it an 85, which is basically the same score you’d get for a pizza delivery driver with no ID. It’s like someone tried to hide in a crowd by sending a single grain of rice to a black hole that doesn’t ask for a passport. MEDIUM (rule score 85) If you’re looking for drama, this is about as dramatic as a single drop of ketchup on a giant pizza.

### 🎯 Verdict & Next Steps
**MEDIUM — because the transaction involves a brand‑new wallet sending funds to a no‑KYC off‑ramp, which raises suspicion but is not conclusive evidence of wrongdoing.**

Flag the transaction for manual review, verify the identity of the sender and the legitimacy of the destination address, and request additional KYC information if possible.

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
The transaction originates from a wallet that was created today (wallet age 0 days) and has only two total transactions, with a balance of 0.000000 ETH. The transfer of 0.0001 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f falls under rule no_kyc_offramp, indicating a deposit to a FixedFloat 1 off‑ramp that does not perform KYC. MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #18: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x0f410c2ddef7a96ccd63347c9959cee9e8fd6b2b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346482-26346482 |

### 💬 What Happened
A brand new wallet sent a tiny amount of ETH to a service that turns crypto into cash without asking for identity. It’s like dropping a handful of coins into a black box that will later hand them out to anyone, but we don’t know who the original owner was.

### 🔥 The Roast
Scored 85 on the no‑kyc‑offramp rule, meaning the wallet tried to sneak ETH into a service that doesn’t ask for ID. MEDIUM (rule score 85) The wallet is so fresh it’s still on its birth certificate, and the amount is so small it could fit in a thimble, but the pattern screams ‘hide‑and‑seek’ for regulators. MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review, cross‑reference the involved addresses with internal and external watchlists, and monitor subsequent activity from the sender and receiver for any escalation of suspicious patterns.

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
The sender address (0x0f410c2ddef7a96ccd63347c9959cee9e8fd6b2b) is a new wallet (0 days old) with only two transactions and no balance, sending 0.0001 ETH to a FixedFloat 1 address. MEDIUM (rule score 85) The transaction count, wallet age, and low value align with known patterns of suspicious activity involving new wallets and unregulated cash‑out services.

</details>

---

## Finding #19: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1eb64b5c0ee44bba072deabfe92acebcb233ef4c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346480-26346480 |

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
| Total Transactions | 2 |
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
| **Sender** | `0x8fad261adbcc6d30202edac35539b2bf18fad353` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346469-26346469 |

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
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #21: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x28395b8eac3c1b63837693895d5a8093ce7ecf3c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0503 ETH** ($122) |
| **Blocks** | 26346466-26346466 |

### 💬 What Happened
A brand‑new wallet that hasn’t existed for even a day just sent 0.0503 ETH (about $122) to a service that lets people move crypto around without showing who they are. It’s like a fresh‑out‑of‑the‑box delivery driver dropping a package into a drop‑box that hides the sender’s address. The sender has no balance left after sending and hasn’t done any other transactions yet.

### 🔥 The Roast
So we have a wallet that’s newer than your last Tinder match, with zero KYC, making a quick dip of 0.0503 ETH into a ‘FixedFloat 1’ service (think of it as a crypto version of a mystery box). The AML engine gave it a 85 out of 100, which is basically saying, ‘Hey, this looks like a no‑KYC off‑ramp, so we’re not too happy.’ It’s like paying a delivery fee to a courier that refuses to give you a receipt.

### 🎯 Verdict & Next Steps
**MEDIUM — the lack of KYC and use of a known off‑ramp service elevate risk, but the transaction size is relatively small.**

Flag the transaction for manual review by the compliance team, and request additional information on the source of funds and the ultimate beneficial owner of the FixedFloat 1 address.

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
The transaction involved a newly created wallet (age 0 days, only 1 transaction) sending 0.0503 ETH to a FixedFloat 1 address, a service identified as a no‑KYC off‑ramp (Rule: no_kyc_offramp). The sender’s wallet shows no remaining balance and zero prior activity. MEDIUM (rule score 85)

</details>

---

## Finding #22: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x44f639f32c29b9955a75eaf3756bf0f2dda743f7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346454-26346454 |

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
| Total Transactions | 2 |
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
| **Sender** | `0xda67382fc7b0848e1cc3c7eaf81f6435f46c2d90` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346453-26346453 |

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
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #24: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4a84b697cce6b4712b65f608934b31f28e4d3111` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346448-26346448 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (0.0001, basically nothing) to an exchange‑like address called FixedFloat 1. Think of it as a new kid dropping a minuscule note into a mailbox that will instantly turn it into cash for someone else, but no one knows who the kid is or where the note came from.

### 🔥 The Roast
Looks like someone just tried to play hide‑and‑seek with their crypto. They created a brand‑new wallet, sent 0.0001 ETH to FixedFloat 1, and then vanished faster than a magician’s rabbit. This is the classic no‑KYC off‑ramp dance (meaning the address is a known “no‑KYC” withdrawal point that lets you cash out without identity checks). The score of 85? MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM — The combination of a brand‑new wallet and a no‑KYC off‑ramp transaction raises suspicion, though the amount is small and no other red flags are present.**

Flag the wallet for manual review, gather additional context such as any linked addresses or prior activity, and monitor for subsequent transactions that could indicate layering or integration steps.

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
The transaction originates from a wallet aged 0 days with only 2 total transactions and a zero balance, indicating a potentially newly created or inactive account. The transfer of 0.0001 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1) triggers the rule no_kyc_offramp (score 85), which flags no‑KYC off‑ramp activity. MEDIUM (rule score 85)

</details>

---

## Finding #25: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3d976f80a6fbb4d2bf9c4b2587f50d271ae68b91` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346446-26346446 |

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
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #26: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5f5fb9dec1bb3e9aafd76eaeaf08674d6412f282` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346428-26346428 |

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

## Finding #27: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4b8cc3bc566a15f798dff6efd48a35ed3e493a09` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.7000 ETH** ($1,698) |
| **Blocks** | 26346423-26346423 |

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
| **Sender** | `0x195ea0b3b4a3b5438341db77ab3c68974f02d9d0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26346413-26346413 |

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
| **Sender** | `0x8f5e73627f48606c30dba96af303fb58e3c90aef` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0001 ETH** ($0) |
| **Blocks** | 26346409-26346409 |

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

## Finding #30: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x677471e0bd452dab34d8ed3dc90d1fcea72d0cc3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$30** (30 USDT) |
| **Blocks** | 26346602-26346602 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $30 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x97ccdbea4632140639ad5ea9b944aa034eb15fd4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **25** token transfers totaling **$4,135** (10 USDT, 16 USDT, 149 USDC, 699 USDC, 32 USDT) |
| **Blocks** | 26346413-26346599 |

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
- **stablecoin_mixing** (+80) — 24 stablecoin transfer(s) to Across SpokePool V2: $4,135 total (USDT, USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x28a4d41776968c1201a807ec51ffb405362b8882` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** token transfers totaling **$2,075** (725 USDT, 500 USDT, 600 USDT, 250 USDT) |
| **Blocks** | 26346452-26346598 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to Across SpokePool V2: $2,075 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc186fa914353c44b2e33ebe05f21846f1048beda` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** token transfers totaling **$76** (0 WETH, 71 USDC, 4 WETH, 0 WBTC) |
| **Blocks** | 26346432-26346591 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $71 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0038dfb2bbc353daa6ad22cb11ee1d78f41b59cd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$147** (9 USDT, 99 USDC, 39 USDC) |
| **Blocks** | 26346544-26346583 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $147 total (USDT, USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9e64d18073cd8ec20e2680124d0551ba1629fa20` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **8** token transfers totaling **$3,621** (0 WETH, 0 WETH, 1,000 USDC, 0 WETH, 907 USDC) |
| **Blocks** | 26346518-26346582 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $3,619 total (USDT, USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x07ffef474a5f75db613b29e27db60e0e0fcc7298` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$983** (983 USDC) |
| **Blocks** | 26346539-26346539 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $983 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3a23f943181408eac424116af7b7790c94cb97a5` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$6** (6 USDC) |
| **Blocks** | 26346514-26346514 |

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

## Finding #38: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9a47f3289794e9bbc6a3c571f6d96ad4e7baed16` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$991** (0 WETH, 991 USDT) |
| **Blocks** | 26346428-26346500 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $991 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x60ac95ec1153aa8199751917ede25d0ca49a36e2` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$329** (329 USDT) |
| **Blocks** | 26346499-26346499 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $329 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3d2d2538b2dde72ac9f2730afe1799040f08f4f0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDT) |
| **Blocks** | 26346489-26346489 |

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

## Finding #41: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$13** (13 USDT) |
| **Blocks** | 26346482-26346482 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $13 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x50cfe7c1938db66a1a6d2e86d36f39fbef3d5c4a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$1,248** (1,248 USDC) |
| **Blocks** | 26346429-26346429 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $1,248 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x511e6fd8c87e617575e3778ec068fc6fccd47450` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346602-26346602 |

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
| Wallet Age | 79 days |
| Total Transactions | 919 |
| Current Balance | 0.008250 ETH |
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
| **Sender** | `0x8cb18339fac3175d4d7da15462417f8c43cfcd5d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.2082 ETH** ($505) |
| **Blocks** | 26346573-26346573 |

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
| Wallet Age | 112 days |
| Total Transactions | 49 |
| Current Balance | 0.001694 ETH |
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
| **Sender** | `0x4933836e2bde547450f61e97ef10312ec9a769f7` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346572-26346572 |

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
| Wallet Age | 655 days |
| Total Transactions | 16 |
| Current Balance | 0.001799 ETH |
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
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346558-26346558 |

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
| Wallet Age | 33 days |
| Total Transactions | 9290 |
| Current Balance | 0.020023 ETH |
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
| **Sender** | `0xae4611cae4846e015383d6dc149f293633f1973d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.1210 ETH** ($293) |
| **Blocks** | 26346554-26346554 |

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
| Wallet Age | 1649 days |
| Total Transactions | 1241 |
| Current Balance | 0.002074 ETH |
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
| **Sender** | `0x0361897d757d13a4afad64a2e1bc561b96a8c7cf` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346537-26346537 |

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
| Total Transactions | 15912 |
| Current Balance | 50.801066 ETH |
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
| **Sender** | `0x35c418f55a66c03584961f924abd2fffbde1277a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.2000 ETH** ($485) |
| **Blocks** | 26346524-26346531 |

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
| Wallet Age | 342 days |
| Total Transactions | 188 |
| Current Balance | 0.043939 ETH |
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
| **Sender** | `0x899652064ecad79feb6189c9f729d2cf07d059a5` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0050 ETH** ($12) |
| **Blocks** | 26346514-26346514 |

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
| Wallet Age | 1301 days |
| Total Transactions | 818 |
| Current Balance | 0.001622 ETH |
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
| **Sender** | `0x03f4ce70b7d5f678c45a43dbc92c45a22ce9134c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0370 ETH** ($90) |
| **Blocks** | 26346514-26346514 |

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
| Wallet Age | 76 days |
| Total Transactions | 40 |
| Current Balance | 0.000114 ETH |
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
| **Sender** | `0xd4c6a7742227e0c323716f76bf99eaf5eb22787f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0100 ETH** ($24) |
| **Blocks** | 26346509-26346509 |

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
| Wallet Age | 638 days |
| Total Transactions | 406 |
| Current Balance | 0.860208 ETH |
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
| **Sender** | `0xf71e7dadfa6d6ae6921fecee353604e0e809363d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346503-26346503 |

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
| Wallet Age | 373 days |
| Total Transactions | 20 |
| Current Balance | 0.000558 ETH |
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
| **Sender** | `0x90a443ad72d91a042cec1e1404cfa396f90171ad` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346490-26346490 |

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
| Wallet Age | 529 days |
| Total Transactions | 140 |
| Current Balance | 0.000138 ETH |
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
| **Sender** | `0x0dc1e92fbcc8413b1341f4c1b1c203c3b1a03d73` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346489-26346489 |

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
| Wallet Age | 366 days |
| Total Transactions | 12699 |
| Current Balance | 0.021735 ETH |
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
| **Sender** | `0x1ecd7118b7497529d38bd5375491f6bfd5dc76da` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346485-26346485 |

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
| Wallet Age | 13 days |
| Total Transactions | 24 |
| Current Balance | 0.000541 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #57: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xc1e27fcb45ee3a300ab8292a13ab1cc341a850a7` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346477-26346477 |

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
| Current Balance | 0.000485 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #58: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x20bebbf8df62e61a0b19d0bdd90ef796b901238b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.5600 ETH** ($1,358) |
| **Blocks** | 26346470-26346470 |

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
| Wallet Age | 572 days |
| Total Transactions | 2005 |
| Current Balance | 0.038385 ETH |
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
| **Sender** | `0x9ed96b285f71aa4c807eebfab774b2dab1149b69` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0035 ETH** ($8) |
| **Blocks** | 26346466-26346466 |

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
| Wallet Age | 1657 days |
| Total Transactions | 22 |
| Current Balance | 0.000393 ETH |
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
| **Sender** | `0x75a7c0268ca0f40146c0fd38ca2787a0b0d9370c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346427-26346454 |

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
| Wallet Age | 58 days |
| Total Transactions | 5545 |
| Current Balance | 0.055318 ETH |
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
| **Sender** | `0xbf58f81d7a175cb3564dd5253d0122bcb206886f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.3335 ETH** ($809) |
| **Blocks** | 26346452-26346452 |

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
| Wallet Age | 747 days |
| Total Transactions | 240 |
| Current Balance | 0.004935 ETH |
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
| **Sender** | `0x240e4dc671bdf3ed1f82cf46a8609f6a6f981ad7` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346441-26346441 |

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
| Wallet Age | 890 days |
| Total Transactions | 115 |
| Current Balance | 1.001257 ETH |
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
| **Sender** | `0x3eff2b7c1cbf138d95673eabfec1dd6735986fec` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.3940 ETH** ($956) |
| **Blocks** | 26346422-26346437 |

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
| Wallet Age | 53 days |
| Total Transactions | 105 |
| Current Balance | 0.600115 ETH |
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
| **Sender** | `0x1306d3126b5506c3e8d402e9a81cacffc725134c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346429-26346429 |

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
| Wallet Age | 1188 days |
| Total Transactions | 127 |
| Current Balance | 0.002197 ETH |
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
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346427-26346427 |

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
| Wallet Age | 1080 days |
| Total Transactions | 213109 |
| Current Balance | 0.891521 ETH |
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
| **Sender** | `0xe05fb2b4de323e3a2e72ec6781a1224ec9a7cbaa` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346417-26346417 |

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
| Wallet Age | 1302 days |
| Total Transactions | 439 |
| Current Balance | 0.000491 ETH |
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
| **Sender** | `0x1df24190992c9c8d8496199c9596169168e61ac5` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26346408-26346408 |

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
| Wallet Age | 352 days |
| Total Transactions | 1429 |
| Current Balance | 0.000216 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**67 suspicious findings** detected across 67 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 4 |
| 🟠 HIGH | 1 |
| Wallets flagged | 67 |
| Suspicious value | 3.7806 ETH ($9,169) + $40,279 in stablecoins |
| Blocks scanned | 26346404 — 26346603 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 6 of 25 attempted analyses this run.

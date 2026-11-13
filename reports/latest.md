# 🔥 AML Roaster Report
**2026-11-13 05:45 UTC** · Ethereum Mainnet · ETH $1,915.28
**Blocks:** 26403801 — 26404000 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26403801 to 26404000 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xef1ec136931ab5728b0783fd87d109c9d15d31f1` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **6** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403822-26403996 |

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
| Wallet Age | 1088 days |
| Total Transactions | 214584 |
| Current Balance | 0.778776 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 6 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 6 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #2: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x07ae8551be970cb1cca11dd7a11f47ae82e70e67` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **30** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403808-26403993 |

### 💬 What Happened
A wallet sent 30 tiny, identical Ethereum transfers of practically nothing to a bridge that moves funds between chains. It’s like someone dropping a handful of coins into a slot machine, one by one, hoping no one notices the pattern. The transfers were all the same tiny amount, which is a classic sign of someone trying to break up a larger movement into many small steps.

### 🔥 The Roast
Look at this: 30 zero‑ETH deposits in a row—scored 70 on structuring (meaning they’re doing the classic smurfing trick, like a magician dividing a big trick into tiny, almost invisible bits). The engine also gave a 60 on peel_chain_linear (so the pattern is a straight‑line peel chain, like peeling an onion layer after layer). And don’t forget the 65 on bridge_hop, which means the funds hit a cross‑chain bridge—because who doesn’t love a good hop to make the money travel like a tourist on a hop‑scotch map? All this adds up to a suspicious activity that’s more confusing than a toddler’s math test.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain, and cross‑chain bridge transfer presents a high‑risk pattern for illicit layering.**

Initiate manual review of the sender’s source of funds and any related addresses. Apply enhanced monitoring to the wallet and any future activity, and consider flagging for compliance escalation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2799 days |
| Total Transactions | 853443 |
| Current Balance | 11.986710 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 30 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 30 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Rule structuring: 30 identical transfers of 0.0000 ETH, indicating potential structuring of funds to avoid detection thresholds. Rule peel_chain_linear: sequential identical deposits suggest a layering technique to obscure origin. Rule bridge_hop: transfer to Across SpokePool V2 indicates use of a cross‑chain bridge, adding complexity to the transaction path. CRITICAL (rule score 195)

</details>

---

## Finding #3: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x20c58c01cc73da90d5ca4dfb4357228c636422d6` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **15** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403814-26403993 |

### 💬 What Happened
The sender made 15 tiny deposits of 0.0000 ETH into a cross‑chain bridge. All deposits were identical, like dropping a dozen identical empty bottles into the same slot at a vending machine. The total value was zero because each transfer was negligible, but the pattern looks suspicious.

### 🔥 The Roast
Score 195? That's not a gym membership, that's a warning. 15 identical 0.0000 ETH deposits? It's like dropping a dozen empty glass bottles into the same slot at a vending machine—who knows where the real cash goes? The engine flags this as [structuring] (meaning the same amount sent repeatedly to dodge detection thresholds) with 70 points, [peel_chain_linear] (meaning a sequence of similar moves, like peeling a linear chain) with 60 points, and [bridge_hop] (meaning the funds hopped across chains via a bridge) with 65 points. If you were trying to be a magician, you should pick a trick that doesn't involve smurfing.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain layering, and cross‑chain bridge activity constitutes a high‑risk suspicious pattern.**

Flag the wallet for manual investigation, monitor subsequent activity for larger transfers, and consider adding it to the watchlist if further patterns emerge.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 41 days |
| Total Transactions | 12075 |
| Current Balance | 0.021381 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 15 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 15 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction record shows 15 identical 0.0000 ETH transfers from wallet 0x20c58c01cc73da90d5ca4dfb4357228c636422d6 to 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2 between blocks 26403814 and 26403993. This activity matches Rule [structuring] with a score of 70, indicating potential smurfing to evade detection thresholds. Rule [peel_chain_linear] with a score of 60 further suggests layering through a linear peel chain. Rule [bridge_hop] with a score of 65 confirms cross‑chain movement, a known risk factor. CRITICAL (rule score 195)

</details>

---

## Finding #4: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xfd0aa7548823c40be6dd85682f0342f35dee121a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **19** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403805-26403988 |

### 💬 What Happened
The sender made 19 almost identical tiny ETH deposits to a cross‑chain bridge, like dropping 19 identical envelopes into a mailbox that hides who sent them. Each deposit was 0.0000 ETH, and they all happened one after another within the same block range. The receiver is Across SpokePool V2, which moves funds between Ethereum and other blockchains.

### 🔥 The Roast
CRITICAL (rule score 195) 19 identical 0.0000 ETH deposits— that’s structuring (meaning sending many tiny amounts to dodge detection) in a row. The peel_chain_linear rule (a fancy way of saying a chain of similar moves) flagged it too, and bridge_hop (because the funds hopped into a cross‑chain bridge) added another hit. It’s like a toddler hiding a cookie by putting one in each of 19 jars— the cookie is invisible, but the pattern screams ‘cheater’.

### 🎯 Verdict & Next Steps
**CRITICAL — the pattern of 19 identical small deposits combined with cross‑chain bridging indicates a high risk of structuring and layering, exceeding the threshold for immediate review.**

Initiate a manual review of the sender's source of funds and the purpose of the bridge transfer; consider flagging the address for monitoring and, if warranted, request additional KYC information from the associated parties.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 91 days |
| Total Transactions | 30757 |
| Current Balance | 0.463740 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 19 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 19 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction record shows 19 consecutive ETH transfers of 0.0000 ETH from address 0xfd0aa7548823c40be6dd85682f0342f35dee121a to address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 via Across SpokePool V2. The AML engine flagged structuring (score 70) due to identical small deposits, peel_chain_linear (score 60) indicating a layering pattern, and bridge_hop (score 65) for cross‑chain movement. CRITICAL (rule score 195)

</details>

---

## Finding #5: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xe58dc537f30b3abff1803b414c181aa4fa5edc41` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403817-26403974 |

### 💬 What Happened
A brand‑new wallet sent four tiny amounts of Ethereum (each 0.0000 ETH) to a bridge called Across SpokePool V2. The deposits were all identical and came in quick succession, like someone dropping identical coins into a slot that hides who sent them. The total amount was zero dollars, but the pattern looks suspicious.

### 🔥 The Roast
Looks like this wallet decided to play a game of "copycat" with its deposits – 70 points on the structuring rule (meaning all four deposits were the same, like a toddler with a stack of identical toy blocks), 60 on peel_chain_linear (layering like a bad magician), and 65 on bridge_hop (cross‑chain hop, basically a bridge to the dark side). CRITICAL (rule score 195)

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of identical small deposits and a cross‑chain bridge hop signals a high likelihood of structuring and layering, requiring immediate investigation.**

Flag this wallet for manual AML review; request source‑of‑funds documentation and monitor for additional transactions; consider placing a temporary hold on related assets pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 4 days |
| Total Transactions | 137 |
| Current Balance | 0.007795 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet 0xe58dc537f30b3abff1803b414c181aa4fa5edc41, aged 4 days with 137 total transactions and a current balance of 0.007795 ETH, performed four identical ETH transfers (0.0000 ETH each) to address 0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5 on Across SpokePool V2 between blocks 26403817-26403974. This activity triggers the structuring rule (score 70), peel_chain_linear rule (score 60), and bridge_hop rule (score 65), resulting in a composite risk score of 195. The pattern is consistent with structuring and layering behaviors, indicating a potential attempt to obscure the source of funds. The wallet remains active with no prior activity history, heightening the need for manual review.

</details>

---

## Finding #6: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x42ca6e3cbf2828c5fb170f2772b816ddd2c8694a` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403832-26403919 |

### 💬 What Happened
The sender pushed five separate, identical 0.0000‑ETH transfers into a bridge service called Across SpokePool V2. Imagine dropping five empty envelopes into a machine that forwards mail without showing who sent them—no real money moved, but the pattern looks like someone is trying to hide how they’re moving funds.

### 🔥 The Roast
Five empty ETH packets, like a magician’s disappearing act, but instead of money it’s just zeros. That’s structuring—splitting a transaction into tiny, identical pieces so you can’t see the whole picture. Then peel_chain_linear—peeling a banana in one smooth line. And a bridge hop—crossing the blockchain equivalent of a ferry to avoid the toll. Basically, this wallet is playing hide‑and‑seek with your compliance software, but nobody’s actually paying.

### 🎯 Verdict & Next Steps
**CRITICAL: The combination of structuring, peel chain, and bridge hop patterns with a high volume of activity signals a high risk of illicit fund movement.**

Flag the address for enhanced due diligence, request source‑of‑funds information, and monitor for future activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 332 days |
| Total Transactions | 29560 |
| Current Balance | 0.199996 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Rule: Structuring (score 70) – five identical 0.0000 ETH deposits indicating potential smurfing. Rule: Peel Chain Linear (score 60) – sequential similar deposits showing layering. Rule: Bridge Hop (score 65) – use of Across SpokePool V2, a cross‑chain bridge, to obscure origin. Evidence: five zero‑value ETH transfers in blocks 26,403,832‑26,403,919 to a bridge address, with a high overall transaction count and recent activity.

</details>

---

## Finding #7: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x6cd1b8cfcd2ca2bcdb46a2d96bd22b92e16ba427` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403890-26403906 |

### 💬 What Happened
The sender made three identical, almost invisible ETH deposits of 0.0000 each, all landing in a cross‑chain bridge that acts like a passport office. Think of it as someone dropping three identical envelopes into a box that hides who mailed them, then sending that box to a different country. The total value is zero, but the pattern suggests an attempt to hide the source of funds.

### 🔥 The Roast
You’ve got a wallet that’s been around for 247 days, but it’s doing a weird dance of 18,269 transactions that look like a bad TikTok challenge: three identical 0 ETH deposits in a row. That’s the textbook "structuring" move (meaning the sender is trying to break up a single transaction into a bunch of tiny ones so it’s harder to spot). Then the "peel_chain_linear" pattern (like peeling a banana one slice at a time) shows they’re layering these zeros to make the trail fuzzy. And the "bridge_hop" (the wallet is hopping over a cross‑chain bridge, basically a teleportation portal) is the cherry on top—like sending the envelope to another country to make it look legit. Bottom line: this looks less like a harmless prank and more like a stealthy smurfing operation.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual review; initiate a detailed transaction tracing exercise and consider filing a SAR with relevant authorities if further evidence emerges.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 247 days |
| Total Transactions | 18269 |
| Current Balance | 0.067763 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Rule: structuring (score 70) – three identical 0 ETH deposits indicate an attempt to conceal transaction volume. Rule: peel_chain_linear (score 60) – sequential deposits form a peel chain, a common layering technique. Rule: bridge_hop (score 65) – use of Across SpokePool V2 cross‑chain bridge suggests an effort to obfuscate origin. Evidence: 18,269 total txs, 0.067 ETH balance, active last day, block range 26403890-26403906.

</details>

---

## Finding #8: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xa60ded4c899e7560dc4ca56b57fbab25c90addeb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **16** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403814-26404000 |

### 💬 What Happened
Think of a person stuffing 16 identical, empty envelopes into a mailbox all at once, then sending them through a maze of delivery services to hide who sent them. In this case, the wallet sent 16 zero‑value transfers to a decentralized exchange settlement address, all at the same block range, trying to disguise the pattern of activity.

### 🔥 The Roast
This guy's playing a game of Monopoly with zero rent—he’s dropping 16 identical, empty envelopes (0 ETH) into the same mailbox (CoW Protocol GPv2Settlement) to hide the fact that he’s actually moving money around. The engine flagged it as structuring (splitting money into tiny chunks), peel_chain_linear (a straight‑line chain of the same move), and bridge_hop (using a cross‑chain bridge to make the trail harder to follow). Basically, he’s trying to look like a very organized janitor cleaning up a mess he made himself.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the transaction for manual review, request source‑of‑fund documentation from the sender, and monitor subsequent activity for related patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 472 days |
| Total Transactions | 51462 |
| Current Balance | 0.005069 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 16 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 16 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The wallet performed 16 identical, zero‑value transactions to the CoW Protocol GPv2Settlement address within a short block window, matching the AML engine’s structuring rule (score 70) for depositing identical amounts. The sequential nature of these transfers triggered the peel_chain_linear rule (score 60), indicating a layering attempt to obscure the origin of funds. The use of a cross‑chain bridge (bridge_hop rule, score 65) further complicates the transaction path. With a composite score of 195, the activity falls into the critical risk band, warranting a formal SAR filing and enhanced due diligence. CRITICAL (rule score 195)

</details>

---

## Finding #9: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5c3593481cba011737e36ded62f1797c9f6afce1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **20** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403809-26404000 |

### 💬 What Happened
Someone sent 20 tiny, identical zero‑ETH deposits to a settlement contract, like a person repeatedly dropping a zero‑value package into a mailbox to hide who sent it.

### 🔥 The Roast
It scored 70 on structuring (meaning the sender tried to hide the real amount by making 20 identical zero‑value deposits, like putting 20 identical empty wrappers in a jar). Then 60 on peel_chain_linear (so it's like a detective line‑up where each suspect looks exactly the same, but they’re actually the same person in disguise). Finally 65 on bridge_hop, because the money went to a cross‑chain bridge, which is the blockchain equivalent of sending a postcard through a secret tunnel. The engine thinks this looks like a classic smurfing attempt – 20 smurf‑sized zero‑ETH deposits to throw off anyone trying to trace the real source.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of 20 identical zero‑value deposits, sequential patterning, and cross‑chain bridge usage constitutes a high‑risk structuring and layering scenario requiring immediate review.**

Flag the sender wallet for manual investigation, monitor for further activity, and consider notifying law enforcement if additional suspicious patterns emerge.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 220 days |
| Total Transactions | 56768 |
| Current Balance | 3.888694 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 20 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 20 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction set triggers three AML rules: structuring (score 70) – 20 identical zero‑value deposits; peel_chain_linear (score 60) – sequential, uniform pattern indicating layering; and bridge_hop (score 65) – deposit to CoW Protocol GPv2Settlement, a cross‑chain bridge. Evidence includes 20 consecutive zero‑ETH transfers in blocks 26403809‑26404000 from wallet 0x5c3593481cba011737e36ded62f1797c9f6afce1 to the settlement contract, with no token transfers and a wallet age of 220 days. The pattern suggests an attempt to obscure the origin of funds via structuring and layering across a bridge.

</details>

---

## Finding #10: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x5ed864e8f37dcb4f79c5172a815d1b3a9147eaab` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **50** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403809-26403996 |

### 💬 What Happened
A wallet sent 50 tiny, identical 0‑ETH transfers to a decentralized trading protocol. It’s like dropping a dozen empty envelopes into a mailbox, all looking the same, to hide the fact that someone is trying to layer activity. The sender’s account is young, busy, and has never stopped sending money, so the pattern stands out like a neon sign on a quiet street.

### 🔥 The Roast
This guy’s doing the classic 50‑pack smurfing trick – sending 0.0000 ETH 50 times, which is basically the blockchain equivalent of a prank call that keeps ringing the same number. Think of it as a magician who keeps pulling the same empty hat out of a stack, hoping nobody notices. The AML engine flagged it with a 70 on structuring, a 60 on peel_chain_linear, and a 65 on bridge_hop – basically a perfect recipe for a suspicious onion. If he wanted to be a low‑profile serial killer, he’d probably need to actually send some ETH, not just zeros.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain, and bridge usage constitutes a high‑risk layering pattern.**

Flag the wallet for internal investigation, request source‑of‑funds documentation, and monitor for subsequent large‑value movements.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 88 days |
| Total Transactions | 67836 |
| Current Balance | 9.532675 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 50 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 50 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The account (0x5ed864e8f37dcb4f79c5172a815d1b3a9147eaab) performed 50 identical transfers of 0.0000 ETH to 0x9008d19f58aabd9ed0d60971565aa8510560ab41 (CoW Protocol GPv2Settlement). This activity aligns with Rule [structuring] (identical small-value transactions), Rule [peel_chain_linear] (sequential similar deposits indicating layering), and Rule [bridge_hop] (cross‑chain bridge usage). CRITICAL (rule score 195) Further human review is warranted to determine intent and source of funds.

</details>

---

## Finding #11: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x38e59dcce64ea3ddece4d98f77e70990fc8f430c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **6** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403831-26403987 |

### 💬 What Happened
The sender made six identical, zero‑Ether deposits into a smart contract that handles trades. Think of it as dropping six empty pizza boxes into a delivery truck—there’s no pizza inside, but the driver will still take them. The pattern looks like an attempt to hide activity by using many tiny, identical transactions.

### 🔥 The Roast
Looks like someone tried to smuggle cash by sending six zero‑eth deposits—like dropping six empty pizza boxes into a truck hoping the driver will notice the pizza later. The engine flags this as structuring (sending many tiny amounts to avoid detection), peel_chain_linear (a straight‑line chain of similar deposits that’s as boring as a marching band), and bridge_hop (the target is a cross‑chain bridge that can mix coins). Even though the total value is $0, the pattern screams ‘I’m hiding something’.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for immediate manual review, monitor all subsequent transactions, and consider placing a temporary hold pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 31 days |
| Total Transactions | 2955 |
| Current Balance | 0.184527 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 6 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 6 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The account performed six consecutive zero‑ETH transfers to the CoW Protocol GPv2Settlement contract, a pattern consistent with structuring (Rule: structuring) and peel chain layering (Rule: peel_chain_linear). The use of a cross‑chain bridge (Rule: bridge_hop) further raises concerns about potential layering. The sender’s wallet is 31 days old, has 2955 total transactions, and currently holds 0.184527 ETH, indicating recent activity that may be related to the observed pattern. This activity merits escalation for manual review under AML guidelines.

</details>

---

## Finding #12: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xb5e5ba15a5aa58df03d91549496d8cd67a15f858` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **10** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403884-26403987 |

### 💬 What Happened
The sender sent ten tiny, identical amounts of nothing (0 ETH) into a smart‑contract settlement address over a short period. It’s like someone trying to drop ten invisible packages into a slot that hides who sent them. The overall value was zero, but the pattern looks like someone is trying to split a single transaction into many tiny ones.

### 🔥 The Roast
So this wallet tried to smuggle 10 packets of zero ETH, like a kid who thinks 0.0000 ETH is a magic number. The structuring rule (splitting a single transaction into many small ones to avoid detection) gave it a 70. Peel chain linear (a sequence of similar deposits) got 60, and the bridge hop (moving assets across chains or protocols) scored 65. Combined, the engine thinks this is a high‑risk activity, like a magician pulling a rabbit out of an empty hat.

### 🎯 Verdict & Next Steps
**CRITICAL – the composite score of 195 and pattern of 10 zero‑eth deposits to a settlement contract triggers high suspicion.**

Flag the wallet for manual review, investigate the source of the 0 ETH deposits, and consider reporting to the AML team for further analysis.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 62 days |
| Total Transactions | 8813 |
| Current Balance | 0.357790 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 10 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 10 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The transaction history shows 10 identical 0.0000 ETH deposits to the CoW Protocol GPv2Settlement address, meeting the criteria for the [structuring] rule (splitting a single transaction into many small ones). The sequential nature of these deposits triggers the [peel_chain_linear] rule (layering pattern). Additionally, the move into a cross‑chain settlement contract triggers the [bridge_hop] rule. The composite score of 195 indicates a high likelihood of suspicious activity.

</details>

---

## Finding #13: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x95480d3f27658e73b2785d30beb0c847d78294c7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403968-26403987 |

### 💬 What Happened
A user sent three tiny, identical amounts of ETH (each 0.0000 ETH, effectively nothing) into a settlement contract that moves funds across chains. It’s like someone dropping the same empty envelope into a slot three times in a row, trying to hide the fact that the same sender is repeatedly moving money through a bridge. The total value was zero, so the blockchain records show no real transfer of value, but the pattern looks suspicious.

### 🔥 The Roast
So this guy is playing a game of hide‑and‑seek with his own money, dropping empty envelopes into a cross‑chain slot like a magician who can’t seem to make a trick. The engine gave him a 70 on structuring (because 0.0000 ETH, 0.0000 ETH, 0.0000 ETH is textbook smurfing), 60 on peel_chain_linear (three identical moves in a row, like a peel‑and‑layer cake), and 65 on bridge_hop (because he’s hopping to CoW Protocol, the blockchain’s version of a bridge that’s more like a hopscotch). In total, it’s a 195 composite score, which is higher than a normal grocery trip to the bank. This is the kind of pattern that makes you want to pull out the magnifying glass and ask, "Hey, where did that money come from?"

### 🎯 Verdict & Next Steps
**The combination of identical micro‑deposits, a peel chain pattern, and cross‑chain bridging yields a composite score of 195, indicating a critical flag for potential layering and smurfing.**

Flag the sender’s wallet for enhanced due diligence. Request source‑of‑funds documentation and transaction purpose; consider freezing if additional suspicious activity is observed.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 734 days |
| Total Transactions | 307497 |
| Current Balance | 4.289169 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The account (0x95480d3f27658e73b2785d30beb0c847d78294c7) executed three consecutive ETH transfers of 0.0000 ETH to the CoW Protocol GPv2Settlement contract within blocks 26403968–26403987, totaling $0. The AML engine flagged this activity under the following rules: [structuring] (score 70) for identical micro‑deposits, [peel_chain_linear] (score 60) for a linear peel chain pattern, and [bridge_hop] (score 65) for the use of a cross‑chain bridge. The composite score of 195 exceeds the critical threshold, warranting enhanced due diligence.

</details>

---

## Finding #14: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x4c5213672f972ae8e3d39d7e3e83d47d39e2f739` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403816-26403979 |

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
| Wallet Age | 232 days |
| Total Transactions | 22363 |
| Current Balance | 0.446734 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #15: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xa7842153fde380a864726d0e91f14f6ffab7d46c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403867-26403965 |

### 💬 What Happened
The sender made five tiny, identical deposits of zero ETH to a DeFi settlement contract, like dropping five identical empty envelopes into a slot so you can’t tell who actually sent them.

### 🔥 The Roast
Scored 70 on structuring (meaning they’re trying to hide the source by making many tiny deposits). 60 on peel_chain_linear (layering, because the deposits are in a straight line like a row of dominoes). 65 on bridge_hop (cross‑chain hop, because the money is being moved to a settlement contract that acts like a bridge). In short, this is the crypto equivalent of a magician’s disappearing act, but with 0.0000 ETH instead of rabbits.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 195)**

Flag the wallet for manual review, investigate the origin of the 0.731 ETH balance, and monitor for further activity to the CoW Protocol or other bridges.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 528 days |
| Total Transactions | 23035 |
| Current Balance | 0.731025 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 5 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 5 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
The AML engine flagged structuring, peel_chain_linear, and bridge_hop. The sender executed five sequential, identical 0.0000 ETH transfers to the CoW Protocol GPv2Settlement contract, a known cross‑chain bridge. This pattern suggests layering and potential obfuscation of source funds. CRITICAL (rule score 195)

</details>

---

## Finding #16: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0xa883710b6dbf008a1cc25722c54583e35884a209` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403815-26403965 |

### 💬 What Happened
The sender sent 0 ETH three times in a row to the CoW Protocol GPv2Settlement contract, all within a short block window. It’s like someone repeatedly dropping a paperweight that weighs nothing into the same slot—no actual change, but the pattern is visible. The system flagged this as a possible attempt to hide a pattern, even though nothing moved.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their ETH but forgot to actually move any coins—just 0‑ETH pushes, like a comedian telling the same joke three times and still hoping for a laugh. The engine threw out a trio of warnings: "structuring" (meaning identical small deposits that could be smurfing), "peel_chain_linear" (layering in a straight line, like peeling a banana one slice at a time), and "bridge_hop" (cross‑chain hopping, like taking a train from one city to another with a stop that’s meant to obscure the route). It’s a neat little show, but nobody’s getting any real money out of it.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of identical zero‑amount transfers, layering pattern, and cross‑chain bridge use signals a high‑risk structuring attempt.**

Flag the wallet for manual compliance review, request source of funds documentation, and monitor subsequent activity for any actual value movement.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 863 days |
| Total Transactions | 27509 |
| Current Balance | 0.346051 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Rule: structuring (identical small deposits that may be an attempt to avoid detection). Rule: peel_chain_linear (sequential similar deposits indicating layering). Rule: bridge_hop (cross‑chain bridge usage). Evidence: three consecutive 0.0000 ETH transfers from wallet 0xa883710b6dbf008a1cc25722c54583e35884a209 to CoW Protocol GPv2Settlement in blocks 26403815‑26403965. The wallet has a high transaction count and is currently active, but the pattern raises a high‑risk flag for potential structuring and layering activity.

</details>

---

## Finding #17: CRITICAL — Score 195

| | |
|---|---|
| **Sender** | `0x3980daa7eaad0b7e0c53cfc5c2760037270da54d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403817-26403845 |

### 💬 What Happened
The sender pushed four identical zero‑ETH transactions into a protocol that moves funds around. Think of it like dropping four empty envelopes into a mail slot one after another—no money leaves, but the repetition looks like someone trying to disguise a real transfer. The total value is $0, so no actual funds were moved, but the pattern raises red flags.

### 🔥 The Roast
You know those people who think they can hide in a crowd by sending the same thing over and over? Yeah, this wallet is doing exactly that—four identical 0‑ETH moves like a spam bot, except it’s a blockchain. The engine gave it a 70 on structuring (meaning "smurfing"—splitting into tiny pieces to dodge detection), a 60 on peel_chain_linear (detecting a straight‑line chain of similar transfers, like peeling an onion layer by layer), and a 65 on bridge_hop (moving across chains, like shuttling money between banks). With a composite score of 195, it’s basically shouting "I’m trying to hide, but I’m not very good at it."

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction pattern meets multiple high‑risk structuring and layering indicators, warranting urgent review.**

Flag the wallet for enhanced due diligence, investigate the source of the funds, and consider freezing the account pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 422 days |
| Total Transactions | 134585 |
| Current Balance | 37.879462 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 195):
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Rule structuring was triggered (score 70) due to four identical 0‑ETH deposits, indicating an attempt to avoid detection through smurfing. Rule peel_chain_linear (score 60) identified a sequential peel chain, a classic layering pattern. Rule bridge_hop (score 65) flagged the movement to CoW Protocol GPv2Settlement, a cross‑chain bridge, increasing the risk profile. The sender’s wallet shows 134,585 prior transactions, 422 days of age, and a current balance of 37.879462 ETH, suggesting a high‑volume, potentially sophisticated user. These factors collectively elevate the transaction to high‑risk territory.

</details>

---

## Finding #18: HIGH — Score 130

| | |
|---|---|
| **Sender** | `0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **25** token transfers totaling **$23,552** (3,460 USDC, 1,550 USDC, 0 WETH, 100 USDC, 50 USDC) |
| **Blocks** | 26403804-26403999 |

### 💬 What Happened
A single wallet sent a bunch of stablecoins (digital dollars) into a mixing service that scrambles transaction trails, so it’s hard to see who really owns the money. Think of it like dropping a stack of bills into a slot machine that shuffles them and hands out new bills—the original owner is hidden. The total was about $23,552 spread over 25 small moves.

### 🔥 The Roast
So 0x1231… decided to play hide‑and‑seek with its $23k in USDC by sending it to Across SpokePool V2. The engine gave it a 130, which is basically the red‑flag emoji on a pizza delivery app. Even the smallest move of 0.0004 USDC shows they’re not messing around— it’s like dropping a coin in a fountain hoping it will become a unicorn. This is the kind of pattern that makes auditors check the receipts and the compliance team say, ‘hold the phone.’

### 🎯 Verdict & Next Steps
**HIGH — due to high composite score and pattern consistent with stablecoin mixing.**

Flag the wallet for manual review, request source‑of‑funds documentation, and add it to the compliance watchlist for ongoing monitoring.

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
- **stablecoin_mixing** (+130) — 23 stablecoin transfer(s) to Across SpokePool V2: $23,552 total (USDC, USDT) from 1 unique sender(s) — 3 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
The transaction history shows 23 stablecoin transfers totaling $23,552 to the Across SpokePool V2 contract. HIGH (rule score 130) The pattern indicates layering or obfuscation of funds and warrants a manual SAR review to trace the source and destination of the assets.

</details>

---

## Finding #19: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x9e64d18073cd8ec20e2680124d0551ba1629fa20` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **9** token transfers totaling **$11,865** (117 WETH, 668 USDC, 676 USDC, 400 USDC, 0 WETH) |
| **Blocks** | 26403805-26403996 |

### 💬 What Happened
A single wallet sent nine different payments, mostly in a stablecoin called USDC, to a special pool on the blockchain that is used to hide where the money came from. Think of it like dropping several envelopes into a locked box that anyone can open but no one can see who put them in. The sender’s wallet has no money left and no clear history, so it’s hard to tell where the funds originally came from.

### 🔥 The Roast
HIGH (rule score 110) The AML engine gave it a whopping 110 on the stablecoin_mixing rule (meaning the system flagged it as a high‑risk mixing activity). If this was a real person, they’d probably be the kind who forgets their wallet key and ends up in a black hole of transactions. The fact that the receiver is a generic pool address makes it look like a one‑way ticket to oblivion. Bottom line: this looks like someone trying to play hide‑and‑seek with their money, and the system is calling out the game.

### 🎯 Verdict & Next Steps
**HIGH — the composite score of 110 and the pattern of multiple stablecoin transfers to a mixing pool warrant high suspicion.**

Flag the transaction set for manual review, investigate the source of the funds, and determine if the sender wallet is associated with any known suspicious activity or identities. If possible, trace the incoming funds to the original source and assess compliance with applicable AML policies.

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
- **stablecoin_mixing** (+110) — 4 stablecoin transfer(s) to Across SpokePool V2: $11,747 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Suspicious activity detected under rule stablecoin_mixing (score: 110). The sender wallet (0x9e64d18073cd8ec20e2680124d0551ba1629fa20) executed nine transfers totaling $11,865 USD, with four stablecoin (USDC) transfers totaling $11,747 to the Across SpokePool V2 address (0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5). HIGH (rule score 110) HIGH (rule score 110)

</details>

---

## Finding #20: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xc186fa914353c44b2e33ebe05f21846f1048beda` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** token transfers totaling **$87,898** (69,839 USDT, 1 WETH, 18,057 USDC, 0 WBTC) |
| **Blocks** | 26403915-26403915 |

### 💬 What Happened
Someone moved almost $88,000 worth of stablecoins (USDT and USDC) through a single address into a decentralized liquidity pool (Across SpokePool V2). It's like someone dropping a huge cash bundle into a vending machine that then splits it up and hides who originally put it there.

### 🔥 The Roast
HIGH (rule score 110) HIGH (rule score 110) And with the zero ETH balance, it's like a ghost account that only exists to do the money‑washing shuffle. If you think this is a legitimate DeFi move, just remember: mixers are the crypto equivalent of a laundromat for dirty money. The only thing more confusing than this is your mom's attempt at making a spreadsheet.

### 🎯 Verdict & Next Steps
**HIGH — the transaction matches the stablecoin_mixing pattern with a composite score of 110, indicating significant potential for layering and obfuscation.**

Flag the sender address for enhanced due diligence, including tracing source of funds and monitoring future activity. Consider engaging forensic analysis to map any downstream recipients and assess potential risk.

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to Across SpokePool V2: $87,897 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction record shows 4 stablecoin transfers (USDT 69,839.4204, USDC 18,057.4503, and two negligible amounts) from a single unknown‑age wallet to the Across SpokePool V2 contract on block 26403915. The total value of $87,898 aligns with the criteria for the 'stablecoin_mixing' rule (Rule ID: stablecoin_mixing). HIGH (rule score 110) HIGH (rule score 110)

</details>

---

## Finding #21: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x7560f0d8df5c0310af3d16e02a2ec44628866f74` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$36,110** (28,618 USDT, 7,492 USDT) |
| **Blocks** | 26403803-26403804 |

### 💬 What Happened
Two separate USDT payments totaling $36,110 were sent from a single unknown wallet to a protocol called Across SpokePool V2. It's like someone dropping two packages into a shared dropbox that hides who sent them. The transactions happened in consecutive blocks, so they were likely part of the same activity.

### 🔥 The Roast
HIGH (rule score 110) It’s like a magician’s hat where the coins just vanish into a black hole. The sender’s balance is zero ETH, so maybe they’re just a coin‑hoarder. If they were trying to hide, they’d at least keep a decent stash of ETH for a grand exit. At this point, the only thing you can do is call the compliance squad and ask them to play detective.

### 🎯 Verdict & Next Steps
**HIGH — the transaction pattern matches a known stablecoin mixing behavior with a composite score of 110, indicating significant risk.**

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to Across SpokePool V2: $36,110 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule: stablecoin_mixing (Rule ID: SC-001). Evidence: Two USDT transfers of $28,617.9925 and $7,491.7646, totaling $36,110, from one unique sender to Across SpokePool V2 in blocks 26403803-26403804. The composite score of 110 indicates high suspicion of mixing activity. Recommend manual investigation to determine source and destination of funds.

</details>

---

## Finding #22: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x71015b64527a5541e3e18e74468f876bb13adf71` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **11** token transfers totaling **$632,756** (3,417 GHO, 3,422 GHO, 1 WETH, 375,113 USDC, 801 USDC) |
| **Blocks** | 26403861-26404000 |

### 💬 What Happened
The sender sent 11 separate payments that together add up to about $633,000 in stablecoins. Most of the money went straight to a smart‑contract address that handles trades for a decentralized exchange. It’s like dropping a big bundle of cash into a machine that then shuffles the money around so nobody knows where it came from.

### 🔥 The Roast
He’s basically trying to play a game of financial hide‑and‑seek with a $632k stash. HIGH (rule score 110) HIGH (rule score 110) If this were a bank, it would be like someone sending a million dollars in checks through a cashier’s desk that forwards them to a shell company. He thinks he’s clever, but the system caught the pattern faster than a pizza delivery guy can say “extra cheese.”

### 🎯 Verdict & Next Steps
**HIGH – the composite score of 110 and the pattern of multiple stablecoin transfers to a settlement protocol indicate a strong mixing activity that requires immediate review.**

Flag the transaction for manual AML review, verify the source of the $632k, and monitor the sender’s address for any further suspicious activity.

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $625,916 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction series triggers the stablecoin_mixing rule (score: 110). Three large stablecoin transfers totaling $625,916 were sent from a single unique sender to the CoW Protocol GPv2Settlement address, a known aggregator that performs intent settlement. HIGH (rule score 110) The sender’s wallet has no publicly known activity history and currently holds negligible ETH balance. HIGH (rule score 110)

</details>

---

## Finding #23: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x8f10b468b06c6fd214b65f87778827f7d113f996` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **26** token transfers totaling **$1,369,844** (0 WETH, 0 aEthWBTC, 124,503 TRUF, 3,997 USDT, 4,333 USDT) |
| **Blocks** | 26403830-26403999 |

### 💬 What Happened
The sender moved about $1.37 million worth of digital dollars—like a stack of cash—into a smart‑contract that acts like a vending machine for DeFi trades. Think of it like dropping a stack of cash into a slot that then shuffles it around so no one can tell where it came from. The biggest chunk ($124,503 worth of a token called TRUF) was sent to a protocol that settles trades on the CoW platform, which is commonly used for mixing.

### 🔥 The Roast
This wallet is doing more moves than a breakdancer at a crypto dance party, with 26 transfers and $1.37M in play. The engine slapped it with a 110 on stablecoin_mixing (meaning it's trying to hide the source like a magician hiding the rabbit). The receiver is a CoW Protocol GPv2Settlement, basically a fancy vending machine for swapping tokens, so it’s probably just a slot to make the money look like it came from a vending machine. If this was a real person, they'd need a bigger bank account to keep up with all those transfers.

### 🎯 Verdict & Next Steps
**HIGH — the pattern matches known stablecoin mixing activity and exceeds the threshold for suspicious behavior.**

Flag the transaction for manual review by the compliance team. Investigate the source of funds and confirm whether the activity is legitimate DeFi trading or part of a layering scheme.

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
- **stablecoin_mixing** (+110) — 5 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $271,412 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Rule: stablecoin_mixing (ID SC-001). Evidence: five stablecoin transfers (USDC, USDT) totalling $271,412 were sent from the subject address to CoW Protocol GPv2Settlement, a known mixing venue. The transaction count (26) and total value ($1,369,844) indicate high-volume activity consistent with layering techniques. The wallet has no recorded balance and unknown activity history, raising red flags for potential source obfuscation.

</details>

---

## Finding #24: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x51c72848c68a965f66fa7a88855f9f7784502a7f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **43** token transfers totaling **$3,067,692** (300,512 USDC, 1 cbBTC, 19,160 USDT, 114,115 USDC, 7,002 DAI) |
| **Blocks** | 26403833-26403999 |

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
- **stablecoin_mixing** (+110) — 18 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,078,612 total (USDC, USDT, DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #25: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xaddc26a3854feabfd20d6bf658254088d83a425a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$56,845** (0 WETH, 0 WETH, 0 WETH, 54,753 USDC, 2,092 ETHFI) |
| **Blocks** | 26403871-26403995 |

### 💬 What Happened
A person sent a bunch of digital money to a fancy trading platform that helps people swap tokens. The bulk of the money was in a stablecoin that’s pegged to the dollar, and it looks like the sender used a mix of small and large transfers to hide the source. Think of it like dropping a large pizza into a delivery box with several small snacks, making it hard to see where the pizza came from.

### 🔥 The Roast
So this guy decided to play hide‑and‑seek with his money, sending a giant slice of USDC to a settlement service that’s basically a crypto version of a Swiss bank. He’s basically saying, ‘I want my dollars to disappear into a smart contract, not a real bank.’ The engine slapped a 110 score on him, which is like getting a red flag on a credit card for suspicious activity. He’s mixing coins like a bartender at a club that’s too busy to notice. If he wants to keep this hush‑hush, he should probably keep it in a pocket, not a wallet.

### 🎯 Verdict & Next Steps
**HIGH — the transaction exceeded the threshold for stablecoin mixing and involved large, split transfers to a settlement protocol, raising significant layering concerns.**

Flag the wallet for manual review, request source of funds documentation, and monitor subsequent activity for any repeat patterns or linkages to known high‑risk addresses. Additionally, cross‑reference the wallet against internal watchlists.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $54,753 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involved a stablecoin transfer of $54,753 USDC to the CoW Protocol GPv2Settlement, a decentralized exchange settlement layer. Rule stablecoin_mixing was triggered with a composite score of 110 due to multiple transfers from a single unique sender. The pattern indicates potential layering and obfuscation of source funds. Further investigation is warranted to assess the legitimacy of the source and intent.

</details>

---

## Finding #26: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x59cd9faf02616fa3111b6dc20c691b9c7b6c18d3` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$68,589** (68,589 USDT) |
| **Blocks** | 26403991-26403991 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $68,589 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x52aa899454998be5b000ad077a46bbe360f4e497` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$16,129** (0 WBTC, 8,771 USDC, 7,358 USDC) |
| **Blocks** | 26403846-26403987 |

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $16,129 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xbdc74a2f5a8aac77eba150681df56ff5e9bdb27b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$40,001** (40,001 USDC) |
| **Blocks** | 26403987-26403987 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $40,001 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xf0adc8f0c7082cb3fabb2b5221a2e5ad01c6d66f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$58,115** (9,077 GHO, 49,038 USDT) |
| **Blocks** | 26403964-26403972 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $49,038 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xd09f16830172e6073e8e5ee5053f35010f1c7d7a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$200,000** (200,000 USDC) |
| **Blocks** | 26403966-26403966 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $200,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xe3d41d19564922c9952f692c5dd0563030f5f2ef` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$181,647** (0 WETH, 181,240 USDC, 407 USDC) |
| **Blocks** | 26403899-26403965 |

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $181,647 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x035035e2e1d073142d4fa7d8f32f097179333d6e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$83,021** (42,021 USDC, 41,000 USDC) |
| **Blocks** | 26403933-26403942 |

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $83,021 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xa97cce04c3a2861ba8544527d385ae85d7266082` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$19,300** (19,300 USDC) |
| **Blocks** | 26403935-26403935 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $19,300 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xaef2ad7abb651945e6d24276715f25bded0ad41e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$134,766** (134,766 USDC) |
| **Blocks** | 26403931-26403931 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $134,766 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x203384cd3d5e0dc4fcd873d4fc54b78923ed269f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$65,402** (65,402 USDC) |
| **Blocks** | 26403924-26403924 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $65,402 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x2a426b6b4589a3a44a053da440c45ff41e16f52c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$554,398** (249,801 USDC, 54,797 USDT, 249,799 USDC) |
| **Blocks** | 26403861-26403922 |

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
- **stablecoin_mixing** (+110) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $554,398 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x9ebb90200f11c77af2c4f3ba1c3086de69326fd4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$24,423** (24,423 USDC) |
| **Blocks** | 26403918-26403918 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $24,423 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x5f4cfc9da95909d976b502de496bc3bacdfcb0a0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100,000** (100,000 USDC) |
| **Blocks** | 26403909-26403909 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $100,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x9f1920d0cbb63ed03376a1e09fd2851d601234c8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100,000** (100,000 USDT) |
| **Blocks** | 26403904-26403904 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $100,000 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x14f362542ce22a9cf392ecc4e95b85837fab37e6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$33,746** (33,746 USDC) |
| **Blocks** | 26403897-26403897 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $33,746 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xc780fd255b5302791ed1a1f6bfb11e8d3f404a50` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$25,000** (25,000 USDC) |
| **Blocks** | 26403892-26403892 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $25,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0x09100e85fab9b4385030cd777644b1f1107a74c0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$34,448** (34,448 USDC) |
| **Blocks** | 26403892-26403892 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $34,448 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xb63e8a8d04999500a97470769d10c4395789836d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$19,271** (19,271 USDC) |
| **Blocks** | 26403880-26403880 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $19,271 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xe7de0c1c5b900eca200947dc4ba88c8d4becc7df` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$400,000** (200,000 USDC, 200,000 USDC) |
| **Blocks** | 26403851-26403873 |

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
- **stablecoin_mixing** (+110) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $400,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #45: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xca18c1f5ead8c5f6217408187db9c377d819bfbf` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$25,000** (25,000 USDC) |
| **Blocks** | 26403845-26403845 |

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $25,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xaace5aeab7265d03487d007e11be7af97ec8ff38` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$10,000** (10,000 USDT) |
| **Blocks** | 26403830-26403830 |

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

## Finding #47: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x97ccdbea4632140639ad5ea9b944aa034eb15fd4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **18** token transfers totaling **$7,795** (315 USDT, 137 USDT, 21 USDT, 16 USDC, 10 USDC) |
| **Blocks** | 26403807-26403983 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 100.

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
- **stablecoin_mixing** (+100) — 16 stablecoin transfer(s) to Across SpokePool V2: $7,794 total (USDC, USDT) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #48: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x28a4d41776968c1201a807ec51ffb405362b8882` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** token transfers totaling **$1,112** (100 USDC, 999 USDT, 3 USDC, 10 USDC) |
| **Blocks** | 26403805-26403949 |

### 💬 What Happened
A wallet was caught interacting with Across SpokePool V2. Our engine flagged it at score 100.

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
- **stablecoin_mixing** (+100) — 4 stablecoin transfer(s) to Across SpokePool V2: $1,112 total (USDC, USDT) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #49: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0xd35d7fb17ee3061ee6ef5f6856a3cef70d5a1cf1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$200** (100 USDC, 100 USDC) |
| **Blocks** | 26403932-26403988 |

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
- **stablecoin_mixing** (+100) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $200 total (USDC) from 1 unique sender(s) — 2 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #50: HIGH — Score 100

| | |
|---|---|
| **Sender** | `0x8d4dbe6dfcd42015e58d8856109f579f27e76a31` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **11** token transfers totaling **$1,323** (100 USDC, 100 USDC, 76 USDC, 24 USDC, 398 USDC) |
| **Blocks** | 26403865-26403985 |

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
- **stablecoin_mixing** (+100) — 11 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,323 total (USDC) from 1 unique sender(s) — 6 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #51: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x60ac95ec1153aa8199751917ede25d0ca49a36e2` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$70** (2 USDC, 68 USDC) |
| **Blocks** | 26403847-26403997 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $70 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #52: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x76db715be89af89a79e4938e14099d0284cc8c13` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$226** (226 USDT) |
| **Blocks** | 26403979-26403979 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $226 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #53: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9a47f3289794e9bbc6a3c571f6d96ad4e7baed16` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **4** token transfers totaling **$740** (37 USDC, 283 USDT, 3 USDT, 418 USDC) |
| **Blocks** | 26403869-26403963 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to Across SpokePool V2: $740 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #54: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfa1b28052bd8087b1cf64ee9429feb324e95b0ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **10** token transfers totaling **$4,121** (13 USDT, 862 USDC, 896 USDC, 496 USDC, 220 USDT) |
| **Blocks** | 26403809-26403954 |

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
- **stablecoin_mixing** (+80) — 10 stablecoin transfer(s) to Across SpokePool V2: $4,121 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #55: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3d2d2538b2dde72ac9f2730afe1799040f08f4f0` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$24** (0 USDT, 24 USDT) |
| **Blocks** | 26403842-26403949 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $24 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #56: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x790a6c3c8f66bf7b10ef183eb587842c12b3af7c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$1,001** (1,001 USDC) |
| **Blocks** | 26403936-26403936 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $1,001 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #57: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3a23f943181408eac424116af7b7790c94cb97a5` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **3** token transfers totaling **$169** (5 USDC, 64 USDC, 100 USDC) |
| **Blocks** | 26403813-26403900 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to Across SpokePool V2: $169 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #58: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4b563a4d34e4b7d13e30bd2444c1d3a7953a4977` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$27** (27 USDT) |
| **Blocks** | 26403900-26403900 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $27 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #59: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc72121c5ae58dd203e4be80c9316391c795d5005` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$170** (170 USDC) |
| **Blocks** | 26403878-26403878 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $170 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #60: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0038dfb2bbc353daa6ad22cb11ee1d78f41b59cd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** token transfers totaling **$1,395** (895 USDC, 500 USDT) |
| **Blocks** | 26403871-26403874 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to Across SpokePool V2: $1,395 total (USDC, USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #61: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8f9183f27054f5ddb5d346cb73cd5799a2b32e4e` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$999** (999 USDC) |
| **Blocks** | 26403849-26403849 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $999 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #62: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xdf4d8cae2bd16b85871c2f84b71e537cd1e333fb` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$34** (34 USDT) |
| **Blocks** | 26403845-26403845 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $34 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #63: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x69460570c93f9de5e2edbc3052bf10125f0ca22d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** token transfer totaling **$371** (371 USDC) |
| **Blocks** | 26403815-26403815 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to Across SpokePool V2: $371 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #64: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc5b748cb3a2100e5a206eff44b1583f20051dc01` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$641** (366 USDC, 276 USDC) |
| **Blocks** | 26403998-26404000 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $641 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #65: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbee3211ab312a8d065c4fef0247448e17a8da000` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **10** token transfers totaling **$2,059** (164 USDC, 0 WETH, 100 USDT, 958 USDT, 315 USDC) |
| **Blocks** | 26403863-26403999 |

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
- **stablecoin_mixing** (+80) — 7 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,059 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #66: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbd2c8cff3d87e524d747a654024f495d782a0a7f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$350** (350 USDT) |
| **Blocks** | 26403999-26403999 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $350 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #67: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc363cbb6c0ea13154f371d816fc50314cc039388` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$486** (304 USDC, 182 USDC) |
| **Blocks** | 26403978-26403998 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $486 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #68: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x85481229790428860b8284af79a42e095c928c45` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$1,234** (1,234 USDT, 0 USDT) |
| **Blocks** | 26403971-26403997 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,234 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #69: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x000000000004444c5dc75cb358380d2e3de08a90` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **19** token transfers totaling **$119,957** (37,252 BOBINA, 296 USDT, 5,657 BALANCE, 1,354 reUSDe, 117 USDC) |
| **Blocks** | 26403831-26403996 |

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
- **stablecoin_mixing** (+80) — 7 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $578 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #70: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xce562a92c8401610d197370c42f5dd07cf21e412` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$500** (100 USDT, 110 USDT, 140 USDT, 150 USDT) |
| **Blocks** | 26403867-26403995 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $500 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #71: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb5378cf59f35e6e8bf5679ec6c22d1c5ff912433` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **12** token transfers totaling **$6** (0 WETH, 2 USDC, 0 WETH, 0 WETH, 0 WETH) |
| **Blocks** | 26403884-26403993 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $6 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #72: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8c09ae4ee8e2ff9cc24c5863da836941eda195ea` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDC) |
| **Blocks** | 26403993-26403993 |

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

## Finding #73: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1b0e092aaeaaed86d9a77cee69d5d5f53ec6c638` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$350** (350 USDT) |
| **Blocks** | 26403992-26403992 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $350 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #74: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe0554a476a092703abdb3ef35c80e0d76d32939f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **14** token transfers totaling **$3,523** (246 USDC, 0 WETH, 0 WETH, 0 WETH, 0 WETH) |
| **Blocks** | 26403831-26403991 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,522 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #75: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb31765d45a6bc3fbec16b162be1aabcbee6911e3` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **7** token transfers totaling **$755** (246 DAI, 117 DAI, 51 DAI, 33 DAI, 247 DAI) |
| **Blocks** | 26403894-26403991 |

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
- **stablecoin_mixing** (+80) — 7 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $755 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #76: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x67336cec42645f55059eff241cb02ea5cc52ff86` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$2,001** (2,001 USDT, 0 cbBTC, 0 cbBTC) |
| **Blocks** | 26403837-26403991 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,001 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #77: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x84f2206d00ea346f7130e0701330751976d38c1e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$310** (310 USDT) |
| **Blocks** | 26403989-26403989 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $310 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #78: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4d68b530920d26c3b01c99fecc19e21011b72bbd` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$477** (100 USDT, 100 USDT, 100 USDT, 76 USDT, 100 USDT) |
| **Blocks** | 26403947-26403988 |

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
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $477 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #79: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x66a9893cc07d91d95644aedd05d03f95e1dba8af` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$0** (0 USDT, 0 WETH) |
| **Blocks** | 26403987-26403987 |

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

## Finding #80: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x241d1ebee7a2c4dc69aa6a251c0f7279078bb11e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2** (2 USDT) |
| **Blocks** | 26403987-26403987 |

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

## Finding #81: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc9d748e601d9984a43da0b80e5b91dc28d31d9fb` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$966** (956 USDC, 10 WETH) |
| **Blocks** | 26403935-26403981 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $956 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #82: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc1f5599cf768040ba8b8aeb284b9d46b70d5d30e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDC) |
| **Blocks** | 26403979-26403979 |

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

## Finding #83: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2e8135be71230c6b1b4045696d41c09db0414226` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$26** (26 USDC) |
| **Blocks** | 26403979-26403979 |

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

## Finding #84: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x12139b8e95b78639943f81e5cf2b45e3a5191df8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$10** (10 USDT) |
| **Blocks** | 26403977-26403977 |

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

## Finding #85: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd51a44d3fae010294c616388b506acda1bfaae46` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,254** (1,254 USDT) |
| **Blocks** | 26403977-26403977 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,254 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #86: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x56534741cd8b152df6d48adf7ac51f75169a83b2` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$2,445** (2,047 USDT, 399 USDT) |
| **Blocks** | 26403970-26403977 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,445 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #87: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x156c4e99f30a1bcd7cb1982a054898f518f910ce` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDT) |
| **Blocks** | 26403973-26403973 |

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

## Finding #88: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x397ff1542f962076d0bfe58ea045ffa2d347aca0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$129** (78 USDC, 50 USDC) |
| **Blocks** | 26403972-26403972 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $129 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #89: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xba12222222228d8ba445958a75a0704d566bf2c8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$113** (113 USDC, 0 WBTC) |
| **Blocks** | 26403970-26403972 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $113 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #90: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1445f32d1a74872ba41f3d8cf4022e9996120b31` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$105** (105 USDC) |
| **Blocks** | 26403972-26403972 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $105 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #91: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x11b815efb8f581194ae79006d24e0d814b7697f6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$35** (0 WETH, 0 WETH, 0 WETH, 35 USDT) |
| **Blocks** | 26403906-26403972 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $35 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #92: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc7bbec68d12a0d1830360f8ec58fa599ba1b0e9b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **9** token transfers totaling **$277** (0 WETH, 0 WETH, 0 WETH, 0 WETH, 0 WETH) |
| **Blocks** | 26403842-26403972 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $276 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #93: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe3c0c6cad89a83c9424d5c21abcc380ceee3ac0f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$100** (50 USDT, 50 USDC) |
| **Blocks** | 26403939-26403972 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $100 total (USDC, USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #94: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6f0f0f3551140f3d328a221a632f512dc57dbbf0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$510** (0 DAI, 0 DAI, 509 USDT) |
| **Blocks** | 26403857-26403972 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $510 total (USDT, DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #95: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6277d5a23485d829e29881e14ccb36d90d0cd993` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 DAI) |
| **Blocks** | 26403972-26403972 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $0 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #96: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5f664b1f291d549caf91e48fcec3b8c49057f744` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDT) |
| **Blocks** | 26403972-26403972 |

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

## Finding #97: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x129bf8f9a1984027b51a103bf067301190184dcf` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$14** (14 USDT) |
| **Blocks** | 26403971-26403971 |

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

## Finding #98: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa76ed5e43c2a680a1c69ffec4e174dea23911e38` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$1** (0 USDC, 0 USDC, 0 USDC) |
| **Blocks** | 26403964-26403971 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #99: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc8d4de3aea790ac1ee7049b6044637e3d023e4c8` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDC) |
| **Blocks** | 26403971-26403971 |

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

## Finding #100: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x00000000000014aa86c5d3c41765bb24e11bd701` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$192** (192 USDC, 0 wstETH) |
| **Blocks** | 26403912-26403971 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $192 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #101: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xee15559a5207d9c00825df5db20f0b6067606cb6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDC) |
| **Blocks** | 26403971-26403971 |

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

## Finding #102: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1a1468974b6fd7531138e0fb507db9b191da955b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2** (2 USDT) |
| **Blocks** | 26403970-26403970 |

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

## Finding #103: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x7f2be416bc2d91ec705e7a415b47e82b9389a707` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$13** (5 USDT, 3 USDT, 2 USDT, 3 USDT) |
| **Blocks** | 26403880-26403969 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $13 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #104: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x03d019a704177dacc61c41c6c48e90043b554446` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$10** (10 USDT) |
| **Blocks** | 26403968-26403968 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $10 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #105: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2c25dbb775aad9aac139b279e3ccc68c03d7fc77` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$3** (2 USDC, 1 USDC) |
| **Blocks** | 26403958-26403968 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #106: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x170ec58a6fa40708a4313bb47d336e17f65c75c3` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$300** (300 USDC) |
| **Blocks** | 26403965-26403965 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $300 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #107: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4933449cde3e9e00e457146e845976585a679121` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$50** (50 USDT) |
| **Blocks** | 26403965-26403965 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $50 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #108: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x57281d1045b459e738393bfdfc17b8e961965474` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$1,329** (800 USDT, 500 USDT, 9 USDT, 20 USDC) |
| **Blocks** | 26403862-26403965 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,329 total (USDC, USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #109: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xefc6516323fbd28e80b85a497b65a86243a54b3e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDC) |
| **Blocks** | 26403964-26403964 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $100 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #110: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x23878914efe38d27c4d67ab83ed1b93a74d4086a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$350** (350 USDT) |
| **Blocks** | 26403964-26403964 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $350 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #111: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x06da0fd433c1a5d7a4faa01111c044910a184553` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$100** (100 USDT) |
| **Blocks** | 26403964-26403964 |

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

## Finding #112: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0afde794b249604d821b978480edcb8533c4dd64` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$8,000** (8,000 USDC) |
| **Blocks** | 26403963-26403963 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $8,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #113: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x19d3498b88345a016683b2377032eb4964400256` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$396** (130 USDC, 92 USDC, 174 USDC) |
| **Blocks** | 26403845-26403960 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $396 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #114: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0d4a11d5eeaac28ec3f61d100daf4d40471f1852` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$40** (40 USDT) |
| **Blocks** | 26403959-26403959 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $40 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #115: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x3cc8daf5bce18122b4d878023e65389f07b2b466` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$48** (24 USDC, 25 USDC) |
| **Blocks** | 26403893-26403957 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $48 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #116: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x32d400d32d656072b9ab27dc32f7a5aff7a3f483` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$70** (33 USDC, 37 USDC) |
| **Blocks** | 26403912-26403956 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $70 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #117: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc849fd58d5001d34f9c3ed9aefe11b7f4fc2412d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$499** (499 USDC) |
| **Blocks** | 26403953-26403953 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $499 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #118: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x98c23e9d8f34fefb1b7bd6a91b7ff122f4e16f5c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$2,125** (975 USDC, 1,000 USDC, 150 USDC) |
| **Blocks** | 26403870-26403949 |

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
- **stablecoin_mixing** (+80) — 3 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,125 total (USDC) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #119: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xde758db54c1b4a87b06b34b30ef0a710dc35388f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **3** token transfers totaling **$150** (100 USDT, 50 USDT, 0 WETH) |
| **Blocks** | 26403831-26403946 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $150 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #120: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x26d8f2d96a33e9926295d72b884249d3e2afee00` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$628** (628 USDT) |
| **Blocks** | 26403945-26403945 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $628 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #121: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x4504db1ca6659fa04b5bc9c96deee4691c58f034` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDT) |
| **Blocks** | 26403944-26403944 |

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

## Finding #122: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2c0552e5dcb79b064fd23e358a86810bc5994244` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$623** (500 USDC, 122 wTAO, 0 cirBTC, 0 cirBTC) |
| **Blocks** | 26403876-26403939 |

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

## Finding #123: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5a049323d8612f41f3d714040551581a85b4c64a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$0** (0 USDC) |
| **Blocks** | 26403937-26403937 |

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

## Finding #124: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x14b0fff65528eb447a2ad83ff6aadd7dce5ad7d0` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,949** (1,949 USDC) |
| **Blocks** | 26403937-26403937 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,949 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #125: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x98ac5b90e4562baee0ed3989fc587dfe3ca7d9b5` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1** (1 USDT) |
| **Blocks** | 26403935-26403935 |

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

## Finding #126: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe08da0d972b74581ec77a3c988e47d6e56bfbb7d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$418** (418 USDC) |
| **Blocks** | 26403932-26403932 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $418 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #127: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x40fc316c3534973a619cc8bcf41b95cad829872e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$11,392** (98 USDT, 11,294 wQUIL) |
| **Blocks** | 26403899-26403932 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $98 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #128: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x905184c521129d4f201964a493d1bbd644cbd3e3` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$5,814** (5,814 USDC) |
| **Blocks** | 26403931-26403931 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $5,814 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #129: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xde87718fd060c137853ee01f957199edd4872b52` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **5** token transfers totaling **$3,341** (15 USDC, 1,356 USDC, 193 USDC, 75 USDC, 1,702 USDC) |
| **Blocks** | 26403845-26403928 |

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
- **stablecoin_mixing** (+80) — 5 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3,341 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #130: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6e2fa1663d120205e820368042edef8d6ccdb7b9` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1** (1 USDT) |
| **Blocks** | 26403927-26403927 |

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

## Finding #131: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x88a0d2619844bed8d1140241e1b3ab2b9dad6bb1` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,423** (2,423 USDT) |
| **Blocks** | 26403927-26403927 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,423 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #132: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5ae13baaef0620fdae1d355495dc51a17adb4082` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$16** (16 USDC) |
| **Blocks** | 26403926-26403926 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $16 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #133: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5290cb6dc9078f6f2c97c8070bf9f68e07c98858` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1** (1 USDC) |
| **Blocks** | 26403922-26403922 |

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

## Finding #134: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xda3510e7e100720b8bcef29e73f0847e0cccc73d` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$47** (47 USDT) |
| **Blocks** | 26403910-26403910 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $47 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #135: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd6e9cb253f719bb0f9a617aa6d5b869fa2d72f17` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,019** (1,019 USDC) |
| **Blocks** | 26403908-26403908 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,019 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #136: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x440888714a6afed60ff44e9975a96e6a36f7fac4` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **4** token transfers totaling **$4,599** (1,155 USDC, 1,150 USDC, 1,147 USDC, 1,147 USDC) |
| **Blocks** | 26403839-26403906 |

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
- **stablecoin_mixing** (+80) — 4 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $4,599 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #137: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xba10f038cc75ba1f5da5f952e0f238b121159fae` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,927** (1,927 USDC) |
| **Blocks** | 26403905-26403905 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,927 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #138: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xbff8e1d06a59f412915f5032b2d89ba3374b8e76` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1** (1 USDT) |
| **Blocks** | 26403899-26403899 |

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

## Finding #139: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x00e5a430102ae3e37ee0233d6d6fb979bd863a7b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$107** (107 USDT) |
| **Blocks** | 26403899-26403899 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $107 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #140: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe4b7538c2e2bc683a3e84ea67aded2dff6c8cef5` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$492** (492 USDT) |
| **Blocks** | 26403899-26403899 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $492 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #141: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x9cb8f120e87d27eba1add0535726fbc03af94053` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$495** (495 USDC) |
| **Blocks** | 26403888-26403888 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $495 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #142: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe3f02b5548d5f6389c641841b0ba87af5e704562` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDC) |
| **Blocks** | 26403886-26403886 |

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

## Finding #143: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x19f578a1e323d270d7f08e6643f5e9ed2281a961` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$238** (238 USDT) |
| **Blocks** | 26403886-26403886 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $238 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #144: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6ccb7fb5a27f693c07849bfaccfc5f205b1321ce` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$390** (390 USDT) |
| **Blocks** | 26403884-26403884 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $390 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #145: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xcb9429292a8b77e9648e2c14378ee3215f340a81` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **2** token transfers totaling **$62** (28 USDT, 35 USDT) |
| **Blocks** | 26403831-26403874 |

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
- **stablecoin_mixing** (+80) — 2 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $62 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #146: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe38126d3114e669e40d7a4f93e373c991ab2f347` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$297** (297 USDC) |
| **Blocks** | 26403872-26403872 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $297 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #147: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa7b1d3a045fe9566513f3ecc858469640c88be29` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,250** (1,250 USDC) |
| **Blocks** | 26403871-26403871 |

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

## Finding #148: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb391ae930ec56baaef52bfc545ae2c58d9afb39f` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$182** (182 USDC) |
| **Blocks** | 26403866-26403866 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $182 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #149: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe29771d17e879beae9be4b7127f3d5c7bbd50a36` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$500** (500 DAI) |
| **Blocks** | 26403865-26403865 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $500 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #150: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5b03cccab7ba3010fa5cad23746cbf0794938e96` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$24** (24 USDT) |
| **Blocks** | 26403865-26403865 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $24 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #151: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1430111c4438ab4b74684dc6d8946690ccd29254` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$70** (70 USDT) |
| **Blocks** | 26403857-26403857 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $70 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #152: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xf6e72db5454dd049d0788e411b06cfaf16853042` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$509** (509 DAI) |
| **Blocks** | 26403857-26403857 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $509 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #153: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xcde850e02a5d1ebedb5e1d2b177af8770354fdb7` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$3** (3 USDC) |
| **Blocks** | 26403854-26403854 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $3 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #154: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x1051c89d5ce343c5f49eb3fa0ae8365560ba9b46` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$152** (152 USDT) |
| **Blocks** | 26403851-26403851 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $152 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #155: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8cc0dc80663c087e0f2eda12d5cb07db7337965b` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$20** (20 USDT) |
| **Blocks** | 26403850-26403850 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $20 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #156: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x04571c32a4e1c5f39bc3a238cb95b215058c432c` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$999** (999 USDC) |
| **Blocks** | 26403849-26403849 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $999 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #157: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xecca2aacf9a2e038989f410210917d2ca8ce6914` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDT) |
| **Blocks** | 26403849-26403849 |

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

## Finding #158: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xdd763f65321ff683b4372a1c63f5a44ecfda90e6` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$7,366** (7,366 USDT) |
| **Blocks** | 26403846-26403846 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $7,366 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #159: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa7c00000840eb345eb88b4282bf6926f5b67e81e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$1,702** (1,702 USDT) |
| **Blocks** | 26403845-26403845 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $1,702 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #160: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xc5a02e2783502cce276f4ff1fcc01cf133e4906a` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$2,000** (2,000 USDC) |
| **Blocks** | 26403837-26403837 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $2,000 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #161: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0bd43047da61afc9514eb1d24cdd49de6f02207e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$8** (8 USDT) |
| **Blocks** | 26403833-26403833 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $8 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #162: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x71a46234bf365d787263f1fe8a56c8857492b732` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$700** (700 USDT) |
| **Blocks** | 26403833-26403833 |

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

## Finding #163: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xb0829450d0f811dff6ed9c73d95b597d8e560567` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$42** (42 USDT) |
| **Blocks** | 26403831-26403831 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $42 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #164: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x655a842f2c9b18998bd24644fe758f733c583097` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** token transfer totaling **$41** (41 USDC) |
| **Blocks** | 26403831-26403831 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to CoW Protocol GPv2Settlement (intent settlement): $41 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #165: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xe5d7ab4518b92469d17f08eed1012c2b7174849d` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403997-26403997 |

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
| Wallet Age | 1382 days |
| Total Transactions | 5 |
| Current Balance | 0.009428 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #166: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x3e426c417b40f3189d64b15dc6662b4af83baa5c` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403994-26403994 |

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
| Wallet Age | 20 days |
| Total Transactions | 10 |
| Current Balance | 0.396171 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #167: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x50c239a876740391e8374ce36ae271718d4622dd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.5052 ETH** ($968) |
| **Blocks** | 26403994-26403994 |

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
| Wallet Age | 3225 days |
| Total Transactions | 22 |
| Current Balance | 0.002314 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #168: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x190178f0bd1f9f68d366000d12633e25afd48314` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403992-26403992 |

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
| Current Balance | 0.049873 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #169: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x37ff19a58a27444d3ac0fd98373dc709261476d5` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0057 ETH** ($11) |
| **Blocks** | 26403986-26403986 |

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
| Wallet Age | 82 days |
| Total Transactions | 12 |
| Current Balance | 0.025091 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #170: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xea86e3ea45ab2e3ea6b2b2d796304f3fc0003533` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403979-26403979 |

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
| Wallet Age | 14 days |
| Total Transactions | 8 |
| Current Balance | 0.001808 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #171: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xd5970bb4588438ba21d4b67a3031d7ca699f8499` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403957-26403970 |

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
| Wallet Age | 694 days |
| Total Transactions | 452 |
| Current Balance | 0.000031 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #172: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x3ffcedbe43de60dcc58ebf5c737f5c47e8de59fd` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0019 ETH** ($4) |
| **Blocks** | 26403888-26403968 |

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
| Wallet Age | 264 days |
| Total Transactions | 5 |
| Current Balance | 0.000135 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #173: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x01342a2682d03a2b52f56d28d21a11e3133dc769` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0061 ETH** ($12) |
| **Blocks** | 26403959-26403959 |

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
| Wallet Age | 1199 days |
| Total Transactions | 35 |
| Current Balance | 0.000115 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #174: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x87c2d03afb2de5cb10dc500bb42e30cbb6bc5240` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403951-26403951 |

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
| Wallet Age | 12 days |
| Total Transactions | 15 |
| Current Balance | 0.003734 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #175: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x769ce45c435bd8be3d2002fd763a52c322185597` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0040 ETH** ($8) |
| **Blocks** | 26403949-26403949 |

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
| Wallet Age | 21 days |
| Total Transactions | 25 |
| Current Balance | 0.003613 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #176: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x75ba6c7588f5f42dcc27c5bbdf4fe289277e8767` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403947-26403947 |

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
| Wallet Age | 377 days |
| Total Transactions | 31 |
| Current Balance | 0.002515 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #177: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x10229ba314aa356a8cff17f279aff54dd7ae3559` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403946-26403946 |

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
| Wallet Age | 123 days |
| Total Transactions | 344 |
| Current Balance | 0.015591 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #178: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xbe2b56805501c317b7e0b69e76ee05b677701d98` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0059 ETH** ($11) |
| **Blocks** | 26403925-26403925 |

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
| Wallet Age | 1552 days |
| Total Transactions | 143 |
| Current Balance | 0.001882 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #179: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x974889b1ea319f8e13dc2fa67415a0c9b6d1c085` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0022 ETH** ($4) |
| **Blocks** | 26403922-26403922 |

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
| Wallet Age | 100 days |
| Total Transactions | 49 |
| Current Balance | 0.001742 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #180: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x479a08a9248e64f7c1b37a78298605b02549b306` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403867-26403893 |

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
| Wallet Age | 135 days |
| Total Transactions | 157 |
| Current Balance | 0.001901 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #181: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xe881d77c58f217a02c05cd63035cb32ca75ab7a4` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0030 ETH** ($6) |
| **Blocks** | 26403878-26403878 |

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
| Wallet Age | 83 days |
| Total Transactions | 491 |
| Current Balance | 0.000215 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #182: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x071e7f8a62d3d098553a41f93ad414c502a8866f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403872-26403872 |

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
| Wallet Age | 32 days |
| Total Transactions | 12 |
| Current Balance | 0.043752 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #183: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xcb3888794af14fe2d088f009de79e7618d182a78` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403867-26403867 |

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
| Wallet Age | 240 days |
| Total Transactions | 68 |
| Current Balance | 0.033792 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #184: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x999f938d97639e825dc963d375c69c78e5e03f38` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403862-26403862 |

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
| Wallet Age | 172 days |
| Total Transactions | 8443 |
| Current Balance | 0.029785 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #185: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x8e1f13a08012f34dc8750ee34b78e90b5616f194` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403860-26403860 |

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
| Wallet Age | 2245 days |
| Total Transactions | 66 |
| Current Balance | 0.006395 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #186: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x057bd3aef5a40e4990230450062a7fcebae4c2ff` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.5036 ETH** ($965) |
| **Blocks** | 26403859-26403859 |

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
| Wallet Age | 450 days |
| Total Transactions | 100 |
| Current Balance | 0.217262 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #187: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xf83fcc48b872b301fbe4980c4bd639afc3975273` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.2620 ETH** ($502) |
| **Blocks** | 26403859-26403859 |

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
| Wallet Age | 124 days |
| Total Transactions | 12 |
| Current Balance | 0.000918 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #188: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x7ff95d2e7f5063423367a0a2c59df700a0796046` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403858-26403858 |

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
| Total Transactions | 67 |
| Current Balance | 0.002647 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #189: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x028a3002f878ac9d51dd34e836fe05d343ca65f2` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403850-26403850 |

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
| Wallet Age | 269 days |
| Total Transactions | 434 |
| Current Balance | 0.012963 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #190: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x9ad7c5c35bf99bb894ccf87dd523ddd2e3dfbe79` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403848-26403848 |

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
| Total Transactions | 192 |
| Current Balance | 0.004843 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #191: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xf0b18fddad37b6a3b6f3c762aca6008e27774e54` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0105 ETH** ($20) |
| **Blocks** | 26403847-26403847 |

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
| Wallet Age | 2596 days |
| Total Transactions | 3005 |
| Current Balance | 0.020280 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #192: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x0dc1e92fbcc8413b1341f4c1b1c203c3b1a03d73` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403831-26403831 |

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
| Total Transactions | 12926 |
| Current Balance | 0.050274 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #193: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xfb375df0e29babe217d04e858d04b1d2df7c6fd2` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0060 ETH** ($11) |
| **Blocks** | 26403827-26403827 |

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
| Wallet Age | 1063 days |
| Total Transactions | 816 |
| Current Balance | 0.000779 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #194: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x9e0653ff7b7f600dcf2cdcdbad15863fc5c7693b` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403816-26403816 |

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
| Wallet Age | 796 days |
| Total Transactions | 292 |
| Current Balance | 0.178035 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #195: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0x5f8e50be79880b16bd75ebdab8638170511a0b5f` |
| **Target** | Across SpokePool V2 (`0x5c7bcd6e7de5423a25...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403805-26403805 |

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
| Wallet Age | 758 days |
| Total Transactions | 2185 |
| Current Balance | 0.098169 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to Across SpokePool V2 — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #196: MEDIUM — Score 65

| | |
|---|---|
| **Sender** | `0xd90acddac86eeeaba70f35a218929c795621607e` |
| **Target** | CoW Protocol GPv2Settlement (intent settlement) (`0x9008d19f58aabd9ed0...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26403931-26403931 |

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
| Total Transactions | 16866 |
| Current Balance | 0.620606 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 65):
- **bridge_hop** (+65) — Deposit to CoW Protocol GPv2Settlement (intent settlement) — cross-chain bridge

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**196 suspicious findings** detected across 196 unique wallets. Highest risk score: **195**.

| | |
|---|---|
| 🔴 CRITICAL | 17 |
| 🟠 HIGH | 33 |
| Wallets flagged | 196 |
| Suspicious value | 1.3161 ETH ($2,521) + $7,706,960 in stablecoins |
| Blocks scanned | 26403801 — 26404000 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 3 of 25 attempted analyses this run.

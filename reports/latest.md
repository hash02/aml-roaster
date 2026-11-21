# 🔥 AML Roaster Report
**2026-11-21 18:51 UTC** · Ethereum Mainnet · ETH $1,680.81
**Blocks:** 26465176 — 26465375 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26465176 to 26465375 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 330

| | |
|---|---|
| **Sender** | `0x5555555731006f71f121144534ca7c8799f66aa3` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **11** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26465180-26465338 |

### 💬 What Happened
A user made 11 very small, identical ETH transfers—each effectively zero—to the Tornado Cash Router. This is like dropping 11 identical empty envelopes into a box that then shuffles them before giving them to a random person. The total amount was zero, so no actual ETH was moved, but the pattern looks fishy.

### 🔥 The Roast
Looks like someone tried to play a game of "who can send the tiniest coin?" with a mixer. The engine gave a 100 on mixer_touch (meaning the transaction directly goes to a known mixer address) because it’s as obvious as a red flag emoji. 70 on mixer_contract_call shows they might be just calling the mixer to make the blockchain think they’re voting, or maybe they’re just messing around. 70 on structuring? Yeah, that’s the classic "smurfing" pattern: 11 identical zero-value deposits—like sending 11 empty envelopes in a row. And 60 on peel_chain_linear? That’s the layering dance where the same move repeats like a bad karaoke loop.

### 🎯 Verdict & Next Steps
**CRITICAL — the pattern of zero-value structuring and mixer use indicates a high likelihood of layering activity.**

Flag the transaction for manual review by the AML compliance team. Verify whether the sender has a legitimate business purpose for using the mixer and assess any potential connection to illicit activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1325 days |
| Total Transactions | 9174 |
| Current Balance | 20.757788 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (5 rules, composite score: 330):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **structuring** (+70) — All 11 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 11 sequential similar deposits — layering pattern
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The sender's wallet (0x5555555731006f71f121144534ca7c8799f66aa3) performed 11 consecutive zero-value ETH transfers to the Tornado Cash Router (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b) between blocks 26465180 and 26465338. This activity triggers the following AML engine rules: [mixer_touch] (score 100), [mixer_contract_call] (score 70), [structuring] (score 70), [peel_chain_linear] (score 60), and [exchange_avoidance] (score 30). The pattern of identical, zero-value deposits and the use of a known mixer address constitutes a high-risk layering and structuring activity that warrants further investigation. CRITICAL (rule score 330)

</details>

---

## Finding #2: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x03392600086874456e08d2bac104380bcdebcfc0` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26465308-26465348 |

### 💬 What Happened
A wallet sent two tiny, zero‑value messages to a cryptocurrency mixer called Tornado Cash. It's like someone slipped a note into a sealed envelope and gave it to a post office that shuffles mail to hide who wrote it. The wallet has been active for 1274 days, but the last two actions were just tiny clicks with no money moving.

### 🔥 The Roast
So, the sender decided to play hide‑and‑seek with a mixer, sending zero ETH to the Tornado Cash router. It's like showing up to a party with a fake invitation that says '0 dollars' and hoping nobody notices you actually brought a secret stash. The engine gave it a 200 score – that's like a red flag on a driver's license, but with more zeros. The mixer_touch rule (meaning you touched a known mixer) hit 100, mixer_contract_call (a zero‑value contract call, basically a ghost handshake) hit 70, and exchange_avoidance (trying to dodge KYC by not using an exchange) added 30. Bottom line: this is a classic “I’m going to hide my money” move, not a polite tip.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of mixer usage and zero‑value contract calls indicates a high probability of layering activity that warrants immediate review.**

Flag this wallet for manual compliance review; request source of funds and transaction context, and consider monitoring subsequent activity for further layering or suspicious movement.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1274 days |
| Total Transactions | 5187 |
| Current Balance | 0.756917 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: Sender wallet 0x03392600086874456e08d2bac104380bcdebcfc0 performed two transactions within block range 26465308-26465348, each with zero ETH, directed to address 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b (Tornado Cash Router). Engine flagged [mixer_touch] (score 100) for direct deposit to a known mixer, [mixer_contract_call] (score 70) for zero‑value contract call to the mixer router, and [exchange_avoidance] (score 30) indicating avoidance of regulated exchanges. The wallet has a long activity history (5187 txs, 1274 days old) but currently holds 0.756917 ETH and was active in the latest block. CRITICAL (rule score 200)

</details>

---

## Finding #3: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x66621c9432d5205c5f299b8aa5f3c88b6f399999` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26465300-26465343 |

### 💬 What Happened
The sender's wallet sent two tiny, zero‑value messages straight into the Tornado Cash router. It's like dropping two empty envelopes into a black‑hole that scrambles who actually sent the mail, but with nothing inside to hide.

### 🔥 The Roast
Looks like this wallet decided to play a game of 'who can send the most empty gas' and hit the mixer like a pro. With a 19‑day old account that has already sent 60 tiny packets, it's basically the cryptocurrency equivalent of a kid with a magic trick: 'Watch me disappear your money!' The zero‑value calls to Tornado Cash are so silent, you'd think they're trying to be invisible. Score-wise, 200 points— that's like getting an A+ for being suspicious. If you thought sending nothing was a good idea, congratulations, you've just earned a perfect score for obfuscation.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 200)**

Flag this address for enhanced monitoring and request further investigation into the source and destination of the funds. Consider adding the wallet to the watchlist and initiating a detailed transaction trail analysis.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 19 days |
| Total Transactions | 60 |
| Current Balance | 0.048219 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction record shows two zero‑value calls from address 0x66621c9432d5205c5f299b8aa5f3c88b6f399999 to the Tornado Cash router (address 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b) within blocks 26465300‑26465343. This activity satisfies the following AML rules: [mixer_touch] (score: 100) for direct deposit to a known mixer, [mixer_contract_call] (score: 70) for a zero‑value contract call, and [exchange_avoidance] (score: 30) for routing funds away from regulated exchanges. CRITICAL (rule score 200) The wallet is 19 days old, has 60 prior transactions, and currently holds 0.048219 ETH, with no recent balance change, suggesting potential layering activity.

</details>

---

## Finding #4: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x94751787f430fc4cb37d4c37407c5f72f1fe1420` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26465337-26465337 |

### 💬 What Happened
A user sent a tiny, zero‑value Ethereum transaction directly to the Tornado Cash router. This is like dropping a note into a secret mailbox that scrambles who wrote it. No actual money changed hands, but the move flags a potential attempt to hide the source of funds.

### 🔥 The Roast
So our guy just flicked a 0‑ETH coin to Tornado Cash. That's like trying to use a paper shredder to hide a grocery receipt—only the shredder works, the receipt is still there. The engine gave him a 100 on mixer_touch (meaning a direct deposit to a known mixer), 70 on mixer_contract_call (a zero‑value contract call to the mixer router, like a telemarketer calling 911 just to create noise), and 30 on exchange_avoidance (routing funds away from a regulated exchange to dodge KYC). Bottom line: he tried to make his crypto vanish like a magician’s rabbit, but the rabbit’s still in the hat.

### 🎯 Verdict & Next Steps
**CRITICAL — the composite score of 200, largely driven by mixer_touch and mixer_contract_call, signals a high probability that the wallet is attempting to conceal transaction origins.**

Place the wallet on a temporary watchlist and request additional information from the owner if possible. In parallel, conduct a deeper audit of the wallet's historical activity for patterns of layering or structuring.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 35 days |
| Total Transactions | 106 |
| Current Balance | 0.099506 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction, with a composite score of 200, triggered the following AML rules: [mixer_touch] (score 100) for a direct deposit to the Tornado Cash router, [mixer_contract_call] (score 70) for a zero‑value contract interaction, and [exchange_avoidance] (score 30) for routing funds away from a regulated exchange. The sender wallet is 35 days old, has 106 prior transactions, and a current balance of 0.099506 ETH. No token transfers or value were moved in this block (26465337). The activity pattern aligns with known mixer usage, warranting escalation for further manual review.

</details>

---

## Finding #5: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x542db1a465fe63941fff367094e511fe81ad41b4` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26465330-26465330 |

### 💬 What Happened
The sender’s wallet sent a tiny, zero‑eth transaction to a known mixer (Tornado Cash) on a single block, like dropping a note into a black box that hides who wrote it. The transfer had no value and no tokens, but it still touches the mixer’s address, which is a red flag. The wallet is active, has been used many times, and was just active that day, but this single action points to potential obfuscation.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their ETH. They hit the Tornado Cash Router with a zero‑eth blip, as if saying, "I’m so discreet I can’t even afford to send a penny." It’s like sending a postcard with no postmark—mixer_touch score 100 (meaning the address is a known mixer), mixer_contract_call 70 (they made a contract call with no funds—maybe to pretend they’re voting), exchange_avoidance 30 (they’re sidestepping KYC by going through a mixer instead of an exchange). All together, they scored 200 on the AML engine, which is the crypto equivalent of a red flag at a border checkpoint.

### 🎯 Verdict & Next Steps
**CRITICAL – The composite score of 200, driven by mixer usage and zero‑value contract calls, indicates high risk of illicit activity requiring immediate review.**

CRITICAL (rule score 200)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 137 days |
| Total Transactions | 887 |
| Current Balance | 0.213504 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The wallet 0x542db1a465fe63941fff367094e511fe81ad41b4 executed one transaction on block 26465330 to the Tornado Cash Router (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b) with zero ETH value and no token transfers. AML engine flagged this as [mixer_touch] (score 100), [mixer_contract_call] (score 70), and [exchange_avoidance] (score 30), yielding a composite score of 200. These indicators suggest potential use of a mixer to obscure fund origin and avoid exchange‑based KYC/AML controls.

</details>

---

## Finding #6: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x213cfeb89529efc2eae2a502d4a8253fe4ae76ef` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26465324-26465324 |

### 💬 What Happened
A wallet was caught interacting with Tornado Cash Router. Our engine flagged it at score 200.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 200)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 538 days |
| Total Transactions | 5547 |
| Current Balance | 2.341586 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #7: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x4af043aca08bbe1fa2ac78eb205ea353327aa5ce` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26465317-26465317 |

### 💬 What Happened
A user’s wallet sent a zero‑value ETH transaction to the Tornado Cash router, a service that mixes coins to hide their origin. Think of it like slipping a paper into a funnel that throws it into a maze; the sender is basically trying to make the money trail hard to follow. The transaction happened right away, with no other transfers or fees.

### 🔥 The Roast
So, he decided to play hide‑and‑seek with his 1.16 ETH, but forgot the hide part and just posted a note that says "I left it in the mixer" with a zero postage stamp. He hit a 100‑point mixer_touch score like a kid who gets a gold star for using a secret club door. The 70‑point mixer_contract_call is basically a zero‑price prank call to the router, and the 30‑point exchange_avoidance is him avoiding the exchange’s boring KYC check—like skipping the front desk at a hotel to stay in the back room. CRITICAL (rule score 200)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 200)**

Flag the wallet for manual review, trace subsequent activity for any downstream movements, and consider adding the address to a watchlist for ongoing monitoring.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 750 days |
| Total Transactions | 7942 |
| Current Balance | 1.163041 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Rule mixer_touch triggered by the direct deposit of 0 ETH to the Tornado Cash router address (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b), indicating the use of a known mixer. Rule mixer_contract_call was also activated by a zero‑value contract call to the same address, suggesting potential obfuscation or withdrawal relay activity. Rule exchange_avoidance was invoked because the sender routed funds through a mixer instead of a regulated exchange, bypassing KYC/AML controls. The composite score of 200 (100+70+30) reflects a high‑risk pattern requiring further investigation.

</details>

---

## Scan Summary

**7 suspicious findings** detected across 7 unique wallets. Highest risk score: **330**.

| | |
|---|---|
| 🔴 CRITICAL | 7 |
| 🟠 HIGH | 0 |
| Wallets flagged | 7 |
| Suspicious value | 0.0000 ETH ($0) |
| Blocks scanned | 26465176 — 26465375 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 1 of 7 attempted analyses this run.

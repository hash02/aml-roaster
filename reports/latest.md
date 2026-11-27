# 🔥 AML Roaster Report
**2026-11-27 20:50 UTC** · Ethereum Mainnet · ETH $1,665.95
**Blocks:** 26508847 — 26509046 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26508847 to 26509046 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x0a5b2bf3ccfb44c1d22f07eed9553ecba752d4ad` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26509018-26509018 |

### 💬 What Happened
The sender’s wallet sent an invisible amount of ETH to the Tornado Cash Router, a service that scrambles who sent the money, like dropping a letter into a dropbox that hides the sender’s address.

### 🔥 The Roast
So the wallet decided to play hide-and-seek with the blockchain, sending a ghost ETH to Tornado Cash—think of it as paying a friend with an empty envelope. The AML engine gave it a 200 score—like a Michelin-starred chef rating a pizza with no cheese. The rule [mixer_touch] (meaning the wallet touched a known mixer) scored 100, and [mixer_contract_call] (meaning a contract call with no value, probably a trick or a vote) scored 70. Even though the transaction was worth $0, the engine thinks it’s suspicious because it’s using a mixer to dodge KYC, which is exactly what [exchange_avoidance] (meaning routing funds to a mixer instead of a regulated exchange) is about.

### 🎯 Verdict & Next Steps
**CRITICAL — transaction triggers high‑suspicion mixer usage pattern with composite score 200, warranting immediate review.**

Flag the wallet for manual review, investigate source and destination of funds, and monitor for related activity. Consider adding to watchlist and notifying relevant compliance officers.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 519 days |
| Total Transactions | 11354 |
| Current Balance | 10.545268 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
SAR: Transaction at block 26509018 shows a direct deposit to Tornado Cash Router, triggering rule [mixer_touch] (score 100). The zero‑value contract call to the same address triggers rule [mixer_contract_call] (score 70). The routing bypasses exchange KYC controls, matching rule [exchange_avoidance] (score 30). CRITICAL (rule score 200) Further human review is warranted.

</details>

---

## Finding #2: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x6170c33ca765fc279287d5002a8976fd2bcae7da` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26508966-26508966 |

### 💬 What Happened
The wallet sent a tiny, empty packet of Ethereum to a known mixer service. It's like dropping an invisible envelope into a black hole that scrambles who sent it and who will get it. Nothing actually changed hands—just a zero‑value call that likely triggers a withdrawal or a vote behind the scenes.

### 🔥 The Roast
So this guy decided to send a packet of nothing to Tornado Cash. It's the blockchain equivalent of posting a postcard that says I sent you zero money and hoping someone still thinks it's a big deal. The engine slapped a 100 on [mixer_touch] because the address hit the mixer like a kid hitting the playground slide. Then a 70 on [mixer_contract_call] for that sneaky zero‑value contract call—maybe a prank or a secret vote. And a 30 on [exchange_avoidance] because obviously you don't want your ETH to get caught by a legit exchange that knows your name. Total score 200—looks like a classic I tried to be invisible but left a breadcrumb.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 200)**

Flag the sender wallet for enhanced due diligence, review any linked transactions, and consider submitting a SAR to the relevant regulatory authority.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 903 days |
| Total Transactions | 10 |
| Current Balance | 1.382644 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction from address 0x6170c33ca765fc279287d5002a8976fd2bcae7da to the Tornado Cash router 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b constitutes a direct deposit to a known mixer, triggering rule [mixer_touch] (score 100). The subsequent zero‑value contract call to the same router activates rule [mixer_contract_call] (score 70), indicating potential withdrawal or governance activity. Additionally, rule [exchange_avoidance] (score 30) is satisfied due to the use of a mixer to avoid KYC/AML controls typically enforced by regulated exchanges. CRITICAL (rule score 200)

</details>

---

## Finding #3: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0xc49415493eb3ec64a0f13d8aa5056f1cfc4ce35c` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26508949-26508949 |

### 💬 What Happened
The sender wallet sent a tiny, zero‑value transaction straight into the Tornado Cash router, a service that mixes crypto to hide origins, like dropping a parcel into a slot that hides who mailed it. No coins were actually moved—just a call to the mixer that could be a trick or a normal withdrawal. The wallet is active, has been around for 3.6 years, and still holds about 0.57 ETH.

### 🔥 The Roast
So, the sender decided to play the ‘invisible coin’ game, sending zero ETH into the Tornado Cash router (a mixer service that shuffles coins to hide where they came from). The AML engine gave this a 200 composite score, like a perfect exam in the art of staying anonymous. The [mixer_touch] rule scored 100, because the transaction was a direct deposit to the mixer, a red flag for obfuscation. The [mixer_contract_call] rule scored 70, because the wallet called the mixer contract, a typical sign of withdrawal or governance activity. And [exchange_avoidance] scored 30 because the funds never hit a legitimate exchange, so the engine thinks they’re trying to avoid KYC.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits multiple high‑risk mixer and exchange avoidance indicators that warrant immediate investigation.**

Flag the wallet for manual review and add it to the watchlist; monitor subsequent activity for further suspicious patterns and downstream transfers.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 1313 days |
| Total Transactions | 6506 |
| Current Balance | 0.570109 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction (block 26508949) involved a direct deposit to the Tornado Cash router, triggering the [mixer_touch] rule (score 100) for known mixer activity. A zero‑value contract call to the same router activated the [mixer_contract_call] rule (score 70), indicating potential withdrawal relay or governance usage. The [exchange_avoidance] rule (score 30) flagged the routing of funds through a mixer instead of a regulated exchange, signaling avoidance of KYC/AML controls. The composite score of 200 places this activity in the high‑risk category per the AML engine, warranting a suspicious activity report and further review.

</details>

---

## Scan Summary

**3 suspicious findings** detected across 3 unique wallets. Highest risk score: **200**.

| | |
|---|---|
| 🔴 CRITICAL | 3 |
| 🟠 HIGH | 0 |
| Wallets flagged | 3 |
| Suspicious value | 0.0000 ETH ($0) |
| Blocks scanned | 26508847 — 26509046 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

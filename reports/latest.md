# 🔥 AML Roaster Report
**2026-11-04 13:58 UTC** · Ethereum Mainnet · ETH $2,317.50
**Blocks:** 26341688 — 26341887 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26341688 to 26341887 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 320

| | |
|---|---|
| **Sender** | `0x39c109d7d826d4651c661a102e5353924da6090e` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **100.0000 ETH** ($231,750) |
| **Blocks** | 26341816-26341816 |

### 💬 What Happened
A brand-new wallet (like a brand-new pizza box) immediately sent all its money, about 100 ETH, into a crypto mixer called Tornado Cash. The wallet had been created that same day and had no other transactions before this huge move, leaving a tiny balance of 0.000841 ETH. In plain terms, it's like someone dropping a large cash bundle into a secret box that hides where it came from and then vanishing.

### 🔥 The Roast
CRITICAL (rule score 320) Score 100 on novel_wallet_dump (a brand-new wallet dumping a huge sum is as suspicious as a kid selling all his toys for cash). Score 50 on whale_transfer (moving 100 ETH is like a whale swimming across the ocean). Score 40 on exit_rush (the wallet is almost empty afterward, like a robber who empties a bank vault and leaves a single coin). Score 30 on exchange_avoidance (the money bypasses regulated exchanges, avoiding the usual KYC checks).

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 320)**

Flag the transaction for manual review and consider adding the wallet address to the watchlist. Notify the compliance team to monitor any subsequent activity and request additional context from the sender if possible.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 7 |
| Current Balance | 0.000841 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (5 rules, composite score: 320):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **novel_wallet_dump** (+100) — Wallet is 0 days old, moving 100.0000 ETH — classic burner pattern
- **whale_transfer** (+50) — Whale-level transfer: 100.0000 ETH ($231,750)
- **exit_rush** (+40) — Wallet balance near zero (0.000841 ETH) after moving 100.0000 ETH — funds fully drained (exit rush)
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The sender address 0x39c109d7d826d4651c661a102e5353924da6090e, created 0 days ago, executed a single transaction of 100 ETH to the Tornado Cash Router address 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b, a known mixer, in block 26341816. This transaction triggers the following AML engine rules: mixer_touch (score 100), novel_wallet_dump (score 100), whale_transfer (score 50), exit_rush (score 40), and exchange_avoidance (score 30). CRITICAL (rule score 320) Compliance teams should treat this as a high-priority flag for further investigation.

</details>

---

## Finding #2: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0xc7f8278721c86ea7a5b5a08ce47359a1f6601c8d` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26341871-26341871 |

### 💬 What Happened
A user sent a tiny, invisible packet of ETH (basically nothing) straight into a mixer called Tornado Cash. Think of it like dropping a letter into a mailbox that scrambles the sender’s address so no one knows where it came from. The transaction happened today on the blockchain, with zero value, but the sender’s wallet is still holding some ETH.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their crypto, but the mixer is so good it hides even the fact that nothing was sent. The engine gave it a 200 score, which is like a gold star for shady behavior—mixer_touch (score 100) for dropping the packet, mixer_contract_call (score 70) for the sneaky contract ping, and exchange_avoidance (score 30) for skipping the KYC party. It’s almost like the wallet said, "I don’t need a bank, I’m a magician."

### 🎯 Verdict & Next Steps
**CRITICAL — this transaction exhibits multiple high‑risk indicators, including mixer usage, zero‑value contract calls, and exchange avoidance.**

Flag the wallet for further investigation, request source‑of‑funds documentation, and monitor subsequent activity for suspicious patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 288 days |
| Total Transactions | 1392 |
| Current Balance | 0.098489 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction triggered the following AML engine rules: [mixer_touch] (score 100) due to a direct deposit to the Tornado Cash Router, [mixer_contract_call] (score 70) because of a zero‑value contract call, and [exchange_avoidance] (score 30) indicating routing funds to a mixer instead of a regulated exchange. The sender wallet has 1392 transactions, is 288 days old, and currently holds 0.098489 ETH, indicating ongoing activity. CRITICAL (rule score 200) The composite score of 200 warrants escalation for manual review.

</details>

---

## Finding #3: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x13523d719b2177c74b8c44fead30c8989cac03ae` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26341764-26341764 |

### 💬 What Happened
The user sent a tiny, almost invisible amount of ETH (essentially nothing) straight into a blockchain mixer called Tornado Cash. Think of it like dropping a paper note into a black box that scrambles who wrote it, so no one can trace where the money came from. The transaction happened right when the wallet was active, so it’s a quick, low‑volume attempt to hide the source of funds.

### 🔥 The Roast
So our friend decided to play hide‑and‑seek with their money, but forgot the "no peeking" rule. The mixer_touch score of 100 (meaning they hit the mixer’s main door) and the mixer_contract_call of 70 (a zero‑value call that might be a secret handshake or a way to whisper to the mixer) show they’re not just passing through a normal exchange. With an exchange_avoidance score of 30, it’s clear they’re sidestepping the usual KYC checkpoints. Basically, they tried to send a ghost‑money through a black‑box with the best disguise in town. This is the kind of activity that makes compliance teams raise eyebrows faster than a magician pulls a rabbit out of a hat.

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction exhibits multiple high‑risk mixer indicators and bypasses standard exchange controls, requiring urgent review.**

Flag the wallet for manual AML review and request source‑of‑funds documentation. Monitor the wallet for additional suspicious activity and consider placing it on a watch list for future transactions.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 50 days |
| Total Transactions | 129 |
| Current Balance | 106.887320 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a direct deposit to the Tornado Cash Router, a known mixer, scoring 100 on the mixer_touch rule. A zero‑value contract call to the same address scored 70 on mixer_contract_call, indicating potential obfuscation or governance activity. The routing of funds through the mixer instead of a regulated exchange triggers a 30-point score under exchange_avoidance, reflecting KYC/AML control circumvention. The composite score of 200 warrants immediate flagging for further investigation.

</details>

---

## Finding #4: CRITICAL — Score 200

| | |
|---|---|
| **Sender** | `0x09efa4777a855eb946df013c8f3e51fc553aa81d` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26341706-26341706 |

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
| Wallet Age | 331 days |
| Total Transactions | 3699 |
| Current Balance | 0.055088 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 200):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #5: HIGH — Score 130

| | |
|---|---|
| **Sender** | `0x999099076be29a81cad25f3bb63eb62c0fd99999` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($232) |
| **Blocks** | 26341731-26341731 |

### 💬 What Happened
A brand‑new wallet just sent 0.1 ETH straight into a service called Tornado Cash, which acts like a privacy vault that hides who owns the money. The sender’s account is only two days old, has made 18 moves, and still has a small balance left after the transfer. This pattern raises a red flag because it looks like a quick drop into a mixer to scrub the transaction trail.

### 🔥 The Roast
Looks like someone just hit the "mixer" button on their crypto, like a magician pulling a rabbit out of a hat, except the rabbit is their ETH and the hat is a blockchain. The engine slapped a 100-point badge for [mixer_touch]—that’s a red flag saying, "Hey, this guy is playing hide and seek with his coins." Add on a 30-point sticker for [exchange_avoidance], meaning they skipped the exchange checkout line to avoid the KYC guard. If you think this is just a harmless game, remember mixers are the blockchain equivalent of a shady alleyway where you can drop off cash and never see who picked it up. Good luck finding the original owner when you trace the money.

### 🎯 Verdict & Next Steps
**HIGH — the combination of a new wallet, direct deposit to a known mixer, and avoidance of exchange KYC triggers a high‑risk indicator.**

Perform a manual review of the sender’s transaction history and associated addresses. Consider submitting a SAR if additional suspicious patterns emerge, and monitor for further activity from the wallet and any linked addresses.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2 days |
| Total Transactions | 18 |
| Current Balance | 0.003860 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 130):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction from 0x999099076be29a81cad25f3bb63eb62c0fd99999 to Tornado Cash Router (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b) involved 0.1000 ETH in block 26341731. The sender’s wallet is only two days old, has 18 prior transactions, and no remaining balance beyond the transferred amount, indicating potential use of the wallet for obfuscation. The AML engine flagged the activity with rule [mixer_touch] (score 100) for direct deposit to a known mixer and rule [exchange_avoidance] (score 30) for routing funds to avoid exchange KYC controls. HIGH (rule score 130)

</details>

---

## Scan Summary

**5 suspicious findings** detected across 5 unique wallets. Highest risk score: **320**.

| | |
|---|---|
| 🔴 CRITICAL | 4 |
| 🟠 HIGH | 1 |
| Wallets flagged | 5 |
| Suspicious value | 100.1000 ETH ($231,982) |
| Blocks scanned | 26341688 — 26341887 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 1 of 5 attempted analyses this run.

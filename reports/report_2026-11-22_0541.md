# 🔥 AML Roaster Report
**2026-11-22 05:41 UTC** · Ethereum Mainnet · ETH $1,647.46
**Blocks:** 26468424 — 26468623 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26468424 to 26468623 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x9b2d5b96764bca81d448456d4a3a4017b71e3ae8` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26468594-26468594 |

### 💬 What Happened
A user sent a tiny, zero-dollar amount of Ethereum into a special privacy system called Railgun, which scrambles the trail of who sent it. Think of it like dropping a note into a locked box that hides the sender’s name. The transaction was basically a test run, as nothing of value moved.

### 🔥 The Roast
Looks like someone tried to make their wallet look like a magician’s assistant. They sent a *zero* ETH to the Railgun Relay (a privacy protocol that hides transaction details), which is like giving a magician a blank card and hoping the audience thinks something mysterious happened. The AML engine gave it a 75, because apparently the privacy protocol is as suspicious as a magician's hat. It’s like sending a message to a friend but telling everyone you used a secret code—just not a very secret one. MEDIUM (rule score 75)

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol for a zero-value transaction raises moderate concern for possible layering or obfuscation, warranting review.**

Flag the account for enhanced monitoring, request additional context from the sender, and cross‑reference with other accounts using Railgun. If further suspicious activity is observed, consider filing a SAR with the compliance team.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 294 days |
| Total Transactions | 495 |
| Current Balance | 0.023250 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
SAR: The wallet 0x9b2d5b96764bca81d448456d4a3a4017b71e3ae8 performed a single zero-value Ethereum transfer to the Railgun Relay on block 26468594. Rule [privacy_protocol] – transactions routed through privacy-enhancing services without value are flagged for potential layering or obfuscation. Evidence: composite score 75, single transaction, no token transfers, sender wallet age 294 days, 495 total txs, current balance 0.023250 ETH, days since last activity 0. Recommend further investigation.

</details>

---

## Finding #2: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xf8280902176a8486a1be2b61239b558e64a39ffd` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26468540-26468540 |

### 💬 What Happened
A user sent a transaction of zero ETH to a privacy service called Railgun. Think of it like dropping a letter into a mailbox that hides the sender's address, but the letter itself is empty. The wallet is about 197 days old and has made 135 transactions, with a small remaining balance.

### 🔥 The Roast
Looks like someone tried to play hide and seek with their crypto, but forgot to bring any money to the party. They hit up Railgun Relay, the fancy privacy club, with a $0 ticket. The AML engine gave it a 75 because privacy protocols always raise eyebrows, even if you’re just sending a blank check. If you’re hoping to stay invisible, just remember: zero value doesn't mean zero risk—it's like putting a note in a mailbox but hoping the postal service never reads it.

### 🎯 Verdict & Next Steps
**MEDIUM — the high privacy protocol score signals a risk of fund obfuscation, but the transaction value is negligible.**

Flag the wallet for manual review and monitor for subsequent high‑value or suspicious activity. MEDIUM (rule score 75)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 197 days |
| Total Transactions | 135 |
| Current Balance | 0.016598 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction (block 26468540) from wallet 0xf8280902176a8486a1be2b61239b558e64a39ffd to the Railgun Relay address 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9 involved a transfer of 0 ETH, triggering the [privacy_protocol] rule with a score of 75. This pattern is consistent with privacy-enhancing service usage, which is a known high-risk activity in AML frameworks. MEDIUM (rule score 75) The composite score indicates a medium level of concern for potential layering or obfuscation of funds.

</details>

---

## Finding #3: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x1ed98663fd1000002e283a0402bd531c54ce6abc` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26468447-26468447 |

### 💬 What Happened
A wallet with 0.011314 ETH sent a tiny amount (essentially nothing) to a Railgun Relay address. Think of it like dropping a note into a locked box that only the box owner can open, but no money changed hands. The transaction was recorded in a single block and the sender was active just that day.

### 🔥 The Roast
So, this person decided to play hide-and-seek with their ETH, but forgot to bring any coins to the party. MEDIUM (rule score 75) It’s like paying a friend to hold your snack while you wait for it to magically appear elsewhere. The AML engine gave it a 75 score on privacy_protocol, which basically means ‘this is a privacy trick that might be used to hide the real source of funds.’

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

MEDIUM (rule score 75) Consider flagging the address for ongoing surveillance.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 334 days |
| Total Transactions | 2644 |
| Current Balance | 0.011314 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 75) Evidence: single block (26468447), zero ETH sent, sender balance 0.011314 ETH, wallet age 334 days, 2644 total tx count, days since last activity 0. The composite score of 75 indicates a moderate risk of obfuscation. MEDIUM (rule score 75)

</details>

---

## Scan Summary

**3 suspicious findings** detected across 3 unique wallets. Highest risk score: **75**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| Wallets flagged | 3 |
| Suspicious value | 0.0000 ETH ($0) |
| Blocks scanned | 26468424 — 26468623 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

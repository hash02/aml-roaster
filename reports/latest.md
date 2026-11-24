# 🔥 AML Roaster Report
**2026-11-24 22:03 UTC** · Ethereum Mainnet · ETH $1,678.62
**Blocks:** 26487678 — 26487877 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26487678 to 26487877 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 330

| | |
|---|---|
| **Sender** | `0x213cfeb89529efc2eae2a502d4a8253fe4ae76ef` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **4** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26487816-26487874 |

### 💬 What Happened
A wallet was caught interacting with Tornado Cash Router. Our engine flagged it at score 330.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 330)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 541 days |
| Total Transactions | 5584 |
| Current Balance | 2.997460 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (5 rules, composite score: 330):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **mixer_contract_call** (+70) — Zero-value contract call to Tornado Cash Router — likely withdrawal relay, governance vote, or obfuscation technique
- **structuring** (+70) — All 4 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 4 sequential similar deposits — layering pattern
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #2: CRITICAL — Score 300

| | |
|---|---|
| **Sender** | `0x36f454cd123b23481d60cc7fba22ea6cbd8d402b` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **2** txs totaling **20.0000 ETH** ($33,572) |
| **Blocks** | 26487682-26487685 |

### 💬 What Happened
A wallet was caught interacting with Tornado Cash Router. Our engine flagged it at score 300.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 300)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 4 |
| Current Balance | 0.000001 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (5 rules, composite score: 300):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **novel_wallet_dump** (+100) — Wallet is 0 days old, moving 20.0000 ETH — classic burner pattern
- **high_value** (+30) — High-value transfer: 20.0000 ETH ($33,572)
- **exit_rush** (+40) — Wallet balance near zero (0.000001 ETH) after moving 20.0000 ETH — funds fully drained (exit rush)
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #3: HIGH — Score 130

| | |
|---|---|
| **Sender** | `0x538b868663fc34bca279bfc03a55a48293e2991e` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($168) |
| **Blocks** | 26487877-26487877 |

### 💬 What Happened
A brand-new wallet sent 0.1 ETH straight into Tornado Cash’s router. Think of it like dropping a $168 envelope into a vending machine that then hands it out to a random stranger, hiding who paid. The wallet only just existed and hasn't moved any money before, so it's like a brand‑new anonymous shop.

### 🔥 The Roast
So this newbie wallet just decided to play hide‑and‑seek with 0.1 ETH at the same time the blockchain’s version of a cloak of invisibility. The mixer_touch rule (meaning the transaction goes straight to a known mixer) gave it a 100-point score — basically the system shouted, ‘Hey, you just used a mixer!’ Then the exchange_avoidance rule (score 30) flagged it for skipping the usual KYC‑friendly exchanges. All in all, the engine thinks this is a classic ‘I’m anonymous, so I’ll hide in a mixer’ scenario.

### 🎯 Verdict & Next Steps
**HIGH (rule score 130)**

Flag the sender address for internal investigation, request additional context on the origin of the 0.1 ETH, and monitor for subsequent activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.015996 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 130):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Transaction from address 0x538b868663fc34bca279bfc03a55a48293e2991e to 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b (Tornado Cash Router) involved 0.1000 ETH in block 26487877. The activity matches Rule [mixer_touch] (direct deposit to a known mixer) with a score of 100, and Rule [exchange_avoidance] (routing funds to avoid KYC/AML controls) with a score of 30. The sender wallet is brand new, with only one transaction and a balance of 0.015996 ETH, indicating a high likelihood of anonymity seeking. Flag for human review per AML policy.

</details>

---

## Finding #4: HIGH — Score 130

| | |
|---|---|
| **Sender** | `0x72804ead01b2458768a53476551ecea3c3da6ed4` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **1.0000 ETH** ($1,679) |
| **Blocks** | 26487862-26487862 |

### 💬 What Happened
The wallet sent 1 ETH to the Tornado Cash Router, which is like dropping a package into a box that scrambles the sender’s identity. This single transaction was the only move in that block, so the activity is very isolated but still suspicious. The sender’s wallet has been active for over six years, but it just used the mixer to hide where the money came from.

### 🔥 The Roast
Look at that, 1 ETH to the Tornado Cash Router. That's like sending a pizza delivery to a secret drop‑off spot and hoping the pizza guy forgets where it came from. The engine gave it a 100 on the mixer_touch rule (meaning this address is a known mixer) and 30 on exchange_avoidance (meaning the funds bypassed a legit exchange). Composite score of 130? That's higher than my coffee order when I need to stay awake during a 4‑hour audit. If this was a bank, they'd call the cops and the cashier would ask if you’re paying with a shell company. But hey, at least the money isn’t going to a pizza place that takes money from a bank.

### 🎯 Verdict & Next Steps
**HIGH — The composite score of 130, driven by a 100-point mixer_touch and a 30-point exchange_avoidance, exceeds typical thresholds for suspicious activity.**

Flag the transaction for manual review and request source‑of‑funds documentation from the wallet holder. Consider cross‑checking with other known mixers and monitor for subsequent transfers that may indicate layering.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2491 days |
| Total Transactions | 127 |
| Current Balance | 0.430641 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 130):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction (block 26487862) shows a single transfer of 1.0000 ETH from address 0x72804ead01b2458768a53476551ecea3c3da6ed4 to the Tornado Cash Router (address 0xd90e2f925da726b50c4ed8d0fb90ad053324f31b). This activity triggers the [mixer_touch] rule with a score of 100, indicating use of a known privacy service. Additionally, the [exchange_avoidance] rule scored 30, reflecting routing funds directly to a mixer rather than a regulated exchange, which is a recognized AML red flag. The sender’s wallet has a long history (2491 days) and a high transaction count (127), yet the recent activity suggests potential attempt to obscure the source of funds. This combination warrants further investigation under AML compliance protocols.

</details>

---

## Finding #5: HIGH — Score 130

| | |
|---|---|
| **Sender** | `0xef73c5975a91aebaec75002dca2b560ba5875a0c` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($168) |
| **Blocks** | 26487705-26487705 |

### 💬 What Happened
A person sent 0.1 ETH (about $168) to a special address that acts like a coin‑tossing machine. That address belongs to Tornado Cash, a service that mixes coins to hide their source. The transaction happened in a single block, meaning it was quick and clean.

### 🔥 The Roast
Looks like someone's trying to play hide‑and‑seek with their money. Tossing 0.1 ETH into Tornado Cash is like dropping a pizza into a slot machine that forgets who ordered it. The engine gave a 130/200, which is like a red flag on a driver’s license: you might be a good driver, but the police are watching. Mixer touch score 100? That’s the equivalent of a detective saying ‘Yep, that’s a known shady alley.’ Exchange avoidance score 30? That just means the sender is skipping the polite front desk at the bank. The wallet’s only 20 days old, like a toddler who just learned to walk, and still has more coins than it can hold. It’s basically a fresh, suspicious little kid with a shiny new toy.

### 🎯 Verdict & Next Steps
**HIGH — the combined score of 130 and the presence of a known mixer and exchange avoidance patterns warrants immediate review.**

Flag the transaction for manual investigation and request additional context from the sender, such as the origin of the funds and intended destination. Monitor the wallet for further activity, especially any movement back to a regulated exchange or any large outgoing transfers.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 20 days |
| Total Transactions | 2 |
| Current Balance | 0.035207 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 130):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
Rule: MIXER_TOUCH (score 100) indicates direct deposit to Tornado Cash Router, a known mixer. Rule: EXCHANGE_AVOIDANCE (score 30) indicates funds routed to a mixer instead of a regulated exchange, suggesting KYC circumvention. The wallet is 20 days old, has only two transactions, and currently holds 0.035207 ETH, implying potential layering. The single 0.1 ETH transfer to the mixer in block 26487705 triggers a high‑risk flag for further investigation.

</details>

---

## Scan Summary

**5 suspicious findings** detected across 5 unique wallets. Highest risk score: **330**.

| | |
|---|---|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 3 |
| Wallets flagged | 5 |
| Suspicious value | 21.2000 ETH ($35,587) |
| Blocks scanned | 26487678 — 26487877 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 2 of 5 attempted analyses this run.

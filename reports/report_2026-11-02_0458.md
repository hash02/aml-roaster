# 🔥 AML Roaster Report
**2026-11-02 04:58 UTC** · Ethereum Mainnet · ETH $2,293.22
**Blocks:** 26324652 — 26324851 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26324652 to 26324851 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xfb97bb357179b24e48ce5a0511187cddc7c4e5de` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26324742-26324742 |

### 💬 What Happened
Someone sent a tiny amount of ETH (almost nothing) to a Railgun relay, which is a privacy protocol that mixes transactions to hide the source. Think of it as dropping a small package into a slot that hides who sent it and where it goes. The transaction was essentially a zero-value transfer, so no money moved, but the pattern suggests an attempt to obscure the chain of ownership.

### 🔥 The Roast
So we got a wallet that’s 88 days old, 53 trips, still holding a fraction of an ETH—like a savings account that’s only got a single penny in it. The sender decided to play hide-and-seek with a Railgun Relay, a privacy protocol that’s basically a digital cloak and dagger. The engine gave it a 75, which is like saying the mystery is pretty deep—maybe the wallet’s trying to become a blockchain celebrity. MEDIUM (rule score 75) The score shows we’re not laughing, but we’re not crying either.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Conduct a manual review of the sender wallet's historical activity and the subsequent transactions to assess for layering or structuring. MEDIUM (rule score 75)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 88 days |
| Total Transactions | 53 |
| Current Balance | 0.000841 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involved a transfer of 0 ETH from address 0xfb97bb357179b24e48ce5a0511187cddc7c4e5de to address 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9 (Railgun Relay) on block 26324742. The AML engine flagged the activity under rule [privacy_protocol] with a composite score of 75, indicating a privacy-protocol deposit that may be used to obfuscate transaction provenance. The sender wallet is 88 days old, has 53 transactions, and currently holds a small balance of 0.000841 ETH, with no time lag since last activity. MEDIUM (rule score 75)

</details>

---

## Scan Summary

**1 suspicious finding** detected across 1 unique wallet. Highest risk score: **75**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| Wallets flagged | 1 |
| Suspicious value | 0.0000 ETH ($0) |
| Blocks scanned | 26324652 — 26324851 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

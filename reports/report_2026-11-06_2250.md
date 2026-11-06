# 🔥 AML Roaster Report
**2026-11-06 22:50 UTC** · Ethereum Mainnet · ETH $2,237.80
**Blocks:** 26358707 — 26358906 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26358707 to 26358906 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: HIGH — Score 130

| | |
|---|---|
| **Sender** | `0x56bfaddd608df084b36da89e6dce5def6897c56e` |
| **Target** | Tornado Cash Router (`0xd90e2f925da726b50c...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($224) |
| **Blocks** | 26358764-26358764 |

### 💬 What Happened
A brand‑new wallet that had never sent or received anything before just pushed 0.1 ETH (about $224) straight into Tornado Cash, a service that shuffles crypto to hide its origin. Think of it like dropping a pizza delivery order into a box that then throws the receipt out the window so no one knows who ordered it. The wallet was empty and only made this single move, so there's no clear purpose other than mixing the funds.

### 🔥 The Roast
This wallet is fresher than a latte on a Monday morning and it just decided to hit a mixer like it was a secret club. The engine slapped it a 100 on [mixer_touch] (meaning it touched a known mixer) and 30 on [exchange_avoidance] (meaning it avoided a legit exchange that would ask for ID). HIGH (rule score 130) Bottom line: this is the crypto equivalent of a one‑night stand with no intention to keep the money in the open.

### 🎯 Verdict & Next Steps
**HIGH — the transaction shows a high‑risk pattern of mixer use and exchange avoidance, with a composite score of 130, exceeding the threshold for immediate review.**

Flag the transaction for manual review by the compliance team. Monitor the wallet for additional activity and cross‑reference it with known suspicious addresses in the AML database.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.006911 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 130):
- **mixer_touch** (+100) — Direct deposit to Tornado Cash Router — known mixer
- **exchange_avoidance** (+30) — Funds routed to Tornado Cash Router instead of legitimate exchange — avoiding KYC/AML controls

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits characteristics consistent with the AML rule [mixer_touch] (direct deposit to the Tornado Cash Router) and [exchange_avoidance] (routing funds to a mixer instead of a regulated exchange). The sender wallet is brand new (age 0 days) with only one transaction, indicating a potential attempt to obfuscate the origin of the funds. The composite score of 130 exceeds the internal threshold for high‑risk transactions, warranting further investigation. HIGH (rule score 130)

</details>

---

## Scan Summary

**1 suspicious finding** detected across 1 unique wallet. Highest risk score: **130**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 1 |
| Wallets flagged | 1 |
| Suspicious value | 0.1000 ETH ($224) |
| Blocks scanned | 26358707 — 26358906 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

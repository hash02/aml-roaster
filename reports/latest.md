# 🔥 AML Roaster Report
**2026-10-31 16:58 UTC** · Ethereum Mainnet · ETH $2,250.70
**Blocks:** 26313889 — 26314088 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26313889 to 26314088 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x36b0843cf3cfd9b0091c91a9a767c0b1043a8cdd` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$200** (200 USDC) |
| **Blocks** | 26314030-26314030 |

### 💬 What Happened
A user sent $200 worth of USDC to a wallet that is known to be used by a service that mixes crypto, like a laundromat for digital money. It's like dropping a package into a box that scrambles the sender's address so nobody knows who really sent it. The transaction happened on a single block and the sender’s history is basically invisible.

### 🔥 The Roast
Looks like someone tried to play hide and seek with their money. MEDIUM (rule score 80) SideShift Hot Wallet is the hot dog stand of mixers, always ready to take orders. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Review the source of funds and verify the legitimacy of the sender. Flag the transaction for manual AML review and monitor for subsequent activity.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $200 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Transaction 0x36b0843cf3cfd9b0091c91a9a767c0b1043a8cdd to 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2 on block 26314030 shows a single USDC transfer of $200. This matches the stablecoin_mixing rule, indicating potential layering or wash activity. The sender’s wallet has no prior activity data and a zero ETH balance, further raising suspicion. Recommend manual review under AML policy and cross‑check with internal watchlists.

</details>

---

## Finding #2: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x16d6ea94064c1e7219db501e9c897f42ee255597` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$1,230** (1,230 USDT) |
| **Blocks** | 26314009-26314009 |

### 💬 What Happened
MEDIUM (rule score 80) It’s like dropping a cash envelope into a machine that scrambles the envelope’s origin so nobody can trace where the money actually came from.

### 🔥 The Roast
So this guy decided to use SideShift, the crypto laundromat that says, "We’ll make your money look like it was never yours." He sent 1,230 USDT – that’s like giving a cashier a $1,230 bill and asking them to print a $1,000 bill in a different color. The engine slapped it a score of 80, basically the crypto equivalent of a red flag that says, "We’re watching you, buddy!"

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Manually review the sender’s wallet history and source of USDT. If no legitimate origin is identified, consider freezing the funds and filing a report with the appropriate regulatory body.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $1,230 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Transaction from 0x16d6ea94064c1e7219db501e9c897f42ee255597 to 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2 (SideShift Hot Wallet) transferred 1,230 USDT (stablecoin). MEDIUM (rule score 80) The sender wallet has no recorded activity and a zero ETH balance, suggesting a potentially suspicious profile. MEDIUM (rule score 80)

</details>

---

## Finding #3: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xd324ac9312ab679499426ef87ee040e8c0a3834e` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$89** (89 DAI) |
| **Blocks** | 26313964-26313964 |

### 💬 What Happened
MEDIUM (rule score 80)

### 🔥 The Roast
Looks like someone tried to hide their $89 DAI in a SideShift hot wallet—like dropping a pizza into a black hole and hoping it never returns. The engine gave it a 80 on the stablecoin_mixing rule (meaning this transaction matches the pattern of a known mixing service). MEDIUM (rule score 80) SideShift is the crypto equivalent of a shady laundromat, and this transaction is basically a slip of paper in that line. MEDIUM (rule score 80)

### 🎯 Verdict & Next Steps
**MEDIUM, because the transaction matches a known stablecoin mixing pattern with a high engine score but no additional red flags.**

Flag the transaction for manual review, investigate the sender’s source of funds, and monitor the receiver wallet for additional suspicious activity.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $89 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) This activity triggers the stablecoin_mixing rule with a score of 80, indicating a high likelihood of mixing activity. MEDIUM (rule score 80)

</details>

---

## Finding #4: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x5e1c343fbbe2c0b954b7889162be4654a9225f59` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$300** (300 USDT) |
| **Blocks** | 26313921-26313921 |

### 💬 What Happened
MEDIUM (rule score 80) Think of it like sending a $300 bill to a dropbox that scrambles who you sent it to. The transaction was a single transfer in one block.

### 🔥 The Roast
Looks like someone wanted their money to disappear faster than a magician’s rabbit. MEDIUM (rule score 80) MEDIUM (rule score 80) If this were a detective show, they'd call it the great USDT shuffle. In short, the money went to the “Where’s My Money” club and the score says, ‘you’re up for review.’

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Open a compliance review of the sender’s wallet history and assess any linked addresses. If additional suspicious patterns emerge, consider filing a SAR with the relevant jurisdiction.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $300 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
The transaction involved a single transfer of 300 USDT from address 0x5e1c343fbbe2c0b954b7889162be4654a9225f59 to address 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2 (SideShift Hot Wallet). MEDIUM (rule score 80) The transaction occurred in block 26313921 with no prior activity from the sender wallet. The pattern suggests potential layering and warrants further investigation.

</details>

---

## Finding #5: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x83c464f7f577d5a8dd9cfccc1a60332fd69a02d4` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$3** (3 USDT) |
| **Blocks** | 26313893-26313893 |

### 💬 What Happened
Someone sent $3 worth of USDT, a digital dollar, to a wallet that belongs to a service called SideShift, which is known for mixing money to hide its source. It's like putting a small cash box into a vending machine that then redistributes the money to an unknown cashier. No other transactions were seen in the same block, so the whole thing is a tiny but suspicious move.

### 🔥 The Roast
Scored 80 on the stablecoin_mixing rule (meaning this is a single USDT transfer to a hot wallet known for mixing). MEDIUM (rule score 80) The sender's wallet has zero ETH balance and no recent activity, so it's like a ghost in the machine. If you thought the transaction was harmless, think again—it's a classic "sneak‑in through the backdoor" move. Maybe the sender was trying to hide a $3 joke, but the system didn't laugh.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 80)**

Flag the transaction for further manual review by the compliance team. MEDIUM (rule score 80)

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $3 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 80) MEDIUM (rule score 80) MEDIUM (rule score 80) MEDIUM (rule score 80)

</details>

---

## Scan Summary

**5 suspicious findings** detected across 5 unique wallets. Highest risk score: **80**.

| | |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| Wallets flagged | 5 |
| Suspicious value | 0.0000 ETH ($0) + $1,822 in stablecoins |
| Blocks scanned | 26313889 — 26314088 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

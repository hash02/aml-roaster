# 🔥 AML Roaster Report
**2026-11-14 22:18 UTC** · Ethereum Mainnet · ETH $1,765.04
**Blocks:** 26415899 — 26416098 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26415899 to 26416098 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 194

| | |
|---|---|
| **Sender** | `0x40f5fe8c7c1185e08f3afd54a47c5121c24b44d3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **4.8000 ETH** ($8,472) |
| **Blocks** | 26415957-26415957 |

### 💬 What Happened
A brand‑new wallet just sent 4.8 ETH (about $8,472) to a FixedFloat address and is now empty. It’s like a fresh cash‑drop machine that takes a big bundle of money and vanishes it in one go, leaving no record of who was behind it.

### 🔥 The Roast
So this new wallet pulled a 4.8 ETH heist and ran off with a zero balance. The engine gave it a 69 on [novel_wallet_dump] (meaning a brand‑new burner wallet dumping funds), 85 on [no_kyc_offramp] (the money went to a FixedFloat address—no KYC, no exit ramp), and 40 on [exit_rush] (the wallet drained itself to nothing). Basically it’s the burner‑plus‑no‑KYC‑plus‑instant‑exit combo. It’s like a kid in a bank vault who opens the door, takes all the cash, and disappears with a clean slate.

### 🎯 Verdict & Next Steps
**CRITICAL — the high composite score and pattern of a brand‑new burner wallet sending a large amount to a non‑KYC off‑ramp with rapid balance depletion indicates a high risk of illicit activity.**

Flag the transaction for manual review, trace the FixedFloat 1 address for downstream activity, and consider filing a SAR if further suspicious patterns are confirmed.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 194):
- **novel_wallet_dump** (+69) — Wallet is 0 days old, moving 4.8000 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 4.8000 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created wallet (0 days old) that transferred 4.8000 ETH to a FixedFloat 1 address. AML engine flagged [novel_wallet_dump] (score 69) indicating a new wallet dumping funds, [no_kyc_offramp] (score 85) indicating transfer to a non‑KYC off‑ramp, and [exit_rush] (score 40) indicating rapid depletion of balance. The combined composite score of 194 exceeds the critical threshold set for potential suspicious activity. Further investigation is warranted.

</details>

---

## Finding #2: CRITICAL — Score 194

| | |
|---|---|
| **Sender** | `0xe96731867d8f08a44df410760c24c60115381bdf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **4.5999 ETH** ($8,119) |
| **Blocks** | 26415944-26415944 |

### 💬 What Happened
The sender’s brand‑new wallet, like a fresh cash‑order, immediately moved almost $8,000 worth of Ethereum to a protocol that doesn’t require any identity checks. After the transfer, the wallet was empty, as if all the money was taken out in a single sweep. It’s a classic quick cash‑out move that raises red flags.

### 🔥 The Roast
So, we’ve got a brand‑new wallet (0 days old) that dumps 4.5999 ETH— that’s the [novel_wallet_dump] (score 69) rule kicking in, meaning the wallet is a new burner. Then it sends that cash to FixedFloat 1, a no‑KYC off‑ramp (score 85) where nobody knows who’s behind the money. And to top it off, the wallet balance goes from 4.5999 ETH to zero in a flash— that’s the [exit_rush] (score 40) warning, like a thief who grabs the loot and disappears before anyone can say “wait!”

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction meets multiple high‑risk indicators including a new wallet dump, no KYC off‑ramp, and rapid balance depletion.**

Flag the transaction for manual review, monitor the receiver address for subsequent activity, and, if possible, request source‑of‑funds information from any custodial service linked to the receiving protocol.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 194):
- **novel_wallet_dump** (+69) — Wallet is 0 days old, moving 4.5999 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 4.5999 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers three high‑risk AML indicators: [novel_wallet_dump] (new wallet making a large outbound transfer), [no_kyc_offramp] (transfer to an anonymous DeFi protocol that does not verify user identity), and [exit_rush] (rapid depletion of wallet balance). The sender’s wallet is 0 days old, has only one transaction, and is completely drained after the move, satisfying the criteria for a potential burner wallet scenario. CRITICAL (rule score 194) This pattern warrants a high‑risk flag for further investigation by compliance personnel.

</details>

---

## Finding #3: CRITICAL — Score 192

| | |
|---|---|
| **Sender** | `0xa64664d0db9bf92f6749d099a1ff9bda2e5040e5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **3.9999 ETH** ($7,060) |
| **Blocks** | 26415927-26415927 |

### 💬 What Happened
A brand‑new wallet just sent almost four whole ETH to a service called FixedFloat 1, and then it disappeared with nothing left. It’s like someone drops a large cash envelope into a vending machine that instantly turns it into a secret code and never lets you see who the envelope came from.

### 🔥 The Roast
So this fresh‑from‑the‑blockchain wallet decided to play hide‑and‑seek with 3.9999 ETH. It’s the kind of burner account that screams “I’m new, I don’t have a KYC profile, and I’ll vanish faster than a Snapchat photo” – and FixedFloat 1 is basically the crypto version of a “no‑question, no‑return” ATM. The engine gave it a 67 for the classic burner dump, 85 for the no‑KYC off‑ramp, and 40 for the exit rush, adding up to a whopping 192. In plain English, it’s like a one‑night stand that leaves a huge bill on the table and then walks away.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits classic burner wallet activity combined with a no‑KYC off‑ramp and complete balance drain.**

Flag the transaction for manual AML review and request additional context on the origin of the 3.9999 ETH. CRITICAL (rule score 192)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 192):
- **novel_wallet_dump** (+67) — Wallet is 0 days old, moving 3.9999 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 3.9999 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet aged 0 days with a single outgoing transfer of 3.9999 ETH to the service FixedFloat 1. According to rule [novel_wallet_dump] (score 67), this is a classic burner pattern due to the wallet’s age and single transaction. Rule [no_kyc_offramp] (score 85) flags the destination as a no‑KYC off‑ramp, increasing risk of illicit movement. CRITICAL (rule score 192) The composite score of 192 exceeds the critical threshold, warranting escalation for manual review.

</details>

---

## Finding #4: CRITICAL — Score 190

| | |
|---|---|
| **Sender** | `0xdd826e666d9c8623e0753b4ef512975cf89c0d48` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.9999 ETH** ($5,295) |
| **Blocks** | 26415905-26415905 |

### 💬 What Happened
Someone just created a brand‑new crypto wallet and immediately sent almost three ETH to a service called FixedFloat, which is a way to move crypto into something that looks like cash. It’s like dropping a big money bag into a slot machine that hides who put it in, then watching it vanish with no trace. The sender’s wallet had no prior activity and now has zero balance, so all the money has been drained in one go.

### 🔥 The Roast
This new wallet is fresher than a donut from the bakery that never opened – 0 days old, 1 transaction, zero balance afterward. The engine gave it a 65 on *novel_wallet_dump* (meaning it’s a brand‑new burner wallet that dumped money), 85 on *no_kyc_offramp* (so it went straight to a no‑KYC off‑ramp called FixedFloat, like a shady cashier that never asks for ID), and 40 on *exit_rush* (the wallet’s balance is literally a ghost after the move). In short, it’s a classic burner‑dump‑exit pattern – a textbook case of someone trying to hide the origin of the funds in a single, clean sweep.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 190)**

Flag the transaction for manual review, verify the source of the 2.9999 ETH, and investigate the FixedFloat wallet’s compliance status. Consider placing a temporary hold until the origin can be confirmed.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 190):
- **novel_wallet_dump** (+65) — Wallet is 0 days old, moving 2.9999 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.9999 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a newly created address (0xdd826e666d9c8623e0753b4ef512975cf89c0d48) that transferred 2.9999 ETH to a FixedFloat wallet (0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f). The sender wallet exhibits a *novel_wallet_dump* pattern (score 65), *no_kyc_offramp* pattern (score 85) indicating a KYC‑free off‑ramp, and *exit_rush* pattern (score 40) showing complete depletion of the wallet balance. These indicators collectively suggest a high probability that the funds were moved to a service designed to obfuscate ownership. CRITICAL (rule score 190)

</details>

---

## Finding #5: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x5158eb29e8fc982ee9732bbdcce764358da7c750` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.2087 ETH** ($3,898) |
| **Blocks** | 26416079-26416079 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 189.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 189)**

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

**Rules Triggered** (3 rules, composite score: 189):
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.2087 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.2087 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #6: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x7b24c53c5a12b34b4ffbbd8a411fea6169a0cc67` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.7034 ETH** ($3,007) |
| **Blocks** | 26416050-26416050 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 188.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 188)**

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

**Rules Triggered** (3 rules, composite score: 188):
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.7034 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.7034 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #7: CRITICAL — Score 187

| | |
|---|---|
| **Sender** | `0x22ed59efa45c565abfe77d195664ff1808bc1a5f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.0756 ETH** ($1,898) |
| **Blocks** | 26416049-26416049 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 187.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 187)**

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

**Rules Triggered** (3 rules, composite score: 187):
- **novel_wallet_dump** (+62) — Wallet is 0 days old, moving 1.0756 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.0756 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #8: CRITICAL — Score 187

| | |
|---|---|
| **Sender** | `0x495a5d5e0db53bb51863f5ca55f3e486074ae54f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.2123 ETH** ($2,140) |
| **Blocks** | 26416003-26416003 |

### 💬 What Happened
A brand new wallet just sent 1.2123 ETH (about $2,140) to a service that turns crypto into a more anonymous form. The sender's account was created the same day it made the move and had no funds left afterward, like someone buying a ticket, using it, and then disappearing. The transaction went to a platform known for helping people hide where their money came from.

### 🔥 The Roast
Looks like someone just bought a brand‑new burner wallet and used it to dump a small fortune into a mystery box—like dropping a package into a slot that hides who sent it. The engine screamed 62 on the novel_wallet_dump rule (meaning this is a brand‑new wallet doing a one‑off dump) and 85 on the no_kyc_offramp rule (so nobody had to show ID to exit). And then the wallet hit the exit_rush rule with a score of 40 (funds gone in a flash). Basically, it’s a classic “I’ll do it tomorrow, but today I’ll just make it vanish” scenario. If this were a real person, they'd probably be hiding in a basement with a pizza delivery order.

### 🎯 Verdict & Next Steps
**CRITICAL — the new wallet, single large transfer to a no‑KYC off‑ramp, and immediate depletion of funds trigger a high‑risk flag under multiple AML rules.**

Flag the transaction for manual AML review and investigate any downstream connections to mixers or high‑risk jurisdictions. Monitor the wallet’s address for further activity and report findings to the compliance team.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 187):
- **novel_wallet_dump** (+62) — Wallet is 0 days old, moving 1.2123 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.2123 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet with 0 days of age and only one outbound transfer of 1.2123 ETH. The sender immediately depleted the wallet balance to 0.000000 ETH, matching the exit_rush pattern. The destination is a FixedFloat service, an identified no‑KYC off‑ramp, triggering the no_kyc_offramp rule. Combined with the novel_wallet_dump rule, the composite score of 187 indicates a high‑risk activity consistent with burner wallet use.

</details>

---

## Finding #9: CRITICAL — Score 187

| | |
|---|---|
| **Sender** | `0x0f7c0ff7ed6f1d18c42ea163ccca8f895c23cf32` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.2079 ETH** ($2,132) |
| **Blocks** | 26415912-26415912 |

### 💬 What Happened
A brand‑new wallet that had never held any money before just sent over $2,100 worth of ETH to a service called FixedFloat 1. After the transfer, the wallet was empty again, like a person who just stole a sandwich and left the kitchen.

### 🔥 The Roast
So, this wallet was brand new, like a fresh‑out‑of‑the‑oven burner, and it decided to dump a couple of thousand dollars into a no‑KYC service called FixedFloat 1 (think of it as a shady ATM that takes your cash and promises it’ll be safe but you never see your money again). The engine gave it a 62 on the novel_wallet_dump rule (because it’s a fresh burner), a 85 on the no_kyc_offramp rule (no identity check before cashing out), and a 40 on the exit_rush rule (it drained the whole pot in one go). The composite score of 187? That’s like a warning light on a car that just took a turn without a turn signal—don’t ignore it.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a brand‑new wallet, a single large transfer to a no‑KYC off‑ramp, and immediate drain of funds signals a high‑risk exit strategy typical of illicit activity.**

Flag the transaction for manual review, trace downstream movements, and request additional source‑of‑funds information from the recipient or related parties.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 187):
- **novel_wallet_dump** (+62) — Wallet is 0 days old, moving 1.2079 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.2079 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers the following AML engine rules: [novel_wallet_dump] (score 62) – wallet age 0 days and single large transfer; [no_kyc_offramp] (score 85) – deposit to FixedFloat 1, a no‑KYC off‑ramp; [exit_rush] (score 40) – wallet balance drops to 0.000000 ETH immediately after transfer, indicating full drainage. The evidence includes a single transaction of 1.2079 ETH ($2,132) from a brand‑new address with no prior activity, and the immediate depletion of funds. This pattern aligns with known burner‑wallet exit strategies used to obscure the source of funds.

</details>

---

## Finding #10: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa99b122dfaf697fac9fc053b89fb8fd07b54797f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0019 ETH** ($3) |
| **Blocks** | 26416004-26416004 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

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

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #11: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x00bd9bc56aace78ec07ea4add9721bb9c1932c8b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0026 ETH** ($5) |
| **Blocks** | 26416002-26416002 |

### 💬 What Happened
A brand new wallet just sent a tiny amount of ETH (about $5) to a service that turns crypto into a fixed value. Think of it like dropping a small package into a vending machine that will later give you a different item, but you never see who put it in. The sender has no history and no balance left after the send, so it's a quick, one‑off move.

### 🔥 The Roast
Looks like the sender just woke up, did a one‑shot ETH drop into FixedFloat 1, and vanished before the coffee machine could finish brewing. With a score of 155, this is more like a bad Tinder date than a legitimate transaction. The no‑KYC off‑ramp rule gave it 85 points, meaning the service lets you get rid of your money without anyone asking for ID (like a shady pawn shop). The Sybil fan‑in rule scored 70, so it's part of a group of wallets all sending similar amounts—think of a bunch of pranksters all buying the same meme coin at the same time. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the wallet for internal review and consider adding it to the watchlist. Monitor for subsequent transfers that may funnel the funds into further layers of obfuscation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction triggers Rule no_kyc_offramp (score 85) because the funds are being transferred to FixedFloat 1, a service that provides a fixed output without requiring identity verification. Rule sybil_fan_in (score 70) is also activated, indicating that this sender is one of multiple wallets depositing similar amounts (~0.003 ETH ±30%) in a short time frame, consistent with a Sybil fan‑in pattern. The composite score of 155 exceeds our high‑risk threshold. CRITICAL (rule score 155)

</details>

---

## Finding #12: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x89e4fe8f8bd70b6998aa9f5e563e84a88203a3ae` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0021 ETH** ($4) |
| **Blocks** | 26415980-26415980 |

### 💬 What Happened
A brand‑new wallet (just created today) sent a tiny amount of ETH — about $4 — to a service called FixedFloat 1. The transaction was the wallet’s second ever move, and it has no ETH left in it now. Think of it as someone dropping a $4 pizza order into a mystery box that hides who ordered it.

### 🔥 The Roast
So the wallet's birth certificate says '0 days old' and its résumé has only two job experiences. It’s basically a fresh‑out-of-the-box crypto newbie sending $4 to a place that says 'no KYC, no questions asked'—like a shady bar that only accepts cash. The engine gave it an 85 on the no‑KYC off‑ramp rule because FixedFloat 1 is that kind of place. And on top of that, the sybil fan‑in rule hit 70 because a dozen other accounts are sending almost the same amount, so it's like a party where everyone brings the exact same weird snack.

### 🎯 Verdict & Next Steps
**CRITICAL — high composite score and presence of both no‑KYC off‑ramp and sybil fan‑in patterns warrant immediate review.**

Flag the transaction for manual review by the compliance team; investigate the source and destination of the funds and monitor the wallet for additional suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet with zero days age, only two total transactions, and a current balance of zero ETH, indicating a rapid depletion of funds. Rule no_kyc_offramp was triggered (score 85) due to the transfer to FixedFloat 1, which operates without KYC verification, raising concerns of an off‑ramp scenario. Rule sybil_fan_in was also triggered (score 70) because the sender is part of a cluster of 12 accounts depositing similar amounts (~0.003 ETH ± 30%), suggesting a potential Sybil fan‑in pattern. The composite score of 155 exceeds the critical threshold, warranting immediate compliance review.

</details>

---

## Finding #13: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x825e7c867e79c2263e95f53fdf0c7d661d205d65` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0019 ETH** ($3) |
| **Blocks** | 26415976-26415976 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

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

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #14: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x9672832b0cc739878e071c548382387e502d6c60` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0022 ETH** ($4) |
| **Blocks** | 26415970-26415970 |

### 💬 What Happened
The sender, a brand‑new wallet that had only made two tiny transactions, just slipped 0.0022 ETH (about $4) into a FixedFloat contract. Think of it like dropping a small package into a slot that hides the sender’s address and then having the package sent to a random recipient—no way to trace where it came from.

### 🔥 The Roast
So this fresh wallet decided to play hide‑and‑seek with 85 points on the no‑KYC off‑ramp rule (meaning the money can leave the network without any identity check). And then it got a 70 on the sybil_fan_in rule—like a fan club of 12 similar wallets all dropping about 0.003 ETH at once. CRITICAL (rule score 155) CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL — composite score 155 indicates high risk due to no‑KYC off‑ramp and sybil fan‑in patterns.**

Flag the transaction for manual compliance review and consider adding the wallet to a watchlist. Verify the source of funds and monitor subsequent activity for potential layering.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 155) The activity triggers the [no_kyc_offramp] rule with a score of 85, indicating a deposit to an off‑ramp without KYC verification, and the [sybil_fan_in] rule with a score of 70 due to a fan‑in pattern of 1 out of 12 senders depositing similar amounts (~0.003 ETH ± 30%). Composite score of 155 exceeds the high‑risk threshold. CRITICAL (rule score 155) The pattern suggests potential layering or obfuscation of funds, warranting further investigation.

</details>

---

## Finding #15: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x82544e4ef6e020dcdf063737860c702604c3e531` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0023 ETH** ($4) |
| **Blocks** | 26415964-26415964 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH ($4) to a mixing service that strips identity. Think of it as dropping a small parcel into a mystery box that hides who dropped it. The sender’s account only had two transactions, zero balance, and has no history, so it’s basically a fresh “newbie" with no track record.

### 🔥 The Roast
Score 85 on no_kyc_offramp (meaning the sender is feeding a service that doesn’t ask for ID, like giving cash to a cashier who says "no ID needed") and 70 on sybil_fan_in (so this is one of dozens of little packets from a swarm of addresses, all dumping ~0.003 ETH into the same spot). Basically, it’s like a group of friends all throwing a handful of coins into a public wishing well and hoping the coins disappear. CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual review, request additional source‑of‑funds information, and monitor future activity from the sender’s address.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Rule no_kyc_offramp triggered: deposit to FixedFloat 1 with no KYC (the service does not verify identity). Rule sybil_fan_in triggered: fan‑in pattern of similar amounts (~0.003 ETH ±30%) from multiple addresses. Composite score 155. Sender wallet age 0 days, tx count 2, current balance 0 ETH. CRITICAL (rule score 155) Flag for manual review.

</details>

---

## Finding #16: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x2ea1f7fd02eaaf92752fb49b7468207bff7afde1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0024 ETH** ($4) |
| **Blocks** | 26415961-26415961 |

### 💬 What Happened
CRITICAL (rule score 155) It’s like a fresh kid putting a small note into a mysterious drop box that hides where it came from. The sender’s account was created the same day and hasn’t moved any money before.

### 🔥 The Roast
CRITICAL (rule score 155) Score of 85 on no_kyc_offramp means this address is basically a front‑door to a shady club where nobody knows who you are. CRITICAL (rule score 155) It’s like a group of kids all tossing identical coins into a black‑hole. If you’re trying to hide, at least be original.

### 🎯 Verdict & Next Steps
**CRITICAL — The combination of a brand-new wallet, no‑KYC off‑ramp, and fan‑in Sybil pattern signals high potential for illicit fund movement.**

Flag the transaction for manual review, request additional source of funds information from the sender, and monitor related addresses for further suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction involves a new wallet (age 0 days, 2 total tx) sending 0.0024 ETH to a FixedFloat address with a composite risk score of 155. Rule no_kyc_offramp (score 85) indicates deposit to a no‑KYC off‑ramp, and rule sybil_fan_in (score 70) indicates fan‑in Sybil pattern with 12 senders depositing similar amounts (~0.003 ETH ± 30%). CRITICAL (rule score 155)

</details>

---

## Finding #17: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x568a906c321ba61e17ea12e73e3b4069abe9b730` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0025 ETH** ($4) |
| **Blocks** | 26415960-26415960 |

### 💬 What Happened
A brand-new wallet just sent $4 worth of ETH to a service called FixedFloat 1. It's like someone dropping a small package into a slot that hides where it came from, and the wallet has never been used before.

### 🔥 The Roast
So this new wallet, fresh out of the blockchain oven, decided to play the 'who's sending me money' game. It sent 0.0025 ETH to a service that probably has no KYC, which is basically like sending cash to a cash machine that doesn't ask for your ID. The engine even flagged it for the no-kyc-off-ramp rule (meaning this is a no‑ID drop‑off spot) and sybil_fan_in (like a fan club of copycat wallets). If this were a grocery store, they'd ask, 'Did you get your money from a friend or a scam?'

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a new wallet, no‑KYC off‑ramp, and Sybil fan‑in pattern warrants immediate review.**

Flag this transaction for manual compliance review, verify the sender’s source of funds, and monitor subsequent activity from the involved addresses.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a 0‑day wallet that has only performed two transactions and currently holds no ETH, indicating a new or potentially disposable address. The transfer of 0.0025 ETH to 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1) triggered rule [no_kyc_offramp] with a score of 85, highlighting an off‑ramp that does not require KYC verification. Additionally, the pattern matches rule [sybil_fan_in] with a score of 70, suggesting a fan‑in Sybil structure where multiple similar wallets funnel funds into the same destination. The composite score of 155 indicates a high likelihood of suspicious activity. CRITICAL (rule score 155)

</details>

---

## Finding #18: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x609a2102bb8b497b99adc0030c45eff4a863d0b0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0033 ETH** ($6) |
| **Blocks** | 26415953-26415953 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

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

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #19: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x678d7f4246e78298015456c76b9bcef78ba56013` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0033 ETH** ($6) |
| **Blocks** | 26415938-26415938 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

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

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #20: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xcccc237456b089f1965d860c3959e3e49afb3b0a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0032 ETH** ($6) |
| **Blocks** | 26415938-26415938 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

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

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #21: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x3b029d23508c61cccd697e49f48e0179c4461855` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0032 ETH** ($6) |
| **Blocks** | 26415935-26415935 |

### 💬 What Happened
A brand‑new wallet, just created, sent a tiny 0.0032 ETH (about $6) to a special deposit address that acts like a vending machine for money—once the coins are dropped in, no one knows who will take them out. The sender’s account has zero balance and only two tiny transactions, and it was active only today. Essentially, it’s like tossing a small package into a slot that hides who will pick it up later.

### 🔥 The Roast
Looks like someone decided to test the new KYC‑free off‑ramp with a fresh wallet (no_kyc_offramp score 85, meaning no identity check before the money leaves the system). On top of that, it’s part of a fan‑in Sybil pattern (sybil_fan_in score 70) – 1 out of 12 senders sending the same 0.003 ETH, as if they’re all clones in a bad copy‑paste attack. The wallet’s age is 0 days, so it’s literally brand new, like a freshly opened box of mystery snacks. With a single transaction in the same block, it’s a textbook example of “drop it in, hope the world doesn’t notice.”

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a brand‑new, KYC‑free deposit into a fixed‑float address and a Sybil fan‑in pattern triggers a critical risk flag per the AML engine.**

Flag the transaction for manual review, request source‑of‑funds documentation and identity verification for the sender, and consider monitoring subsequent activity or placing a temporary hold on the account.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 2 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 155):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **sybil_fan_in** (+70) — 1 of 12 senders depositing similar amounts (~0.003 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
This activity triggers AML engine rule [no_kyc_offramp] due to a deposit to a FixedFloat 1 address without any KYC verification, and rule [sybil_fan_in] because the sender is one of 12 wallets sending similar amounts (~0.003 ETH ± 30%) into the same address. The sender’s wallet is 0 days old, has only 2 transactions, and currently holds zero balance, indicating a potentially new, low‑volume source of funds. The transaction was executed in block 26415935 and involved 0.0032 ETH ($6) to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f. These factors collectively raise a high‑risk flag for potential layering or obfuscation of funds.

</details>

---

## Finding #22: HIGH — Score 110

| | |
|---|---|
| **Sender** | `0xa091157b634196a5f19fd159181b16989a416199` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$15,000** (15,000 USDT) |
| **Blocks** | 26415928-26415928 |

### 💬 What Happened
HIGH (rule score 110) Think of it like dropping a parcel into a slot that scrambles who sent it, making it hard to trace. The transaction happened in a single block, so it was a quick, one‑off move.

### 🔥 The Roast
Looks like someone decided to play hide‑and‑seek with their money and used SideShift as the ultimate hiding spot. Sending $15,000 of USDT into a hot wallet that mixes coins is like throwing a bunch of coins into a blender and hoping nobody notices the original flavor. HIGH (rule score 110) If you’re hoping to keep your money anonymous, congratulations—you’ve just made it onto our high‑risk list.

### 🎯 Verdict & Next Steps
**HIGH (rule score 110)**

Flag the transaction for manual review by the compliance team, investigate the source wallet's history, and consider additional due diligence or reporting if further red flags emerge.

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
- **stablecoin_mixing** (+110) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $15,000 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Transaction: 0xa091157b634196a5f19fd159181b16989a416199 sent 15,000 USDT to 0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2 (SideShift Hot Wallet) in block 26415928. HIGH (rule score 110) HIGH (rule score 110) This activity should be reviewed for possible connection to suspicious behavior.

</details>

---

## Finding #23: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x35a1381ad62cf83d15405e06005fa8a9a9622356` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0333 ETH** ($59) |
| **Blocks** | 26416048-26416048 |

### 💬 What Happened
A brand‑new wallet sent 0.0333 ETH (about $59) straight into a SideShift Hot Wallet, which is basically a blender that scrambles who sent the money. The sender had no history—no previous transactions, no balance left, and it all happened in one go. This is like dropping a single drop of coffee into a machine that then mixes it with a pot of others, making it hard to trace where it came from.

### 🔥 The Roast
MEDIUM (rule score 85) Rule no_kyc_offramp scored 85, meaning the engine flagged that this is a deposit to a known off‑ramp that doesn't require identity verification. Basically, it’s a "no‑KYC, no‑question" move—like a shady cashier that never asks for ID. If this were a real bank, they'd put a red flag on that transaction and probably call the cops. In crypto, they just throw a warning in the engine and hope you don’t get caught.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review and request additional context from the sender. MEDIUM (rule score 85)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000010 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: The subject wallet (0x35a1381ad62cf83d15405e06005fa8a9a9622356) created on the same day as the transaction (wallet age 0 days) performed a single outbound transfer of 0.0333 ETH to the SideShift Hot Wallet address (0xcdd37ada79f589c15bd4f8fd2083dc88e34a2af2). The transfer was a one‑off, high‑risk off‑ramp activity with no prior transaction history or KYC information, triggering rule [no_kyc_offramp] with a score of 85. MEDIUM (rule score 85) The transaction falls within block 26416048. MEDIUM (rule score 85)

</details>

---

## Finding #24: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd48c6395e5c65a93cac9711989476fc626dcfb5c` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.2717 ETH** ($479) |
| **Blocks** | 26416022-26416022 |

### 💬 What Happened
A brand‑new wallet sent almost $500 worth of ETH to a SideShift hot wallet, which acts like a black box that hides where the money came from. The transaction is the wallet’s first activity and it has almost no balance left after the send.

### 🔥 The Roast
This address is like a newborn baby that just decided to throw a party and immediately RSVP to a black hole. The wallet is 0 days old, only did one transaction, and sent 0.2717 ETH to a SideShift Hot Wallet— that’s the kind of off‑ramp that would make a KYC officer raise an eyebrow. Rule no_kyc_offramp (meaning the fund was moved to a place that doesn’t require identity verification) gave it a whopping 85 on the score. If you think a 0‑day wallet could be a legitimate user, think again. MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM risk due to the no‑KYC off‑ramp pattern and the sender’s new wallet status.**

Flag the transaction for manual review by compliance. Consider cross‑checking the SideShift wallet for known suspicious activity and request additional source‑of‑funds information if possible.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000012 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
The sender wallet (0xd48c6395e5c65a93cac9711989476fc626dcfb5c) is a newly created address (0 days old) with a single outbound transfer of 0.2717 ETH to a SideShift hot wallet. This transaction triggers the AML Engine’s no_kyc_offramp rule, scoring 85, indicating a high likelihood of an unverified off‑ramp activity. The transaction occurs within block 26416022, with no token transfers, and the sender’s current balance is negligible. MEDIUM (rule score 85)

</details>

---

## Finding #25: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x7ab9ef42e7db3171cf84e35fcbcbd27020b8adcf` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0235 ETH** ($41) |
| **Blocks** | 26416010-26416010 |

### 💬 What Happened
A brand-new wallet (only 0 days old) sent 0.0235 ETH—about $41—to a SideShift hot wallet, which is a service that moves funds around to hide where they came from. It’s like dropping a parcel into a box that immediately shuffles it through several random lockers so the original sender’s identity gets lost. MEDIUM (rule score 85)

### 🔥 The Roast
So we have a new kid on the block—wallet age zero, no previous history, and it just drops a modest ETH bundle into a SideShift Hot Wallet. That’s the classic ‘no‑KYC off‑ramp’ move: the wallet is like a tourist who pays for a one‑way ticket but never shows a passport (no_KYC_offramp, meaning no know‑your‑customer verification before the money leaves). The address is as fresh as a morning coffee, yet it’s already on the move—probably trying to make the money as anonymous as a ghost in a haunted house. MEDIUM (rule score 85)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

MEDIUM (rule score 85)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000014 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
The transaction involved a newly created wallet (0‑day age, single transaction) that sent 0.0235 ETH to a SideShift Hot Wallet (an off‑ramp service known for facilitating anonymous transfers). This activity satisfies Rule no_kyc_offramp, indicating a deposit to an off‑ramp with no KYC verification. The single transaction and lack of prior activity raise concerns about potential layering and anonymity‑enhancing services. MEDIUM (rule score 85)

</details>

---

## Finding #26: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5408161eecc21c840b38a688a0371385972db080` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0500 ETH** ($88) |
| **Blocks** | 26416010-26416010 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 85.

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
| Current Balance | 0.000014 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5ad82db075e276153e9bb35c0223e836ec5cded4` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0056 ETH** ($10) |
| **Blocks** | 26415987-26415987 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 85.

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
| Current Balance | 0.000014 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x36eece7284997eb796c3f81a30ce0f3dced231a7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0011 ETH** ($2) |
| **Blocks** | 26416097-26416097 |

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
| **Sender** | `0x00ab4574f5d4b539e714901c6f963a7fc85179d3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0010 ETH** ($2) |
| **Blocks** | 26416086-26416086 |

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

## Finding #30: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc58891870964587b89f732efff86862692597344` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0011 ETH** ($2) |
| **Blocks** | 26416084-26416084 |

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

## Finding #31: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x457660c8c13d4c4f9b6b5db2c7ef4c98ecc3376a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2392 ETH** ($422) |
| **Blocks** | 26416083-26416083 |

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

## Finding #32: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xccdaf2cc86f85cee45fb8a29e93de00cc05a47a9` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26416080-26416080 |

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

## Finding #33: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd829056e9ce5478a2bb410cd77738c0c247a7e10` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0011 ETH** ($2) |
| **Blocks** | 26416075-26416075 |

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

## Finding #34: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x6793de2586e037b6d2f8295f0cb4a0d89d4f3454` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0012 ETH** ($2) |
| **Blocks** | 26416075-26416075 |

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

## Finding #35: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x01ef2da34ed6b07ae3fbcd7a965b79bd344852bc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0012 ETH** ($2) |
| **Blocks** | 26416073-26416073 |

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

## Finding #36: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x6ccc8c4111e2a40158608595e946dd7b1c88ccc4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0012 ETH** ($2) |
| **Blocks** | 26416073-26416073 |

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

## Finding #37: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa1ce61dea8a127664e9fa3d7d56b012e6196653a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0013 ETH** ($2) |
| **Blocks** | 26416069-26416069 |

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

## Finding #38: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf469f875ba3fae48cf79f67aa3d8a3cf4f6fe725` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0014 ETH** ($2) |
| **Blocks** | 26416065-26416065 |

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

## Finding #39: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x92466fa624e1624669d2c4671e933eac2aeafacf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0013 ETH** ($2) |
| **Blocks** | 26416063-26416063 |

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

## Finding #40: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xcbf65a46a5129d742a5f21a22111ca14adebaffb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0119 ETH** ($21) |
| **Blocks** | 26416061-26416061 |

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

## Finding #41: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x87d240e53c60c542c13bc9ece9b5720ede210635` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0013 ETH** ($2) |
| **Blocks** | 26416060-26416060 |

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

## Finding #42: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x447d503458c4eabd609a6b8fddd669a636b1109f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26416057-26416057 |

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

## Finding #43: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x745ca8c7328af90497234125fcf2afed0144d753` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0014 ETH** ($2) |
| **Blocks** | 26416047-26416047 |

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

## Finding #44: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x45864edb1ad66df72ac2f50a4bc382399c5b8a81` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0063 ETH** ($11) |
| **Blocks** | 26416045-26416045 |

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

## Finding #45: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc6e918fcdb4812ef71d50cb25c2422d5f73bd83b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0016 ETH** ($3) |
| **Blocks** | 26416044-26416044 |

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

## Finding #46: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x0502441fb787687714a2c6e7299aeb856f40d713` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0014 ETH** ($2) |
| **Blocks** | 26416044-26416044 |

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

## Finding #47: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8c094e09957fc2bd97f853016b1338e4fb0e9ffe` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0016 ETH** ($3) |
| **Blocks** | 26416040-26416040 |

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

## Finding #48: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd4bee24968959c6fff9ae05e550e9faa58cdd9a2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0014 ETH** ($2) |
| **Blocks** | 26416038-26416038 |

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

## Finding #49: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd1abc0660ccf3e0b966731195d6702528ed33a4a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0017 ETH** ($3) |
| **Blocks** | 26416034-26416034 |

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

## Finding #50: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x2c0470c7b03268f75a1d44fe798a4fd35ba94817` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0015 ETH** ($3) |
| **Blocks** | 26416033-26416033 |

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

## Finding #51: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc791b6192d9065f44bbe7a4b9338c1d5c35f371e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.8380 ETH** ($1,479) |
| **Blocks** | 26416020-26416020 |

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

## Finding #52: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xbdccaa7b1a0a9674b4ab22902286a4b44d36ff8e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0015 ETH** ($3) |
| **Blocks** | 26416018-26416018 |

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

## Finding #53: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x6d284939396ddb836343560191ca926d41d5076e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0015 ETH** ($3) |
| **Blocks** | 26416015-26416015 |

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

## Finding #54: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x677563ab77ac6fc708f2ab59b0b271d8dd7c5275` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0017 ETH** ($3) |
| **Blocks** | 26416014-26416014 |

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

## Finding #55: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb2976f097f8a5619613aa801d7c9292e8dbc8b45` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0017 ETH** ($3) |
| **Blocks** | 26416013-26416013 |

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

## Finding #56: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xfffadba6865119863a2a20fa4e2569e73afc4b3b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0018 ETH** ($3) |
| **Blocks** | 26416012-26416012 |

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

## Finding #57: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4a9509e5062e3eb761abb73955f65d29659c53d3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0017 ETH** ($3) |
| **Blocks** | 26416012-26416012 |

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

## Finding #58: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x575dc29ba4d9df8a111a9f69ff4cda4273207035` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0017 ETH** ($3) |
| **Blocks** | 26416009-26416009 |

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

## Finding #59: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x37329b39673f01eafa8232a1a94d48b2d0c3a2df` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0015 ETH** ($3) |
| **Blocks** | 26416008-26416008 |

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

## Finding #60: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xcaf3b4582b4a1461ce5968b439ddd08539255bb2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0018 ETH** ($3) |
| **Blocks** | 26416005-26416005 |

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

## Finding #61: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x42e8182acc0032bec4a128689abe3d27b2195b68` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0795 ETH** ($140) |
| **Blocks** | 26416005-26416005 |

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

## Finding #62: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x09a6df79d678eeac12a424dc1e39ede285c9fa3f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0018 ETH** ($3) |
| **Blocks** | 26415994-26415994 |

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

## Finding #63: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x84e5099d46e70bc09da5eb5215429cf7891b19a3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0018 ETH** ($3) |
| **Blocks** | 26415993-26415993 |

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

## Finding #64: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x183c3e13ee17427a7af2c30ca09d89a5c6ae4312` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1104 ETH** ($195) |
| **Blocks** | 26415985-26415985 |

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

## Finding #65: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x2d654eba9babb567169c94bf548ca5bd08d25363` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0017 ETH** ($3) |
| **Blocks** | 26415982-26415982 |

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

## Finding #66: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x668d96587c37ae6ca05803c8066f251088f90a50` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0018 ETH** ($3) |
| **Blocks** | 26415977-26415977 |

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

## Finding #67: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd6f8d048127ff46b99f5201635281085036bbb91` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0670 ETH** ($118) |
| **Blocks** | 26415974-26415974 |

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

## Finding #68: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x320f5aa6c4994e843cf72595d23c7e8125b8d8e3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0047 ETH** ($8) |
| **Blocks** | 26415971-26415971 |

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

## Finding #69: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd3c69d4da6340d876bd013178ed106fd7de96ea1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2000 ETH** ($353) |
| **Blocks** | 26415957-26415957 |

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

## Finding #70: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x289bf4c3b238f11ea3e6ceefa305799673caeb80` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1609 ETH** ($284) |
| **Blocks** | 26415954-26415954 |

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

## Finding #71: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x593dc93f724b709f7c83e48ce54fe233c57abc1e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0035 ETH** ($6) |
| **Blocks** | 26415949-26415949 |

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

## Finding #72: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4154dcb8152f8d2a1650bcc5e55e4c36a9379a7f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0171 ETH** ($30) |
| **Blocks** | 26415946-26415946 |

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

## Finding #73: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8eed9cdbb3e6c59b6c37be5307636e7c20f6db47` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0608 ETH** ($107) |
| **Blocks** | 26415935-26415935 |

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

## Finding #74: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x177f12a589c6806e196841d45651e0d5830dfb6e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0045 ETH** ($8) |
| **Blocks** | 26415933-26415933 |

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

## Finding #75: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd0bb87137cfe6d895394ced7c14b8e21ccd67261` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0144 ETH** ($25) |
| **Blocks** | 26415929-26415929 |

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

## Finding #76: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1c4f886d1e2c49a6c830bcba98b4d78fc5caf583` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0039 ETH** ($7) |
| **Blocks** | 26415929-26415929 |

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

## Finding #77: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb0eda87aa2f3c0d2eef5134cfdd0b9dc33954905` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0051 ETH** ($9) |
| **Blocks** | 26415918-26415918 |

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

## Finding #78: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x400afce789f7e4c58092eecde6e22718f98e21a1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2559 ETH** ($452) |
| **Blocks** | 26415918-26415918 |

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

## Finding #79: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5295671a2d09255b0b2b4ef6b6e34ebb0f8e9ecf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.4999 ETH** ($882) |
| **Blocks** | 26415917-26415917 |

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

## Finding #80: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xe16774b804e811a90aa3fd8d2a56c539b7c284da` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0045 ETH** ($8) |
| **Blocks** | 26415917-26415917 |

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

## Finding #81: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf91117d716028d09a6e1e552650882ce184704b2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0046 ETH** ($8) |
| **Blocks** | 26415915-26415915 |

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

## Finding #82: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5afe98342527536232b8ad7fd22ed611bc31018b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1999 ETH** ($353) |
| **Blocks** | 26415914-26415914 |

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

## Finding #83: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x02cc249750abcfe67c2ebe21ded9af4407932dd2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0684 ETH** ($121) |
| **Blocks** | 26415911-26415911 |

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

## Finding #84: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1f0d95782c3419997acb4971d4cd8692f33c3bda` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0052 ETH** ($9) |
| **Blocks** | 26415907-26415907 |

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

## Finding #85: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x83c9d6b3fc867b0f90464e887a714ee7062cdec2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0052 ETH** ($9) |
| **Blocks** | 26415903-26415903 |

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

## Finding #86: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1b96050a8b76013b32011e3eca1112238b9acb4b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0045 ETH** ($8) |
| **Blocks** | 26415902-26415902 |

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

## Finding #87: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8b918bab4989d2ded0521a0e99907a16a616f1a2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0055 ETH** ($10) |
| **Blocks** | 26415899-26415899 |

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

## Finding #88: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6fcc45614b7d2f84dedeb692971b19625ca32c61` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$636** (636 USDC) |
| **Blocks** | 26416034-26416034 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $636 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #89: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x6a000f20005980200259b80c5102003040001068` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$2,523** (2,523 USDT) |
| **Blocks** | 26416005-26416005 |

### 💬 What Happened
A wallet was caught interacting with SideShift Hot Wallet. Our engine flagged it at score 80.

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $2,523 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #90: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8c8643431e1b82b3f372d6ef6f0450ca30fa35a8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$15** (15 USDC) |
| **Blocks** | 26416097-26416097 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $15 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #91: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x71b9e5e2c2bc52c19a70c3219bd8ecdc4031d8b3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$3,000** (3,000 USDT) |
| **Blocks** | 26416095-26416095 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $3,000 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #92: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x245a39af35d8e8c7b1cfd6c44e05c1d3a59b52c3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDT) |
| **Blocks** | 26416093-26416093 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $1,000 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #93: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2ec854d1e623eeca5ca3fa2e68229879377b5dee` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$1,000** (1,000 USDT) |
| **Blocks** | 26416092-26416092 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $1,000 total (USDT) from 1 unique sender(s) — 1 round-number amount(s) (denomination layering)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #94: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x2b13616171591adf0ce5b56cdbc0e757b323233f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$250** (250 USDT) |
| **Blocks** | 26416092-26416092 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $250 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #95: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x8bad1ff26c52e18275cffd3518117803c92c14c5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$11** (11 USDC) |
| **Blocks** | 26416038-26416038 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $11 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**95 suspicious findings** detected across 95 unique wallets. Highest risk score: **194**.

| | |
|---|---|
| 🔴 CRITICAL | 21 |
| 🟠 HIGH | 1 |
| Wallets flagged | 95 |
| Suspicious value | 27.1502 ETH ($47,921) + $23,434 in stablecoins |
| Blocks scanned | 26415899 — 26416098 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 8 of 25 attempted analyses this run.

# 🔥 AML Roaster Report
**2026-11-09 15:47 UTC** · Ethereum Mainnet · ETH $2,128.65
**Blocks:** 26378050 — 26378249 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26378050 to 26378249 checked (about 40 min). 7 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 7 addresses attempted, 6 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## ⚠️ Partial Run

This scan reached its 900s time budget and stopped early so a report could still be written. 6 of 8 watched addresses in this batch were scanned. The rest were deferred to the next run: FixedFloat 1 (`0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f`), Stargate Router (`0x8731d54e9d02c286767d56ac03e8037c07e01e98`).

---

**Coverage note:** 96 of the findings below were raised while profiling an address whose scan was then cut short by the time budget, so that address counts as deferred above even though it produced findings. Those findings are preliminary: the address keeps its previous scan position, is scanned again on the next run, and its findings are re-derived in full then.

---

## Finding #1: CRITICAL — Score 198

| | |
|---|---|
| **Sender** | `0xe35eaa7735518aec99bb2d383756a60bd9c09262` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **6.6098 ETH** ($14,070) |
| **Blocks** | 26378099-26378099 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 198.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 198)**

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

**Rules Triggered** (3 rules, composite score: 198):
- **novel_wallet_dump** (+73) — Wallet is 0 days old, moving 6.6098 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 6.6098 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #2: CRITICAL — Score 191

| | |
|---|---|
| **Sender** | `0x25657d90f1e5ae092a28efd155560c4ad6c7f15a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **3.1978 ETH** ($6,807) |
| **Blocks** | 26378242-26378242 |

### 💬 What Happened
A brand-new wallet sent almost $6,800 worth of ETH to a service that can turn it into anonymous crypto. It’s like dropping a package into a slot that hides who sent it and where it ends up. The wallet had no prior activity and now has no balance left.

### 🔥 The Roast
This new wallet is so fresh it probably hasn’t even had a chance to buy a coffee. It dumped 3.1978 ETH – that’s like a small fortune in one go – right after opening the account, a classic burner move (novel_wallet_dump). Then it vanished, leaving a zero balance, like a magician who pulls a rabbit out of a hat and never returns it (exit_rush). No KYC off‑ramp? That’s the crypto version of driving without a license (no_kyc_offramp). The engine scored 191 points, so it’s basically screaming, ‘We see a red flag here!’

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 191)**

Flag the transaction for manual investigation. Request source‑of‑funds documentation and monitor the receiver for further suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 191):
- **novel_wallet_dump** (+66) — Wallet is 0 days old, moving 3.1978 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 3.1978 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a 0‑day old wallet (rule: novel_wallet_dump) transferring 3.1978 ETH (~$6,807) to FixedFloat 1, a known off‑ramp with no KYC (rule: no_kyc_offramp). The sender immediately emptied its balance (rule: exit_rush). CRITICAL (rule score 191) The composite score of 191 triggers a high‑priority flag for manual review.

</details>

---

## Finding #3: CRITICAL — Score 191

| | |
|---|---|
| **Sender** | `0x1054956a0782668a532e6efe791b9631bc046c87` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **3.0335 ETH** ($6,457) |
| **Blocks** | 26378173-26378173 |

### 💬 What Happened
CRITICAL (rule score 191) Think of it like dropping a package into a black‑box locker that takes your parcel and then hands it out anonymously; the original sender never shows up on the delivery receipt.

### 🔥 The Roast
So this wallet just popped up, dumped its whole fortune into a no‑KYC off‑ramp (meaning no identity check, like a shady bar that doesn’t ask for ID), and then vanished with a zero balance. The engine gave it a 66 for novel_wallet_dump (new wallet doing a big move), 85 for no_kyc_offramp (sending straight to a service that doesn’t verify who’s who), and 40 for exit_rush (emptying the account in one go). CRITICAL (rule score 191)

### 🎯 Verdict & Next Steps
**CRITICAL – The combination of a brand‑new wallet, a single large transfer to a no‑KYC service, and immediate balance depletion triggers high‑risk AML thresholds.**

Flag the transaction for manual review, investigate the source of the 3.0335 ETH, and monitor the receiving address for further suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 191):
- **novel_wallet_dump** (+66) — Wallet is 0 days old, moving 3.0335 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 3.0335 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits classic high‑risk patterns: (1) novel_wallet_dump rule triggered due to a wallet age of 0 days and a single outbound transfer of 3.0335 ETH; (2) no_kyc_offramp rule flagged because the funds were moved to FixedFloat 1, a known no‑KYC off‑ramp; (3) exit_rush rule indicated by the wallet’s balance dropping to 0.000000 ETH immediately after the transfer, suggesting a complete drain. These indicators collectively raise suspicion of potential illicit activity and warrant further investigation.

</details>

---

## Finding #4: CRITICAL — Score 190

| | |
|---|---|
| **Sender** | `0x9727d48fe1df82de7820ef7f46c035ab8090f0de` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.7984 ETH** ($5,957) |
| **Blocks** | 26378214-26378214 |

### 💬 What Happened
A brand‑new wallet was created today and immediately sent about $6,000 worth of ETH to a service called FixedFloat 1. The sender’s balance is now zero, like a cashier who just emptied a register and left the shop empty.

### 🔥 The Roast
So we’ve got a fresh burner wallet (novel_wallet_dump) that just dumped a hefty 2.7984 ETH into a no‑KYC off‑ramp (no_kyc_offramp) and then disappeared with an empty balance (exit_rush). It’s the blockchain equivalent of a guy walking into a casino, betting all his chips, and leaving the casino with nothing but a receipt. The engine thinks this is a classic "burner and drain" pattern—like a magician pulling a rabbit out of a hat that’s actually a hole in the floor. If you’re looking for a good plot twist, this is it: a zero‑balance after a single big send.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits classic burner wallet and no‑KYC off‑ramp patterns indicating high risk of illicit activity.**

Flag for manual review, trace the destination address, and check for any links to known mixers or suspicious entities.

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
- **novel_wallet_dump** (+65) — Wallet is 0 days old, moving 2.7984 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.7984 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction is flagged under rules novel_wallet_dump, no_kyc_offramp, and exit_rush. Evidence includes a wallet age of 0 days, a single transaction of 2.7984 ETH, and a current balance of 0.000000 ETH. CRITICAL (rule score 190)

</details>

---

## Finding #5: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x3be575720a16c3e60fc3e3ec338d235af9138c3a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.1335 ETH** ($4,541) |
| **Blocks** | 26378245-26378245 |

### 💬 What Happened
A brand‑new wallet, like a fresh burner phone, sent about $4,500 worth of ETH straight to a service that lets people cash out without checking who they are. The sender’s account was empty before and after, so all the money disappeared in one go.

### 🔥 The Roast
Looks like someone just pulled a fresh burner out of the crypto toolbox and dumped a neat 2.1335 ETH into a no‑KYC off‑ramp (that’s what the [no_kyc_offramp] rule means: the service doesn’t ask for identity). With a 64‑point [novel_wallet_dump] score, this wallet is basically a one‑day old burner, and the [exit_rush] score of 40 shows it’s a classic exit‑rush pattern—move and vanish. CRITICAL (rule score 189) Good luck trying to trace the cash, folks!

### 🎯 Verdict & Next Steps
**CRITICAL – The composite score of 189 and the combination of burner wallet, no‑KYC off‑ramp, and exit rush patterns indicate a high likelihood of illicit activity.**

Flag this transaction for manual review, monitor the recipient address for subsequent movements, and consider enhanced due diligence on any linked wallets.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.1335 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.1335 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet with 0 days of activity, 1 transaction, and no remaining balance (Rule: novel_wallet_dump). The destination is a FixedFloat 1 address, which is a recognized no‑KYC off‑ramp (Rule: no_kyc_offramp). The sender’s balance after the transfer is 0.000000 ETH, indicating a complete drain (Rule: exit_rush). Combined, the composite score of 189 indicates a high‑risk burner wallet engaging in a single‑step exit strategy that warrants further investigation.

</details>

---

## Finding #6: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0xd36d4f91463a3a76e60cd51e674d776785acb143` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.3347 ETH** ($4,970) |
| **Blocks** | 26378242-26378242 |

### 💬 What Happened
A brand‑new wallet that was created just now sent about 2.33 ETH (roughly $5,000) straight to a service called FixedFloat 1. It didn’t have any previous transactions, and after the send the wallet shows a balance of zero, like someone emptied a new bank account and walked away.

### 🔥 The Roast
This looks like a classic burner wallet, fresh as a mint and empty as a fridge after a midnight snack. The engine gave it a 64 on novel_wallet_dump (meaning it’s brand new and throwing money around like a kid with a candy stash). Then a 85 on no_kyc_offramp (the money goes to a place that doesn’t ask for identity, because who needs ID when you’re playing hide and seek?). Finally a 40 on exit_rush (the wallet is drained in a single move, like a magician pulling a rabbit out of a hat and then forgetting where he put the hat). Bottom line: this is a fast‑and‑furious money‑drain that would make a circus ringmaster blush.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of a brand‑new burner wallet, a KYC‑free off‑ramp, and an immediate balance drain signals a high‑risk scenario warranting urgent human review.**

Flag the transaction for manual AML review, investigate the source of the 2.3347 ETH, and monitor the destination address for further suspicious activity. If the investigation cannot establish a legitimate source, consider reporting to the relevant regulatory body.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.3347 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.3347 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet with a 0‑day age and a single outgoing transfer of 2.3347 ETH to FixedFloat 1. Rule [novel_wallet_dump] scored 64, indicating a newly created wallet engaged in a large transfer. Rule [no_kyc_offramp] scored 85, flagging an off‑ramp that does not require KYC, increasing the risk of anonymous movement. Rule [exit_rush] scored 40, reflecting that the wallet balance is zero after the transfer, consistent with a rapid drain pattern. These patterns collectively raise concerns under the AML engine’s high‑risk criteria.

</details>

---

## Finding #7: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0xc349a2f762aeba790b3f176807100c0b68466690` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.2777 ETH** ($4,849) |
| **Blocks** | 26378224-26378224 |

### 💬 What Happened
Someone just sent almost $5,000 worth of ETH from a brand-new wallet that had never been used before, and the money ended up in a service that lets you hide who owns it. The sender's address had zero balance after the transfer, so all the funds vanished from that wallet. Basically, it’s like dropping a package into a slot that hides who sent it, and then walking away.

### 🔥 The Roast
First, the new wallet dumped a huge chunk of ETH—classic "novel_wallet_dump" (meaning a brand‑new address moves a big amount in one go). Then it slid into FixedFloat 1, a place that doesn’t do any KYC, so we hit the "no_kyc_offramp" (no identity check before the money leaves). Finally, the wallet was empty after the move, a textbook "exit_rush" (all the money drained in a single shot). CRITICAL (rule score 189) Bottom line: it’s the crypto equivalent of a magician pulling a rabbit out of a hat and then disappearing with the hat itself.

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction displays a new wallet dumping a large amount into a non‑KYC off‑ramp followed by an exit rush, meeting multiple high‑risk AML indicators.**

Flag the transaction for manual review, investigate the source and destination addresses, and consider placing the receiver address on an enhanced monitoring list.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.2777 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.2777 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Rule: novel_wallet_dump – triggered by wallet age 0 days, transaction count 1, and a transfer of 2.2777 ETH, indicating a new wallet dumping a large amount. Rule: no_kyc_offramp – triggered by the deposit to FixedFloat 1, a service that does not perform KYC on outgoing funds, creating a high‑risk off‑ramp scenario. Rule: exit_rush – triggered by the wallet balance dropping to 0.000000 ETH immediately after the transfer, suggesting a rapid fund depletion. CRITICAL (rule score 189)

</details>

---

## Finding #8: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x471f58b106ae36ff9eb9d166a75f5d53a4e47f0d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.4126 ETH** ($5,136) |
| **Blocks** | 26378215-26378215 |

### 💬 What Happened
A brand‑new wallet (just created today) sent all 2.41 ETH it had to a service called FixedFloat 1, basically dumping its entire balance in a single move and leaving the wallet empty again. It’s like someone dropping a whole bag of cash into a black‑hole machine and never checking back.

### 🔥 The Roast
Looks like we’ve got a one‑night stand‑up act here: a brand‑new wallet (0 days old, so fresh out of the crypto factory) decided to play the ‘dump‑and‑run’ game and sent a tidy 2.41 ETH to FixedFloat 1—think of it as the crypto equivalent of dropping a bag of money into a vending machine that promises a fixed price but never returns the change. The engine gave it a 64 for “novel_wallet_dump” (meaning it’s a brand‑new burner wallet), 85 for “no_kyc_offramp” (the recipient is a KYC‑free service, like a shady back‑door), and 40 for “exit_rush” (the wallet is now a ghost, balance zero). The total score of 189 is like a red flag on a speedometer—fast, loud, and ready to crash.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction matches high‑risk patterns: novel wallet dump, no‑KYC off‑ramp, and exit rush.**

Flag this transaction for manual compliance review, investigate the source of the 2.4126 ETH, and monitor for any follow‑up activity from the same or related addresses.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.4126 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.4126 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction originates from a wallet with zero days of age and a single prior transaction, indicating a fresh burner wallet. The wallet moved 2.4126 ETH to FixedFloat 1, a KYC‑free off‑ramp, and subsequently has a balance of 0.000000 ETH, consistent with an exit rush pattern. The AML engine flagged the activity under the following rules: [novel_wallet_dump] (score: 64), [no_kyc_offramp] (score: 85), and [exit_rush] (score: 40), resulting in a composite score of 189, which exceeds the high‑risk threshold for manual review.

</details>

---

## Finding #9: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x34e4ddf4d32f1a1821cc94574037753fbecf367c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.2972 ETH** ($4,890) |
| **Blocks** | 26378165-26378165 |

### 💬 What Happened
A brand‑new wallet just sent all of its money (about $4,890 worth of ETH) to a service that doesn’t ask for any identity info. After the move the wallet is empty, like a fresh bottle that just got poured out. Basically, someone dropped a full bottle of liquid into a black‑box machine and then vanished.

### 🔥 The Roast
So we’ve got a brand new wallet (novel_wallet_dump, meaning it’s a burner that dumps funds instantly), it sent all its ETH to FixedFloat 1 (no_kyc_offramp, meaning no identity check on the exit point), and then it’s empty (exit_rush, meaning the funds were drained in a heartbeat). That’s the classic "I just made a new wallet, dropped money in, and then pretended I never existed" routine. If you think this is a harmless experiment, it’s actually the blockchain equivalent of a smoke‑and‑mushroom trick at a party.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction displays a high‑risk burner wallet pattern with a no‑KYC off‑ramp, scoring 189.**

Flag the sender address for manual AML review, verify the source of funds, and consider adding the FixedFloat 1 address to the watchlist for potential suspicious activity.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.2972 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.2972 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The sender wallet is 0 days old, with only one transaction of 2.2972 ETH, leaving a balance of 0.000000 ETH. This pattern satisfies the novel_wallet_dump rule (high risk for burner wallets) and the no_kyc_offramp rule (use of a no‑KYC off‑ramp). The exit_rush rule is also triggered due to the rapid depletion of the wallet balance. The transaction should be escalated for manual review under the AML policy for high‑risk burner wallet activity.

</details>

---

## Finding #10: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x9ab4aede638d699d1a607cd6c07033f31728929d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.0084 ETH** ($4,275) |
| **Blocks** | 26378150-26378150 |

### 💬 What Happened
A brand‑new wallet (just created today) sent about 2 ETH, roughly $4,275, to a service that lets people move crypto around without showing their identity. Think of it like dropping a big package into a drop‑box that hides who sent it and where it will end up, then the sender’s box is empty. The transaction is the only one the wallet ever did, and it’s already empty again.

### 🔥 The Roast
So, this fresh wallet decided to play hide‑and‑seek with 2 ETH and vanished faster than a magician’s coin trick. The wallet’s age? 0 days – like a newborn that just got its first paycheck. It hit a FixedFloat 1 service (a no‑KYC off‑ramp, meaning no identity check, just a quick way to move money) and then drained itself – exit rush, the classic “I’m gone” move. Scores: 64 for a new wallet dump, 85 for no‑KYC off‑ramp, 40 for draining the balance – total 189. Basically, it’s a textbook burner wallet in the making. CRITICAL (rule score 189)

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction matches a classic burner wallet dump into a no‑KYC off‑ramp with an exit rush, scoring 189 and indicating high risk of illicit use.**

Flag the transaction for manual review, trace downstream transfers, and consider filing a SAR if additional suspicious patterns emerge.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.0084 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.0084 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers multiple AML rules: [novel_wallet_dump] (score: 64) due to the wallet’s zero‑day age and large outbound transfer; [no_kyc_offramp] (score: 85) because the funds were sent to a FixedFloat service with no identity verification; and [exit_rush] (score: 40) as the wallet’s balance drops to zero immediately after the transfer. The composite score of 189 exceeds our high‑risk threshold. The evidence includes a single 2.0084 ETH transfer, wallet age 0 days, and zero remaining balance, all of which align with typical burner wallet patterns used to obfuscate source funds. This activity warrants further human investigation to determine the legitimacy of the source and destination of the funds.

</details>

---

## Finding #11: CRITICAL — Score 189

| | |
|---|---|
| **Sender** | `0x0dd3cc750372520fa09ea09bd90db4714b84aa1c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **2.2685 ETH** ($4,829) |
| **Blocks** | 26378099-26378099 |

### 💬 What Happened
A brand-new wallet that had never been used before sent 2.2685 ETH (about $4,829) to a service called FixedFloat 1. The sender had zero balance afterward, meaning all the money was moved out in one go. This is like a fresh pizza delivery guy dropping a whole pizza box into a slot that hides who paid for it.

### 🔥 The Roast
Well look at that, a shiny new wallet that just appeared out of nowhere decided to play the role of a burner—just like a kid who leaves a note in a mailbox and then disappears. The wallet's first move was a full 2.2685 ETH transfer to FixedFloat 1, which is a no‑KYC off‑ramp (think of it as a cash‑in‑a‑candy‑store that doesn't ask for ID). The engine gave it a 64 on the novel_wallet_dump (new wallet dumping money) rule, 85 on no_kyc_offramp (no‑KYC exit), and 40 on exit_rush (balance wiped out). Combined, it scored 189—like a high‑stakes poker hand that everyone wants to see. If you think this is a harmless transfer, just remember: the only thing more suspicious than a zero‑balance burner is a zero‑balance burner that just spent all its cash.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 189)**

Flag this wallet for manual AML review, investigate the source of the 2.2685 ETH, and monitor the destination address for subsequent suspicious activity. Consider adding the transaction to a watchlist for future monitoring.

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
- **novel_wallet_dump** (+64) — Wallet is 0 days old, moving 2.2685 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 2.2685 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
This transaction involves a wallet that was created on the same day it performed its only outgoing transfer (Wallet age 0 days). The transfer amount of 2.2685 ETH (~$4,829) was sent to FixedFloat 1, a known non‑KYC off‑ramp, triggering rule [no_kyc_offramp] with a score of 85. The wallet balance after the transaction is zero, satisfying rule [exit_rush] with a score of 40, indicating a full depletion of funds. CRITICAL (rule score 189)

</details>

---

## Finding #12: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x6cf129dc61157d53e0ddd35ceb01bea2f5111d91` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9542 ETH** ($4,160) |
| **Blocks** | 26378185-26378185 |

### 💬 What Happened
A brand-new wallet just sent almost $4,200 worth of ETH to a service that takes out-of-sight money and doesn't do identity checks. The sender's account had never held any money before and now it has none after the transfer. Basically, it's like dropping a cash box into a black hole that no one can trace back to the owner.

### 🔥 The Roast
This new kid on the block just dumped 1.9542 ETH (that’s about $4,160) into a no-kyc off-ramp, scoring a 63 on novel_wallet_dump (meaning the wallet is brand new and dumping a big chunk) and a 85 on no_kyc_offramp (meaning no identity verification before moving money). The exit rush score of 40 shows the wallet drained all its funds in a blink. Looks like someone tried to play hide-and-seek with their money, but the game’s over and the house won.

### 🎯 Verdict & Next Steps
**CRITICAL: The combination of a brand-new wallet, large single transfer to a no-kyc service, and immediate balance depletion warrants a high suspicion of money movement obfuscation.**

Flag this transaction for manual review, trace the source of the 1.9542 ETH, and consider freezing the destination address if further suspicious activity is confirmed.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9542 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9542 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a wallet age of 0 days with a single outgoing transfer of 1.9542 ETH, leaving the balance at 0.000000 ETH, matching the novel_wallet_dump rule (score 63). The transfer to FixedFloat 1, an off-ramp with no KYC, triggers the no_kyc_offramp rule (score 85). The rapid depletion of the wallet balance triggers the exit_rush rule (score 40). This pattern indicates a potential attempt to obfuscate the source of funds and should be escalated for further investigation.

</details>

---

## Finding #13: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x1d1b3d2bc493057f9263a0eaa3bcc1361c6435b0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9177 ETH** ($4,082) |
| **Blocks** | 26378175-26378175 |

### 💬 What Happened
A brand-new wallet just sent about $4,000 worth of ETH to a service that doesn’t do identity checks, and then it’s gone empty – it’s like someone drops a cash package in a mystery box and then walks away with the bag in hand.

### 🔥 The Roast
So this wallet is fresher than a morning coffee (novel_wallet_dump, meaning it’s a brand‑new address that just dumped a big chunk of crypto). Then it slides that money into a FixedFloat 1 service with zero KYC (no_kyc_offramp, meaning the receiver doesn’t verify who’s sending the money). Finally, the wallet empties faster than a pizza delivery guy on a coffee break (exit_rush, meaning the sender’s balance drops to zero right after the move). CRITICAL (rule score 188)

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 188)**

Flag the transaction for a detailed compliance review, investigate the source of the funds and the legitimacy of the FixedFloat service, and consider freezing the involved addresses if further evidence of illicit activity surfaces.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9177 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9177 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
This transaction exhibits a high‑risk pattern consistent with Rule novel_wallet_dump (new wallet, single transaction, large ETH transfer) and Rule no_kyc_offramp (transfer to a non‑KYC service). The sender’s wallet balance drops to zero immediately after the transfer, matching Rule exit_rush. The composite score of 188 exceeds our critical threshold and warrants immediate manual review for potential illicit activity.

</details>

---

## Finding #14: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x0813174415a719a0ec1ed7aed621baa09bd22940` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9452 ETH** ($4,141) |
| **Blocks** | 26378160-26378160 |

### 💬 What Happened
A brand-new wallet just sent almost $4,200 worth of Ethereum to a service that turns crypto into a different kind of coin (like sending cash into a vending machine that gives you a mystery box). The sender had zero history and no money left after the send, which is what you see when someone tries to hide where the money came from. The whole thing happened in a single transaction on a single block, so there's no trail to follow.

### 🔥 The Roast
Look at that newborn wallet—fresh out of the womb and already moving 1.9452 ETH like a toddler with a sugar rush. It hit the "novel_wallet_dump" score of 63, which is the engine’s way of saying, "Hey, you just dumped cash into a burner, buddy!" The "no_kyc_offramp" hit 85, meaning the money went to FixedFloat 1 with no identity check—like sending cash to a friend who never gives you their driver’s license. And the "exit_rush" of 40? That tells us the wallet drained itself faster than a zombie on a caffeine binge.

### 🎯 Verdict & Next Steps
**CRITICAL — The transaction displays classic burner wallet, KYC‑exempt off‑ramp, and rapid exit, indicating a high likelihood of illicit intent.**

Flag the transaction for manual review by compliance, request additional context from the receiving service, and monitor any subsequent activity originating from the sender or receiver addresses.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9452 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9452 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction was initiated from a 0‑day wallet with a single outbound transfer of 1.9452 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f, an exchange service (FixedFloat 1). According to rule "novel_wallet_dump", the wallet’s age and volume qualify it as a high‑risk burner. Rule "no_kyc_offramp" flags the destination as a KYC‑exempt off‑ramp. Rule "exit_rush" indicates the sender’s balance dropped to zero immediately after the transfer, consistent with a rapid fund exit strategy. These patterns warrant further investigation.

</details>

---

## Finding #15: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x5d32f08759f299bb8f33a07ac25aa6db741fb82d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.8737 ETH** ($3,988) |
| **Blocks** | 26378137-26378137 |

### 💬 What Happened
CRITICAL (rule score 188) The wallet was created, used, and emptied in the same block, like a one‑night stand that leaves no paper trail.

### 🔥 The Roast
Look at that new wallet, 0 days old, like a newborn baby that just learned to walk and decided to drop a $4k package into the crypto dark alley. The engine gave it a 188 composite score, which is basically a red flag louder than a fire alarm at a bank. The "novel_wallet_dump" (meaning a brand‑new wallet that dumps a large amount of funds in one go) rule says this is a classic burner pattern, the "no_kyc_offramp" (transfer to a non‑KYC off‑ramp service) rule says the receiver is a shady off‑ramp that doesn't require identity, and "exit_rush" (wallet drained itself immediately after sending) means the wallet drained itself faster than a squirrel on espresso. CRITICAL (rule score 188)

### 🎯 Verdict & Next Steps
**CRITICAL — The composite score of 188, combined with a brand-new burner wallet, no‑KYC off‑ramp transfer, and immediate balance depletion, indicates a high likelihood of illicit activity.**

CRITICAL (rule score 188)

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.8737 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.8737 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The sender wallet, 0 days old, performed a single transaction of 1.8737 ETH to a FixedFloat 1 address. This activity triggered the following AML rules: [novel_wallet_dump] (new wallet dumping large amount), [no_kyc_offramp] (transfer to a non‑KYC off‑ramp service), and [exit_rush] (wallet balance after transfer is zero). The composite score of 188 exceeds the critical threshold. The transaction is flagged for manual review.

</details>

---

## Finding #16: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x36665e322acaa2519e6d8308d96e3c9546e7a480` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9260 ETH** ($4,100) |
| **Blocks** | 26378111-26378111 |

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9260 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9260 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #17: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x700c41236e8070bb97c98b622dd76f5b36384069` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.8861 ETH** ($4,015) |
| **Blocks** | 26378102-26378102 |

### 💬 What Happened
CRITICAL (rule score 188) The sender had zero previous activity and now has no funds left, which looks like a quick drop-and-vanish scheme. It's basically a one‑shot burner wallet feeding into a privacy tool.

### 🔥 The Roast
So this fresh‑from‑the‑bank wallet decided to play hide‑and‑seek with 1.8861 ETH—big bucks for a one‑day old address. CRITICAL (rule score 188) No KYC on the off‑ramp, so the money is now as anonymous as a pizza delivery in a no‑name town. The engine gave it a 188, which is basically saying, 'Hey, this looks like a burner wallet that ran a quick exit.' If you’re looking for a mystery, this is the kind of puzzle that makes you want to pull your hair out.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 188)**

Flag the transaction for manual review by the AML compliance team. Investigate the source and destination addresses, check for any known associations, and consider freezing the assets pending further analysis.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.8861 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.8861 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: The sender wallet (0x700c41236e8070bb97c98b622dd76f5b36384069) is newly created (age 0 days) and has executed a single transaction of 1.8861 ETH to a FixedFloat 1 address. CRITICAL (rule score 188) CRITICAL (rule score 188)

</details>

---

## Finding #18: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x3db5735942a67640588d33cbb52a0f2ee2702a02` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9105 ETH** ($4,067) |
| **Blocks** | 26378088-26378088 |

### 💬 What Happened
A brand-new wallet just created on the blockchain sent almost $4,000 worth of ETH to a FixedFloat address, leaving the sender with a zero balance. It's like a person drops a package into a drop‑box and then disappears, showing a classic burner wallet pattern. The whole move looks like a quick dump of funds to hide the origin.

### 🔥 The Roast
This wallet is so new it’s probably still in the diaper phase; the engine gave it a 63 on *novel_wallet_dump* (meaning it thinks the wallet is fresh out of the crypto factory). The 85 on *no_kyc_offramp* shows the person is avoiding the identity check, like trying to get into a club without a ticket. And the 40 on *exit_rush* indicates the wallet drained faster than a coffee shop on a Monday morning. All together, a composite of 188 makes it more suspicious than a clown at a bank heist.

### 🎯 Verdict & Next Steps
**CRITICAL: composite score of 188 indicates high risk of burner wallet activity with no KYC off‑ramp.**

Flag the transaction for manual review by the compliance team; investigate the source of the funds and monitor the receiver address for further suspicious activity.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9105 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9105 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The sender wallet was created on the same day as the transaction, with a total transaction count of one and a final balance of zero. The transfer of 1.9105 ETH to a FixedFloat 1 address triggered the engine's *novel_wallet_dump* rule (score 63) for a new wallet performing a large outbound transfer, the *no_kyc_offramp* rule (score 85) for an off‑ramp lacking KYC, and the *exit_rush* rule (score 40) indicating a rapid depletion of the wallet balance. The composite risk score of 188 exceeds the high‑risk threshold set by the AML program. The transaction should be flagged for manual review to assess potential illicit activity.

</details>

---

## Finding #19: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x52647f7aef0cf112e50ac4caba85a4564a9ef16c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9420 ETH** ($4,134) |
| **Blocks** | 26378081-26378081 |

### 💬 What Happened
A brand‑new wallet (zero days old) sent about 1.94 ETH—roughly $4,134—to a service called FixedFloat 1. The whole amount was moved in one go and the sender’s balance went from 1.94 ETH to zero, like someone dropping a bag of cash into a black‑hole slot and never looking back.

### 🔥 The Roast
So we have a fresh burner wallet that just dropped a whole chunk of ETH into FixedFloat 1, a place where nobody does KYC checks (no_kyc_offramp = 85). The wallet is a one‑time use thing (novel_wallet_dump = 63) and then it disappears like a magician’s assistant (exit_rush = 40). It’s basically the crypto equivalent of a one‑night stand that ends with the money vanishing into thin air. If you’re hoping to keep that 1.94 ETH safe, you might want to double‑check where it’s going. The composite score of 188? That’s the red flag on the street sign.

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction exhibits a high‑risk burner wallet pattern with no KYC off‑ramp and an immediate exit of funds.**

Flag the transaction for manual review and trace the downstream flow of the 1.9420 ETH through FixedFloat 1 to identify any further suspicious activity. Consider applying additional AML checks on any subsequent transactions involving the same address or related wallets.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9420 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9420 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The source wallet is newly created (age 0 days) with a single outbound transaction of 1.9420 ETH to the FixedFloat 1 address. This activity matches the [novel_wallet_dump] rule (score 63) due to the wallet’s fresh status and one‑off transfer of a sizeable amount, and the [no_kyc_offramp] rule (score 85) because the destination is a non‑KYC off‑ramp service. The [exit_rush] rule (score 40) is triggered by the wallet’s balance dropping to zero immediately after the transfer, indicating a rapid exit of funds. The composite score of 188 exceeds the critical threshold, warranting further investigation.

</details>

---

## Finding #20: CRITICAL — Score 187

| | |
|---|---|
| **Sender** | `0xff03c03857ccf6dede5ed42394b6af564ecf847e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.0036 ETH** ($2,136) |
| **Blocks** | 26378101-26378101 |

### 💬 What Happened
A brand‑new wallet, like a fresh burner phone, sent a little over one ETH to a service that lets you move funds without showing who you are. The sender had never been used before, and after sending the money it has no balance left—so it’s as if the wallet just swallowed its own cash. In plain terms, someone opened a new wallet, dumped a chunk of crypto into a shady off‑ramp, and then vanished.

### 🔥 The Roast
Looks like someone just opened a new burner wallet (novel_wallet_dump = a wallet that’s 0 days old and dumps a big chunk of money) and sent 1.0036 ETH to FixedFloat 1 (no_kyc_offramp = sending to a place that doesn’t verify you). After the transfer the wallet is empty (exit_rush = draining the balance in a single move). It’s the classic “drop a package in a slot that hides who sent it” move. If you’re looking for a good story, you’ve just found a textbook example of how to make a clean exit in one swift swipe.

### 🎯 Verdict & Next Steps
**CRITICAL: The combination of a brand‑new wallet, a single large transfer to an unverified off‑ramp, and a complete balance drain constitutes a high‑risk pattern warranting immediate manual review.**

CRITICAL (rule score 187)

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
- **novel_wallet_dump** (+62) — Wallet is 0 days old, moving 1.0036 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.0036 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The sender wallet (0xff03c03857ccf6dede5ed42394b6af564ecf847e) is 0 days old and executed a single transaction of 1.0036 ETH to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1). Rule [novel_wallet_dump] was triggered due to the wallet’s age and the large single transfer. Rule [no_kyc_offramp] applies because the recipient is an off‑ramp with no KYC. Rule [exit_rush] is flagged because the wallet balance dropped from 1.0036 ETH to 0 after the transaction, indicating a full drain.

</details>

---

## Finding #21: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xaa3ed28591acbe11f438e9eb107dd4a907ceb99a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26378248-26378248 |

### 💬 What Happened
A brand‑new wallet just sent about $2 worth of ETH to a service called FixedFloat 1. Think of it like dropping a tiny, anonymous package into a box that hides who shipped it. The sender’s account is brand new and has barely used the network, so no one knows where the money is coming from.

### 🔥 The Roast
So we’ve got a fresh wallet (0‑day, like a freshly minted cryptocurrency puppy) that just slid $2 into FixedFloat 1, which is basically the crypto world’s version of a “no‑KYC off‑ramp” (meaning the sender can’t prove who they are). The engine flagged a sybil fan‑in pattern (multiple new accounts sending similar small amounts, like a bunch of friends all tipping the same tiny coin to the same place). CRITICAL (rule score 155)

### 🎯 Verdict & Next Steps
**CRITICAL: composite score of 155 from no‑KYC off‑ramp and sybil fan‑in patterns indicates high risk.**

Flag the transaction for manual AML review, request source‑of‑funds documentation if available, and consider reporting to relevant authorities if further red flags emerge.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
This transaction was evaluated under the following AML rules: [no_kyc_offramp] (score 85) due to the transfer to FixedFloat 1 with no identity verification, and [sybil_fan_in] (score 70) for the presence of a new wallet among 16 similar senders depositing comparable amounts. The composite risk score of 155 exceeds the critical threshold. The wallet has a 0‑day age and only 2 transactions, with a current balance of zero, indicating potential layering activity. CRITICAL (rule score 155)

</details>

---

## Finding #22: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xd9c42010d4f0c061fcc088c6da4ea3cbb081a24a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0011 ETH** ($2) |
| **Blocks** | 26378239-26378239 |

### 💬 What Happened
A brand‑new wallet just sent a tiny amount of ETH—about $2—to a service called FixedFloat 1. Think of it like dropping a single coin into a vending machine that then hides where the coin came from. The wallet has only ever made two tiny moves and now has no balance left, so it looks like a quick, anonymous drop.

### 🔥 The Roast
This is the crypto equivalent of a secret admirer sending a $2 tip to a mystery café—no ID, no receipts, just a quick swipe. The engine gave it a 155 score, which is like saying, “Hey, this is a big red flag, not a tiny bump in the road.” Rule no_kyc_offramp (meaning the wallet can cash out without any identity verification) got 85 points, and sybil_fan_in (meaning a bunch of wallets are all funneling similar amounts into the same place) snagged another 70—so it's basically the blockchain’s version of a shady party where everyone brings the same weird snack. In short, this is the kind of transaction that makes auditors want to grab a coffee and investigate.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual AML review, investigate the source and destination of the funds, and consider restricting further activity from this wallet pending investigation.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Suspicious Activity Report: The sender wallet (0xd9c42010d4f0c061fcc088c6da4ea3cbb081a24a) is 0 days old, with only 2 total transactions and a current balance of 0.000000 ETH, indicating a fresh, potentially high-risk account. The transaction of 0.0011 ETH to FixedFloat 1 triggered Rule [no_kyc_offramp] (score 85) due to the lack of identity verification at the off‑ramp, and Rule [sybil_fan_in] (score 70) due to the fan‑in pattern of multiple wallets sending similar amounts (~0.001 ETH ± 30%). Combined, the composite score of 155 signals a high risk of illicit layering or structuring.

</details>

---

## Finding #23: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xc32516b4d2cd3155f8a9e801e03adfca043f3670` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0009 ETH** ($2) |
| **Blocks** | 26378237-26378237 |

### 💬 What Happened
CRITICAL (rule score 155) The sender had no balance before, has only made two transactions, and the money is going straight into a place that doesn’t do identity checks.

### 🔥 The Roast
CRITICAL (rule score 155) CRITICAL (rule score 155) Looks like the crypto equivalent of a group of friends all sending the exact same $2 bill to a bank that doesn’t verify who’s sending it—nice party trick, but probably a red flag. The composite score of 155 is like a warning light on your dashboard: “Hey, we’re watching you!”

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 155)**

Flag the transaction for manual AML review. CRITICAL (rule score 155)

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 155) Rule [sybil_fan_in] is triggered by the fan‑in pattern of multiple new wallets (1 of 16) sending similar amounts (~0.001 ETH ± 30%) to the same address. The sender wallet is brand new (0 days) and has no balance, indicating potential layering or obfuscation of funds. The transaction size is small, but the combination of new wallet, no‑KYC off‑ramp, and Sybil fan‑in pattern constitutes a high‑risk indicator per AML policy.

</details>

---

## Finding #24: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xe59613376650eef980481438b4dac6394d8dab0b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0009 ETH** ($2) |
| **Blocks** | 26378236-26378236 |

### 💬 What Happened
A brand‑new wallet (only a couple of hours old) just sent a tiny packet of 0.0009 ETH to a service called FixedFloat 1. Think of it as dropping a single dollar bill into a vending machine that then hands it out to a random customer—no one knows who it came from, and you don’t see a receipt. The wallet has barely done anything else, so we’re left wondering if it’s a fresh shell for a hidden operation.

### 🔥 The Roast
Looks like someone just used a fresh‑in‑the‑shop wallet to play hide‑and‑seek with a little crypto. They slipped 0.0009 ETH into FixedFloat 1, a place that’s basically a “no‑KYC” off‑ramp (meaning no identity check). The engine gave it a high score of 85 on the no_kyc_offramp rule (that’s the big red flag). And the pattern? 70 points on sybil_fan_in—so they’re part of a bunch of similar wallets all feeding the same funnel. Bottom line: they’re all doing the same trick with the same amount, like a synchronized swimming team of bad actors.

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of a brand‑new wallet, deposit to a no‑KYC off‑ramp, and Sybil fan‑in pattern signals high potential for illicit activity.**

Flag the transaction for manual review, cross‑reference with other wallets in the same fan‑in cluster, and consider additional due diligence such as IP checks or source of funds inquiries.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
The account 0xe59613376650eef980481438b4dac6394d8dab0b, with zero days of age and only two prior transactions, executed a single transfer of 0.0009 ETH to the FixedFloat 1 service. This activity aligns with the AML engine’s [no_kyc_offramp] rule (score: 85), indicating a deposit to a non‑KYC enabled off‑ramp. Additionally, the transaction falls under the [sybil_fan_in] rule (score: 70), as it is part of a fan‑in pattern involving 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%). CRITICAL (rule score 155)

</details>

---

## Finding #25: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x90fac787b3de3390ee2b428d7e0efb8ca56cd128` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26378235-26378235 |

### 💬 What Happened
CRITICAL (rule score 155) The sender’s wallet had only two transactions, now has zero balance, and this is the only outgoing transfer we see. Think of it like someone dropping a single coin into a slot that instantly scrambles the trail, making it hard to tell who sent it.

### 🔥 The Roast
CRITICAL (rule score 155) (Sybil fan‑in: many similar accounts funneling money into one address.) The composite score of 155 is basically the AML equivalent of a police scanner blaring a red‑flag alert. It’s suspicious enough that even a kid on a playground would say, “Hey, that looks fishy!”

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction meets high‑risk AML criteria due to a no‑KYC off‑ramp and Sybil fan‑in patterns, warranting immediate review.**

Flag the transaction for manual review, request additional source‑of‑funds information, and consider a temporary hold on the recipient address pending further investigation.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
This transaction has triggered a critical flag under AML Rule [no_kyc_offramp] due to the transfer to FixedFloat 1, a service that does not require identity verification, and under Rule [sybil_fan_in] because the sender is one of 16 accounts depositing nearly identical amounts (~0.001 ETH ± 30%) into the same address. The sender wallet is new (0 days old), has performed only two transactions, and currently holds no balance, indicating a typical pattern used to obscure the origin of funds. CRITICAL (rule score 155) This pattern warrants further human investigation to determine the source and legitimacy of the funds.

</details>

---

## Finding #26: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xf5b47294e719817579d65742fb9aa9f536ad0db8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0009 ETH** ($2) |
| **Blocks** | 26378233-26378233 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #27: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xaed2548b44f64360984881cf046a52aca106fbac` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($2) |
| **Blocks** | 26378219-26378219 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #28: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xe4c69feec0c0720341699c0f29fa8079c1570de3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0009 ETH** ($2) |
| **Blocks** | 26378219-26378219 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #29: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x0ab683a1c2efe36fda8cc10dc69580ab9efd7fb7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0009 ETH** ($2) |
| **Blocks** | 26378218-26378218 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #30: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xfd76dda5f3c955160332d3ab65b9e63a950a8c66` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26378187-26378187 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #31: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x0ce0e8a73a8f18725e7a0f193d20642bf905db07` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26378185-26378185 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #32: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x4ce4c556df7c0da561000fcbde97063477465e4a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0009 ETH** ($2) |
| **Blocks** | 26378171-26378171 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #33: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xca6ce898b84dfbe9413b5d52347801dd881527a7` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26378170-26378170 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #34: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0x1ce83220023341571ed13c8d9fdddb7167ac4dd4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0008 ETH** ($2) |
| **Blocks** | 26378167-26378167 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #35: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa461080cb373d74768dc019725668f1c46bd846c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($1) |
| **Blocks** | 26378149-26378149 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #36: CRITICAL — Score 155

| | |
|---|---|
| **Sender** | `0xa0368a3d80d029aab1b4d56b711497afd916d5ed` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0007 ETH** ($2) |
| **Blocks** | 26378148-26378148 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 155.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

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
- **sybil_fan_in** (+70) — 1 of 16 senders depositing similar amounts (~0.001 ETH ± 30%) — fan-in Sybil pattern

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #37: HIGH — Score 135

| | |
|---|---|
| **Sender** | `0x5a6b875c6035987e5a6688aad54540a003753612` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **10** txs totaling **0.0170 ETH** ($36) |
| **Blocks** | 26378120-26378190 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 135.

### 🔥 The Roast
No automated commentary for this finding: per-finding analysis is capped per run and goes to the highest scores first.

### 🎯 Verdict & Next Steps
**HIGH (rule score 135)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 2 days |
| Total Transactions | 12 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (2 rules, composite score: 135):
- **structuring** (+50) — 10/10 amounts near round numbers — possible threshold avoidance
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #38: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x53cbceee717f16a1231f74da069f8e60d127885c` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378188-26378188 |

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
| Current Balance | 0.000027 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #39: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xedb5edd4988e01fcfc69b28db10ef491ad149955` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378160-26378160 |

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
| Current Balance | 0.000017 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #40: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1f52ce8505833b755f6c3b5b20ba6b4510515def` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0087 ETH** ($18) |
| **Blocks** | 26378115-26378115 |

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
| Current Balance | 0.000004 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #41: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x24f05d721164628e2b41244db80d69a9c50ffc22` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378110-26378110 |

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
| Current Balance | 0.000018 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #42: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x53cbc58f639c708a1509c1f2b39c7a2b76d0885c` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.4472 ETH** ($952) |
| **Blocks** | 26378105-26378105 |

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
| Current Balance | 0.000005 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #43: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xedb5edcebea2e4ece87380a38abf6a7292829955` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.4472 ETH** ($952) |
| **Blocks** | 26378074-26378074 |

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
| Current Balance | 0.000003 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #44: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf533db7cd7439676d83dee7fbf16474e63117917` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378057-26378057 |

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

## Finding #45: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x6414bb812ab25fc875c86224fc9919bdbd138831` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0093 ETH** ($20) |
| **Blocks** | 26378050-26378050 |

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
| Current Balance | 0.000005 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #46: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x08131e16da23fac38c8cd74940357bd322ef2940` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378246-26378246 |

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
| Current Balance | 0.000020 ETH |
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
| **Sender** | `0x6cf127be526be33edb3cafd91c651877be601d91` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378244-26378244 |

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
| Current Balance | 0.000030 ETH |
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
| **Sender** | `0x2aaa2a5047c442324e7db56a2d511de1af439f75` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0011 ETH** ($2) |
| **Blocks** | 26378240-26378240 |

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
| **Sender** | `0x1d1b399035ccb54df4a6047840976a9a854635b0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378233-26378233 |

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
| Current Balance | 0.000028 ETH |
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
| **Sender** | `0x2489a3e6074030f810dc68bfed1109406a2080d8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0012 ETH** ($2) |
| **Blocks** | 26378232-26378232 |

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
| **Sender** | `0x1da360fd90164cac35d704af91cc5d5b8bef35e3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0075 ETH** ($16) |
| **Blocks** | 26378227-26378227 |

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
| **Sender** | `0x5d32fd64432886c83cc3803152ab6b8f9ff3b82d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378219-26378219 |

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
| Current Balance | 0.000009 ETH |
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
| **Sender** | `0x13c8fd63613e6201c4b4d308bc41a5dc2552f66d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26378210-26378210 |

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
| **Sender** | `0xb0db10c661145b49794761fc2853c2e96f13ce0b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0569 ETH** ($121) |
| **Blocks** | 26378209-26378209 |

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

## Finding #55: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xebf2f0100cb342d0004430b3f67f17b3c8bb8dc5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0006 ETH** ($1) |
| **Blocks** | 26378206-26378206 |

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
| **Sender** | `0x72cb2eeff6c16a1d7c2a8676825c8317d9fff26b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26378199-26378199 |

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
| **Sender** | `0x7e54fa6b1536c98d1706af9ad17c4d9bb3bd7d06` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0735 ETH** ($156) |
| **Blocks** | 26378194-26378194 |

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

## Finding #58: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x6a9a625d164d040417fdd148079e84ae392a5201` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378190-26378190 |

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
| Current Balance | 0.000014 ETH |
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
| **Sender** | `0xd60e0cbcbb2a0eabd24c50fba5fcd743808a6780` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0354 ETH** ($75) |
| **Blocks** | 26378190-26378190 |

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

## Finding #60: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xad5eb7699cccdb5674eb4eeca571b61d4aa711b4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378188-26378188 |

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
| Current Balance | 0.000028 ETH |
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
| **Sender** | `0x533d8a0d8037552f2c5daa892d88417410103130` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378184-26378184 |

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

## Finding #62: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa37fdce76559317558bac08bb5c7cb36391d7c9f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0100 ETH** ($21) |
| **Blocks** | 26378181-26378181 |

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

## Finding #63: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x9e9d8f965aaa0b0aee1a3e70166d1b20c5f1747f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378179-26378179 |

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
| **Sender** | `0x38e5943296f69d8dff56f9f7e0385efb80a6da47` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378178-26378178 |

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
| Current Balance | 0.000021 ETH |
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
| **Sender** | `0x3db57c5833a3f4668b5567b17e63130c5f7f2a02` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378177-26378177 |

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
| Current Balance | 0.000020 ETH |
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
| **Sender** | `0xa79ee66e9c5dae6578180ab71907472ef6dc5670` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378172-26378172 |

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
| Current Balance | 0.000020 ETH |
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
| **Sender** | `0x36665c4880382744edc7002bc660532154dba480` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378170-26378170 |

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
| Current Balance | 0.000030 ETH |
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
| **Sender** | `0x52647dda4dff1fc2cf5ff722378af5aceb4cf16c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378170-26378170 |

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
| Current Balance | 0.000019 ETH |
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
| **Sender** | `0x195d16e16478ad6250e1de4a26f6d6029e955d44` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0002 ETH** ($0) |
| **Blocks** | 26378159-26378159 |

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

## Finding #70: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x277ab0eb604565f79fdf59dc847be6561eed665c` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378150-26378150 |

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
| Current Balance | 0.000011 ETH |
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
| **Sender** | `0x3c70a78778fbdec208beb4caf883b8091e8ca9fc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1503 ETH** ($320) |
| **Blocks** | 26378150-26378150 |

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

## Finding #72: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x266c0a24281ea65a635ac3f2ae432f961af0d9ea` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1000 ETH** ($213) |
| **Blocks** | 26378141-26378141 |

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
| **Sender** | `0xc3fe0dc7b6998372055ce12b1a0c0c8e09b8e045` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378138-26378138 |

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
| Current Balance | 0.000011 ETH |
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
| **Sender** | `0xcd59e8994e483fdd4f4220e0b1106926d10c3ce0` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.5119 ETH** ($1,090) |
| **Blocks** | 26378135-26378135 |

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

## Finding #75: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd468ae428f7fae6480f959474ab83be7c70d6668` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26378133-26378133 |

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

## Finding #76: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x223b5d4b1f4e523e979c09356e382d3a199c100e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2500 ETH** ($532) |
| **Blocks** | 26378131-26378131 |

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

## Finding #77: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3418f7707dcd46e026de2072daaf5cda3320aac1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378129-26378129 |

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
| **Sender** | `0x6a9a6fd9382f57c77ac900d09325d5f144705201` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.4220 ETH** ($898) |
| **Blocks** | 26378126-26378126 |

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
| **Sender** | `0xed7a55663d72616b58298c6aa7b85c47b4752ddc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0805 ETH** ($171) |
| **Blocks** | 26378125-26378125 |

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
| **Sender** | `0xb852dea6fa0a94ea61815252d9a8533df3ae89c4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26378117-26378117 |

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
| **Sender** | `0x38e59e16ad21bd443a41fc5236b908ca0062da47` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.9820 ETH** ($2,090) |
| **Blocks** | 26378116-26378116 |

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

## Finding #82: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4cb5e8fed294f2b08bc8bdd802501544aed120dc` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378115-26378115 |

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

## Finding #83: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x68eb06a6824e39dd665c53bd3ffeb7b032153f7f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26378113-26378113 |

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

## Finding #84: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x16859171cc3bf8d0a26b56877f3ad7ccf5f3ce48` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1046 ETH** ($223) |
| **Blocks** | 26378113-26378113 |

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

## Finding #85: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x0a72e39987623c6eb5f103289cb08189f41551fb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378108-26378108 |

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
| Current Balance | 0.000013 ETH |
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
| **Sender** | `0xd6429c843155725b57d4ded21fa06dfe603b186b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1098 ETH** ($234) |
| **Blocks** | 26378106-26378106 |

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

## Finding #87: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xfeebf2c6bf4b7521243ebe5902bb18009cfe6717` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378105-26378105 |

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

## Finding #88: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x52f5f5840e565bcacca0b1afca1d7b2ebb0a1d41` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378102-26378102 |

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
| Current Balance | 0.000016 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #89: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa2baa58faa533c3bf2b64f8077e316b6c83a4085` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0060 ETH** ($13) |
| **Blocks** | 26378100-26378100 |

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

## Finding #90: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xc6521682bc47c1db122e746150743fb2ce69df37` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26378099-26378099 |

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

## Finding #91: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4bb26b211e063626ac844c5c2a75d4db2774f554` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26378093-26378093 |

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

## Finding #92: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x9ad8a379146c18484ae248f76236ca88dd0bd4f2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0004 ETH** ($1) |
| **Blocks** | 26378093-26378093 |

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

## Finding #93: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xad5eb10d6302e9c24ad778875ef03c89766e11b4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1693 ETH** ($360) |
| **Blocks** | 26378092-26378092 |

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

## Finding #94: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x26b84fa63e2772181a98e6739a9ec511f3e587bd` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378090-26378090 |

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

## Finding #95: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf3ec4abc5cbe2784566aa46c2b357b7d561987af` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378085-26378085 |

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

## Finding #96: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x223fa6d63d013181e2dbe466a5dba26c63258547` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378084-26378084 |

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
| Current Balance | 0.000015 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #97: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x7c044ee3a82511f80314611e4a84b9cf480f52e1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.3755 ETH** ($799) |
| **Blocks** | 26378082-26378082 |

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

## Finding #98: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x09ccc1d2ecd300408fded51508c5518c5e057124` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378079-26378079 |

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
| Current Balance | 0.000013 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #99: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa79eeebfdccce3c83b2962779020d882a2af5670` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0804 ETH** ($171) |
| **Blocks** | 26378079-26378079 |

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

## Finding #100: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x6199d7fb7fdf430880a41ea65add0918d126a4f8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378075-26378075 |

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

## Finding #101: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd1cad712f654fb57863c39b7b7101a15fa2552ad` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26378074-26378074 |

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
| Current Balance | 0.000015 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #102: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x8a650e8f0f573eba9555d5bfe318f960c368149d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0003 ETH** ($1) |
| **Blocks** | 26378071-26378071 |

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

## Finding #103: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4a3de9238c470c34235d8958cdd7509c77cf2bde` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378070-26378070 |

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

## Finding #104: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xcd994c7b1f7a992c4fee8d7a674722c22cb9fd66` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0005 ETH** ($1) |
| **Blocks** | 26378069-26378069 |

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

## Finding #105: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xcbe11a435df51107989779606aef6eacf60ef22b` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$674** (674 USDC) |
| **Blocks** | 26378150-26378150 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $674 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #106: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa5b818d6ff3d26960cd1c007ca3a9ee5c2a159ac` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$136** (136 USDT) |
| **Blocks** | 26378061-26378061 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $136 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #107: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0x0383e15a8dcacc83fa82c6af62e20b11a7e89537` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$142** (142 DAI) |
| **Blocks** | 26378050-26378050 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $142 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**107 suspicious findings** detected across 107 unique wallets. Highest risk score: **198**.

| | |
|---|---|
| 🔴 CRITICAL | 36 |
| 🟠 HIGH | 1 |
| Wallets flagged | 107 |
| Suspicious value | 52.2111 ETH ($111,139) + $952 in stablecoins |
| Blocks scanned | 26378050 — 26378249 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 2 of 25 attempted analyses this run.

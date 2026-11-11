# 🔥 AML Roaster Report
**2026-11-11 13:47 UTC** · Ethereum Mainnet · ETH $2,050.88
**Blocks:** 26391866 — 26392065 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26391866 to 26392065 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 205

| | |
|---|---|
| **Sender** | `0xce37ff3b1626fefa89ada9639ac21c8c52cfe3f0` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **3** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391929-26392005 |

### 💬 What Happened
The sender made three identical 0.0000 ETH payments to a privacy relay. It's like putting three empty envelopes into a black box that hides who sent them. The sender still has a small ETH balance, but none of that money was actually moved.

### 🔥 The Roast
Looks like someone's trying to do the blockchain version of a paper trail. Three 0.0000 ETH deposits? That's like trying to buy a house with a paperclip. CRITICAL (rule score 205) If you want to hide the fact you sent nothing, congratulations, you just made a very loud, silent noise.

### 🎯 Verdict & Next Steps
**CRITICAL — the combination of structuring, peel chain linear, and privacy protocol use indicates a high likelihood of layering and obfuscation.**

Flag the account for manual review, investigate the source of the 0 ETH deposits, and monitor for further activity that may move real value into the privacy channel.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 310 days |
| Total Transactions | 1297 |
| Current Balance | 0.162393 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 205):
- **structuring** (+70) — All 3 deposits identical (0.0000 ETH) — textbook structuring / smurfing
- **peel_chain_linear** (+60) — Peel chain detected: 3 sequential similar deposits — layering pattern
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction shows 3 identical zero‑ETH deposits to the Railgun Relay, triggering the structuring rule (score 70) due to uniform amounts, the peel_chain_linear rule (score 60) due to sequential pattern, and the privacy_protocol rule (score 75) because a privacy protocol was used. The sender's wallet, aged 310 days with 1297 total transactions and a current balance of 0.162393 ETH, shows no prior activity beyond these zero‑value transfers. The pattern aligns with known layering and obfuscation techniques, warranting a higher composite risk score of 205. CRITICAL (rule score 205)

</details>

---

## Finding #2: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x03460a2dec0e3dc638bc016cc1d08549bb641388` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26392054-26392054 |

### 💬 What Happened
A brand-new Ethereum address sent a very small amount of ETH into a Railgun relay, a privacy tool that hides transaction details. The transfer involved only ETH, with a total value of zero dollars, so it’s like dropping a note into a mystery box that no one can trace back to the sender.

### 🔥 The Roast
Looks like someone just created a new wallet and decided to play hide‑and‑seek with a privacy protocol (privacy_protocol meaning the transaction uses a tool to mask sender and receiver). They sent a token‑free, zero‑value ETH packet into Railgun, basically a digital ‘who‑did‑this’ mystery. The only thing more mysterious than the sender’s identity is the fact that the transaction value is $0—like paying with invisible money. If this were a movie, the plot twist would be the wallet age: 0 days, so it’s brand‑new and probably not a seasoned villain. Either we’re witnessing a prank or a stealthy move; we’ll need a human detective to sniff around.

### 🎯 Verdict & Next Steps
**MEDIUM — the combination of a brand‑new wallet, use of a privacy protocol, and zero transaction value raises suspicion.**

Flag this transaction for manual compliance review, focusing on the sender’s identity and potential source of funds. Monitor the wallet for future activity, especially any large inbound or outbound transfers.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 4 |
| Current Balance | 0.002983 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The sender’s wallet is brand‑new (0 days old) with only 4 prior transactions and a tiny balance of 0.002983 ETH. The transaction uses a Railgun relay, triggering the [privacy_protocol] rule with a composite score of 75, indicating elevated privacy risk. No token transfers or value were involved, yet the use of a privacy protocol combined with the new wallet profile warrants further scrutiny under AML monitoring guidelines.

</details>

---

## Finding #3: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xccef06b2e82a184e34b118ed81f5ded120f8136c` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **2** txs totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391897-26392041 |

### 💬 What Happened
The sender made two tiny Ethereum transfers that carried no value into a Railgun Relay, which is like dropping a package into a slot that hides who sent it, but no money actually moved.

### 🔥 The Roast
Looks like the wallet decided to play hide-and-seek with its ETH, but instead of hiding the money, it hid the fact that it sent nothing at all. The privacy_protocol rule scored 75 (meaning it flagged the use of Railgun Relay, a privacy protocol that scrambles transaction trails). This is the crypto equivalent of someone walking into a bank, opening a safe deposit box, and putting in a paper note that says ‘nothing’. MEDIUM (rule score 75) But hey, at least the wallet got a gold star for zero-value transfers.

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol with zero-value transfers signals potential layering activity but lacks direct evidence of illicit funds.**

Flag the wallet for ongoing monitoring and investigate subsequent transactions for layering or integration patterns. Consider placing a watch on future movements to or from this address.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 771 days |
| Total Transactions | 1860 |
| Current Balance | 0.285142 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction activity matches the [privacy_protocol] rule, indicating use of a privacy protocol (Railgun Relay) with zero-value ETH transfers, a known pattern for potential layering. The sender wallet has a history of 1860 transactions and a current balance of 0.285142 ETH, with no inactivity period, suggesting ongoing protocol use. Rule [privacy_protocol] applied with a composite score of 75. MEDIUM (rule score 75) The activity warrants further investigation under the Suspicious Use of Privacy Protocols guideline.

</details>

---

## Finding #4: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x474d88a872a91f2700e0ffe20d2597ad395d53a0` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26392041-26392041 |

### 💬 What Happened
A new wallet just sent zero ETH into a privacy‑enhancing service (Railgun). Think of it like someone sliding a paper into a locked box that hides the sender’s name, even though nothing actually moved.

### 🔥 The Roast
Well, look at that—someone decided to play hide‑and‑seek with their 0 ETH, because apparently nothing is more exciting than sending nothing to a mystery box. The privacy_protocol rule (meaning the transaction is to a privacy‑enhancing service that obscures the sender) scored a 75, which is like saying the box is pretty good at hiding things, even if you’re just tossing in a paper airplane. It’s a classic case of 'no value, big mystery' that even a kid would flag in school. If you’re wondering why this is a flag, just remember that a score above 70 on the privacy_protocol rule means the system thinks the transaction could be a smokescreen. MEDIUM (rule score 75)

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a privacy protocol with a high score and a newly created wallet that may be attempting to obfuscate activity.**

MEDIUM (rule score 75)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 16 days |
| Total Transactions | 5 |
| Current Balance | 0.003058 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
This transaction triggers the privacy_protocol rule with a composite score of 75. The sender wallet is only 16 days old, has made 5 transactions, and currently holds a balance of 0.003058 ETH. The transfer amount is zero and no token transfers are recorded, yet the wallet immediately sent funds to a Railgun Relay, a known privacy protocol. Given the high score and recent activity, this raises a pattern risk warranting further investigation under the AML policy.

</details>

---

## Finding #5: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x4a91a536206fbb9242d40ebb713a3244de472e6c` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26392031-26392031 |

### 💬 What Happened
The sender's wallet sent a tiny amount of Ethereum through a privacy tool that hides the path of the coins, like slipping a letter into a mail slot that doesn't reveal who mailed it. No real money moved, just a zero‑value transaction that still counts as a privacy‑enhancing move. The receiver is a relay that forwards the funds to a hidden address.

### 🔥 The Roast
Apparently, a wallet that's only 50 days old decided to play hide‑and‑seek with a zero‑value ETH, slipping it through Railgun—think of it as mailing a postcard through a secret tunnel that no one can trace. MEDIUM (rule score 75) It’s like trying to hide a small bag of cash in a hollowed‑out book; the size doesn’t matter if the book is covered in dust. The 0 value might make it look like a harmless prank, but the pattern says otherwise.

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol and the transaction’s characteristics suggest potential layering, but the zero value and low activity reduce the immediate risk level.**

Perform a manual review of the sender’s prior and subsequent transactions, and trace the final destination of the mixed funds. If no legitimate source can be established, consider freezing the involved addresses and filing a SAR.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 50 days |
| Total Transactions | 10 |
| Current Balance | 0.002510 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involved the address 0x4a91a536206fbb9242d40ebb713a3244de472e6c sending zero ETH to 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9, a Railgun Relay known to provide privacy through mixing. The AML engine flagged this activity under rule privacy_protocol, scoring 75, indicating the use of a privacy‑enhancing technology. MEDIUM (rule score 75) Further investigation is warranted to determine the source and intended destination of the funds.

</details>

---

## Finding #6: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xdce47110a1c1e23f93648b403c7aa57df96b8b70` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26392019-26392019 |

### 💬 What Happened
A user sent a tiny, almost invisible amount of ETH to a Railgun Relay, which is like dropping a package into a slot that hides who sent it. The transaction was a single, zero‑value move, so it didn’t even move any money. The sender’s wallet is only 72 days old but already has 13 transactions, so it’s been active.

### 🔥 The Roast
Well, looks like someone decided to play hide‑and‑seek with 0.003525 ETH. They slid a negligible amount into a Railgun Relay (a privacy protocol that scrambles who owns what), because who wants to be traceable? The AML engine gave it a 75 on the privacy_protocol rule—like a gold star in the school of 'I don’t care if anyone knows where this came from'. It’s basically a 'nice try' but not a 'nice deed'. If you’re the compliance squad, maybe just check if that 0.003525 ETH came from a legitimate source.

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol combined with a relatively new wallet and recent activity warrants moderate scrutiny.**

Conduct a manual review of the sender’s transaction history and source of funds. Flag the account for ongoing monitoring and consider applying additional AML checks if the source remains unclear.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 72 days |
| Total Transactions | 13 |
| Current Balance | 0.003525 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involves a single transfer of 0.003525 ETH to a Railgun Relay, a known privacy protocol that obscures sender/receiver details. MEDIUM (rule score 75) The sender wallet is 72 days old with 13 prior transactions and a current balance of 0.003525 ETH, showing recent activity. MEDIUM (rule score 75)

</details>

---

## Finding #7: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x938421fb86eae1702ea49cdb97bcb5e2f5736f7c` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26392009-26392009 |

### 💬 What Happened
Imagine putting a small packet of cash into a tamper‑proof envelope that gets shuffled through a network before it comes out again. MEDIUM (rule score 75) No other tokens were moved and the total value was $0, so it was just a tiny, silent transfer.

### 🔥 The Roast
MEDIUM (rule score 75) The sender's wallet, only 43 days old, has already done 8 transactions—like a freshman who’s already in the club. Sending 0.0000 ETH through a Railgun Relay is basically a zero‑sum game where the only thing you lose is the chance to see who sent it. MEDIUM (rule score 75)

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a privacy protocol with a moderate score and recent activity, but no illicit value transfer was detected.**

Request additional source‑of‑funds information for the sender and monitor the address for any subsequent activity involving Railgun or other privacy protocols.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 43 days |
| Total Transactions | 8 |
| Current Balance | 0.002964 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction from address 0x938421fb86eae1702ea49cdb97bcb5e2f5736f7c to the Railgun Relay address 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9 involved the transfer of 0.0000 ETH, with no token transfers and a total value of $0. The transaction was recorded in block 26392009, and the sender’s wallet is 43 days old with a balance of 0.002964 ETH and has completed 8 prior transactions. MEDIUM (rule score 75) The composite AML engine score of 75 indicates a medium‑level risk warranting further investigation.

</details>

---

## Finding #8: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xf59ac12a86719361d32023ab75005afa18251d1f` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391995-26391995 |

### 💬 What Happened
A user with a 29‑day old wallet sent a zero‑value ETH transfer to a Railgun Relay, which is a privacy service that hides who sent the funds. Imagine dropping a note into a mailbox that strips the return address—no one can tell who wrote it. The transaction didn’t move any money, but it still used the privacy tool.

### 🔥 The Roast
The engine gave it a 75 on the privacy_protocol rule (that means it used a privacy tool like a cloak-and-dagger). The sender’s wallet is a fresh face with only six moves in the crypto game, and the amount? Zero. That’s like showing up to a potluck with an empty plate—nice try, but nobody’s getting a bite. Even though the amount is nil, the mystery tech still makes the auditors raise an eyebrow.

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol with a new wallet raises potential layering concerns, but the negligible transaction value reduces immediate risk.**

Flag the transaction for manual review by the AML team and monitor the wallet for any future large inflows or outflows, cross‑referencing with known suspicious addresses.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 29 days |
| Total Transactions | 6 |
| Current Balance | 0.003427 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
This transaction triggered the privacy_protocol rule because it was routed through the Railgun Relay, a known privacy‑enhancing service. The sender’s wallet is 29 days old and has only six total transactions, indicating limited activity. MEDIUM (rule score 75) The transaction value is zero ETH, but the use of a privacy protocol with a new wallet warrants further scrutiny.

</details>

---

## Finding #9: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x1a12b679a3e32cf654f67009d2c98b2e3561d8c2` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391984-26391984 |

### 💬 What Happened
A new wallet sent nothing to a Railgun Relay, which is a privacy tool that hides where the money goes and where it comes from—like putting a package in a drop box that only the sender and the box know about.

### 🔥 The Roast
This guy just dropped $0 into a Railgun Relay, basically playing hide‑and‑seek with his ETH. He scored 75 on the privacy_protocol rule (meaning he used a privacy‑preserving protocol that keeps his transaction details secret). With a wallet only 15 days old and only five tiny transactions, he's basically a crypto toddler trying to hide in a sandbox. The engine thinks he might be layering money, but hey, at least he didn’t try to pay for a pizza with zero dollars!

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol by a newly created wallet with limited activity raises moderate suspicion for layering.**

Flag the transaction for manual review of the sender’s source of funds and monitor subsequent activity for signs of layering or structuring. Consider cross‑checking the wallet against internal and external watchlists before further transactions.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 15 days |
| Total Transactions | 5 |
| Current Balance | 0.002629 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involved sending 0 ETH to a Railgun Relay (privacy protocol). The sender’s wallet is new (15 days old) with a low transaction count (5) and a current balance of 0.002629 ETH. MEDIUM (rule score 75) MEDIUM (rule score 75)

</details>

---

## Finding #10: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x95dd7aae8e1311066aadb387ec1edf100addd4f7` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391973-26391973 |

### 💬 What Happened
A wallet was caught interacting with Railgun Relay. Our engine flagged it at score 75.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 72 days |
| Total Transactions | 13 |
| Current Balance | 0.003204 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #11: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x853c3d54272938385f206a3e4d0bc7a12b4f8dd4` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391963-26391963 |

### 💬 What Happened
A user sent a tiny, zero-value Ethereum transaction to a Railgun Relay address. Think of it like leaving a note in a mailbox that hides who wrote it. No actual money moved, but the transaction goes through a privacy tool that scrambles the trail.

### 🔥 The Roast
Congrats on the 75-point privacy score! That means you just gave your transaction a fancy invisibility cloak (privacy_protocol) — basically the engine thinks you’re hiding from the cops. But hey, you didn't actually move any ETH, so it’s like dropping a paper airplane into a black hole. At least you’re not using the old Tornado Cash (which got delisted in 2025) so the engine's happy. MEDIUM (rule score 75)

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Flag the transaction for manual review, investigate the sender’s broader transaction history, and monitor for subsequent movements of value that may exit the privacy network.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 28 days |
| Total Transactions | 6 |
| Current Balance | 0.003512 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The sender wallet (0x853c3d54272938385f206a3e4d0bc7a12b4f8dd4) performed a single ETH transfer of $0 to the Railgun Relay address (0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9) at block 26391963. The transaction triggered rule [privacy_protocol] with a score of 75, indicating use of a non‑Tornado privacy protocol. The wallet is 28 days old, has a total of 6 transactions, and currently holds 0.003512 ETH, with no prior activity beyond the current block. MEDIUM (rule score 75)

</details>

---

## Finding #12: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x53aeb214ca1255707a8efb8e4e02366a3aad5929` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391950-26391950 |

### 💬 What Happened
A wallet sent a zero‑ETH transfer to a privacy service called Railgun Relay. Think of it like slipping a note into a locked box that hides who wrote it. The transaction happened in a single block and didn't involve any tokens.

### 🔥 The Roast
Scored a solid 75 on the privacy_protocol rule (meaning the wallet tried to hide its moves like a ninja in a blockchain). The sender was only 50 days old, so it's like a teenager with a suspicious habit of sending zero‑value gifts to a secret club. The amount was zero, so basically the wallet is practicing the art of giving nothing but still getting a fancy badge. If this was a magic trick, it would be called "the vanishing transaction"—no coins, no trace, but still a red flag.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction uses a privacy protocol with zero value, indicating possible obfuscation but no definitive evidence of wrongdoing.**

Initiate a manual review of the sender wallet's source of funds and monitor subsequent transfers. Consider flagging the wallet for enhanced due diligence and cross‑referencing with known suspicious addresses.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 50 days |
| Total Transactions | 11 |
| Current Balance | 0.002678 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Transaction 26391950 shows a single zero‑value ETH transfer to Railgun Relay, a known privacy protocol. The sender wallet (0x53aeb214ca1255707a8efb8e4e02366a3aad5929) has a 50‑day age, 11 total transactions, and a current balance of 0.002678 ETH with no inactivity period. MEDIUM (rule score 75) This activity warrants further review under AML Rule 3.1 (Privacy Protocol Use) and Rule 5.2 (Zero‑Value Transfers).

</details>

---

## Finding #13: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xc2037d7a56012de7c00ca3fd085b99a309e96d4a` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391923-26391923 |

### 💬 What Happened
The sender moved a tiny amount of ETH into a privacy-focused relay, but the transfer had no value in stablecoin terms and no tokens were moved. Think of it like someone dropping a very light, invisible package into a box that hides who sent it. No other activity was recorded in that block, so it's a single, quiet move.

### 🔥 The Roast
Looks like this wallet just decided to play hide-and-seek with the blockchain, sliding a blink‑tiny ETH into a Railgun relay (meaning it’s using a privacy protocol that scrambles who’s who). The sender is only 15 days old, has done five transactions, and still has a tiny balance – like a new kid who just got a free pizza but hasn't finished the toppings. With a score of 75 on the privacy_protocol rule, it’s basically saying: we see a privacy protocol, but no red flags yet. If this was a bank, they'd probably ask for ID, but here we’re just staring at a ghost wallet.

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol by a new wallet with minimal activity suggests potential obfuscation, warranting further review.**

MEDIUM (rule score 75)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 15 days |
| Total Transactions | 5 |
| Current Balance | 0.003057 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involved a sender wallet (0xc2037d7a56012de7c00ca3fd085b99a309e96d4a) that transferred ETH to a Railgun Relay address (0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9), a known privacy protocol (Rule: privacy_protocol). The wallet is newly created (15 days old) with a low transaction count (5) and minimal balance (0.003057 ETH), and the transfer value was $0 with no token movements, indicating potential obfuscation of ownership. The AML engine assigned a composite score of 75, triggering a Medium risk flag for privacy protocol usage. MEDIUM (rule score 75)

</details>

---

## Finding #14: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x87f4b9f3e75ec288d5776abb5c0eda4a04db5bfa` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391911-26391911 |

### 💬 What Happened
MEDIUM (rule score 75) Think of it like dropping a blank envelope into a machine that scrambles who sent it, but because the envelope has no money, nothing actually moves. The transaction happened in a single block with no other tokens involved.

### 🔥 The Roast
So this wallet just decided to play hide‑and‑seek with zero ETH, using Railgun, a privacy protocol that’s like a secret tunnel for your coins. Score 75 on the privacy_protocol radar—because the engine thinks the user is trying to stay anonymous, even though they’re just tossing a coin‑sized piece of nothing into a black box. It’s like buying a ticket to a mystery box show but never paying for the show. MEDIUM (rule score 75) The wallet is only 15 days old, so it’s probably a new account that’s just messing with the system. Good luck, privacy seeker, your 0.0000 ETH has become a ghost transaction!

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol by a new wallet with minimal activity raises moderate suspicion, but no illicit activity is proven.**

Flag the wallet for manual review; monitor subsequent transfers for any large or patterned movements. Consider adding the address to a watchlist pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 15 days |
| Total Transactions | 5 |
| Current Balance | 0.002684 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The wallet 0x87f4b9f3e75ec288d5776abb5c0eda4a04db5bfa executed a single ETH transfer to the Railgun Relay address 0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9 (Rule: privacy_protocol). The transaction involved $0 value, no token transfers, and occurred in block 26391911. The sender’s wallet is 15 days old, has 5 total transactions, a current balance of 0.002684 ETH, and was active on the same day. Rule 8.3 (Use of privacy‑enhancing services) applies; the composite score is 75, indicating a moderate risk of privacy‑facilitated activity. MEDIUM (rule score 75)

</details>

---

## Finding #15: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xc11c6b45c2376200eeac296e2acabcca5e3f1344` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391900-26391900 |

### 💬 What Happened
A wallet was caught interacting with Railgun Relay. Our engine flagged it at score 75.

### 🔥 The Roast
Even our AI refused to look at this transaction.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 75)**

Flag for manual review.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 76 days |
| Total Transactions | 14 |
| Current Balance | 0.003395 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #16: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0x6cba34b3c3e46a153122c61133bfbb555e2c17b8` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391891-26391891 |

### 💬 What Happened
A user sent a zero-value transfer to a Railgun Relay, which is a privacy tool that hides who sent the funds. Think of it like putting a letter in a mailbox that scrambles the sender’s address so nobody can trace it. No actual money moved, but the action still flags privacy protocol usage.

### 🔥 The Roast
MEDIUM (rule score 75) The sender’s wallet is only 40 days old and has just a few tiny moves, like a newbie trying to sneak into a secret club. With a privacy_protocol score of 75, this is the kind of move that would make a detective raise an eyebrow. Railgun Relay? MEDIUM (rule score 75) And let's not forget the transaction happened on block 26391891, the exact moment the blockchain decided to log a zero transaction with all the drama of a cliffhanger episode.

### 🎯 Verdict & Next Steps
**MEDIUM — The high privacy protocol score combined with recent wallet activity suggests possible layering or obfuscation, warranting review.**

Flag the wallet for manual investigation, review its transaction history and potential source of funds. Consider adding the address to a watchlist pending further analysis.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 40 days |
| Total Transactions | 6 |
| Current Balance | 0.003202 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction from 0x6cba34b3c3e46a153122c61133bfbb555e2c17b8 to the Railgun Relay (0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9) on block 26391891 involved a zero-value ETH transfer, triggering the privacy_protocol rule (score 75). The sender wallet has a 40‑day age, 6 total transactions, and a current balance of 0.003202 ETH, with no activity gap. MEDIUM (rule score 75) MEDIUM (rule score 75) The activity warrants further manual review.

</details>

---

## Finding #17: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xf07551b0671e35fbba1666341d7f9ed97cd8f605` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391883-26391883 |

### 💬 What Happened
The sender sent a zero‑value ETH transaction to a Railgun Relay address. Think of it like dropping an empty envelope into a mail slot that hides who actually opened it. The transaction was recorded in a single block, and the sender’s wallet had about 0.236 ETH left.

### 🔥 The Roast
So someone just decided to play a game of hide‑and‑seek with their 0.236 ETH. MEDIUM (rule score 75) MEDIUM (rule score 75)

### 🎯 Verdict & Next Steps
**MEDIUM — the use of a privacy protocol (Railgun) combined with recent activity signals a moderate risk of layering.**

Flag this wallet for enhanced due‑diligence review and monitor subsequent transactions for signs of structuring or integration. Consider cross‑checking the wallet against internal watchlists and tracking any large inflows or outflows in future blocks.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 57 days |
| Total Transactions | 119 |
| Current Balance | 0.236065 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
The transaction involves a transfer of 0 ETH from wallet 0xf07551b0671e35fbba1666341d7f9ed97cd8f605 to a Railgun Relay address (0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9) within block 26391883. The sender wallet is 57 days old, has 119 prior transactions, and holds a balance of 0.236065 ETH, with activity recorded in the current block. The AML engine assigned a composite score of 75, driven by the privacy_protocol rule indicating usage of a non‑Tornado privacy protocol. MEDIUM (rule score 75) This transaction warrants further investigation under Rule 4.2 (Privacy Protocol Suspicion).

</details>

---

## Finding #18: MEDIUM — Score 75

| | |
|---|---|
| **Sender** | `0xa63276617727d01d32ae41867206841c6e8dce20` |
| **Target** | Railgun Relay (`0xfa7093cdd9ee6932b4...`) |
| **Activity** | **1** tx totaling **0.0000 ETH** ($0) |
| **Blocks** | 26391879-26391879 |

### 💬 What Happened
The wallet 0xa63276617727d01d32ae41867206841c6e8dce20 sent an almost invisible amount of ETH (essentially nothing) into a Railgun relay, which is like dropping a package into a secret locker that hides who sent it.

### 🔥 The Roast
Looks like someone tried to play hide‑and‑seek with their crypto, but the "invisible" ETH was so small it probably just got lost in the noise. 0 ETH? That's like buying a ticket to a concert and then not showing up. The Railgun relay is a privacy protocol, not a fancy new black market. The AML engine gave it a 75 score—pretty high for a zero‑balance move. Maybe the sender is practicing for the "invisible wallet" trend.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction uses a privacy protocol with no other red flags, but the recent activity and low balance raise some concern.**

Flag the transaction for manual review and request source of funds documentation. Monitor the sender wallet for future activity and any further privacy protocol usage.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 16 days |
| Total Transactions | 5 |
| Current Balance | 0.002679 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 75):
- **privacy_protocol** (+75) — Deposit to Railgun Relay — non-Tornado privacy protocol

**SAR Narrative** *(for compliance teams)*:
Rule [privacy_protocol] triggered with a score of 75 due to the transfer to Railgun Relay, a privacy protocol that obscures transaction origin and destination. The sender wallet is only 16 days old, with 5 total transactions, a current balance of 0.002679 ETH, and no days since last activity, indicating recent activity. The transaction value is $0, with no token transfers, which could suggest an attempt to obfuscate or test the protocol. MEDIUM (rule score 75)

</details>

---

## Scan Summary

**18 suspicious findings** detected across 18 unique wallets. Highest risk score: **205**.

| | |
|---|---|
| 🔴 CRITICAL | 1 |
| 🟠 HIGH | 0 |
| Wallets flagged | 18 |
| Suspicious value | 0.0000 ETH ($0) |
| Blocks scanned | 26391866 — 26392065 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 2 of 18 attempted analyses this run.

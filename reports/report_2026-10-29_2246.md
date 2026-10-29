# 🔥 AML Roaster Report
**2026-10-29 22:41 UTC** · Ethereum Mainnet · ETH $2,270.25
**Blocks:** 26301212 — 26301411 · **Watched Addresses:** 49 · **Detection Rules:** 13
**Engine:** NEXUS AML v2 (rule set from aml-detection-engine)
**Coverage:** blocks 26301212 to 26301411 checked (about 40 min). 8 of 49 addresses. Each address is revisited about every 42 hours. Activity outside these windows is not checked. 8 addresses attempted, 8 addresses fully scanned, 0 fetch failures (0 Etherscan rate-limit, 0 other). AI commentary is limited to 25 highest-scoring findings.

---

## Finding #1: CRITICAL — Score 255

| | |
|---|---|
| **Sender** | `0x502ca2dbaa0bcf748d0c90e694113af6622ca236` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **20.9995 ETH** ($47,674) |
| **Blocks** | 26301247-26301247 |

### 💬 What Happened
A brand new wallet just sent almost $48,000 worth of ETH to a service that turns your money into something anonymous. It's like a brand-new mailbox that drops a huge parcel into a black hole that hides the sender and the receiver. The wallet was created and used in the same day, and after sending the money it has zero balance left.

### 🔥 The Roast
This address just performed the classic 'burner wallet' routine: create a fresh wallet, dump a fat stack of ETH, and vanish like a magician with a rabbit (novel_wallet_dump score 100). Then it hit the 'no KYC off‑ramp' jackpot, slurping the funds into FixedFloat 1, which is basically a digital cloak of invisibility (no_kyc_offramp score 85). With 20.9995 ETH ($47,674) in the bag, it also got a high‑value sticker (high_value score 30). Finally, the wallet did the exit rush: zero balance after the dump (exit_rush score 40). Total score 255—like a bad Tinder date that goes viral.

### 🎯 Verdict & Next Steps
**CRITICAL — composite score 255 indicates a high‑risk burner wallet draining a large amount into an anonymous off‑ramp.**

CRITICAL (rule score 255)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (4 rules, composite score: 255):
- **novel_wallet_dump** (+100) — Wallet is 0 days old, moving 20.9995 ETH — classic burner pattern
- **high_value** (+30) — High-value transfer: 20.9995 ETH ($47,674)
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 20.9995 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
Suspicious activity detected involving a 0‑day wallet (rule: novel_wallet_dump). The wallet transferred 20.9995 ETH ($47,674) to address 0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f (FixedFloat 1) with no KYC‑verified off‑ramp (rule: no_kyc_offramp). The transaction is high‑value (rule: high_value) and the wallet balance is zero after the transfer, indicating a potential exit rush (rule: exit_rush). The composite risk score of 255 warrants immediate escalation for manual review.

</details>

---

## Finding #2: CRITICAL — Score 248

| | |
|---|---|
| **Sender** | `0x5490ada72a5c4e3d59989a0d96b2bc5ffa68969d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **16.7624 ETH** ($38,055) |
| **Blocks** | 26301385-26301385 |

### 💬 What Happened
A brand‑new wallet with no previous history sent about $38,000 worth of ETH to a service called FixedFloat 1, which is like a cash‑machine that instantly turns the money into something you can’t trace. The sender’s account was empty before and after the move, so all the cash disappeared in one go.

### 🔥 The Roast
Looks like someone just built a fresh burner wallet (novel_wallet_dump – meaning the wallet was created and used immediately) and dumped a huge chunk of ETH (high_value – 16.7 ETH is big money) into a no‑KYC off‑ramp (no_kyc_offramp – the service doesn’t verify who’s sending it). Then the wallet’s balance went to zero (exit_rush – the owner drained the account in a single rush). In short, it’s the crypto equivalent of buying a gun, using it, and then blowing it up in a dumpster. If this were a bank, we’d call it a “one‑off high‑value cash‑out with no identity check.”

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 248)**

Flag the transaction for manual review, request source‑of‑funds information from the sender, and consider adding the wallet to the AML watchlist pending further investigation.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (4 rules, composite score: 248):
- **novel_wallet_dump** (+93) — Wallet is 0 days old, moving 16.7624 ETH — classic burner pattern
- **high_value** (+30) — High-value transfer: 16.7624 ETH ($38,055)
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 16.7624 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers multiple AML risk indicators: (1) novel_wallet_dump – wallet age 0 days, single transaction of 16.7624 ETH; (2) high_value – transfer exceeds $35,000 threshold; (3) no_kyc_offramp – recipient is FixedFloat 1, a service lacking KYC; (4) exit_rush – sender’s balance drops to zero after the transfer. CRITICAL (rule score 248) These patterns warrant further investigation under AML policy rules for high‑risk transactions and suspicious activity reporting.

</details>

---

## Finding #3: CRITICAL — Score 193

| | |
|---|---|
| **Sender** | `0x2f4e8603663caa75f7810a97c3547fef423dda06` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **4.3183 ETH** ($9,804) |
| **Blocks** | 26301255-26301255 |

### 💬 What Happened
CRITICAL (rule score 193) The wallet had no balance before or after the transfer, meaning all the money was drained out in one go. In plain terms, it’s a textbook burner wallet used to exit funds without any identity verification.

### 🔥 The Roast
First, this wallet is so fresh it probably still has its birth certificate in the cloud. CRITICAL (rule score 193) The mover didn’t bother with any KYC (that’s the 'no_kyc_offramp' score of 85, because who wants to fill out forms when you’re just sending money to a black box?), and it drained its balance in one swoop—classic 'exit_rush' (score 40). In short, it’s like a teenager dropping a $10,000 pizza bill into a mystery box and never looking back.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 193)**

CRITICAL (rule score 193)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000000 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (3 rules, composite score: 193):
- **novel_wallet_dump** (+68) — Wallet is 0 days old, moving 4.3183 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 4.3183 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
CRITICAL (rule score 193) According to Rule novel_wallet_dump, the new wallet’s activity is a high‑risk pattern of a burner wallet. Rule no_kyc_offramp flags the lack of KYC verification on the off‑ramp service, and Rule exit_rush indicates an immediate balance drain after the transfer. These combined signals warrant heightened scrutiny for potential illicit movement of funds.

</details>

---

## Finding #4: CRITICAL — Score 191

| | |
|---|---|
| **Sender** | `0xc160102bac3452410a152739b78e20de1cc93a2a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **3.4994 ETH** ($7,945) |
| **Blocks** | 26301270-26301270 |

### 💬 What Happened
A brand‑new wallet, created today, sent almost $8,000 worth of Ethereum to a service called FixedFloat 1. The wallet had no previous activity and now has nothing left in it—it's like a one‑night party that empties the cash box.

### 🔥 The Roast
Looks like someone just created a brand‑new wallet (0 days old) and shot almost $8k worth of ETH into FixedFloat 1—think of it as a high‑stakes casino that doesn’t ask for your ID. The engine gave it a 66 on novel_wallet_dump (new wallet doing a big dump), 85 on no_kyc_offramp (no ID required to get the money out), and 40 on exit_rush (the wallet is now empty, like a magician’s trick). Combined score of 191? That’s the red‑flag equivalent of a warning light that says, ‘Hey, this might be a burner wallet used to clean money.’

### 🎯 Verdict & Next Steps
**CRITICAL — the transaction displays multiple high‑risk indicators: a new burner wallet, a large ETH transfer to a non‑KYC off‑ramp, and instant balance depletion.**

Flag the transaction for manual AML review; verify the source of funds, assess the legitimacy of FixedFloat 1, and document findings for potential reporting.

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
- **novel_wallet_dump** (+66) — Wallet is 0 days old, moving 3.4994 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 3.4994 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers three AML rule alerts: [novel_wallet_dump] (wallet age 0 days, moving 3.4994 ETH), [no_kyc_offramp] (transfer to FixedFloat 1, a non‑KYC off‑ramp), and [exit_rush] (wallet balance drained to 0.000000 ETH immediately after transfer). CRITICAL (rule score 191) CRITICAL (rule score 191)

</details>

---

## Finding #5: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0xf5421f8333ce42493c22ab7ab22ccd687afab46a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9996 ETH** ($4,540) |
| **Blocks** | 26301378-26301378 |

### 💬 What Happened
A brand-new crypto wallet, just created yesterday, sent almost 2 ETH to a service that doesn’t ask for identity—like dropping a pizza order slip into a dumpster and walking away. The wallet had no previous activity and now its balance is zero after that single transfer. The move looks like a quick cash‑drain from a fresh burner account.

### 🔥 The Roast
This transaction scored a whopping 188 on the AML radar—think of it as a red‑flag billboard on a highway. The novel_wallet_dump rule (meaning a brand‑new wallet that dumps a big chunk of money like a student who just found a stash of candy) gave 63 points. No_KYC_offramp (the wallet sent money to FixedFloat 1, which is a service that doesn’t do identity checks) racked up 85, and exit_rush (the wallet emptied itself in one go) added another 40. Basically, it’s a one‑shot, no‑questions‑asked burner that’s trying to hide its trail faster than a magician pulls a rabbit out of a hat.

### 🎯 Verdict & Next Steps
**CRITICAL (rule score 188)**

Flag the transaction for manual review, investigate the destination address, and check for any related activity or connections to known mixers.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9996 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9996 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The sender wallet is 0 days old and has only one transaction of 1.9996 ETH, matching the novel_wallet_dump rule. The transfer to FixedFloat 1 triggers the no_kyc_offramp rule, indicating an off‑ramp without identity verification. The exit_rush rule is satisfied as the wallet balance is zero immediately after the transfer. The composite score of 188 signals a high‑risk pattern consistent with potential illicit activity requiring further investigation.

</details>

---

## Finding #6: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x6c58c319c451f9fa4b1c5aad64c77e8a6608ef8f` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9994 ETH** ($4,539) |
| **Blocks** | 26301259-26301259 |

### 💬 What Happened
A brand-new wallet (like a freshly minted burner) sent almost 2 ETH (~$4,539) to a FixedFloat 1 address in a single block, and then the wallet’s balance dropped to zero. It’s like dropping a large cash envelope into a cash machine that then disappears, leaving no trace of the sender.

### 🔥 The Roast
This is like a magician pulling 1.9994 ETH out of a hat and then vanishing the hat. The sender wallet is brand new (0 days old) – basically a fresh burner that made one move and then vanished. The AML engine gave it a 188 composite score, which is higher than the average coffee shop’s latte score. Rule 'novel_wallet_dump' flagged it because it dumped nearly 2 ETH from a brand‑new wallet, 'no_kyc_offramp' gave a high score because the funds went to a no‑KYC service, and 'exit_rush' shows the wallet was emptied – classic drain‑and‑leave.

### 🎯 Verdict & Next Steps
**CRITICAL — The transaction shows a high‑risk burner wallet pattern with no KYC off‑ramp and complete drainage of funds, warranting urgent review.**

Flag the transaction for manual investigation, trace the flow through the FixedFloat 1 address, and request additional context from the receiver’s platform or any downstream custodial service.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9994 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9994 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction exhibits a 188 composite score, exceeding the threshold for high‑risk activity. Rule novel_wallet_dump (score 63) indicates a brand‑new wallet (0 days old) transferring nearly 2 ETH in a single transaction, consistent with burner wallet behavior. Rule no_kyc_offramp (score 85) shows the funds were moved to a FixedFloat 1 address, a no‑KYC off‑ramp, which is a known risk for layering. Rule exit_rush (score 40) confirms the wallet balance is zero after the transfer, indicating a complete drainage of funds. These indicators collectively trigger a high‑risk alert requiring immediate human review.

</details>

---

## Finding #7: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0xb697b318b0a30518479a6986a56f085fe9758c33` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9995 ETH** ($4,539) |
| **Blocks** | 26301246-26301246 |

### 💬 What Happened
A brand‑new wallet (like a freshly opened cash box) sent almost 2 ETH to a service that turns crypto into cash. The sender never had any past activity and now has no money left, which is a classic “burner wallet” move.

### 🔥 The Roast
So we got a 0‑day wallet that decided to play the "I’ll take your money and disappear" game. It dumped 1.9995 ETH into a FixedFloat address, which is basically a crypto version of a one‑time ATM. The wallet is now empty like a pizza box after you finish the last slice—exit rush in full effect. CRITICAL (rule score 188) Good luck finding the culprit, folks!

### 🎯 Verdict & Next Steps
**CRITICAL – the combination of a brand‑new wallet, large single transfer to a non‑KYC off‑ramp, and immediate balance depletion signals a high‑risk suspicious activity pattern.**

Flag this transaction for manual compliance review, request additional source‑of‑funds information, and monitor the receiver address for related activity.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9995 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9995 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers the following AML rules: novel_wallet_dump (score: 63) – 0‑day wallet with a large single transfer; no_kyc_offramp (score: 85) – transfer to a FixedFloat 1 address with no KYC; exit_rush (score: 40) – wallet balance reduced to zero after the transfer. Evidence includes a single 1.9995 ETH transaction from a fresh wallet to a non‑KYC off‑ramp, resulting in a zero balance.

</details>

---

## Finding #8: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0xfba1546883ae55a5a09237452aa71e7b730d45b3` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.6195 ETH** ($3,677) |
| **Blocks** | 26301241-26301241 |

### 💬 What Happened
Someone just created a brand-new wallet, moved 1.6195 ETH (about $3,700) into a service called FixedFloat 1, and then the wallet has no balance left. It's like a person dropping a $3,700 package into a drop-box and never coming back to see who picked it up.

### 🔥 The Roast
Look at this rookie burner—just born and already trying to move big bucks. The engine flagged it with a 63 on novel_wallet_dump (meaning this wallet is brand‑new and dumping money). Then 85 on no_kyc_offramp because they're sending money to a service that doesn’t ask for ID—classic ‘I don’t care who you are’ move. And 40 on exit_rush because the wallet is empty after the move—like a magician who disappears with a coin. 188 total score? That’s basically a red flag waving at the compliance desk like a neon sign.

### 🎯 Verdict & Next Steps
**CRITICAL – the transaction displays multiple high‑risk indicators (new wallet, no KYC off‑ramp, rapid exit) that suggest an attempt to conceal the source and destination of funds.**

Flag the transaction for manual review, trace downstream flows through FixedFloat 1, and request source verification if the originating entity can be identified.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.6195 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.6195 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction triggers three high‑risk AML rules: novel_wallet_dump (score 63) indicating a new wallet immediately moving a large sum, no_kyc_offramp (score 85) showing a transfer to a non‑KYC service, and exit_rush (score 40) where the sender’s balance drops to zero after the transfer. CRITICAL (rule score 188) The composite score of 188 exceeds the critical threshold and warrants further investigation.

</details>

---

## Finding #9: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0xba1b56305ad9b50b595b8954e52eb521c602a667` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9995 ETH** ($4,539) |
| **Blocks** | 26301235-26301235 |

### 💬 What Happened
A brand‑new wallet just created on the blockchain sent almost two ETH to a service that turns crypto into cash. The sender’s balance is now zero, like someone dropping a package into a slot that hides who sent it, and then walking away. It looks like a classic burner wallet being emptied into a non‑KYC cash‑out service.

### 🔥 The Roast
So we got a fresh burner wallet (novel_wallet_dump score 63 – meaning the wallet just popped up and dumped all its money) that sent 1.9995 ETH to a FixedFloat 1 address (no_kyc_offramp score 85 – the receiver doesn’t do identity checks). After the move the sender’s balance is zero (exit_rush score 40 – the wallet is emptied in a flash). Composite score 188? That’s like a red flag on a speed‑run cheat code. This is the kind of move that would make a crypto‑security guard raise an eyebrow and a compliance officer grab a cup of coffee and start a manual review.

### 🎯 Verdict & Next Steps
**CRITICAL — The transaction matches multiple high‑risk patterns (novel wallet dump, no KYC off‑ramp, exit rush) and exceeds the threshold, warranting immediate investigation.**

Flag the transaction for manual AML review and add the receiving address to the watchlist. Monitor subsequent activity and consider reporting to relevant regulatory bodies if suspicious patterns continue.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9995 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9995 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
This transaction exhibits multiple high‑risk indicators: novel_wallet_dump (wallet age 0 days, 1 transaction, large transfer), no_kyc_offramp (funds sent to an off‑ramp service with no identity verification), and exit_rush (wallet balance dropped to 0.000000 ETH immediately after the transfer). The composite score of 188 exceeds the critical threshold, suggesting potential misuse of a burner wallet for anonymous cash‑out. CRITICAL (rule score 188)

</details>

---

## Finding #10: CRITICAL — Score 188

| | |
|---|---|
| **Sender** | `0x841da723a92821dcddc4bdc731ac5f4d92d30976` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **1.9993 ETH** ($4,539) |
| **Blocks** | 26301220-26301220 |

### 💬 What Happened
A brand‑new wallet just dropped almost 2 ETH into a service that doesn't ask for any ID, and then the wallet is empty again, like a kid who borrows a toy, uses it, and disappears with it.

### 🔥 The Roast
This wallet is a textbook novel_wallet_dump (meaning it was created today and immediately sent a big chunk of crypto). It then hit a no_kyc_offramp (the money went to a place that lets you off‑ramp without showing who you are), and the exit_rush (the wallet emptied out like a magician pulling a rabbit out of a hat) was 100% on point. Basically, it’s a new burner account that plays the ‘don’t look, I’m gone’ game in the blockchain world.

### 🎯 Verdict & Next Steps
**The combination of a brand‑new wallet, large single transfer to a non‑KYC off‑ramp, and immediate balance depletion triggers a critical risk flag.**

Perform a manual review of the sender’s source of funds and request additional verification from the recipient’s platform. Flag the wallet for monitoring in the compliance system.

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
- **novel_wallet_dump** (+63) — Wallet is 0 days old, moving 1.9993 ETH — classic burner pattern
- **no_kyc_offramp** (+85) — Deposit to FixedFloat 1 — no-KYC off-ramp
- **exit_rush** (+40) — Wallet balance near zero (0.000000 ETH) after moving 1.9993 ETH — funds fully drained (exit rush)

**SAR Narrative** *(for compliance teams)*:
The transaction involves a 0‑day old sender wallet (0x841da723a92821dcddc4bdc731ac5f4d92d30976) that moved 1.9993 ETH to a FixedFloat 1 address, a known non‑KYC off‑ramp. Rule novel_wallet_dump flagged the brand‑new wallet with a large outbound transfer (score 63). Rule no_kyc_offramp flagged the destination as an identity‑unverified off‑ramp (score 85). Rule exit_rush noted the sender’s balance dropped to zero immediately after the transfer (score 40). Composite score of 188 indicates a high‑risk pattern requiring further investigation.

</details>

---

## Finding #11: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x91588ca96d8a1b5a86b9f750a1e55de3d30bc2cc` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0038 ETH** ($9) |
| **Blocks** | 26301378-26301378 |

### 💬 What Happened
MEDIUM (rule score 85) Because the sender had no prior activity and no identity verification, it's like someone dropping a package into a box that then gets forwarded to a mysterious recipient. The transaction was the only one the wallet ever made, so it looks suspicious.

### 🔥 The Roast
Looks like someone's brand-new wallet decided to play hide-and-seek with the blockchain. The sender's wallet is as old as a newborn—0 days—so it's probably a fresh burner. MEDIUM (rule score 85) If you think that's a low score, remember 85 is the kind of score that makes regulators raise their eyebrows. This is basically the crypto equivalent of dropping a $9 bill into a piggy bank that then disappears into a black hole.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review. Verify the source of funds and confirm whether the destination address is linked to any known illicit activity. If no legitimate source is identified, consider freezing or reporting per internal policy.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000146 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
The sender wallet (0x91588ca96d8a1b5a86b9f750a1e55de3d30bc2cc) was created on the same day as the transaction and had no prior activity, indicating a new, potentially disposable address. MEDIUM (rule score 85) MEDIUM (rule score 85) MEDIUM (rule score 85) The pattern warrants a manual review to determine the legitimacy of the source and destination addresses.

</details>

---

## Finding #12: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb90af949204c14be3ec01e86c68205b34988c836` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0226 ETH** ($51) |
| **Blocks** | 26301366-26301366 |

### 💬 What Happened
A brand‑new wallet that had never sent or received any funds before sent about $51 worth of ETH to a SideShift hot wallet. This is like a person dropping a $51 bill into a vending machine that then sells it to a bank teller who never asks who the money came from.

### 🔥 The Roast
Looks like someone just hit the "no‑kyc off‑ramp" button on a brand new wallet. That rule (meaning the funds go to a service that can convert crypto to fiat without verifying identity) gave it a high score of 85. It's the blockchain equivalent of a shady street vendor who never asks for ID. The wallet is a zero‑day, one‑transaction, 0‑balance account—classic "new wallet, big move" scenario. If you’re looking for a clean transaction, you’d better keep your money in a wallet that actually knows your face.

### 🎯 Verdict & Next Steps
**MEDIUM — high risk score and new wallet activity warrant further review, but no definitive evidence of wrongdoing.**

MEDIUM (rule score 85)

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000226 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
The transaction involves a sender wallet aged 0 days with a single outbound transfer of 0.0226 ETH to the SideShift Hot Wallet, a known off‑ramp service lacking KYC verification. This activity triggers Rule no_kyc_offramp, which assesses the risk of unverified fiat conversion. The composite score of 85 indicates a high risk of potential misuse of the off‑ramp for anonymous fund movement.

</details>

---

## Finding #13: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xdb0db6f89e8d6df64afa3e095b6463a4dbf0c6cc` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0181 ETH** ($41) |
| **Blocks** | 26301345-26301345 |

### 💬 What Happened
A brand-new wallet sent about $41 worth of Ethereum to a hot wallet that lets people move money without showing ID. It's like dropping a package into a mailbox that has no lock, so nobody knows who sent it. The sender never used the wallet before and now has almost no balance left.

### 🔥 The Roast
Looks like a fresh wallet decided to play the no‑KYC off‑ramp game by sending $41 straight into the SideShift Hot Wallet. MEDIUM (rule score 85) The AML engine slapped an 85 out of 100 on this move, basically saying, "We see you, and you're risky." This is the kind of transaction that would make even the most seasoned crypto‑lawyer raise an eyebrow.

### 🎯 Verdict & Next Steps
**MEDIUM — The high composite score and use of a no‑KYC off‑ramp with a brand‑new sender wallet suggest moderate risk, but no direct evidence of wrongdoing.**

Flag the transaction for manual review and monitor subsequent activity of both sender and receiver addresses for further suspicious patterns.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000231 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
The transaction involved a single transfer of 0.0181 ETH (≈$41) from a wallet with no prior activity to a SideShift Hot Wallet, which is classified as a no‑KYC off‑ramp. Rule no_kyc_offramp was triggered with a score of 85, indicating a high likelihood that the funds are moving through an anonymous channel. The sender wallet was created on the same day as the transaction and has a negligible balance afterward. This pattern aligns with known suspicious activity involving immediate deposits to anonymous off‑ramp services.

</details>

---

## Finding #14: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4b488a2ece52e34ddd0c1bb7f546e595c20ef5cf` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** tx totaling **0.0119 ETH** ($27) |
| **Blocks** | 26301239-26301239 |

### 💬 What Happened
MEDIUM (rule score 85) Think of it like a freshly opened gift bag sending a few dollars into a black‑hole box that scrambles who sent it. Because the sender has no history and no way to identify who owns the money, this is a red flag for potential illicit activity.

### 🔥 The Roast
Looks like someone just dropped a 0.0119 ETH coin in the SideShift hot wallet, which is basically the cryptocurrency version of a dumpster fire. This wallet has zero age and zero prior transactions—it's the blockchain equivalent of a brand‑new anonymous account with a suspicious appetite for mixers. The AML engine gave it an 85, which is basically the same as a warning sign flashing 'KYC? Not here!' So if you thought you could hide your money in plain sight, this is the worst way to do it.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review by compliance. Consider requesting additional transaction history or KYC information from the sender if possible, and monitor the receiver's wallet for further suspicious activity.

<details>
<summary>📊 Wallet Profile & Engine Details (click to expand)</summary>

**Sender Wallet:**
| Metric | Value |
|--------|-------|
| Wallet Age | 0 days |
| Total Transactions | 1 |
| Current Balance | 0.000193 ETH |
| Days Since Last Activity | 0 |

**Rules Triggered** (1 rules, composite score: 85):
- **no_kyc_offramp** (+85) — Deposit to SideShift Hot Wallet — no-KYC off-ramp

**SAR Narrative** *(for compliance teams)*:
MEDIUM (rule score 85) MEDIUM (rule score 85) MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #15: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1901018fc737819ad1d8d04f14d9341b718f467a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0053 ETH** ($12) |
| **Blocks** | 26301409-26301409 |

### 💬 What Happened
A brand‑new wallet (just created today) sent about $12 worth of ETH to a special kind of withdrawal address that doesn’t ask for ID. Think of it like dropping a small tip into a no‑ID cash‑out machine. There was only one transaction and no other activity on either side.

### 🔥 The Roast
Looks like a fresh‑out‑of‑the‑oven wallet decided to play the no‑ID game and slipped $12 into a FixedFloat 1— that’s the crypto equivalent of a secret admirer using a cash‑only ATM that doesn’t ask for a driver's license. The engine gave it a solid 85 on the no‑KYC off‑ramp rule, which is basically the red flag that says "this is a shady exit point." If the wallet had been older or the amount bigger, it’d be a full‑blown mystery; but at $12 it’s more like a curious tourist leaving a tip in a tourist trap. Still, the system’s score says we should keep an eye on it, because even a $12 tip can be a breadcrumb in a larger scam.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction is a new wallet sending to a fixed float off‑ramp without KYC, scoring high on the no‑KYC off‑ramp rule, but the amount is small and no other red flags.**

Flag the transaction for manual review, verify the source of funds, and monitor subsequent activity from both the sender and receiver addresses for any suspicious patterns.

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
The transaction involves a newly created wallet (age 0 days, 1 tx) sending 0.0053 ETH ($12) to a FixedFloat 1 address, which is classified as a no‑KYC off‑ramp. The AML engine flagged the activity under rule [no_kyc_offramp] with a score of 85, contributing to a composite risk score of 85. MEDIUM (rule score 85) This pattern of new wallet activity to an unverified off‑ramp warrants further investigation.

</details>

---

## Finding #16: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa6fc5615998c43ca9d404b3d0bff684c4d8275f1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0152 ETH** ($34) |
| **Blocks** | 26301393-26301393 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
Even our AI refused to look at this transaction.

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
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #17: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb7eaeae1c9ba92f4c4acdf20667b522d7fd60e29` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0183 ETH** ($41) |
| **Blocks** | 26301389-26301389 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
Even our AI refused to look at this transaction.

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
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #18: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x5173afd8647c685d8f894f61d0dba336b68673c5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0256 ETH** ($58) |
| **Blocks** | 26301384-26301384 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
Even our AI refused to look at this transaction.

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
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #19: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x2f2378793fa51dfb60531a460a8a4f7b87abefb5` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0997 ETH** ($226) |
| **Blocks** | 26301384-26301384 |

### 💬 What Happened
A brand‑new wallet (it was created on the same day it sent money) just dropped 0.0997 ETH (about $226) into a service called FixedFloat 1. Think of it like a new kid at a school handing over a small amount of cash to a mysterious vending machine that promises to give you back the same amount later, but you have no idea who’s behind the machine.

### 🔥 The Roast
Looks like someone just tried to play hide‑and‑seek with their money: 85 points on the no_kyc_offramp rule (meaning the transfer goes to a platform that doesn’t ask for identity before you can cash out). MEDIUM (rule score 85) The sender’s wallet age is 0 days, so it’s probably a freshly minted, single‑use burner. In short, it’s a textbook case of “new wallet, big money, no KYC” and you’d better keep an eye on it before it vanishes into thin air.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag this transaction for manual review and request additional context from the sender. MEDIUM (rule score 85)

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
The transaction involves a new wallet (0 days old) with a single outgoing transfer of 0.0997 ETH to a FixedFloat 1 address. This activity matches the AML rule no_kyc_offramp, which flags transfers to off‑ramps that do not require identity verification prior to withdrawal. MEDIUM (rule score 85) The transaction value of $226 USD further raises the risk profile under the no_kyc_offramp rule.

</details>

---

## Finding #20: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xf22948bdd6fc1b76797c277e372f21cea3bd548e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0206 ETH** ($47) |
| **Blocks** | 26301383-26301383 |

### 💬 What Happened
A wallet was caught interacting with FixedFloat 1. Our engine flagged it at score 85.

### 🔥 The Roast
Even our AI refused to look at this transaction.

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
Automated commentary unavailable for this finding; the verdict is based on the rule score alone.

</details>

---

## Finding #21: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb9fef9a43fa71ac1de70fe21a9cb456ebb0916b6` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.4370 ETH** ($992) |
| **Blocks** | 26301381-26301381 |

### 💬 What Happened
A brand-new Ethereum wallet, fresh as a newborn, sent almost $1,000 worth of ETH to a DeFi contract that doesn't ask for identity verification. Think of it like dropping a cash-filled envelope into a black box that keeps the sender’s name secret. The sender’s wallet had no previous activity and ended up empty after the transfer, like a magician who disappears the money.

### 🔥 The Roast
Looks like someone just bought a ‘no‑identity’ DeFi contract and sent it their whole wallet balance. The wallet was brand‑new, like a baby, and it decided to vanish its money in one swoop—talk about a dramatic exit! With a composite score of 85, this is the kind of transaction that would make a compliance officer raise an eyebrow. And hey, if you thought your grandma’s savings were safe, think again—she could have just sent her money to a contract that doesn’t even ask for a driver’s license.

### 🎯 Verdict & Next Steps
**MEDIUM — the transaction involves a brand‑new wallet sending a sizable amount to a non‑verified DeFi contract, raising potential anonymity concerns.**

Flag the transaction for manual review and request source‑of‑funds confirmation. Monitor the destination address for subsequent activity and apply additional due‑diligence if further high‑value transfers occur.

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
The transaction involves a wallet with an age of 0 days, a single prior transaction, and a balance of 0 ETH after the transfer, indicating it is newly created and immediately used. The wallet sent 0.4370 ETH (≈$992) to the FixedFloat 1 contract, a non‑KYC off‑ramp (meaning the contract does not require identity verification). Rule no_kyc_offramp was triggered with a score of 85, contributing to the overall composite score of 85. MEDIUM (rule score 85)

</details>

---

## Finding #22: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x6405319cd4f2211d2f4b0700f95193a7903be425` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0238 ETH** ($54) |
| **Blocks** | 26301380-26301380 |

### 💬 What Happened
A brand‑new wallet just sent 0.0238 ETH (about $54) to a FixedFloat service. The sender’s account is brand‑new (0 days old) and has only done two transactions, so it’s like a new delivery driver dropping a small package into a slot that hides who sent it. The transfer is only a single, small ETH move and there are no other tokens involved.

### 🔥 The Roast
MEDIUM (rule score 85) The engine flags it as a "no_kyc_offramp" hit, which means the recipient service doesn’t do any identity checks (think of it as a cashier that never asks for ID). With a composite score of 85, it’s basically a red flag that says, "Hey, this guy just made a tiny crypto move from a brand‑new wallet with no paperwork, and we’re not sure where the money came from." If you’re looking for a joke, it’s the crypto equivalent of a stranger asking for a loan in cash with no credit check.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review, request source‑of‑funds documentation, and monitor the wallet for additional suspicious activity.

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
The transaction originates from a wallet created on the same day as the transfer, with only two prior transactions and a zero current balance. The recipient is a FixedFloat 1 service that offers an off‑ramp without requiring Know‑Your‑Customer (KYC) verification, triggering the AML rule no_kyc_offramp (score: 85). MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #23: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xd40196f35ce7444f89bd5b33e9659d3c28fb353b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0111 ETH** ($25) |
| **Blocks** | 26301379-26301379 |

### 💬 What Happened
A brand-new wallet just sent a tiny amount of ETH (about $25) to a well-known mixing service. Think of it like dropping a single dollar bill into a slot machine that immediately scrambles who put it in, so no one can tell who the original sender was.

### 🔥 The Roast
Looks like a brand-new wallet decided to play hide-and-seek with 0.0111 ETH. That amount is about the price of a latte, so maybe the sender just wanted to test the waters. MEDIUM (rule score 85) With a composite score of 85, the AML engine is basically shouting, "No KYC off‑ramp!" (meaning the funds are being moved to an address that doesn't require identity verification). If you’re a compliance officer, this is your cue to put on your detective hat.

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review, verify the source of funds, and consider requesting additional KYC information from the sender if possible.

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
MEDIUM (rule score 85) MEDIUM (rule score 85) MEDIUM (rule score 85) MEDIUM (rule score 85)

</details>

---

## Finding #24: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x134ac90c769754a054872dd4f11a07eba7ddab40` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0226 ETH** ($51) |
| **Blocks** | 26301377-26301377 |

### 💬 What Happened
A brand‑new Ethereum wallet just sent a small amount of ETH (about $51) to a service that can turn crypto into cash. The sender’s account was created just now, had never moved money before, and now it’s empty again. MEDIUM (rule score 85)

### 🔥 The Roast
Looks like someone just opened a fresh wallet, slotted a few ETH into a FixedFloat 1 address, and vanished into the ether. The AML engine gave it an 85 score, basically flashing the 'no KYC off‑ramp' red flag. It’s like a kid with a brand‑new backpack sneaking into a casino and buying chips with a fake ID – only the ID is missing, not the fun. The only thing missing is a receipt, but the engine already knows you’re trying to hide where the cash came from.

### 🎯 Verdict & Next Steps
**MEDIUM – the lack of KYC on an off‑ramp service combined with a brand‑new wallet suggests a moderate risk of illicit activity.**

Flag the transaction for manual review, request source‑of‑funds information, and monitor the receiver address for future suspicious activity.

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
The transaction involves a new wallet (age 0 days) that sent 0.0226 ETH to a FixedFloat 1 address. Rule NO_KYC_OFF_RAMP (Rule 4.1) was triggered due to the lack of KYC verification for the off‑ramp service. The wallet had a single transaction, no prior activity, and the balance is now zero, raising concerns about the source of funds. MEDIUM (rule score 85)

</details>

---

## Finding #25: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xb42604460ddeb78e1058d8e34833d99b126c6d25` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0274 ETH** ($62) |
| **Blocks** | 26301374-26301374 |

### 💬 What Happened
A brand‑new wallet, which had just been created, sent 0.0274 ETH (about $62) to a service called FixedFloat 1. The transaction was a one‑off, with no other activity, and the sender’s balance went to zero right after. Think of it like dropping a small package into a vending machine that will deliver it somewhere else, but you never know who the package came from or where it will end up.

### 🔥 The Roast
So this fresh‑from‑the‑factory wallet decided it wanted to play hide‑and‑seek with 62 bucks worth of crypto. It sent it straight to FixedFloat 1, a place that’s basically the ‘no‑KYC off‑ramp’ of the crypto world. The engine gave it a whopping 85 on the no_kyc_offramp rule (meaning no identity check, just straight to the unknown), which is like putting a $62 gift card in a slot that only gives out anonymous cash. The wallet is so new it probably hasn't even had a chance to get a coffee yet, and yet it’s already moving money faster than a toddler in a candy store. Bottom line: this is a classic case of “I’m new, I don’t care about IDs, I’ll just send it somewhere and vanish.”

### 🎯 Verdict & Next Steps
**MEDIUM (rule score 85)**

Flag the transaction for manual review, request source‑of‑funds documentation from the sender if possible, and monitor any subsequent activity involving the same wallet or FixedFloat 1 for suspicious patterns.

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
The transaction originates from a wallet with zero days of age and a single outgoing transaction totaling 0.0274 ETH ($62) to FixedFloat 1, a known off‑ramp service. The AML engine flagged the activity under rule no_kyc_offramp (score 85) due to the lack of any KYC verification at the destination, indicating a potential attempt to obscure the source of funds. The wallet’s balance post‑transaction is zero, and no prior transaction history is available, raising concerns about the legitimacy of the source and the possibility of layering. Further investigation is warranted to determine the origin of the funds and ensure compliance with regulatory obligations.

</details>

---

## Finding #26: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x3912814dae1aed51ae36652428247b9432d4a2ba` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0275 ETH** ($62) |
| **Blocks** | 26301358-26301358 |

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

## Finding #27: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x536714ace035f35b52adc10c1b86306206267e60` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0337 ETH** ($77) |
| **Blocks** | 26301350-26301350 |

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

## Finding #28: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x1fef0c908e2ba91572b219a00133316fd8353cc4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0365 ETH** ($83) |
| **Blocks** | 26301347-26301347 |

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
| **Sender** | `0x16683af337fa002772c2fc37f7252e47c653425b` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.2230 ETH** ($506) |
| **Blocks** | 26301345-26301345 |

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

## Finding #30: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x07e16c30c4f805a7de66381c4ff077711e54a133` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.4192 ETH** ($952) |
| **Blocks** | 26301343-26301343 |

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

## Finding #31: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x63c0cfd208b6e899d42597292239213c45e185a1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0079 ETH** ($18) |
| **Blocks** | 26301325-26301325 |

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
| **Sender** | `0xe4691b764ee9220c6411572e9769610100b9b4bb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0526 ETH** ($119) |
| **Blocks** | 26301323-26301323 |

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
| **Sender** | `0x8979e97a1a02e1041b9ef37fbd248a16c47f0022` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0292 ETH** ($66) |
| **Blocks** | 26301299-26301299 |

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
| **Sender** | `0x17f0cfa8462ec0b4dd06b3419af3f432efaf40e4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0260 ETH** ($59) |
| **Blocks** | 26301296-26301296 |

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
| **Sender** | `0x27e68ef02dbba0291efdd2ddfaa57b83d8d45fc8` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0253 ETH** ($57) |
| **Blocks** | 26301293-26301293 |

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
| **Sender** | `0x614b7181807056d933b89933b81a05457b3bc576` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.9991 ETH** ($2,268) |
| **Blocks** | 26301290-26301290 |

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

## Finding #37: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xbad2864fb37cf514ceadb273e2b128706a334dc2` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.9991 ETH** ($2,268) |
| **Blocks** | 26301287-26301287 |

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

## Finding #38: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x888b98578570703e80fcc7fc45fe79340c240ee6` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0907 ETH** ($206) |
| **Blocks** | 26301279-26301279 |

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

## Finding #39: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x831c12fa551b01b946fe65bcf84564c542148770` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0262 ETH** ($59) |
| **Blocks** | 26301279-26301279 |

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
| **Sender** | `0x909c9a718b5d5e12685bac922d3874fd12a6206a` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0268 ETH** ($61) |
| **Blocks** | 26301278-26301278 |

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

## Finding #41: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xa0bd9e959f81fcb34ff12464f381fa96a4d5966d` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1212 ETH** ($275) |
| **Blocks** | 26301273-26301273 |

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

## Finding #42: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x568ee684e71d9bb7bfbdfb46fa0f5f6e01447a75` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0195 ETH** ($44) |
| **Blocks** | 26301265-26301265 |

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
| **Sender** | `0x0a0d91454cded4ce608a41694b8b3b0b35072f35` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.1152 ETH** ($262) |
| **Blocks** | 26301258-26301258 |

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

## Finding #44: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x09dc48fa754007a5c9d638588789a162ba041bc1` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0227 ETH** ($51) |
| **Blocks** | 26301252-26301252 |

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
| **Sender** | `0x29290bb5e04129e3ddb84a48217e9a19b862c4e4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0862 ETH** ($196) |
| **Blocks** | 26301248-26301248 |

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

## Finding #46: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0x4e34c4b71c76a99a49660e16c2fc0c81e6a95c18` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0055 ETH** ($13) |
| **Blocks** | 26301246-26301246 |

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

## Finding #47: MEDIUM — Score 85

| | |
|---|---|
| **Sender** | `0xfc2799b857a9ca0c263c31c5b89a152442079b02` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0246 ETH** ($56) |
| **Blocks** | 26301244-26301244 |

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
| **Sender** | `0x955c2a2f269b834b7a8ec48a9326d704443ff307` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0259 ETH** ($59) |
| **Blocks** | 26301243-26301243 |

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
| **Sender** | `0x186dd849fbe9303f63465a6da50beaf5f374b1e4` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0259 ETH** ($59) |
| **Blocks** | 26301241-26301241 |

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
| **Sender** | `0xf2bf128c043f48138f27db7ebd70ca7be8de1ecf` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0376 ETH** ($85) |
| **Blocks** | 26301226-26301226 |

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
| **Sender** | `0xd60f4ac7bfee770c98f7c61b27434599ce07162e` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0963 ETH** ($219) |
| **Blocks** | 26301223-26301223 |

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
| **Sender** | `0xd6afcf1990ee2d0191e960a3000ea27a111acd47` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0421 ETH** ($96) |
| **Blocks** | 26301219-26301219 |

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
| **Sender** | `0x80a3052d3072d5b90c565fa9b0c38a7de16db9fb` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** tx totaling **0.0388 ETH** ($88) |
| **Blocks** | 26301215-26301215 |

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

## Finding #54: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xa3d9c29cf1204efd0b0cdaa430cec745e4969eb2` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$6,000** (6,000 DAI) |
| **Blocks** | 26301377-26301377 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $6,000 total (DAI) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #55: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xfdc8880e042045fcde870ad8effe814a54d838a9` |
| **Target** | SideShift Hot Wallet (`0xcdd37ada79f589c15b...`) |
| **Activity** | **1** token transfer totaling **$60** (60 USDT) |
| **Blocks** | 26301220-26301220 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to SideShift Hot Wallet: $60 total (USDT) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Finding #56: MEDIUM — Score 80

| | |
|---|---|
| **Sender** | `0xe429ab4ccdef112b09cff0aeaa7a3c6db04cbbb9` |
| **Target** | FixedFloat 1 (`0x4e5b2e1dc63f6b91cb...`) |
| **Activity** | **1** token transfer totaling **$161** (161 USDC) |
| **Blocks** | 26301411-26301411 |

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
- **stablecoin_mixing** (+80) — 1 stablecoin transfer(s) to FixedFloat 1: $161 total (USDC) from 1 unique sender(s)

**SAR Narrative** *(for compliance teams)*:
Automated commentary not generated for this finding (per-run analysis cap); the verdict is based on the rule score alone.

</details>

---

## Scan Summary

**56 suspicious findings** detected across 56 unique wallets. Highest risk score: **255**.

| | |
|---|---|
| 🔴 CRITICAL | 10 |
| 🟠 HIGH | 0 |
| Wallets flagged | 56 |
| Suspicious value | 61.6437 ETH ($139,947) + $6,221 in stablecoins |
| Blocks scanned | 26301212 — 26301411 |

---
*AML Roaster v2 — NEXUS Engine · 13 detection rules · automated scan*

Automated commentary unavailable for 4 of 25 attempted analyses this run.

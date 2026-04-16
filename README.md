# 🔥 AML Roaster

Automated Ethereum transaction monitor that catches suspicious on-chain activity and roasts it — because compliance should be entertaining.

## What It Does

Every 30 minutes, this agent:
1. Pulls live Ethereum blockchain data from Etherscan
2. Monitors known mixer addresses (Tornado Cash, eXch, Lazarus Group wallets)
3. Flags suspicious patterns: structuring, rapid-fire deposits, high-value transfers
4. Generates a roast (sarcastic commentary) + professional SAR narrative using Groq AI
5. Commits the report to this repo

## Red Flags Detected

- **Structuring** — Multiple identical deposits to mixers (deposit splitting)
- **Rapid-fire** — Clustered transactions within short time windows (automated/scripted)
- **Mixer interaction** — Direct deposits to OFAC-sanctioned Tornado Cash contracts
- **High value** — Transfers above 10 ETH to/from watched addresses
- **State-sponsored** — Interaction with known Lazarus Group (DPRK) wallets

## Reports

Auto-generated reports land in [`reports/`](./reports/). Each report includes:
- Transaction details and red flags
- 🔥 **Roast** — brutally funny crypto Twitter-style commentary
- 📋 **SAR Narrative** — professional suspicious activity report language
- ⚡ **Risk Verdict** — HIGH / MEDIUM / LOW with justification
- 🎯 **Recommended Action** — what an investigator should do next

## Setup

### GitHub Actions (Automated)
Already configured — runs every 30 minutes via `.github/workflows/roaster.yml`.

**Required Secrets:**
- `GROQ_API_KEY` — Free API key from [groq.com](https://groq.com)
- `ETHERSCAN_API_KEY` — Optional, improves rate limits ([etherscan.io](https://etherscan.io/apis))

### Local
```bash
pip install -r requirements.txt
export GROQ_API_KEY="your_key_here"
python roaster.py
```

## Stack
- **Data:** Etherscan API (free tier)
- **AI:** Groq (Llama 3.3 70B, free tier)
- **Infra:** GitHub Actions (free for public repos)
- **Language:** Python 3.11

## Coming Soon
- Twitter/X auto-posting
- Email notifications
- Multi-chain support (Polygon, Arbitrum, Base)

## Author
Built by [HASH](https://bionicbanker.tech) — Computer Engineer, Blockchain Builder, Financial Advisor.

---
*This is an educational and research tool. Not financial or legal advice.*

#!/usr/bin/env python3
"""
AML Roaster — Telegram Bot Listener
Accepts commands: /scan, /report, /status, /help
Runs as a long-polling Telegram bot.
"""

import os
import sys
import json
import time
import requests
from datetime import datetime, timezone
from pathlib import Path

# Load .env manually
ENV_PATH = Path(__file__).parent / ".env"
if ENV_PATH.exists():
    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip())

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
REPORTS_DIR = Path(__file__).parent / "reports"
BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"


def send_message(chat_id, text, parse_mode="Markdown"):
    """Send a text message to Telegram."""
    try:
        # Telegram has a 4096 char limit per message
        while text:
            chunk = text[:4000]
            text = text[4000:]
            requests.post(f"{BASE_URL}/sendMessage", json={
                "chat_id": chat_id,
                "text": chunk,
                "parse_mode": parse_mode,
            }, timeout=10)
    except Exception as e:
        print(f"[ERROR] Failed to send message: {e}")


def send_document(chat_id, filepath, caption=""):
    """Send a file as a Telegram document."""
    try:
        with open(filepath, "rb") as f:
            requests.post(f"{BASE_URL}/sendDocument", data={
                "chat_id": chat_id,
                "caption": caption,
            }, files={"document": f}, timeout=30)
    except Exception as e:
        print(f"[ERROR] Failed to send document: {e}")


def handle_scan(chat_id):
    """Run a full roaster scan and send results."""
    send_message(chat_id, "Running AML scan... this takes ~30 seconds.")

    try:
        import roaster
        # Run the scan
        eth_price = roaster.get_eth_price() or 2000.0
        latest_block = roaster.get_latest_block()
        num_blocks = 200
        findings = roaster.scan_recent_blocks(num_blocks=num_blocks)

        scan_meta = {
            "block_range": f"{latest_block - num_blocks + 1} — {latest_block}",
        }

        report = roaster.generate_report(findings, eth_price, scan_meta)

        # Save report
        now = datetime.now(timezone.utc)
        filename = f"report_{now.strftime('%Y-%m-%d_%H%M')}.md"
        filepath = REPORTS_DIR / filename
        filepath.write_text(report, encoding="utf-8")
        (REPORTS_DIR / "latest.md").write_text(report, encoding="utf-8")
        roaster.save_scan_data(findings, eth_price, scan_meta)

        if findings:
            msg = f"*SCAN COMPLETE — {len(findings)} finding(s)*\n\n"
            msg += f"ETH: ${eth_price:,.2f} | Blocks: {scan_meta['block_range']}\n\n"
            for f in findings[:5]:
                msg += f"[{f['risk_level']}] Score {f['risk_score']} — {f['sender'][:10]}... -> {f['receiver_label']}\n"
            if len(findings) > 5:
                msg += f"\n...and {len(findings) - 5} more"
            send_message(chat_id, msg)
        else:
            send_message(chat_id, f"*SCAN COMPLETE* — No suspicious activity.\n\nETH: ${eth_price:,.2f} | Blocks: {scan_meta['block_range']}")

        # Send full report as document
        send_document(chat_id, filepath, caption=f"Full report — {now.strftime('%Y-%m-%d %H:%M')} UTC")

    except Exception as e:
        send_message(chat_id, f"Scan failed: `{e}`")


def handle_report(chat_id):
    """Send the latest report."""
    latest = REPORTS_DIR / "latest.md"
    if latest.exists():
        send_document(chat_id, latest, caption="Latest AML Roaster Report")
    else:
        send_message(chat_id, "No reports found yet. Run /scan first.")


def handle_status(chat_id):
    """Send bot status and stats."""
    data_file = REPORTS_DIR / "data.json"
    if not data_file.exists():
        send_message(chat_id, "No scan data yet. Run /scan first.")
        return

    try:
        data = json.loads(data_file.read_text())
        stats = data.get("stats", {})
        scans = data.get("scans", [])
        last = scans[-1] if scans else None

        msg = "*AML ROASTER STATUS*\n\n"
        msg += f"Total Scans: *{stats.get('total_scans', 0)}*\n"
        msg += f"Total Findings: *{stats.get('total_findings', 0)}*\n"
        msg += f"Unique Senders: *{stats.get('unique_senders', 0)}*\n"
        msg += f"Highest Score: *{stats.get('highest_score', 0)}*\n"
        msg += f"Critical Alerts: *{stats.get('critical_count', 0)}*\n"
        if last:
            msg += f"\nLast Scan: {last.get('timestamp', '—')}\n"
            msg += f"ETH Price: ${last.get('eth_price', 0):,.2f}\n"
            msg += f"Blocks: {last.get('block_range', '—')}\n"
            msg += f"Findings: {last.get('total_findings', 0)}"
        msg += "\n\nDetection Rules: 13 active\nEngine: NEXUS AML v2"
        send_message(chat_id, msg)
    except Exception as e:
        send_message(chat_id, f"Error reading status: `{e}`")


def handle_help(chat_id):
    """Send help message."""
    msg = "*AML Roaster Bot Commands*\n\n"
    msg += "/scan — Run a full AML scan now\n"
    msg += "/report — Get the latest report\n"
    msg += "/status — Show bot stats and status\n"
    msg += "/help — Show this message"
    send_message(chat_id, msg)


def poll():
    """Long-poll for Telegram updates and handle commands."""
    if not BOT_TOKEN:
        print("[ERROR] TELEGRAM_BOT_TOKEN not set")
        sys.exit(1)

    print("=" * 50)
    print("AML Roaster Bot — Listening for commands")
    print(f"Bot token: {BOT_TOKEN[:10]}...")
    print(f"Authorized chat: {CHAT_ID or 'any'}")
    print("=" * 50)

    offset = 0
    handlers = {
        "/scan": handle_scan,
        "/report": handle_report,
        "/status": handle_status,
        "/help": handle_help,
        "/start": handle_help,
    }

    while True:
        try:
            r = requests.get(f"{BASE_URL}/getUpdates", params={
                "offset": offset,
                "timeout": 30,
            }, timeout=35)

            updates = r.json().get("result", [])

            for update in updates:
                offset = update["update_id"] + 1
                msg = update.get("message", {})
                chat_id = msg.get("chat", {}).get("id")
                text = (msg.get("text") or "").strip()

                if not chat_id or not text:
                    continue

                # Optional: restrict to authorized chat
                if CHAT_ID and str(chat_id) != str(CHAT_ID):
                    send_message(chat_id, "Unauthorized. This bot is private.")
                    continue

                cmd = text.split()[0].lower().split("@")[0]
                print(f"[CMD] {cmd} from {chat_id}")

                handler = handlers.get(cmd)
                if handler:
                    handler(chat_id)
                else:
                    send_message(chat_id, f"Unknown command: `{cmd}`\nType /help for available commands.")

        except requests.exceptions.Timeout:
            continue
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(5)


if __name__ == "__main__":
    poll()

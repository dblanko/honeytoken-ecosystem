#!/usr/bin/env python3
"""
fake_postgres_listener.py

A bare-bones TCP server that listens on port 5432 (the standard
Postgres port). It doesn't speak the Postgres wire protocol at all --
it just notices that something connected (and grabs the first few
bytes, which for a real psql client is usually the StartupMessage
with a username/database in it, handy context for the alert), fires
a Telegram alert, and drops the connection.

Why: the connection_string honeytoken from honeytoken_cli.py points
its hostname at this box. Anyone who stole that string and tries to
connect gets caught the moment the TCP handshake happens -- before
the connection even has a chance to fail on auth.

Deploy: any cheap box works -- a $5 VPS, Oracle free tier, whatever.
Needs port 5432 reachable and Python 3.8+.

Run:
    export TELEGRAM_BOT_TOKEN=xxxx
    export TELEGRAM_CHAT_ID=xxxx
    python3 fake_postgres_listener.py
"""

import asyncio
import os
from datetime import datetime, timezone

import urllib.request
import urllib.parse
import json

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "5432"))


def send_telegram_alert(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set, alert not sent")
        print(text)
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "Markdown",
    }).encode()
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[!] Failed to send Telegram alert: {e}")


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"
    port = peer[1] if peer else "unknown"
    now = datetime.now(timezone.utc).isoformat()

    raw_preview = b""
    try:
        # A real client usually sends the StartupMessage right away
        raw_preview = await asyncio.wait_for(reader.read(512), timeout=2.0)
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass

    printable = raw_preview.decode("utf-8", errors="replace")
    text = (
        f"🚨 *HONEYTOKEN: DB CONNECTION STRING USED*\n\n"
        f"*Attacker IP:* `{ip}`\n"
        f"*Source port:* {port}\n"
        f"*Time (UTC):* {now}\n"
        f"*First bytes of the packet:*\n```{printable[:300]}```"
    )
    print(text)
    send_telegram_alert(text)

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def main():
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("=" * 60)
        print("[!] WARNING: TELEGRAM_BOT_TOKEN and/or TELEGRAM_CHAT_ID")
        print("    are not set. The listener will still run and log")
        print("    connections to stdout, but it will NOT send any")
        print("    Telegram alerts until both are set.")
        print()
        print("    If you're running this via Docker Compose, check")
        print("    that .env exists (copy it from .env.example) and")
        print("    that both values are actually filled in, not blank.")
        print("=" * 60)

    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    print(f"[+] Fake Postgres canary listener running on port {LISTEN_PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())

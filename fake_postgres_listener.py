#!/usr/bin/env python3
"""
fake_postgres_listener.py

A TCP server on port 5432 (the standard Postgres port) that tells apart
three kinds of connections:

  1. A real Postgres client -- it sent a StartupMessage (protocol 3.x)
     with a user/database in it. This is what actually using the leaked
     connection string looks like. If the login matches the decoy
     (the names honeytoken_cli.py generates, or DECOY_USERS /
     DECOY_DATABASES) it is a full alert, with the parsed user and
     database. Any other login (postgres, test, ...) is a
     credential-spraying bot: console-only, see ALERT_ON_UNMATCHED.

  2. A bare SSL probe -- an SSLRequest (and maybe a TLS handshake) with
     no StartupMessage after it. This is what mass scanners send, so it
     is console-only by default (ALERT_ON_SSL_PROBE=1 to alert). We do
     accept TLS (self-signed cert from the Dockerfile) because the
     generated DSN uses sslmode=require: a real client using it only
     sends its StartupMessage after the TLS handshake succeeds.

  3. Everything else -- HTTP GETs, raw TLS ClientHellos, SSH banners,
     empty connects, scanner junk. Any public IP on port 5432 gets this
     within hours. Logged to stdout only, NEVER sent to Telegram.

Alerts are also deduplicated per source IP (same 5-minute window and
digest-every-50 logic as cloudflare_worker.js), kept in memory since
there's no KV store here.

Why: the connection_string honeytoken from honeytoken_cli.py points
its hostname at this box. Anyone who stole that string and tries to
connect gets caught -- but only a real Postgres client using the decoy
login counts as "used the string"; a bare TCP connect proves nothing.

Deploy: any cheap box works -- a $5 VPS, Oracle free tier, whatever.
Needs port 5432 reachable and Python 3.11+ (StreamWriter.start_tls).
The Docker image already has it.

Run:
    export TELEGRAM_BOT_TOKEN=xxxx
    export TELEGRAM_CHAT_ID=xxxx
    # Optional: only if the decoy was NOT made by honeytoken_cli.py
    # export DECOY_USERS=svc_xxxxxx
    # export DECOY_DATABASES=prod_xxxxx
    python3 fake_postgres_listener.py
"""

import sys

if sys.version_info < (3, 11):
    sys.exit("fake_postgres_listener.py needs Python 3.11+ "
             "(StreamWriter.start_tls). The Docker image already has it.")

import asyncio
import html
import json
import os
import re
import ssl
import struct
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "5432"))

# Same values as cloudflare_worker.js
DEDUP_WINDOW_SECONDS = 300  # 5 minutes
DIGEST_EVERY = 50           # every 50th repeat sends a short digest

# Postgres wire-protocol magic numbers (second int32 of the first message)
STARTUP_PROTOCOL_MAJOR = 3     # any 3.x: 3.0 = 196608 (3 << 16), 3.2 = (3 << 16) | 2
SSL_REQUEST_CODE = 80877103
CANCEL_REQUEST_CODE = 80877102
GSS_ENC_REQUEST_CODE = 80877104

MAX_STARTUP_BODY = 8192  # sanity cap on what we'll read for a StartupMessage
MAX_NEGOTIATION_STEPS = 4  # GSSENCRequest -> SSLRequest -> StartupMessage, with a spare
MAX_FIELD_LEN = 64         # attacker-controlled strings are cut to this in alerts/logs

# --- Limits, so a flood of connections can't take the box (or Telegram) down ---
MAX_CONNECTIONS = int(os.environ.get("MAX_CONNECTIONS", "200"))        # simultaneous, total
MAX_CONN_PER_IP = int(os.environ.get("MAX_CONN_PER_IP", "20"))         # simultaneous, per source IP
CONNECTION_DEADLINE = float(os.environ.get("CONNECTION_DEADLINE", "15"))  # seconds to classify a connection
MAX_ALERTS_PER_MINUTE = int(os.environ.get("MAX_ALERTS_PER_MINUTE", "20"))  # Telegram allows ~20/min per group chat
MAX_DEDUP_ENTRIES = 10000                                              # cap on remembered IPs
# Healthcheck: the event loop touches this file; the Docker HEALTHCHECK
# fails if it goes stale (no network probe, so no noise in the logs).
HEARTBEAT_FILE = os.environ.get("HEARTBEAT_FILE", "/tmp/heartbeat")
HEARTBEAT_INTERVAL = 10
# Watchdog: a plain `docker compose` never restarts an *unhealthy* container,
# only one that exits. So a separate thread (it keeps running even if the
# event loop is stuck) ends the process when the loop hasn't beaten for this
# long, and `restart: unless-stopped` brings the container back.
WATCHDOG_TIMEOUT = float(os.environ.get("WATCHDOG_TIMEOUT", "60"))
_last_beat = time.monotonic()

# Telegram delivery: a lost alert is the one failure a canary cannot afford.
TELEGRAM_ATTEMPTS = 3
# One "listener started" message per start, so a silent misconfiguration
# (bad token, wrong chat id) shows up immediately and restarts are visible.
STARTUP_NOTICE = os.environ.get("STARTUP_NOTICE", "1") != "0"

# Geo/ISP enrichment via ip-api.com (free, no key, ~45 req/min, HTTP only).
# Only called for IPs that are about to produce an alert, never for noise.
# Set GEO_LOOKUP=0 to disable (the attacker IP is sent to a third party).
GEO_LOOKUP = os.environ.get("GEO_LOOKUP", "1") != "0"

# TLS: the generated DSN uses sslmode=require, so a real client refuses to
# continue unless we answer its SSLRequest with 'S' and complete a TLS
# handshake. Self-signed is fine: require does not verify the certificate.
# The Dockerfile generates the cert; without one we fall back to 'N' (and
# then a sslmode=require client can never reach its StartupMessage).
TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE", "/app/tls/cert.pem")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE", "/app/tls/key.pem")
_tls_ctx = None

# A bare SSLRequest with no StartupMessage after it is what mass scanners
# send, so by default it is console-only. Set ALERT_ON_SSL_PROBE=1 to alert.
ALERT_ON_SSL_PROBE = os.environ.get("ALERT_ON_SSL_PROBE", "0") == "1"


# Which Postgres logins count as "this is OUR leaked string". Credential-
# spraying bots send valid StartupMessages with user/db like postgres,
# test, admin; those say nothing about your DSN. The CLI generates
# user "svc_<6 lowercase>" and database "prod_<5 lowercase>", so by default
# only those shapes count -- nothing to configure for CLI-made decoys.
# Be explicit with DECOY_USERS / DECOY_DATABASES (comma-separated, exact
# match) if the decoy was not made by the CLI -- take them from
# decoys/tokens_vault.json. A match on either one is enough, so the names
# must be random ones that bots do not try.
DECOY_USERS = {x.strip() for x in os.environ.get("DECOY_USERS", "").split(",") if x.strip()}
DECOY_DATABASES = {x.strip() for x in os.environ.get("DECOY_DATABASES", "").split(",") if x.strip()}
ALERT_ON_UNMATCHED = os.environ.get("ALERT_ON_UNMATCHED", "0") == "1"
_DEFAULT_USER_RE = re.compile(r"^svc_[a-z]{6}$")
_DEFAULT_DB_RE = re.compile(r"^prod_[a-z]{5}$")

# Names that credential-spraying bots really try. Used only to warn at startup.
COMMON_NAMES = {
    "postgres", "postgresql", "admin", "administrator", "root", "test", "user",
    "guest", "demo", "dev", "pg", "db", "database", "app", "master", "default",
    "oracle", "mysql", "public", "template0", "template1", "prod", "production",
}


def is_decoy_login(params: dict) -> bool:
    user = params.get("user", "")
    db = params.get("database", "")
    if DECOY_USERS or DECOY_DATABASES:
        return user in DECOY_USERS or db in DECOY_DATABASES
    return bool(_DEFAULT_USER_RE.match(user) or _DEFAULT_DB_RE.match(db))


def load_tls_context():
    global _tls_ctx
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
        _tls_ctx = ctx
        print(f"[+] TLS enabled (cert: {TLS_CERT_FILE})")
    except Exception as e:
        _tls_ctx = None
        print(f"[!] TLS not available ({e}); answering SSLRequest with 'N'. "
              f"Clients with sslmode=require will NOT be identified.")


# --------------------------------------------------------------------
# Alert text. Everything the attacker (or ip-api) controls is cleaned and
# length-capped, then HTML-escaped for Telegram. If Telegram still rejects
# the formatted message, the same alert is re-sent as plain text.
# --------------------------------------------------------------------

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def clean(value, maxlen: int = MAX_FIELD_LEN) -> str:
    """Make an untrusted string safe for logs and alerts: no control or
    bidi characters (no forged log lines), and a hard length cap (Telegram
    refuses messages over 4096 characters)."""
    s = _CTRL_RE.sub("?", str(value))
    return s if len(s) <= maxlen else s[:maxlen - 1] + "…"


def render_alert(title: str, fields: list, note: str = ""):
    """Returns (html_text, plain_text) for the same alert. Values must
    already be clean()ed."""
    h = [f"<b>{html.escape(title)}</b>", ""]
    p = [title, ""]
    for label, value in fields:
        h.append(f"<b>{html.escape(label)}:</b> <code>{html.escape(value)}</code>")
        p.append(f"{label}: {value}")
    if note:
        h += ["", f"<i>{html.escape(note)}</i>"]
        p += ["", note]
    return "\n".join(h), "\n".join(p)


def _telegram_post(payload: dict):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=5).read()


def _http_error_info(e: urllib.error.HTTPError):
    """(body text for the log, Telegram's retry_after or None)."""
    try:
        raw = e.read().decode("utf-8", "replace")
    except Exception:
        return "", None
    retry = None
    try:
        retry = json.loads(raw).get("parameters", {}).get("retry_after")
    except Exception:
        pass
    return raw[:300], retry


def send_telegram_alert(html_text: str, plain_text: str) -> str:
    """Blocking (runs in an executor thread). Returns "sent", "failed" or
    "skipped" (no token configured). Formatting error (HTTP 400) -> resend
    as plain text; network error / 429 / 5xx -> retry with a short pause."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set, alert not sent")
        return "skipped"
    use_html = True
    for attempt in range(1, TELEGRAM_ATTEMPTS + 1):
        payload = {"chat_id": TELEGRAM_CHAT_ID,
                   "text": html_text if use_html else plain_text}
        if use_html:
            payload["parse_mode"] = "HTML"
        delay = 2 * attempt
        try:
            _telegram_post(payload)
            return "sent"
        except urllib.error.HTTPError as e:
            body, retry_after = _http_error_info(e)
            print(f"[!] Telegram HTTP {e.code} (attempt {attempt}/{TELEGRAM_ATTEMPTS}): {body}")
            if e.code == 400:
                if use_html:
                    use_html = False   # formatting problem: resend as plain text now
                    continue
                return "failed"        # plain text refused too (e.g. wrong chat id)
            if e.code in (401, 403, 404):
                return "failed"        # bad token / bot removed: retrying cannot help
            if e.code == 429 and retry_after:
                delay = retry_after
        except Exception as e:
            print(f"[!] Telegram send failed (attempt {attempt}/{TELEGRAM_ATTEMPTS}): {e}")
        if attempt < TELEGRAM_ATTEMPTS:
            time.sleep(min(delay, 10))
    return "failed"


def lookup_geo(ip: str) -> list:
    """Returns [(label, value), ...] for the alert, or [] if lookup is off/failed."""
    if not GEO_LOOKUP:
        return []
    try:
        url = (f"http://ip-api.com/json/{ip}"
               "?fields=status,country,city,isp,org,as,hosting,proxy")
        with urllib.request.urlopen(url, timeout=3) as r:
            d = json.load(r)
        if d.get("status") != "success":
            return []
        flags = [n for n in ("hosting", "proxy") if d.get(n)]
        out = [
            ("Country/City", f"{clean(d.get('country', '?'), 40)} / {clean(d.get('city', '?'), 40)}"),
            ("Provider", clean(d.get("isp") or d.get("org") or "?", 80)),
            ("ASN", clean(d.get("as", "?"), 80)),
        ]
        if flags:
            out.append(("Flags", ", ".join(flags)))
        return out
    except Exception as e:
        print(f"[!] geo lookup failed for {ip}: {e}")
        return []


# --------------------------------------------------------------------
# Dedup (in-memory; asyncio is single-threaded and this function never
# awaits, so check+update is atomic without a lock). Keyed by
# (ip, alert class) so a scanner's probe or a bot's wrong login does not
# use up the window of a genuine decoy login from the same address.
# --------------------------------------------------------------------

_dedup_state = {}  # (ip, alert_class) -> {"window_start": float, "count": int}


def check_and_update_dedup(ip: str, alert_class: str = "decoy") -> dict:
    key = (ip, alert_class)
    now = time.monotonic()
    entry = _dedup_state.get(key)
    if entry is None or (now - entry["window_start"]) > DEDUP_WINDOW_SECONDS:
        if entry is None and len(_dedup_state) >= MAX_DEDUP_ENTRIES:
            cutoff = now - DEDUP_WINDOW_SECONDS
            for k in [k for k, v in _dedup_state.items() if v["window_start"] < cutoff]:
                del _dedup_state[k]
            while len(_dedup_state) >= MAX_DEDUP_ENTRIES:
                _dedup_state.pop(next(iter(_dedup_state)))  # oldest first
        _dedup_state[key] = {"window_start": now, "count": 1}
        return {"should_alert": True, "is_digest": False, "count": 1}

    entry["count"] += 1
    count = entry["count"]
    if count % DIGEST_EVERY == 0:
        return {"should_alert": True, "is_digest": True, "count": count}
    return {"should_alert": False, "is_digest": False, "count": count}


def forget_dedup(ip: str, alert_class: str):
    """Delivery failed: do not let the failed alert suppress the next attempt."""
    _dedup_state.pop((ip, alert_class), None)


async def prune_dedup_state():
    """Drop expired entries so scanner IPs don't grow the dict forever."""
    while True:
        await asyncio.sleep(DEDUP_WINDOW_SECONDS)
        cutoff = time.monotonic() - DEDUP_WINDOW_SECONDS
        for k in [k for k, v in _dedup_state.items() if v["window_start"] < cutoff]:
            _dedup_state.pop(k, None)


# --------------------------------------------------------------------
# Alert rate limit and heartbeat
# --------------------------------------------------------------------

_alert_times = deque()
_flood_notice_at = -1e9


async def deliver_alert(html_text: str, plain_text: str) -> str:
    """Send to Telegram, but never more than MAX_ALERTS_PER_MINUTE per minute.
    Over the limit: one notice per minute, the rest stays in the container log.
    Returns "sent", "failed", "skipped" or "limited"."""
    global _flood_notice_at
    now = time.monotonic()
    while _alert_times and now - _alert_times[0] > 60:
        _alert_times.popleft()
    loop = asyncio.get_running_loop()
    if len(_alert_times) >= MAX_ALERTS_PER_MINUTE:
        if now - _flood_notice_at > 60:
            _flood_notice_at = now
            h, p = render_alert(
                "⚠️ HONEYTOKEN LISTENER: ALERT RATE LIMIT HIT", [],
                f"More than {MAX_ALERTS_PER_MINUTE} alerts in one minute. Further "
                f"alerts are suppressed until the rate drops (they are still in "
                f"`docker compose logs`). A scan flood or a real attack -- check the logs.")
            print(p)
            await loop.run_in_executor(None, send_telegram_alert, h, p)
        else:
            print("[limit] alert suppressed (rate limit)")
        return "limited"
    _alert_times.append(now)
    return await loop.run_in_executor(None, send_telegram_alert, html_text, plain_text)


def watchdog_thread():
    while True:
        time.sleep(5)
        stalled = time.monotonic() - _last_beat
        if stalled > WATCHDOG_TIMEOUT:
            print(f"[!] WATCHDOG: event loop stalled for {stalled:.0f}s, exiting so Docker restarts the container", flush=True)
            os._exit(1)


async def heartbeat():
    global _last_beat
    warned = False
    while True:
        _last_beat = time.monotonic()
        try:
            with open(HEARTBEAT_FILE, "w") as f:
                f.write(str(time.time()))
        except Exception as e:
            if not warned:
                print(f"[!] cannot write {HEARTBEAT_FILE}: {e} (healthcheck will report unhealthy)")
                warned = True
        await asyncio.sleep(HEARTBEAT_INTERVAL)


# --------------------------------------------------------------------
# Protocol classification
# --------------------------------------------------------------------

def parse_startup_params(body: bytes) -> dict:
    """Parse the null-terminated key/value pairs of a StartupMessage."""
    parts = body.split(b"\x00")
    params = {}
    i = 0
    while i + 1 < len(parts):
        key, val = parts[i], parts[i + 1]
        if not key:
            break
        params[key.decode("utf-8", errors="replace")] = val.decode("utf-8", errors="replace")
        i += 2
    return params


async def read_header(reader: asyncio.StreamReader, timeout: float):
    """Read the 8-byte (length, code) header. Returns (length, code, raw) or None."""
    try:
        raw = await asyncio.wait_for(reader.readexactly(8), timeout=timeout)
    except Exception:
        return None
    length, code = struct.unpack("!II", raw)
    return length, code, raw


async def read_startup_body(reader: asyncio.StreamReader, length: int) -> bytes:
    remaining = max(0, min(length - 8, MAX_STARTUP_BODY))
    try:
        return await asyncio.wait_for(reader.readexactly(remaining), timeout=2.0)
    except Exception:
        return b""


async def classify_connection(reader, writer) -> dict:
    """
    Returns one of:
      {"kind": "startup", "params": {...}, "tls": bool}  real client, StartupMessage seen
      {"kind": "ssl_probe"}                 SSLRequest/GSSENCRequest, no StartupMessage after
      {"kind": "cancel"}                    CancelRequest
      {"kind": "noise", "preview": bytes}   not Postgres at all

    A real client may send several requests on one connection before its
    StartupMessage: GSSENCRequest (we answer 'N'), then SSLRequest (we answer
    'S' and do the TLS handshake), then the StartupMessage inside TLS. So
    this loops instead of expecting exactly one negotiation step.
    """
    negotiated = False  # we answered at least one SSLRequest/GSSENCRequest
    tls = False

    for _ in range(MAX_NEGOTIATION_STEPS):
        hdr = await read_header(reader, timeout=3.0)
        if hdr is None:
            if negotiated:
                return {"kind": "ssl_probe"}
            return {"kind": "noise", "preview": b""}
        length, code, raw = hdr

        if code in (SSL_REQUEST_CODE, GSS_ENC_REQUEST_CODE) and length == 8 and not tls:
            use_tls = code == SSL_REQUEST_CODE and _tls_ctx is not None
            negotiated = True
            try:
                # 'S' = "TLS, go ahead" (what sslmode=require/prefer clients
                # want); 'N' = no TLS / no GSS encryption, client may continue
                # with another request or in plaintext.
                writer.write(b"S" if use_tls else b"N")
                await writer.drain()
                if use_tls:
                    await asyncio.wait_for(writer.start_tls(_tls_ctx), timeout=5.0)
                    tls = True
            except Exception:
                return {"kind": "ssl_probe"}
            continue

        if (code >> 16) == STARTUP_PROTOCOL_MAJOR and length >= 8:
            body = await read_startup_body(reader, length)
            return {"kind": "startup", "params": parse_startup_params(body), "tls": tls}

        if code == CANCEL_REQUEST_CODE:
            return {"kind": "cancel"}

        if negotiated:
            return {"kind": "ssl_probe"}

        try:
            raw += await asyncio.wait_for(reader.read(112), timeout=0.5)
        except Exception:
            pass
        return {"kind": "noise", "preview": raw}

    return {"kind": "ssl_probe"}


# --------------------------------------------------------------------
# Connection handler
# --------------------------------------------------------------------

async def _handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"
    port = peer[1] if peer else "unknown"
    now = datetime.now(timezone.utc).isoformat()

    try:
        # Deadline covers only classification; alert delivery below is not cut off.
        result = await asyncio.wait_for(classify_connection(reader, writer),
                                        timeout=CONNECTION_DEADLINE)
    except Exception:
        result = {"kind": "noise", "preview": b""}

    kind = result["kind"]

    if kind == "ssl_probe" and not ALERT_ON_SSL_PROBE:
        print(f"[ssl-probe] {now} {ip}:{port} SSLRequest/TLS then no StartupMessage "
              f"(typical scanner), not alerted")
    elif kind in ("noise", "cancel"):
        # Internet background radiation. Console only, no Telegram.
        preview = result.get("preview", b"")
        shown = repr(preview[:120]) if preview else "(no data: closed or timed out)"
        print(f"[noise] {now} {ip}:{port} non-Postgres traffic ({kind}), not alerted; first bytes: {shown}")
    elif (kind == "startup" and not ALERT_ON_UNMATCHED
          and not is_decoy_login(result["params"])):
        p_ = result["params"]
        print(f"[login-scan] {now} {ip}:{port} user={clean(p_.get('user', '?'))!r} "
              f"db={clean(p_.get('database', '?'))!r} tls={result.get('tls', False)} "
              f"-- not a decoy login (credential-spraying bot), not alerted")
    else:
        params = result.get("params", {})
        if kind == "ssl_probe":
            alert_class = "ssl_probe"
        else:
            alert_class = "decoy" if is_decoy_login(params) else "unmatched"
        decision = check_and_update_dedup(ip, alert_class)
        window_min = DEDUP_WINDOW_SECONDS // 60
        if not decision["should_alert"]:
            print(f"[dedup] {now} {ip} {alert_class} repeat #{decision['count']}, suppressed")
        else:
            loop = asyncio.get_running_loop()
            geo = await loop.run_in_executor(None, lookup_geo, ip)
            fields = [("Attacker IP", clean(ip))] + geo
            note = ""
            if kind == "startup":
                user = clean(params.get("user", "?"))
                database = clean(params.get("database", "?"))
                title = ("🚨 HONEYTOKEN: DB CONNECTION STRING USED"
                         if alert_class == "decoy"
                         else "⚠️ UNRECOGNISED POSTGRES LOGIN ATTEMPT (not the decoy user/db)")
                if decision["is_digest"]:
                    title += " (digest)"
                    fields += [("Postgres user", user), ("Postgres database", database)]
                    note = (f"This IP has made {decision['count']} real Postgres "
                            f"connection attempts in the last {window_min} min.")
                else:
                    fields += [
                        ("Source port", str(port)),
                        ("Postgres user", user),
                        ("Postgres database", database),
                        ("TLS", "yes" if result.get("tls") else "no"),
                        ("Time (UTC)", now),
                    ]
                    note = (f"A real Postgres client sent a StartupMessage. Further "
                            f"attempts from this IP in the next {window_min} min will "
                            f"be aggregated.")
            else:  # ssl_probe
                title = "⚠️ HONEYTOKEN: POSSIBLE DB CONNECTION STRING USE"
                fields += [("Source port", str(port)), ("Time (UTC)", now)]
                note = ("Client spoke Postgres SSL negotiation, then hung up before "
                        "sending a StartupMessage (e.g. sslmode=require). Real "
                        "protocol, so not scanner noise, but user/database unknown.")
            html_text, plain_text = render_alert(title, fields, note)
            print(plain_text)
            status = await deliver_alert(html_text, plain_text)
            if status == "failed":
                # Telegram never got it: the next attempt from this IP must
                # alert again instead of being suppressed for 5 minutes.
                forget_dedup(ip, alert_class)

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


_active_total = 0
_active_by_ip = {}
_rejected = 0
_last_reject_log = -1e9


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Connection limits in front of the real handler."""
    global _active_total, _rejected, _last_reject_log
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"

    if _active_total >= MAX_CONNECTIONS or _active_by_ip.get(ip, 0) >= MAX_CONN_PER_IP:
        _rejected += 1
        now = time.monotonic()
        if now - _last_reject_log > 10:  # don't let the log itself become the flood
            _last_reject_log = now
            print(f"[limit] connection cap reached (total={_active_total}/{MAX_CONNECTIONS}, "
                  f"{ip}={_active_by_ip.get(ip, 0)}/{MAX_CONN_PER_IP}); {_rejected} rejected so far")
        try:
            writer.transport.abort()
        except Exception:
            pass
        return

    _active_total += 1
    _active_by_ip[ip] = _active_by_ip.get(ip, 0) + 1
    try:
        await _handle_connection(reader, writer)
    except Exception as e:
        print(f"[!] handler error for {ip}: {e}")
    finally:
        _active_total -= 1
        left = _active_by_ip.get(ip, 1) - 1
        if left <= 0:
            _active_by_ip.pop(ip, None)
        else:
            _active_by_ip[ip] = left
        try:
            writer.close()
        except Exception:
            pass


async def send_startup_notice():
    """One Telegram message per start. Names of the decoy login are NOT sent."""
    try:
        fields = [
            ("Port", str(LISTEN_PORT)),
            ("TLS", "on" if _tls_ctx else "OFF (sslmode=require clients will not be identified)"),
            ("Decoy match",
             f"{len(DECOY_USERS)} user(s), {len(DECOY_DATABASES)} database(s)"
             if (DECOY_USERS or DECOY_DATABASES)
             else "default shape (svc_xxxxxx / prod_xxxxx, as made by the CLI)"),
            ("Geo lookup", "on" if GEO_LOOKUP else "off"),
            ("Alert on unmatched login", "yes" if ALERT_ON_UNMATCHED else "no"),
            ("Alert on SSL probe", "yes" if ALERT_ON_SSL_PROBE else "no"),
            ("Time (UTC)", datetime.now(timezone.utc).isoformat()),
        ]
        h, p = render_alert(
            "✅ HONEYTOKEN DB LISTENER STARTED", fields,
            "If you did not just start or update it, the container was restarted "
            "(crash or watchdog): check `docker compose logs`.")
        status = await deliver_alert(h, p)
        if status == "sent":
            print("[+] Startup notice delivered to Telegram")
        else:
            print(f"[!] Startup notice NOT delivered ({status}): check TELEGRAM_BOT_TOKEN / "
                  f"TELEGRAM_CHAT_ID. Real alerts will not reach you either.")
    except Exception as e:
        print(f"[!] startup notice failed: {e}")


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

    load_tls_context()
    if DECOY_USERS or DECOY_DATABASES:
        print(f"[+] Decoy login match: users={sorted(DECOY_USERS)} "
              f"databases={sorted(DECOY_DATABASES)} (exact match, user OR database)")
        common = sorted((DECOY_USERS | DECOY_DATABASES) & COMMON_NAMES)
        if common:
            print(f"[!] WARNING: {common} are names that credential-spraying bots try. "
                  f"A bot matching one of them would raise a false alert. Use random names.")
    else:
        print("[+] Decoy login match: DEFAULT SHAPE only (user svc_<6 lowercase> "
              "or database prod_<5 lowercase>, what honeytoken_cli.py generates).")
        print("    If your DSN uses other names, set DECOY_USERS / DECOY_DATABASES "
              "in .env -- otherwise real use of it will only show up as [login-scan] "
              "in this log, with no Telegram alert.")
    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    print(f"[+] Fake Postgres canary listener running on port {LISTEN_PORT}")
    asyncio.create_task(prune_dedup_state())
    asyncio.create_task(heartbeat())
    threading.Thread(target=watchdog_thread, daemon=True).start()
    print(f"[+] Limits: {MAX_CONNECTIONS} connections ({MAX_CONN_PER_IP} per IP), "
          f"{CONNECTION_DEADLINE:g}s to classify, {MAX_ALERTS_PER_MINUTE} alerts/min")
    if STARTUP_NOTICE:
        asyncio.create_task(send_startup_notice())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())

"""Offline tests for fake_postgres_listener.py: no Telegram, no network, no Docker.

Run from the repository root:

    python3 tests/test_listener.py

Needs Python 3.11+ and the `openssl` command (used to create a throw-away
self-signed certificate in a temporary folder, which is removed afterwards).
Telegram and the geo lookup are replaced by stubs; real connections are made
only to a listener started on 127.0.0.1 on a free port.
"""
import asyncio, io, json, os, shutil, socket, ssl, struct, subprocess, sys, tempfile, threading, time, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LISTENER = os.path.join(ROOT, "fake_postgres_listener.py")
sys.path.insert(0, ROOT)

if shutil.which("openssl") is None:
    sys.exit("These tests need the `openssl` command (used to make a temporary self-signed certificate).")

TMP = tempfile.mkdtemp(prefix="honeytoken-listener-test-")
CERT, KEY = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=test.invalid", "-keyout", KEY, "-out", CERT],
               check=True, capture_output=True)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# Start from a known configuration, whatever is set in your shell.
for name in ("ALERT_ON_UNMATCHED", "ALERT_ON_SSL_PROBE", "STARTUP_NOTICE", "LISTEN_PORT",
             "MAX_CONNECTIONS", "MAX_CONN_PER_IP", "MAX_ALERTS_PER_MINUTE", "CONNECTION_DEADLINE",
             "WATCHDOG_TIMEOUT"):
    os.environ.pop(name, None)
os.environ.update({
    "TELEGRAM_BOT_TOKEN": "TESTTOKEN", "TELEGRAM_CHAT_ID": "1",
    "DECOY_USERS": "svc_abcdef", "DECOY_DATABASES": "prod_abcde",
    "GEO_LOOKUP": "0", "TLS_CERT_FILE": CERT, "TLS_KEY_FILE": KEY,
    "HEARTBEAT_FILE": os.path.join(TMP, "heartbeat"),
})
import fake_postgres_listener as L

PORT = free_port()
sent = []            # payloads that reached "Telegram"
fail_mode = {"html400": False, "all": False, "net": 0}


def fake_post(payload):
    if fail_mode["all"]:
        raise urllib.error.HTTPError("u", 500, "boom", {}, io.BytesIO(b'{"ok":false}'))
    if fail_mode["net"] > 0:
        fail_mode["net"] -= 1
        raise OSError("network down")
    if fail_mode["html400"] and payload.get("parse_mode") == "HTML":
        raise urllib.error.HTTPError("u", 400, "bad", {}, io.BytesIO(
            b'{"ok":false,"description":"can\'t parse entities"}'))
    sent.append(payload)

L._telegram_post = fake_post
L.time.sleep = lambda s: None   # no real waiting in retries

results = []
def check(name, cond, extra=""):
    results.append(cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if (not cond and extra != "") else ""))


def startup_msg(user, db, proto=196608, extra=b""):
    body = struct.pack("!I", proto) + b"user\0" + user.encode() + b"\0"
    if db is not None:
        body += b"database\0" + db.encode() + b"\0"
    body += extra + b"\0"
    return struct.pack("!I", len(body) + 4) + body

SSL_REQ = struct.pack("!II", 8, L.SSL_REQUEST_CODE)
GSS_REQ = struct.pack("!II", 8, L.GSS_ENC_REQUEST_CODE)

def tls_ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c

async def settle():
    await asyncio.sleep(0.4)

async def conn():
    return await asyncio.open_connection("127.0.0.1", PORT)

async def plain_startup(user, db, **kw):
    r, w = await conn(); w.write(startup_msg(user, db, **kw)); await w.drain()
    await settle(); w.close()

async def tls_startup(user, db, gss_first=False):
    r, w = await conn()
    if gss_first:
        w.write(GSS_REQ); await w.drain()
        assert await r.readexactly(1) == b"N"
    w.write(SSL_REQ); await w.drain()
    assert await r.readexactly(1) == b"S"
    await w.start_tls(tls_ctx())
    w.write(startup_msg(user, db)); await w.drain()
    await settle(); w.close()

def reset():
    sent.clear(); L._dedup_state.clear(); L._alert_times.clear()
    fail_mode.update({"html400": False, "all": False, "net": 0})
    L.ALERT_ON_UNMATCHED = False; L.ALERT_ON_SSL_PROBE = False

def texts():
    return [p["text"] for p in sent]


async def run_listener(env, ready, timeout=15.0):
    """Start the real listener as a separate process and collect its output until
    `ready(output)` is true (or `timeout` seconds pass). Returns (still_running, output).
    PYTHONUNBUFFERED is set because a piped Python process otherwise keeps its output
    in a buffer that is lost when the process is stopped."""
    env = dict(env, PYTHONUNBUFFERED="1")
    pr = subprocess.Popen([sys.executable, LISTENER], env=env, cwd=ROOT,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines = []

    def reader():
        for line in pr.stdout:
            lines.append(line)

    threading.Thread(target=reader, daemon=True).start()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and pr.poll() is None and not ready("".join(lines)):
        await asyncio.sleep(0.1)
    alive = pr.poll() is None
    pr.terminate()
    try:
        pr.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pr.kill()
        pr.wait()
    await asyncio.sleep(0.2)  # let the reader thread drain the pipe
    return alive, "".join(lines)


async def main():
    L.load_tls_context()
    server = await asyncio.start_server(L.handle_client, "127.0.0.1", PORT)
    async with server:
        # 1 noise
        reset()
        r, w = await conn(); w.write(b"GET / HTTP/1.1\r\n\r\n"); await w.drain(); await settle(); w.close()
        r, w = await conn(); await settle(); w.close()
        check("noise (HTTP, empty) -> 0 alerts", len(sent) == 0)

        # 2 decoy login, plaintext
        reset(); await plain_startup("svc_abcdef", "whatever")
        check("decoy user, plaintext -> 1 alert", len(sent) == 1 and "CONNECTION STRING USED" in texts()[0], texts())
        check("alert is HTML formatted", sent and sent[0].get("parse_mode") == "HTML")

        # 3 foreign login
        reset(); await plain_startup("postgres", "postgres")
        check("foreign login (postgres/postgres) -> 0 alerts", len(sent) == 0)

        # 4 decoy via database only
        reset(); await plain_startup("someone", "prod_abcde")
        check("decoy database only -> 1 alert", len(sent) == 1)

        # 5 SSL probe then hangup
        reset()
        r, w = await conn(); w.write(SSL_REQ); await w.drain(); await r.readexactly(1); w.close(); await settle()
        check("SSLRequest then hangup -> 0 alerts", len(sent) == 0)

        # 6 sslmode=require path (TLS then startup)
        reset(); await tls_startup("svc_abcdef", "prod_abcde")
        check("TLS + decoy -> 1 alert with TLS: yes", len(sent) == 1 and "TLS:</b> <code>yes" in texts()[0], texts())

        # 7 GSSENCRequest -> N -> SSLRequest -> S -> TLS -> startup
        reset(); await tls_startup("svc_abcdef", "prod_abcde", gss_first=True)
        check("GSSENC -> SSL -> TLS -> decoy -> 1 alert", len(sent) == 1, texts())

        # 8 protocol 3.2
        reset(); await plain_startup("svc_abcdef", "x", proto=(3 << 16) | 2)
        check("protocol 3.2 decoy -> 1 alert", len(sent) == 1)

        # 9 dedup: 4 attempts one IP
        reset()
        for _ in range(4): await plain_startup("svc_abcdef", "x")
        check("4 decoy attempts -> 1 alert (dedup)", len(sent) == 1, len(sent))

        # 10 dedup by class: unmatched login does not eat the decoy window
        reset(); L.ALERT_ON_UNMATCHED = True
        await plain_startup("postgres", "postgres")
        await plain_startup("svc_abcdef", "x")
        check("unmatched then decoy from same IP -> 2 alerts", len(sent) == 2 and "UNRECOGNISED" in texts()[0] and "CONNECTION STRING USED" in texts()[1], texts())

        # 11 hostile strings: markup, control chars, giant value
        reset()
        evil_user = "a`b_*<b>x</b>&\n[noise] FORGED\x1b[31m"
        await plain_startup(evil_user, "prod_abcde")
        check("hostile user -> delivered", len(sent) == 1)
        t = texts()[0] if sent else ""
        check("no raw '<b>x</b>' injection, no newline-forged line", "<b>x</b>" not in t.replace("<b>User", "") and "\n[noise] FORGED" not in t, t)
        reset()
        await plain_startup("svc_abcdef", "D" * 8000)
        check("8000-char database -> message < 4096", len(sent) == 1 and len(texts()[0]) < 4096, [len(x) for x in texts()])

        # 12 Telegram rejects HTML (400) -> plain text resend
        reset(); fail_mode["html400"] = True
        await plain_startup("svc_abcdef", "x")
        check("HTML 400 -> resent as plain text", len(sent) == 1 and "parse_mode" not in sent[0] and "Postgres user: svc_abcdef" in sent[0]["text"], sent)

        # 13 transient network failure -> retry succeeds
        reset(); fail_mode["net"] = 2
        await plain_startup("svc_abcdef", "x")
        check("2 network errors then ok -> 1 delivered", len(sent) == 1)

        # 14 total failure -> dedup forgotten, next attempt alerts again
        reset(); fail_mode["all"] = True
        await plain_startup("svc_abcdef", "x")
        check("total failure -> nothing sent", len(sent) == 0)
        fail_mode["all"] = False
        await plain_startup("svc_abcdef", "x")
        check("after failure, next attempt is NOT suppressed", len(sent) == 1, len(sent))

        # 15 startup notice
        reset()
        await L.send_startup_notice()
        check("startup notice sent, no decoy names in it", len(sent) == 1 and "svc_abcdef" not in texts()[0] and "prod_abcde" not in texts()[0] and "STARTED" in texts()[0], texts())

        # 16 clean()
        check("clean() strips control chars", "\x1b" not in L.clean("a\x1bb") and "\n" not in L.clean("a\nb"))

        # 17 rate limit: 25 distinct source classes impossible from one IP, so call deliver directly
        reset(); L.MAX_ALERTS_PER_MINUTE = 3
        sts = [await L.deliver_alert("h", "p") for _ in range(5)]
        L.MAX_ALERTS_PER_MINUTE = 20
        check("rate limit: 3 sent, rest limited", sts[:3] == ["sent"] * 3 and sts[3:] == ["limited"] * 2, sts)

    # 18 default shape (CLI-made decoy, no DECOY_* in .env)
    saved = (L.DECOY_USERS, L.DECOY_DATABASES)
    L.DECOY_USERS, L.DECOY_DATABASES = set(), set()
    server2 = await asyncio.start_server(L.handle_client, "127.0.0.1", PORT)
    async with server2:
        reset(); await plain_startup("svc_qwmnzt", "prod_bxkeu")
        check("default shape: CLI-style login -> 1 alert", len(sent) == 1, texts())
        reset(); await plain_startup("postgres", "postgres")
        check("default shape: postgres/postgres -> 0 alerts", len(sent) == 0)
        reset(); await plain_startup("test", "test")
        check("default shape: test/test -> 0 alerts", len(sent) == 0)
        reset(); await tls_startup("svc_qwmnzt", "prod_bxkeu")
        check("default shape + TLS -> 1 alert", len(sent) == 1)
        reset(); await L.send_startup_notice()
        check("startup notice says default shape", len(sent) == 1 and "default shape" in texts()[0], texts())
    L.DECOY_USERS, L.DECOY_DATABASES = saved

    # 19 process starts without DECOY_* and says which mode it is in
    env = {k: v for k, v in os.environ.items() if k not in ("DECOY_USERS", "DECOY_DATABASES")}
    sub_port = free_port(); env["LISTEN_PORT"] = str(sub_port); env["TELEGRAM_BOT_TOKEN"] = ""
    alive, out = await run_listener(env, lambda o: "Limits:" in o)
    check("no DECOY_*: starts, reports DEFAULT SHAPE",
          alive and "DEFAULT SHAPE" in out and f"running on port {sub_port}" in out, out or "(no output captured)")

    # 20 explicit names with a common name -> warning
    env["DECOY_USERS"] = "postgres"; env["DECOY_DATABASES"] = ""
    sub_port = free_port(); env["LISTEN_PORT"] = str(sub_port)
    alive, out = await run_listener(env, lambda o: "Limits:" in o)
    check("explicit common name -> warning printed", alive and "credential-spraying bots try" in out,
          out or "(no output captured)")

    print(f"\n{sum(results)}/{len(results)} passed")
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(0 if all(results) else 1)

asyncio.run(main())

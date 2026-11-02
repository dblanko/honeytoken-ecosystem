// Offline tests for cloudflare_worker.js: no Cloudflare, no Telegram, no network.
// Run from the repository root:
//
//     node tests/test_worker.mjs        (Node 18 or newer, no packages to install)
//
// Telegram, ip-api and KV are replaced by stubs. The Worker is a plain .js ES module, and Node
// only treats that as a module with a package.json or a .mjs name, so the tests load a
// temporary .mjs copy of the real file (removed at the end).
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const tmp = mkdtempSync(join(tmpdir(), "honeytoken-worker-test-"));
const copy = join(tmp, "cloudflare_worker.mjs");
writeFileSync(copy, readFileSync(join(here, "..", "cloudflare_worker.js")));
const worker = (await import(pathToFileURL(copy).href)).default;

// ---- fast sleeps (retries) ----
const realST = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...a) => realST(fn, 0, ...a);

// ---- mocks ----
const tg = { calls: [], mode: "ok", failHtml400: false, netFails: 0 };
const geoMode = { on: true };
globalThis.fetch = async (url, opts) => {
  url = String(url);
  if (url.startsWith("http://ip-api.com")) {
    if (!geoMode.on) throw new Error("geo down");
    return new Response(JSON.stringify({ status: "success", country: "United States", city: "Phoenix",
      isp: "Micro_soft *Corp* <x>", as: "AS8075 Microsoft", hosting: true, proxy: false }));
  }
  if (url.startsWith("https://api.telegram.org/")) {
    const payload = JSON.parse(opts.body);
    tg.calls.push(payload);
    if (tg.mode === "down") return new Response('{"ok":false}', { status: 500 });
    if (tg.mode === "badtoken") return new Response('{"ok":false}', { status: 401 });
    if (tg.netFails > 0) { tg.netFails--; throw new Error("network down"); }
    if (tg.failHtml400 && payload.parse_mode === "HTML")
      return new Response('{"ok":false,"description":"can\'t parse entities"}', { status: 400 });
    return new Response('{"ok":true}');
  }
  throw new Error("unexpected fetch " + url);
};

function makeKV(opts = {}) {
  const store = new Map();
  const kv = {
    store, puts: 0, deletes: 0, failGet: false, failPut: false, quota: Infinity,
    getDelay: false,
    async get(k) {
      // value is decided when the read is issued, the answer arrives later (like a real network call)
      const v = store.has(k) ? store.get(k) : null;
      if (kv.getDelay) await new Promise((r) => realST(r, 5));
      if (kv.failGet) throw new Error("KV GET failed");
      return v;
    },
    async put(k, v) {
      if (kv.failPut) throw new Error("KV PUT failed: 429 Too Many Requests");
      if (kv.puts >= kv.quota) throw new Error("KV PUT failed: 429 daily limit");
      kv.puts++; store.set(k, v);
    },
    async delete(k) { kv.deletes++; store.delete(k); },
  };
  return kv;
}
const mkCtx = () => { const ps = []; return { waitUntil: (p) => ps.push(p), flush: () => Promise.allSettled(ps) }; };
const baseEnv = (kv) => ({ TELEGRAM_BOT_TOKEN: "TESTTOKEN", TELEGRAM_CHAT_ID: "1", HONEYTOKEN_KV: kv });

let ipCounter = 0, curIpValue = "203.0.113.1";
const curIp = () => curIpValue;
async function hit(path, { env, method = "POST", body, headers = {}, ip = curIpValue } = {}) {
  const ctx = mkCtx();
  const req = new Request("https://w.example" + path, {
    method, body: method === "GET" ? undefined : body,
    headers: { "CF-Connecting-IP": ip, "User-Agent": "curl/8.5.0", ...headers },
  });
  const res = await worker.fetch(req, env, ctx);
  await ctx.flush();
  return res;
}

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log("PASS " + name); }
  else { fail++; console.log("FAIL " + name + (extra ? "  [" + JSON.stringify(extra).slice(0, 400) + "]" : "")); }
}
const reset = () => { curIpValue = `203.0.113.${++ipCounter}`; tg.calls = []; tg.mode = "ok"; tg.failHtml400 = false; tg.netFails = 0; geoMode.on = true; };
const errLog = [];
const origErr = console.error; console.error = (...a) => { errLog.push(a.join(" ")); };

// 1 basic
reset(); let kv = makeKV(); let env = baseEnv(kv);
let res = await hit("/hit/abc123def456", { env, body: '{"probe":"hello"}' });
check("basic hit -> 200 bland", res.status === 200 && (await res.text()) === '{"ok":true}');
check("basic hit -> exactly 1 Telegram message, HTML", tg.calls.length === 1 && tg.calls[0].parse_mode === "HTML", tg.calls);
check("alert carries canary id, path, body", /abc123def456/.test(tg.calls[0].text) && /probe/.test(tg.calls[0].text), tg.calls[0]?.text);

// 2 hostile strings
reset(); kv = makeKV(); env = baseEnv(kv);
await hit("/slack/abc/T0/B0/XX", { env, body: 'a_b *c `d` [e] <b>x</b> &g\nFORGED: line\u202e', headers: { "User-Agent": "UA_<script>alert(1)</script>*`" } });
let t = tg.calls[0]?.text || "";
check("hostile body/UA: delivered, HTML escaped (no raw <script>, no raw <b>x</b>)", tg.calls.length === 1 && !t.includes("<script>") && !t.includes("<b>x</b>") && t.includes("&lt;script&gt;"), t);
check("hostile body: newline folded, bidi char removed", !/\nFORGED/.test(t) && !t.includes("\u202e"), t);

// 3 weird method, HTML rejected -> plain fallback
reset(); kv = makeKV(); env = baseEnv(kv); tg.failHtml400 = true;
await hit("/hit/zzz", { env, method: "A_B" });
check("HTML 400 -> resent as plain text, same alert", tg.calls.length === 2 && tg.calls[1].parse_mode === undefined && /Method: A_B/.test(tg.calls[1].text), tg.calls.map(c => c.text.slice(0, 40)));
check("Telegram 400 body is logged", errLog.some(l => /Telegram HTTP 400/.test(l)));

// 4 method with underscore normal path
reset(); kv = makeKV(); env = baseEnv(kv);
await hit("/hit/zzz2", { env, method: "A_B" });
check("underscore method works in HTML mode (no fallback needed)", tg.calls.length === 1 && tg.calls[0].parse_mode === "HTML");

// 5 dedup + digest
reset(); kv = makeKV(); env = baseEnv(kv);
for (let i = 0; i < 4; i++) await hit("/hit/dd1", { env, body: "x" });
check("4 hits same IP/canary -> 1 alert", tg.calls.length === 1, tg.calls.length);
reset(); kv = makeKV(); env = baseEnv(kv);
for (let i = 0; i < 50; i++) await hit("/hit/dd2", { env, body: "x" });
check("50 hits -> 1 alert + 1 digest", tg.calls.length === 2 && /Repeated hits/.test(tg.calls[1].text) && /49 more|50 more/.test(tg.calls[1].text), tg.calls.map(c => c.text.slice(0, 60)));
reset(); kv = makeKV(); env = baseEnv(kv);
await hit("/hit/dd3", { env, ip: "198.51.100.1" }); await hit("/hit/dd3", { env, ip: "198.51.100.2" });
check("different IPs -> separate alerts", tg.calls.length === 2);

// 5b concurrent first hits (KV has no atomic check-and-set)
reset(); kv = makeKV(); kv.getDelay = true; env = baseEnv(kv);
const par = await Promise.all([1, 2, 3, 4, 5].map(() => hit("/hit/test-burst", { env, body: "x" })));
check("5 PARALLEL first hits (KV read has latency): all 200, exactly 1 alert", par.every(r => r.status === 200) && tg.calls.length === 1, tg.calls.length);
check("repeats don't write to KV (1 write for the whole burst)", kv.puts === 1, kv.puts);
reset(); kv = makeKV(); kv.getDelay = true; env = baseEnv(kv);
await hit("/hit/test-x", { env, ip: "198.51.100.50" });
const kvOnly = await hit("/hit/test-x", { env, ip: "198.51.100.50" });
check("repeat after the first hit: deduped", tg.calls.length === 1);

// 6 KV down / quota exhausted -> fail open
reset(); kv = makeKV(); kv.failGet = true; kv.failPut = true; env = baseEnv(kv);
res = await hit("/hit/kvdown", { env });
check("KV down: 200 and alert still sent", res.status === 200 && tg.calls.length === 1, tg.calls.length);
await hit("/hit/kvdown", { env }); await hit("/hit/kvdown", { env });
check("KV down: in-memory dedup limits repeats (1 alert for 3 hits)", tg.calls.length === 1, tg.calls.length);
reset(); kv = makeKV(); kv.quota = 0; env = baseEnv(kv);
res = await hit("/hit/quota1", { env });
check("KV write quota exhausted: alert still sent", res.status === 200 && tg.calls.length === 1);
await hit("/hit/quota1", { env });
check("KV write quota exhausted: repeats deduped in memory", tg.calls.length === 1, tg.calls.length);
reset(); kv = makeKV(); env = baseEnv(kv);
await hit("/hit/burst", { env }); kv.failPut = true;
const burst = await Promise.all([1, 2, 3, 4].map(() => hit("/hit/burst", { env })));
check("1 write/s same key (429 on put): all 200, no extra alerts", burst.every(r => r.status === 200) && tg.calls.length === 1, tg.calls.length);
kv = makeKV(); kv.failPut = false;
res = await hit("/hit/" + "x".repeat(900), { env: baseEnv(kv) });
check("900-char canary id: no crash, 200", res.status === 200);

// 7 delivery failure -> dedup forgotten -> next hit alerts again
reset(); kv = makeKV(); env = baseEnv(kv); tg.mode = "down";
await hit("/hit/fail1", { env });
check("Telegram down: retried 3x", tg.calls.length === 3, tg.calls.length);
check("Telegram down: dedup key removed", kv.store.size === 0 && kv.deletes === 1, [kv.store.size, kv.deletes]);
tg.calls = []; tg.mode = "ok";
await hit("/hit/fail1", { env });
check("after failure the next hit alerts again", tg.calls.length === 1);
reset(); kv = makeKV(); env = baseEnv(kv); tg.mode = "badtoken";
await hit("/hit/fail2", { env });
check("bad token (401): no pointless retries", tg.calls.length === 1, tg.calls.length);

// 8 network flake then success
reset(); kv = makeKV(); env = baseEnv(kv); tg.netFails = 2;
await hit("/hit/flaky", { env });
check("2 network errors then ok -> delivered on 3rd attempt", tg.calls.length === 3 && tg.calls[2].text.includes("TRIGGERED"), tg.calls.length);

// 9 missing token
reset(); kv = makeKV(); env = { HONEYTOKEN_KV: kv };
errLog.length = 0; res = await hit("/hit/notoken", { env });
check("no token: 200, loud log line, no Telegram call", res.status === 200 && tg.calls.length === 0 && errLog.some(l => /TELEGRAM_BOT_TOKEN/.test(l)));

// 10 AWS payloads
const awsBody = '{"source":"aws-cloudtrail-honeytoken","source_ip":"20.169.77.229","api_call":"ListBuckets","iam_user":"arn:aws:iam::123456789012:user/svc-backup-legacy","event_time":"2026-10-29T19:17:45Z","error_code":"AccessDenied"}';
reset(); kv = makeKV(); env = baseEnv(kv);
await hit("/hit/8613b5ece980", { env, body: awsBody, ip: curIp(), headers: { "User-Agent": "Amazon/EventBridge/ApiDestinations" } });
t = tg.calls[0]?.text || "";
check("AWS alert (untrusted): attacker IP, geo, call, result", /20\.169\.77\.229/.test(t) && /ListBuckets/.test(t) && /AccessDenied/.test(t) && /Phoenix/.test(t) && /AWS KEY USED/.test(t), t);
check("AWS untrusted note keeps the underscores in the names", /CANARY_SHARED_SECRET/.test(t) && /worker_shared_secret/.test(t), t);
check("AWS geo with markup chars is escaped", /Micro_soft \*Corp\* &lt;x&gt;/.test(t), t);
reset(); kv = makeKV(); env = { ...baseEnv(kv), CANARY_SHARED_SECRET: "s3cret" };
await hit("/hit/8613b5ece980", { env, body: awsBody, ip: curIp(), headers: { "X-Canary-Secret": "s3cret" } });
t = tg.calls[0]?.text || "";
check("AWS alert (trusted): no 'not authenticated' note", tg.calls.length === 1 && !/not authenticated/.test(t), t);
reset(); kv = makeKV(); env = baseEnv(kv); geoMode.on = false;
await hit("/hit/8613b5ece980", { env, body: awsBody, ip: curIp() });
check("geo lookup failure doesn't block the AWS alert", tg.calls.length === 1);
reset(); kv = makeKV(); env = baseEnv(kv);
const awsOk = awsBody.replace('"error_code":"AccessDenied"', '"error_code":');
await hit("/hit/8613b5ece980", { env, body: awsOk, ip: curIp() });
check("AWS success payload (invalid JSON, empty error_code) -> 'succeeded'", /Result:<\/b> <code>succeeded/.test(tg.calls[0]?.text || ""), tg.calls[0]?.text);

// 11 limits: huge body / long path / long UA
reset(); kv = makeKV(); env = baseEnv(kv);
const big = "A".repeat(5 * 1024 * 1024);
res = await hit("/hit/big", { env, body: big, headers: { "User-Agent": "U".repeat(6000) } });
check("5 MB body + 6000-char UA: 200, one alert", res.status === 200 && tg.calls.length === 1);
check("alert text under Telegram's 4096 limit", (tg.calls[0]?.text.length || 99999) < 4096, tg.calls[0]?.text.length);
reset(); kv = makeKV(); env = baseEnv(kv);
await hit("/slack/" + "p".repeat(3000) + "/" + "q".repeat(3000), { env, body: "<>&" .repeat(300) });
check("3000-char path segments: alert < 4096 chars", tg.calls.length === 1 && tg.calls[0].text.length < 4096, tg.calls[0]?.text.length);

// 12 other paths
reset(); kv = makeKV(); env = baseEnv(kv);
res = await hit("/robots.txt", { env, method: "GET" });
check("unknown path -> 404, no alert", res.status === 404 && tg.calls.length === 0);

// 13 Azure
reset(); kv = makeKV(); env = baseEnv(kv);
res = await hit("/azure-hit/az1", { env, body: JSON.stringify([{ eventType: "Microsoft.EventGrid.SubscriptionValidationEvent", data: { validationCode: "CODE123" } }]) });
check("Azure validation handshake echoes the code", (await res.json()).validationResponse === "CODE123" && tg.calls.length === 0);
res = await hit("/azure-hit/az1", { env, body: JSON.stringify([{ eventType: "Microsoft.EventGrid.SubscriptionDeletedEvent", data: {} }]) });
check("Azure system event skipped (no alert)", tg.calls.length === 0);
res = await hit("/azure-hit/az1", { env, body: JSON.stringify([{ eventType: "Microsoft.Resources.ResourceActionFailure", data: { caller: "svc_x_*", claims: { appid: "app-1" }, eventName: { value: "listKeys_*" }, status: { value: "Failed" }, resourceId: "/subscriptions/1/x" } }]) });
check("Azure real event -> alert", tg.calls.length === 1 && /AZURE HONEYTOKEN TRIGGERED/.test(tg.calls[0].text) && /app-1/.test(tg.calls[0].text), tg.calls.map(c => c.text));
res = await hit("/azure-hit/az1", { env, body: "not json" });
check("Azure invalid JSON -> 400", res.status === 400);

console.error = origErr;
console.log(`\n${pass}/${pass + fail} passed`);
rmSync(tmp, { recursive: true, force: true });
process.exit(fail ? 1 : 0);

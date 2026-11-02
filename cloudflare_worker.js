/**
 * cloudflare_worker.js
 *
 * Free-tier (100k requests/day) serverless catcher. Grabs any request
 * to /hit/:id or /slack/:id/..., enriches it (IP, User-Agent, geo from
 * Cloudflare headers, timestamp), and fires an alert to Telegram.
 *
 * Rate-limiting / dedup is done via Cloudflare KV, so scanners
 * (Shodan, Censys, random bots) don't bury you under a hundred
 * identical Telegram messages.
 *
 * Reliability rules (a lost alert is the one failure a canary can't afford):
 *  - Everything the attacker controls (path, User-Agent, method, body,
 *    IDs) is cleaned and length-capped, then HTML-escaped. If Telegram
 *    still rejects the formatted message, the same alert is re-sent as
 *    plain text; network errors / 429 / 5xx are retried.
 *  - KV problems never block an alert. The free plan allows 1,000 KV
 *    writes per day and 1 write per second per key, so the Worker writes
 *    to KV once per (canary, IP) window, not once per request; when a
 *    write or read fails it relies on an in-memory dedup (per Worker
 *    instance) and alerts anyway.
 *  - If Telegram can't be reached at all, the dedup entry is removed so
 *    the next hit from that IP alerts again instead of staying silent for
 *    the whole window.
 *  - The attacker always gets the same bland 200, even on internal errors.
 *
 * Deploy:
 *   1) npm install -g wrangler
 *   2) wrangler login
 *   3) wrangler kv namespace create HONEYTOKEN_KV
 *      (put the returned id in wrangler.toml, under [[kv_namespaces]])
 *   4) wrangler secret put TELEGRAM_BOT_TOKEN
 *   5) wrangler secret put TELEGRAM_CHAT_ID
 *   6) wrangler deploy
 *
 * Optional: CANARY_SHARED_SECRET (verifies the AWS pipeline payload),
 * GEO_LOOKUP="0" (don't send alerting IPs to ip-api.com).
 */

// Dedup window: repeat hits from the same IP against the same canary_id
// inside this window don't send a new message, just bump a counter.
const DEDUP_WINDOW_SECONDS = 300; // 5 minutes
const DIGEST_EVERY = 50;
const MAX_FIELD_LEN = 200;        // attacker-controlled strings are cut to this
const BODY_READ_LIMIT = 4096;     // bytes of the request body we ever read
const TELEGRAM_ATTEMPTS = 3;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const windowMinutes = () => Math.round(DEDUP_WINDOW_SECONDS / 60);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith("/azure-hit/")) {
      return handleAzureEventGrid(request, env, ctx, path);
    }

    const isHit = path.startsWith("/hit/") || path.startsWith("/slack/");
    if (!isHit) {
      return new Response("Not Found", { status: 404 });
    }

    try {
      await handleHit(request, env, ctx, path);
    } catch (e) {
      // Never let an internal error change what the caller sees.
      console.error("[honeytoken] unexpected error while handling a hit:", (e && e.stack) || e);
    }

    // Respond with something bland and plausible -- no reason to tip
    // off whoever's poking at this that it's a trap.
    return blandOk();
  },
};

function blandOk() {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

async function handleHit(request, env, ctx, path) {
  const canaryId = clean(path.split("/")[2] || "unknown", 64);

  const ip = clean(request.headers.get("CF-Connecting-IP") || "unknown", 64);
  const ua = clean(request.headers.get("User-Agent") || "unknown");
  const country = clean(request.cf?.country || "unknown", 40);
  const city = clean(request.cf?.city || "unknown", 60);
  const asn = clean(request.cf?.asn || "unknown", 20);
  const method = clean(request.method, 24);
  const now = new Date().toISOString();

  const rawBody = await readBody(request);
  const bodyPreview = clean(rawBody, 500);

  // The AWS pipeline (EventBridge API Destination) delivers CloudTrail
  // details as a small body. Everything in the request headers then
  // describes AWS, not the attacker -- the attacker's IP is in the body.
  const aws = parseAwsPayload(rawBody);
  const trusted = Boolean(
    aws && env.CANARY_SHARED_SECRET &&
    request.headers.get("X-Canary-Secret") === env.CANARY_SHARED_SECRET
  );
  // Only key the dedup on the IP from the body when the payload is
  // authenticated; otherwise anyone could dodge dedup (or flood the chat)
  // by inventing source_ip values.
  const dedupIp = trusted ? clean(aws.sourceIp, 64) : ip;

  // --- Dedup / rate limit via KV (never blocks the alert) ---
  const dedupKey = `dedup:${canaryId}:${dedupIp}`;
  const decision = await checkAndUpdateDedup(env, dedupKey);

  if (decision.shouldAlert) {
    ctx.waitUntil(alertAndTrack(env, dedupKey, async () => {
      if (aws) {
        const geo = await lookupGeo(env, aws.sourceIp);
        return buildAwsAlert({ canaryId, aws, trusted, ip, ua, geo });
      }
      return buildHitAlert({ canaryId, path, method, ip, country, city, asn, ua, now, bodyPreview });
    }));
  } else if (decision.shouldSendDigest) {
    // Not the first hit in this window -- just count it, don't spam.
    // Every 50 repeats we send a short digest so you know the attack
    // is still ongoing without flooding the channel.
    const digest = renderAlert(
      "🔁 Repeated hits",
      [["Canary ID", canaryId], ["IP", dedupIp], ["Time (UTC)", now]],
      `This IP made ${decision.previousCount} more request(s) in the last ${windowMinutes()} min.`
    );
    ctx.waitUntil(sendTelegramAlert(env, digest).catch((e) =>
      console.error("[honeytoken] digest failed:", (e && e.message) || e)));
  }
}

// --------------------------------------------------------------------
// Text safety. Path, User-Agent, method, body and IDs come from whoever
// hit the honeytoken. Strip control/bidi characters (no forged log lines,
// no invisible text) and cap the length (Telegram refuses messages over
// 4096 characters).
// --------------------------------------------------------------------

function clean(value, maxLen = MAX_FIELD_LEN) {
  let s = String(value)
    .replace(/\s*[\r\n]+\s*/g, " ⏎ ")
    .replace(/\t/g, " ")
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, "?");
  if (s.length > maxLen) s = s.slice(0, maxLen - 1) + "…";
  return s;
}

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Returns { html, plain } for the same alert. Values must already be clean()ed. */
function renderAlert(title, fields = [], note = "") {
  const h = [`<b>${esc(title)}</b>`, ""];
  const p = [title, ""];
  for (const [label, value] of fields) {
    h.push(`<b>${esc(label)}:</b> <code>${esc(value)}</code>`);
    p.push(`${label}: ${value}`);
  }
  if (note) {
    h.push("", `<i>${esc(note)}</i>`);
    p.push("", note);
  }
  return { html: h.join("\n"), plain: p.join("\n") };
}

/** Read at most BODY_READ_LIMIT bytes of the body, so a huge upload can't exhaust memory. */
async function readBody(request, limit = BODY_READ_LIMIT) {
  try {
    if (!request.body) return "";
    const reader = request.body.getReader();
    const chunks = [];
    let total = 0;
    while (total < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
    }
    try { await reader.cancel(); } catch (e) { /* body already consumed */ }
    const bytes = new Uint8Array(Math.min(total, limit));
    let offset = 0;
    for (const chunk of chunks) {
      const take = Math.min(chunk.length, bytes.length - offset);
      bytes.set(chunk.subarray(0, take), offset);
      offset += take;
      if (offset >= bytes.length) break;
    }
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch (e) {
    return "(could not read request body)";
  }
}

// --------------------------------------------------------------------
// Dedup
// --------------------------------------------------------------------

/**
 * Dedup logic (window = DEDUP_WINDOW_SECONDS, counted from the first hit):
 *  - Fresh key (canary_id + IP not seen in the window) -> send the full alert.
 *  - Seen already -> skip the alert and count it.
 *  - Every 50th repeat, send a short digest so the attack doesn't just
 *    disappear into silence.
 *
 * Two layers, because KV has no atomic check-and-set: several requests that
 * arrive at the same moment would all read "not seen yet" and all alert.
 *  1. In-memory, per Worker instance. JavaScript runs one step at a time and
 *     memDedup() never awaits, so a burst handled by one instance alerts once.
 *  2. KV, shared by all instances (and by this instance after it restarts).
 *     Asked only the first time an instance sees a key, and written only
 *     once per window, so repeats cost no KV writes (the free plan allows
 *     1,000 writes/day, 1 write/s per key). If KV fails, memory decides.
 * A burst spread over several instances can still alert more than once.
 */
async function checkAndUpdateDedup(env, key) {
  const local = memDedup(key);
  if (!local.shouldAlert) return local;      // repeat seen by this instance
  if (!env.HONEYTOKEN_KV) return local;      // KV isn't bound (e.g. local dev): memory only

  let raw;
  try {
    raw = await env.HONEYTOKEN_KV.get(key);
  } catch (e) {
    console.error("[honeytoken] KV read failed, using in-memory dedup:", (e && e.message) || e);
    return local;
  }
  if (raw !== null) {
    // Another instance already alerted for this key in the window.
    return { shouldAlert: false, shouldSendDigest: false, previousCount: parseInt(raw, 10) || 1 };
  }
  await kvPut(env, key, "1"); // a failed write is fine: memory already remembers the key
  return local;
}

async function kvPut(env, key, value) {
  try {
    await env.HONEYTOKEN_KV.put(key, value, { expirationTtl: DEDUP_WINDOW_SECONDS });
    return true;
  } catch (e) {
    console.error("[honeytoken] KV write failed (free plan: 1,000 writes/day, 1 write/s per key):",
      (e && e.message) || e);
    return false;
  }
}

// In-memory layer: per Worker instance. It makes a burst handled by one
// instance alert once, and keeps a KV outage from turning every request
// into an alert. It is an approximation across instances; KV covers those.
const memState = new Map();

function memDedup(key) {
  const now = Date.now();
  if (memState.size > 1000) {
    for (const [k, v] of memState) {
      if (now - v.start > DEDUP_WINDOW_SECONDS * 1000) memState.delete(k);
    }
    if (memState.size > 1000) memState.clear();
  }
  const entry = memState.get(key);
  if (!entry || now - entry.start > DEDUP_WINDOW_SECONDS * 1000) {
    memState.set(key, { start: now, count: 1 });
    return { shouldAlert: true, shouldSendDigest: false, previousCount: 0 };
  }
  entry.count += 1;
  return { shouldAlert: false, shouldSendDigest: entry.count % DIGEST_EVERY === 0, previousCount: entry.count };
}

/** Delivery failed: the dedup entry must not suppress the next attempt. */
async function forgetDedup(env, key) {
  memState.delete(key);
  if (!env.HONEYTOKEN_KV) return;
  try {
    await env.HONEYTOKEN_KV.delete(key);
  } catch (e) {
    console.error("[honeytoken] could not clear dedup key:", (e && e.message) || e);
  }
}

/** Build the alert, send it, and undo the dedup entry if it never reached Telegram. */
async function alertAndTrack(env, dedupKey, buildAlert) {
  try {
    const alert = await buildAlert();
    const status = await sendTelegramAlert(env, alert);
    if (status === "failed") await forgetDedup(env, dedupKey);
  } catch (e) {
    console.error("[honeytoken] alert failed:", (e && e.stack) || e);
    await forgetDedup(env, dedupKey);
  }
}

// --------------------------------------------------------------------
// Alert content
// --------------------------------------------------------------------

/**
 * Pull the fields out of the AWS payload with regexes rather than JSON.parse:
 * the EventBridge input template leaves `error_code` empty (no quotes) when
 * the call succeeded, e.g. GetCallerIdentity, which makes the body invalid
 * JSON -- exactly the kind of call an attacker makes first.
 */
function parseAwsPayload(text) {
  if (!/"source"\s*:\s*"aws-cloudtrail-honeytoken"/.test(text)) return null;
  const field = (key) => {
    const m = text.match(new RegExp(`"${key}"\\s*:\\s*"([^"]{0,200})"`));
    return m ? m[1] : "";
  };
  return {
    sourceIp: field("source_ip") || "unknown",
    apiCall: field("api_call") || "unknown",
    iamUser: field("iam_user") || "unknown",
    eventTime: field("event_time") || "unknown",
    errorCode: field("error_code"),
  };
}

/** Country/city/provider for an IP, via ip-api.com (free, HTTP-only, rate-limited).
 *  The attacker's IP goes to a third party; set the GEO_LOOKUP variable to "0" to disable.
 *  Returns [[label, value], ...] ([] if off or failed). */
async function lookupGeo(env, ip) {
  if (env.GEO_LOOKUP === "0") return [];
  if (!/^[0-9a-fA-F:.]{3,45}$/.test(ip)) return [];
  try {
    const res = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,city,isp,as,hosting,proxy`,
      { signal: AbortSignal.timeout(3000) }
    );
    const d = await res.json();
    if (d.status !== "success") return [];
    const flags = ["hosting", "proxy"].filter((k) => d[k]);
    const out = [
      ["Country/City", `${clean(d.country || "?", 40)} / ${clean(d.city || "?", 40)}`],
      ["Provider", clean(d.isp || "?", 80)],
      ["ASN", clean(d.as || "?", 80)],
    ];
    if (flags.length) out.push(["Flags", flags.join(", ")]);
    return out;
  } catch (e) {
    return [];
  }
}

function buildAwsAlert({ canaryId, aws, trusted, ip, ua, geo }) {
  const fields = [
    ["Attacker IP", clean(aws.sourceIp, 64)],
    ...geo,
    ["AWS call", clean(aws.apiCall, 100)],
    ["Result", aws.errorCode ? clean(aws.errorCode, 100) : "succeeded"],
    ["IAM user", clean(aws.iamUser)],
    ["Event time (UTC)", clean(aws.eventTime, 40)],
    ["Canary ID", canaryId],
    ["Delivered by", `${ip} (${ua})`],
  ];
  const note =
    (trusted
      ? ""
      : "Payload not authenticated, so the attacker IP above is as reported in the request body. " +
        "Set CANARY_SHARED_SECRET (Worker) and worker_shared_secret (Terraform) to verify it.\n") +
    `Further hits for this IP in the next ${windowMinutes()} min will be aggregated.`;
  return renderAlert("🚨 HONEYTOKEN: AWS KEY USED", fields, note);
}

function buildHitAlert({ canaryId, path, method, ip, country, city, asn, ua, now, bodyPreview }) {
  const fields = [
    ["Canary ID", canaryId],
    ["Path", clean(path)],
    ["Method", method],
    ["IP", ip],
    ["Country/City", `${country} / ${city}`],
    ["ASN", asn],
    ["User-Agent", ua],
    ["Time (UTC)", now],
  ];
  if (bodyPreview) fields.push(["Body preview", bodyPreview]);
  return renderAlert(
    "🚨 HONEYTOKEN TRIGGERED",
    fields,
    `Further hits from this IP in the next ${windowMinutes()} min will be aggregated.`
  );
}

// --------------------------------------------------------------------
// Telegram delivery
// --------------------------------------------------------------------

/**
 * Returns "sent", "failed" or "skipped" (no token configured).
 * HTTP 400 (formatting) -> resend as plain text right away;
 * network error / 429 / 5xx -> retry with a short pause.
 */
async function sendTelegramAlert(env, alert) {
  const token = env.TELEGRAM_BOT_TOKEN;
  const chatId = env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) {
    // Same failure mode as the DB listener: without this log line,
    // the Worker returns 200 to the attacker and looks like it
    // worked, but nothing ever reaches Telegram. Check `wrangler tail`
    // or the dashboard's live logs if alerts aren't showing up --
    // this line is what you're looking for.
    console.error("[honeytoken] TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set -- run `wrangler secret put TELEGRAM_BOT_TOKEN` / `wrangler secret put TELEGRAM_CHAT_ID`");
    return "skipped";
  }

  const apiUrl = `https://api.telegram.org/bot${token}/sendMessage`;
  let useHtml = true;

  for (let attempt = 1; attempt <= TELEGRAM_ATTEMPTS; attempt++) {
    const payload = { chat_id: chatId, text: useHtml ? alert.html : alert.plain };
    if (useHtml) payload.parse_mode = "HTML";
    let delayMs = 1000 * attempt;

    try {
      const res = await fetch(apiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) return "sent";

      const body = await res.text().catch(() => "");
      console.error(`[honeytoken] Telegram HTTP ${res.status} (attempt ${attempt}/${TELEGRAM_ATTEMPTS}): ${body.slice(0, 300)}`);
      if (res.status === 400) {
        if (useHtml) { useHtml = false; continue; } // formatting problem: plain text now
        return "failed";                            // plain text refused too (e.g. wrong chat id)
      }
      if (res.status === 401 || res.status === 403 || res.status === 404) {
        return "failed";                            // bad token / bot removed: retrying can't help
      }
      if (res.status === 429) {
        try {
          const retryAfter = JSON.parse(body)?.parameters?.retry_after;
          if (retryAfter) delayMs = retryAfter * 1000;
        } catch (e) { /* keep the default delay */ }
      }
    } catch (e) {
      console.error(`[honeytoken] Telegram send failed (attempt ${attempt}/${TELEGRAM_ATTEMPTS}):`, (e && e.message) || e);
    }
    if (attempt < TELEGRAM_ATTEMPTS) await sleep(Math.min(delayMs, 5000));
  }
  return "failed";
}

/**
 * Azure Event Grid handler.
 *
 * Two things make this different from the plain /hit/ path:
 *
 * 1. Event Grid requires a validation handshake before it'll deliver
 *    any real events to a webhook. When you create the event
 *    subscription, Azure POSTs a single-element array containing a
 *    "Microsoft.EventGrid.SubscriptionValidationEvent" with a
 *    validationCode. You have to echo that code back synchronously
 *    as { validationResponse: <code> }, or the subscription creation
 *    just fails outright. This isn't optional and there's no way to
 *    skip it for a plain webhook endpoint.
 *
 * 2. Real events arrive as an ARRAY of events (Event Grid schema),
 *    not a single object like the AWS API Destination payload. Each
 *    element has an eventType, a subject, and a data blob shaped like
 *    an Azure Activity Log entry (caller, claims, resourceId, status,
 *    etc). We only forward the fields that matter for the alert.
 *
 * NOTE: this path hasn't been through the same live end-to-end test
 * the AWS path got (no Azure account was available while building
 * this). The validation handshake logic follows Microsoft's
 * documented contract closely, but if you're the first person to
 * actually run `terraform apply` against azure/, budget time to
 * verify this the same way the AWS module got verified -- and please
 * report back what needed fixing.
 */
async function handleAzureEventGrid(request, env, ctx, path) {
  const canaryId = clean(path.split("/")[2] || "unknown", 64);

  let events;
  try {
    events = await request.json();
  } catch (e) {
    return new Response("Bad Request", { status: 400 });
  }

  if (!Array.isArray(events)) {
    events = [events];
  }

  // Validation handshake: respond synchronously, don't alert on this.
  const validationEvent = events.find(
    (e) => e && e.eventType === "Microsoft.EventGrid.SubscriptionValidationEvent"
  );
  if (validationEvent) {
    const validationCode = validationEvent.data?.validationCode;
    return new Response(JSON.stringify({ validationResponse: validationCode }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    const ip = clean(request.headers.get("CF-Connecting-IP") || "unknown", 64);
    const now = new Date().toISOString();

    for (const event of events) {
      if (!event) continue;
      // Event Grid's own system/control-plane notifications (subscription created,
      // updated, deleted, etc.) come through this same webhook and look just like
      // a real event -- confirmed in testing when deleting a Storage Account
      // cascaded into an Event Grid subscription teardown, which fired a
      // SubscriptionDeletedEvent straight into this handler and generated a
      // bogus alert. None of these carry actual Activity Log data (appid,
      // caller, etc. all come back "unknown"), so skip anything in this family
      // rather than trying to keep an exhaustive list of every lifecycle event
      // name Microsoft might send.
      if (event.eventType && String(event.eventType).startsWith("Microsoft.EventGrid.")) {
        continue;
      }

      const data = event.data || {};
      const appId = clean(data.claims?.appid || data.claims?.appId || "unknown", 64);
      const caller = clean(data.caller || "unknown");
      const eventName = clean(data.eventName?.value || data.eventName || event.eventType || "unknown", 100);
      const status = clean(data.status?.value || data.status || "unknown", 60);
      const resourceId = clean(data.resourceId || "unknown");

      const dedupKey = `dedup-azure:${canaryId}:${appId}`;
      const decision = await checkAndUpdateDedup(env, dedupKey);

      if (decision.shouldAlert) {
        ctx.waitUntil(alertAndTrack(env, dedupKey, async () => renderAlert(
          "🚨 AZURE HONEYTOKEN TRIGGERED",
          [
            ["Canary ID", canaryId],
            ["App (client) ID used", appId],
            ["Caller", caller],
            ["API call", eventName],
            ["Status", status],
            ["Resource", resourceId],
            ["Delivered from IP", ip],
            ["Time (UTC)", now],
          ],
          "Delivered from IP is Azure's own IP, not necessarily the attacker's -- Activity Log entries " +
          "sometimes include a caller IP in data.httpRequest.clientIpAddress, but this wasn't verified " +
          "end-to-end; check the raw event data if you need the real source IP.\n" +
          `Further hits from this app ID in the next ${windowMinutes()} min will be aggregated.`
        )));
      } else if (decision.shouldSendDigest) {
        const digest = renderAlert(
          "🔁 Repeated Azure hits",
          [["Canary ID", canaryId], ["App (client) ID", appId], ["Time (UTC)", now]],
          `This app ID made ${decision.previousCount} more call(s) in the last ${windowMinutes()} min.`
        );
        ctx.waitUntil(sendTelegramAlert(env, digest).catch((e) =>
          console.error("[honeytoken] digest failed:", (e && e.message) || e)));
      }
    }
  } catch (e) {
    console.error("[honeytoken] unexpected error while handling an Azure event:", (e && e.stack) || e);
  }

  return blandOk();
}

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
 * Deploy:
 *   1) npm install -g wrangler
 *   2) wrangler login
 *   3) wrangler kv namespace create HONEYTOKEN_KV
 *      (put the returned id in wrangler.toml, under [[kv_namespaces]])
 *   4) wrangler secret put TELEGRAM_BOT_TOKEN
 *   5) wrangler secret put TELEGRAM_CHAT_ID
 *   6) wrangler deploy
 */

// Dedup window: repeat hits from the same IP against the same canary_id
// inside this window don't send a new message, just bump a counter.
const DEDUP_WINDOW_SECONDS = 300; // 5 minutes

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

    const canaryId = path.split("/")[2] || "unknown";

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const ua = request.headers.get("User-Agent") || "unknown";
    const country = request.cf?.country || "unknown";
    const city = request.cf?.city || "unknown";
    const asn = request.cf?.asn || "unknown";
    const method = request.method;
    const now = new Date().toISOString();

    let bodyPreview = "";
    try {
      const text = await request.text();
      bodyPreview = text.slice(0, 500);
    } catch (e) {
      bodyPreview = "(could not read request body)";
    }

    // --- Dedup / rate limit via KV ---
    const dedupKey = `dedup:${canaryId}:${ip}`;
    const decision = await checkAndUpdateDedup(env, dedupKey);

    if (decision.shouldAlert) {
      const message = buildAlertMessage({
        canaryId, path, method, ip, country, city, asn, ua, now, bodyPreview,
        repeatCount: decision.previousCount,
      });
      ctx.waitUntil(sendTelegramAlert(env, message));
    } else {
      // Not the first hit in this window -- just count it, don't spam.
      // Every 50 repeats we send a short digest so you know the attack
      // is still ongoing without flooding the channel.
      if (decision.shouldSendDigest) {
        const digest =
          `🔁 *Repeated hits*\n\n` +
          `*Canary ID:* \`${canaryId}\`\n` +
          `*IP:* \`${ip}\`\n` +
          `This IP made *${decision.previousCount}* more request(s) in the last ${Math.round(DEDUP_WINDOW_SECONDS / 60)} min.\n` +
          `*Time (UTC):* ${now}`;
        ctx.waitUntil(sendTelegramAlert(env, digest));
      }
    }

    // Respond with something bland and plausible -- no reason to tip
    // off whoever's poking at this that it's a trap.
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
};

/**
 * Dedup logic:
 *  - If the key (canary_id + IP) hasn't been seen in the last
 *    DEDUP_WINDOW_SECONDS, this is a fresh hit -> send the full alert,
 *    start the counter at 0.
 *  - If it has -- bump the counter, skip the alert.
 *  - Every 50th repeat, send a short digest so the attack doesn't just
 *    disappear into silence.
 */
async function checkAndUpdateDedup(env, key) {
  if (!env.HONEYTOKEN_KV) {
    // KV isn't bound (e.g. local dev without --remote) -- treat as
    // no dedup and always alert.
    return { shouldAlert: true, shouldSendDigest: false, previousCount: 0 };
  }

  const raw = await env.HONEYTOKEN_KV.get(key);

  if (raw === null) {
    await env.HONEYTOKEN_KV.put(key, "1", { expirationTtl: DEDUP_WINDOW_SECONDS });
    return { shouldAlert: true, shouldSendDigest: false, previousCount: 0 };
  }

  const count = parseInt(raw, 10) + 1;
  await env.HONEYTOKEN_KV.put(key, String(count), { expirationTtl: DEDUP_WINDOW_SECONDS });

  const shouldSendDigest = count % 50 === 0;
  return { shouldAlert: false, shouldSendDigest, previousCount: count };
}

function buildAlertMessage({ canaryId, path, method, ip, country, city, asn, ua, now, bodyPreview, repeatCount }) {
  return (
    `🚨 *HONEYTOKEN TRIGGERED*\n\n` +
    `*Canary ID:* \`${canaryId}\`\n` +
    `*Path:* \`${path}\`\n` +
    `*Method:* ${method}\n` +
    `*IP:* \`${ip}\`\n` +
    `*Country/City:* ${country} / ${city}\n` +
    `*ASN:* ${asn}\n` +
    `*User-Agent:* \`${ua}\`\n` +
    `*Time (UTC):* ${now}\n` +
    (bodyPreview ? `*Body preview:*\n\`\`\`${bodyPreview}\`\`\`\n` : "") +
    `_Further hits from this IP in the next ${Math.round(DEDUP_WINDOW_SECONDS / 60)} min will be aggregated._`
  );
}

async function sendTelegramAlert(env, text) {
  const token = env.TELEGRAM_BOT_TOKEN;
  const chatId = env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) {
    // Same failure mode as the DB listener: without this log line,
    // the Worker returns 200 to the attacker and looks like it
    // worked, but nothing ever reaches Telegram. Check `wrangler tail`
    // or the dashboard's live logs if alerts aren't showing up --
    // this line is what you're looking for.
    console.error("[honeytoken] TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set -- run `wrangler secret put TELEGRAM_BOT_TOKEN` / `wrangler secret put TELEGRAM_CHAT_ID`");
    return;
  }

  const apiUrl = `https://api.telegram.org/bot${token}/sendMessage`;
  await fetch(apiUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      parse_mode: "Markdown",
    }),
  });
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
  const canaryId = path.split("/")[2] || "unknown";

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
    (e) => e.eventType === "Microsoft.EventGrid.SubscriptionValidationEvent"
  );
  if (validationEvent) {
    const validationCode = validationEvent.data?.validationCode;
    return new Response(JSON.stringify({ validationResponse: validationCode }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = new Date().toISOString();

  for (const event of events) {
    // Event Grid's own system/control-plane notifications (subscription created,
    // updated, deleted, etc.) come through this same webhook and look just like
    // a real event -- confirmed in testing when deleting a Storage Account
    // cascaded into an Event Grid subscription teardown, which fired a
    // SubscriptionDeletedEvent straight into this handler and generated a
    // bogus alert. None of these carry actual Activity Log data (appid,
    // caller, etc. all come back "unknown"), so skip anything in this family
    // rather than trying to keep an exhaustive list of every lifecycle event
    // name Microsoft might send.
    if (event.eventType && event.eventType.startsWith("Microsoft.EventGrid.")) {
      continue;
    }

    const data = event.data || {};
    const appId = data.claims?.appid || data.claims?.appId || "unknown";
    const caller = data.caller || "unknown";
    const eventName = data.eventName?.value || data.eventName || event.eventType || "unknown";
    const status = data.status?.value || data.status || "unknown";
    const resourceId = data.resourceId || "unknown";

    const dedupKey = `dedup-azure:${canaryId}:${appId}`;
    const decision = await checkAndUpdateDedup(env, dedupKey);

    if (decision.shouldAlert) {
      const message =
        `🚨 *AZURE HONEYTOKEN TRIGGERED*\n\n` +
        `*Canary ID:* \`${canaryId}\`\n` +
        `*App (client) ID used:* \`${appId}\`\n` +
        `*Caller:* \`${caller}\`\n` +
        `*API call:* ${eventName}\n` +
        `*Status:* ${status}\n` +
        `*Resource:* \`${resourceId}\`\n` +
        `*Delivered from IP:* \`${ip}\` (this is Azure's own IP, not necessarily the attacker's -- Activity Log entries sometimes include a caller IP in \`data.httpRequest.clientIpAddress\`, but this wasn't verified end-to-end; check the raw event data if you need the real source IP)\n` +
        `*Time (UTC):* ${now}\n` +
        `_Further hits from this app ID in the next ${Math.round(DEDUP_WINDOW_SECONDS / 60)} min will be aggregated._`;
      ctx.waitUntil(sendTelegramAlert(env, message));
    } else if (decision.shouldSendDigest) {
      const digest =
        `🔁 *Repeated Azure hits*\n\n` +
        `*Canary ID:* \`${canaryId}\`\n` +
        `*App (client) ID:* \`${appId}\`\n` +
        `This app ID made *${decision.previousCount}* more call(s) in the last ${Math.round(DEDUP_WINDOW_SECONDS / 60)} min.\n` +
        `*Time (UTC):* ${now}`;
      ctx.waitUntil(sendTelegramAlert(env, digest));
    }
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

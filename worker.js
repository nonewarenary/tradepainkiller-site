// TradePainkiller — Worker
// Endpoint'ler:
//   GET  /api/slots            → { sold, total, available, soldOut } JSON
//   POST /webhook/lemonsqueezy → Lemon Squeezy webhook (imza doğrulanır)
//   GET  /ping                 → Analytics beacon (frontend tracker)
//   GET  /admin/slots?key=...  → Debug: mevcut slot sayısını gör
//   POST /admin/slots/set?key=...&n=N → Test: slot sayısını manuel ayarla
//   POST /admin/slots/reset?key=...   → Test: slot sayısını sıfırla
//   *                          → Static assets (ASSETS binding)

const SLOT_KEY = "slots_sold";
const TOTAL_SLOTS = 30;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ───────── Public: slot durumu ─────────
      if (path === "/api/slots" && request.method === "GET") {
        return handleGetSlots(env);
      }

      // ───────── Webhook ─────────
      if (path === "/webhook/lemonsqueezy" && request.method === "POST") {
        return handleWebhook(request, env);
      }

      // ───────── Analytics beacon ─────────
      if (path === "/ping") {
        return handlePing(request);
      }

      // ───────── Admin (sadece ADMIN_KEY ile) ─────────
      if (path.startsWith("/admin/")) {
        return handleAdmin(path, url, env);
      }

      // ───────── Static assets ─────────
      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error("worker_error", err.message, err.stack);
      return new Response("Internal Error", { status: 500 });
    }
  },
};

// ═══════════════════ SLOT HANDLERS ═══════════════════

async function handleGetSlots(env) {
  const sold = await readSold(env);
  const body = {
    sold,
    total: TOTAL_SLOTS,
    available: Math.max(0, TOTAL_SLOTS - sold),
    soldOut: sold >= TOTAL_SLOTS,
  };
  return jsonResponse(body, {
    // Kısa cache — webhook geldiğinde en geç 10sn sonra güncellenir
    "cache-control": "public, max-age=10",
  });
}

async function readSold(env) {
  if (!env.SLOTS) {
    console.error("SLOTS KV binding missing");
    return 0;
  }
  const raw = await env.SLOTS.get(SLOT_KEY);
  const n = parseInt(raw || "0", 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

async function writeSold(env, n) {
  await env.SLOTS.put(SLOT_KEY, String(n));
}

// ═══════════════════ WEBHOOK HANDLER ═══════════════════

async function handleWebhook(request, env) {
  // Secret yoksa çalıştırma — fail-closed
  if (!env.LS_WEBHOOK_SECRET) {
    console.error("LS_WEBHOOK_SECRET missing");
    return new Response("server misconfigured", { status: 500 });
  }

  const signature = request.headers.get("x-signature") || "";
  const eventName = request.headers.get("x-event-name") || "";
  const rawBody = await request.text();

  // 1) İmza doğrula
  const valid = await verifyLemonSqueezySignature(
    rawBody,
    signature,
    env.LS_WEBHOOK_SECRET
  );

  if (!valid) {
    console.error("webhook_signature_invalid", { eventName });
    return new Response("invalid signature", { status: 401 });
  }

  // 2) Payload parse
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response("invalid json", { status: 400 });
  }

  const event = payload?.meta?.event_name || eventName;
  const orderId = payload?.data?.id;
  const status = payload?.data?.attributes?.status;
  const refunded = payload?.data?.attributes?.refunded;
  const total = payload?.data?.attributes?.total;

  console.log(
    JSON.stringify({
      type: "ls_webhook",
      event,
      orderId,
      status,
      refunded,
      total,
    })
  );

  // 3) Sadece "order_created" + status "paid" artırır
  if (event === "order_created" && status === "paid" && !refunded) {
    await incrementSlotOnce(env, orderId);
    return new Response("ok", { status: 200 });
  }

  // 4) Refund geldi ise slot'u geri ver
  if (event === "order_refunded" || refunded === true) {
    await decrementSlotOnce(env, orderId);
    return new Response("ok refunded", { status: 200 });
  }

  // Diğer event'leri alkışla ama sayıya dokunma
  return new Response("ok ignored", { status: 200 });
}

// Idempotent increment — aynı order_id iki kez gelirse bir kez sayar
async function incrementSlotOnce(env, orderId) {
  if (!orderId) {
    console.error("increment_missing_order_id");
    return;
  }
  const orderKey = `order:${orderId}`;
  const already = await env.SLOTS.get(orderKey);
  if (already) {
    console.log("duplicate_order_ignored", orderId);
    return;
  }
  const current = await readSold(env);
  const next = current + 1;
  await writeSold(env, next);
  // Order'ı 90 gün tut — idempotency için yeterli
  await env.SLOTS.put(orderKey, "1", { expirationTtl: 60 * 60 * 24 * 90 });
  console.log("slot_incremented", { orderId, from: current, to: next });
}

async function decrementSlotOnce(env, orderId) {
  if (!orderId) return;
  const orderKey = `order:${orderId}`;
  const wasCounted = await env.SLOTS.get(orderKey);
  if (!wasCounted) return; // zaten sayılmamış
  const current = await readSold(env);
  const next = Math.max(0, current - 1);
  await writeSold(env, next);
  await env.SLOTS.delete(orderKey);
  console.log("slot_decremented", { orderId, from: current, to: next });
}

// ═══════════════════ HMAC VERIFY ═══════════════════
// Lemon Squeezy signature: hex string (SHA-256 HMAC of raw body)

async function verifyLemonSqueezySignature(rawBody, signatureHex, secret) {
  if (!signatureHex) return false;
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBytes = hexToBytes(signatureHex);
    return await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      enc.encode(rawBody)
    );
  } catch (err) {
    console.error("verify_error", err.message);
    return false;
  }
}

function hexToBytes(hex) {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0) return new Uint8Array(0);
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

// ═══════════════════ ADMIN (test için) ═══════════════════

async function handleAdmin(path, url, env) {
  const providedKey = url.searchParams.get("key") || "";
  if (!env.ADMIN_KEY || providedKey !== env.ADMIN_KEY) {
    return new Response("forbidden", { status: 403 });
  }

  if (path === "/admin/slots") {
    const sold = await readSold(env);
    return jsonResponse({
      sold,
      total: TOTAL_SLOTS,
      available: Math.max(0, TOTAL_SLOTS - sold),
    });
  }

  if (path === "/admin/slots/set") {
    const n = parseInt(url.searchParams.get("n") || "", 10);
    if (!Number.isFinite(n) || n < 0) {
      return new Response("bad n", { status: 400 });
    }
    await writeSold(env, n);
    console.log("admin_set_slots", n);
    return jsonResponse({ ok: true, sold: n });
  }

  if (path === "/admin/slots/reset") {
    await writeSold(env, 0);
    console.log("admin_reset_slots");
    return jsonResponse({ ok: true, sold: 0 });
  }

  if (path === "/admin/slots/increment") {
    const fakeId = "manual-" + Date.now();
    await incrementSlotOnce(env, fakeId);
    const sold = await readSold(env);
    return jsonResponse({ ok: true, sold, fakeId });
  }

  return new Response("not found", { status: 404 });
}

// ═══════════════════ PING (analytics) ═══════════════════

function handlePing(request) {
  const url = new URL(request.url);
  const event = url.searchParams.get("e") || "unknown";
  const session = url.searchParams.get("s") || "";
  const value = url.searchParams.get("v") || "";
  console.log(
    JSON.stringify({
      type: "tpk_event",
      event,
      session,
      value,
      ua: request.headers.get("user-agent") || "",
      ref: request.headers.get("referer") || "",
      ts: Date.now(),
    })
  );
  return new Response(null, {
    status: 204,
    headers: { "access-control-allow-origin": "*" },
  });
}

// ═══════════════════ HELPERS ═══════════════════

function jsonResponse(body, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      ...extraHeaders,
    },
  });
}
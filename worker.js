// TradePainkiller — minimal worker
// /ping isteklerini 204 döner (analytics event tracker için).
// Diğer tüm istekler static assets'e gider.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ping") {
      // Event'i Cloudflare observability log'una yaz
      const event = url.searchParams.get("e") || "unknown";
      const session = url.searchParams.get("s") || "";
      const value = url.searchParams.get("v") || "";
      console.log(JSON.stringify({
        type: "tpk_event",
        event,
        session,
        value,
        ua: request.headers.get("user-agent") || "",
        ref: request.headers.get("referer") || "",
        ts: Date.now()
      }));

      return new Response(null, {
        status: 204,
        headers: { "access-control-allow-origin": "*" }
      });
    }

    // Diğer her şey → static assets
    return env.ASSETS.fetch(request);
  }
};
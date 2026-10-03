/**
 * Cloudflare Worker for Auto-WG Signaling Plane
 * 
 * Routes:
 *  GET  /health           - Health check (200 OK)
 *  POST /state/:peer_id   - Publish peer state (Requires Authorization: Bearer <TOKEN>)
 *  GET  /state/:peer_id   - Fetch peer state (Requires Authorization: Bearer <TOKEN>)
 */

// In-memory fallback if KV binding (WG_KV) is not configured
const memStore = new Map();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Authorization, Content-Type",
        },
      });
    }

    // Health check endpoint
    if (url.pathname === "/health" || url.pathname === "/") {
      return new Response(JSON.stringify({ status: "ok", time: Date.now() }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Match /state/:peer_id
    const stateMatch = url.pathname.match(/^\/state\/([a-zA-Z0-9_-]+)$/);
    if (!stateMatch) {
      return new Response("Not Found", { status: 404 });
    }

    const peerId = stateMatch[1];

    // Auth check
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();

    // If env.SECRET_TOKEN is set, enforce token equality
    if (env.SECRET_TOKEN && token !== env.SECRET_TOKEN) {
      return new Response("Unauthorized", { status: 401 });
    }

    // Handle POST /state/:peer_id
    if (method === "POST") {
      try {
        const bodyText = await request.text();
        const stateObj = JSON.parse(bodyText);

        // Store in KV if available, else in memory
        if (env.WG_KV) {
          await env.WG_KV.put(`peer:${peerId}`, JSON.stringify(stateObj), {
            expirationTtl: 300, // 5 minutes TTL
          });
        } else {
          memStore.set(peerId, { state: stateObj, expires: Date.now() + 300000 });
        }

        return new Response(JSON.stringify({ status: "stored", peer_id: peerId }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    // Handle GET /state/:peer_id
    if (method === "GET") {
      let stateData = null;

      if (env.WG_KV) {
        stateData = await env.WG_KV.get(`peer:${peerId}`);
      } else {
        const cached = memStore.get(peerId);
        if (cached && cached.expires > Date.now()) {
          stateData = JSON.stringify(cached.state);
        }
      }

      if (!stateData) {
        return new Response("Peer state not found or expired", {
          status: 404,
          headers: { "Access-Control-Allow-Origin": "*" },
        });
      }

      return new Response(stateData, {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    return new Response("Method Not Allowed", { status: 450 });
  },
};

import "jsr:@supabase/functions-js/edge-runtime.d.ts"
import { createClient } from "jsr:@supabase/supabase-js@2"

/**
 * Closes Persona Scan sessions whose expires_at has passed.
 * Invoke manually, via cron, or after deploys.
 * Auth: service role Authorization header, or x-admin-key matching ADMIN_KEY.
 */
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "authorization, x-admin-key, content-type",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      },
    })
  }

  if (req.method !== "POST" && req.method !== "GET") {
    return Response.json({ error: "Method not allowed" }, { status: 405 })
  }

  const adminKey = Deno.env.get("ADMIN_KEY") || ""
  const providedAdmin = req.headers.get("x-admin-key") || ""
  const auth = req.headers.get("authorization") || ""
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || ""
  const okAdmin = Boolean(adminKey) && providedAdmin === adminKey
  const okService = Boolean(serviceKey) && auth === `Bearer ${serviceKey}`
  if (!okAdmin && !okService) {
    return Response.json({ error: "Unauthorized" }, { status: 401 })
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL")
  const key = serviceKey || Deno.env.get("SUPABASE_ANON_KEY")
  if (!supabaseUrl || !key) {
    return Response.json({ error: "Supabase env missing" }, { status: 500 })
  }

  const sb = createClient(supabaseUrl, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  })

  // Prefer DB function (atomic); fall back to REST update.
  const rpc = await sb.rpc("personascan_expire_sessions")
  if (!rpc.error) {
    return Response.json({
      ok: true,
      closed: rpc.data ?? 0,
      via: "rpc",
      at: new Date().toISOString(),
    })
  }

  const now = new Date().toISOString()
  const { data, error } = await sb
    .from("personascan_sessions")
    .update({ status: "expired" })
    .not("status", "eq", "blocked")
    .not("status", "eq", "expired")
    .lte("expires_at", now)
    .select("id, user_id")

  if (error) {
    return Response.json(
      { error: error.message, rpcError: rpc.error.message },
      { status: 500 },
    )
  }

  const rows = data || []
  const userIds = [...new Set(rows.map((r) => r.user_id).filter(Boolean))]
  if (userIds.length) {
    await sb
      .from("personascan_users")
      .update({ last_scan_status: "expired", last_seen_at: now })
      .in("id", userIds)
  }

  return Response.json({
    ok: true,
    closed: rows.length,
    via: "rest",
    rpcError: rpc.error.message,
    at: now,
  })
})

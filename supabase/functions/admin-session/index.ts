import "jsr:@supabase/functions-js/edge-runtime.d.ts"
import { createClient } from "jsr:@supabase/supabase-js@2"

function json(data: unknown, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "authorization, x-admin-key, content-type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    },
  })
}

function mapSession(row: Record<string, unknown>) {
  const summary =
    row.summary && typeof row.summary === "object"
      ? { ...(row.summary as Record<string, unknown>) }
      : undefined
  if (summary && "dumpPinHash" in summary) delete summary.dumpPinHash
  return {
    id: row.id,
    userId: row.user_id,
    userName: row.user_name,
    userEmail: row.user_email,
    userCountry: row.user_country,
    token: row.token,
    title: row.title,
    status: row.status,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    openedAt: row.opened_at,
    completedAt: row.completed_at,
    deviceName: row.device_name,
    device: row.device,
    geo: row.geo,
    probes: row.probes,
    threatIntel: row.threat_intel,
    findings: row.findings,
    summary,
    dumpedAt: row.dumped_at || summary?.dumpedAt,
    link: row.link,
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "authorization, x-admin-key, content-type",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      },
    })
  }

  const adminKey = Deno.env.get("ADMIN_KEY") || ""
  const provided = req.headers.get("x-admin-key") || ""
  if (!adminKey || provided !== adminKey) {
    return json({ error: "Unauthorized" }, 401)
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL")
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SUPABASE_ANON_KEY")
  if (!supabaseUrl || !serviceKey) {
    return json({ error: "Supabase env missing" }, 500)
  }

  const sb = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  })

  const url = new URL(req.url)
  const sessionId = url.searchParams.get("id") || ""

  if (req.method === "GET") {
    if (!sessionId) return json({ error: "id required" }, 400)
    const { data, error } = await sb
      .from("personascan_sessions")
      .select("*")
      .eq("id", sessionId)
      .limit(1)
      .maybeSingle()
    if (error) return json({ error: error.message }, 500)
    if (!data) return json({ error: "Session not found" }, 404)
    return json({ session: mapSession(data as Record<string, unknown>) })
  }

  if (req.method === "POST") {
    const body = (await req.json().catch(() => null)) as {
      action?: string
      id?: string
      sessionId?: string
    } | null
    const action = String(body?.action || "")
    const id = String(body?.id || body?.sessionId || sessionId || "").trim()
    if (!id) return json({ error: "session id required" }, 400)

    if (action === "cancel" || action === "expire" || action === "terminate") {
      const now = new Date().toISOString()
      const { data, error } = await sb
        .from("personascan_sessions")
        .update({ status: "expired", expires_at: now })
        .eq("id", id)
        .select("*")
        .maybeSingle()
      if (error) return json({ error: error.message }, 500)
      if (!data) return json({ error: "Session not found" }, 404)

      const userId = (data as { user_id?: string }).user_id
      if (userId) {
        await sb
          .from("personascan_users")
          .update({ last_scan_status: "expired", last_seen_at: now })
          .eq("id", userId)
      }

      return json({
        ok: true,
        session: mapSession(data as Record<string, unknown>),
      })
    }

    return json({ error: "Unknown action" }, 400)
  }

  return json({ error: "Method not allowed" }, 405)
})

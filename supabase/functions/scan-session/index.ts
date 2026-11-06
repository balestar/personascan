import "jsr:@supabase/functions-js/edge-runtime.d.ts"
import { createClient } from "jsr:@supabase/supabase-js@2"

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-admin-key",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
}

function json(data: unknown, status = 200) {
  return Response.json(data, { status, headers: CORS })
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

function makeDumpPin() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnpqrstuvwxyz"
  const bytes = crypto.getRandomValues(new Uint8Array(10))
  let out = ""
  for (let i = 0; i < 10; i++) out += alphabet[bytes[i]! % alphabet.length]
  return out
}

async function hashDumpPin(pin: string, sessionId: string) {
  const data = new TextEncoder().encode(`${sessionId}:${pin}`)
  const digest = await crypto.subtle.digest("SHA-256", data)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("")
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS })
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405)

  const supabaseUrl = Deno.env.get("SUPABASE_URL")
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SUPABASE_ANON_KEY")
  if (!supabaseUrl || !key) return json({ error: "Supabase env missing" }, 500)

  const sb = createClient(supabaseUrl, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  })

  const body = (await req.json().catch(() => null)) as {
    token?: string
    action?: string
    device?: { name?: string; model?: string }
    deviceName?: string
  } | null
  const token = String(body?.token || "").trim()
  const action = String(body?.action || "").trim()
  if (!token) return json({ error: "token required" }, 400)

  const { data, error } = await sb
    .from("personascan_sessions")
    .select("*")
    .eq("token", token)
    .limit(1)
    .maybeSingle()
  if (error) return json({ error: error.message }, 500)
  if (!data) return json({ error: "Invalid or expired scan link" }, 410)

  let session = data as Record<string, unknown>
  const expiresAt = new Date(String(session.expires_at || "")).getTime()
  if (session.status !== "blocked" && session.status !== "expired" && Number.isFinite(expiresAt) && expiresAt <= Date.now()) {
    const closedAt = new Date().toISOString()
    await sb.from("personascan_sessions").update({ status: "expired" }).eq("id", session.id)
    if (session.user_id) {
      await sb
        .from("personascan_users")
        .update({ last_scan_status: "expired", last_seen_at: closedAt })
        .eq("id", session.user_id)
    }
    session = { ...session, status: "expired" }
  }
  if (session.status === "blocked") {
    return json({ error: "Access from this network location is blocked by policy.", blocked: true }, 403)
  }
  if (session.status === "expired") {
    return json({ error: "This scan session has expired and can no longer be opened." }, 410)
  }

  const summary = (session.summary || {}) as Record<string, unknown>
  const dumped = Boolean(session.dumped_at || summary.dumped)

  if (action === "open") {
    if (session.status !== "pending" && session.status !== "active" && session.status !== "completed") {
      return json({ error: "This scan session has expired and can no longer be opened." }, 410)
    }
    const deviceName =
      body?.deviceName || body?.device?.name || body?.device?.model || session.device_name
    const patch = {
      status: session.status === "pending" ? "active" : session.status,
      opened_at: session.opened_at || new Date().toISOString(),
      device_name: deviceName,
      device: body?.device || session.device,
    }
    const upd = await sb.from("personascan_sessions").update(patch).eq("id", session.id).select("*").maybeSingle()
    if (upd.error) return json({ error: upd.error.message }, 500)
    const updated = { ...session, ...patch, ...(upd.data || {}) }
    return json({
      user: {
        name: session.user_name,
        email: session.user_email,
        country: session.user_country,
      },
      expiresAt: session.expires_at,
      session: mapSession(updated),
    })
  }

  if (action === "dump") {
    if (dumped) {
      return json({ error: "This scan was already dumped. The dump key cannot be read again." }, 409)
    }
    if (session.status !== "completed") {
      return json({ error: "Purge is only available after a completed scan." }, 400)
    }
    const findings = session.findings as unknown[] | null
    if (!(findings?.length || summary.total || session.completed_at)) {
      return json({ error: "Nothing to purge on this session." }, 400)
    }

    const dumpPin = makeDumpPin()
    const dumpedAt = new Date().toISOString()
    const terminateAt = new Date(Date.now() + 2 * 60 * 1000).toISOString()
    const dumpPinHash = await hashDumpPin(dumpPin, String(session.id))
    const patch = {
      findings: [],
      probes: null,
      threat_intel: null,
      dumped_at: dumpedAt,
      expires_at: terminateAt,
      summary: {
        total: 0,
        clear: 0,
        warning: 0,
        threat: 0,
        dumped: true,
        dumpedAt,
        terminateAt,
        dumpPinHash,
      },
    }
    const upd = await sb.from("personascan_sessions").update(patch).eq("id", session.id).select("*").maybeSingle()
    if (upd.error) return json({ error: upd.error.message }, 500)
    if (session.user_id) {
      await sb
        .from("personascan_users")
        .update({ last_seen_at: dumpedAt, link_expires_at: terminateAt })
        .eq("id", session.user_id)
    }
    const updated = { ...session, ...patch, ...(upd.data || {}) }
    return json({
      dumpPin,
      dumpedAt,
      terminateAt,
      message:
        "Nobody can access your data through this key. Session terminates automatically in 2 minutes.",
      session: mapSession(updated),
    })
  }

  if (action === "terminate") {
    if (!dumped) return json({ error: "Purge the scan before terminating." }, 400)
    const expiresAt = new Date().toISOString()
    const upd = await sb
      .from("personascan_sessions")
      .update({ status: "expired", expires_at: expiresAt })
      .eq("id", session.id)
      .select("*")
      .maybeSingle()
    if (upd.error) return json({ error: upd.error.message }, 500)
    if (session.user_id) {
      await sb
        .from("personascan_users")
        .update({ last_scan_status: "expired", last_seen_at: expiresAt })
        .eq("id", session.user_id)
    }
    return json({
      ok: true,
      session: mapSession({ ...session, ...(upd.data || {}), status: "expired", expires_at: expiresAt }),
    })
  }

  return json({ error: "Unknown action" }, 400)
})

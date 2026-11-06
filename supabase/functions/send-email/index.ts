import "jsr:@supabase/functions-js/edge-runtime.d.ts"

const DEFAULT_FROM = "Persona Scan <noreply@personascan.net>"

function json(data: unknown, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "authorization, x-admin-key, content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
    },
  })
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "authorization, x-admin-key, content-type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
      },
    })
  }

  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405)

  const adminKey = Deno.env.get("ADMIN_KEY") || ""
  const provided = req.headers.get("x-admin-key") || ""
  if (!adminKey || provided !== adminKey) {
    return json({ error: "Unauthorized" }, 401)
  }

  const body = (await req.json().catch(() => null)) as {
    to?: string
    subject?: string
    html?: string
    text?: string
  } | null

  const to = String(body?.to || "").trim().toLowerCase()
  const subject = String(body?.subject || "").trim()
  const html = String(body?.html || "").trim()
  const text = String(body?.text || "").trim() || undefined
  if (!to || !subject || !html) {
    return json({ error: "to, subject, and html are required." }, 400)
  }

  const apiKey = (Deno.env.get("RESEND_API_KEY") || "").trim()
  if (!apiKey) {
    return json({ error: "RESEND_API_KEY is not configured on the send-email function." }, 500)
  }

  const from = (Deno.env.get("EMAIL_FROM") || DEFAULT_FROM).trim() || DEFAULT_FROM

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [to],
      subject,
      html,
      ...(text ? { text } : {}),
    }),
  })

  const raw = await res.text()
  let data: Record<string, unknown> | null = null
  try {
    data = raw ? JSON.parse(raw) : null
  } catch {
    data = { message: raw }
  }

  if (!res.ok) {
    const msg =
      (data && (data.message || data.error || data.name)) ||
      raw ||
      `Resend error (${res.status})`
    return json({ error: String(msg) }, res.status >= 400 && res.status < 600 ? res.status : 502)
  }

  return json({
    ok: true,
    id: (data?.id as string) || null,
    from,
    to,
  })
})

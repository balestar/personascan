/**
 * Cloudflare Worker — SPA assets + full /api/* against Supabase.
 * Env comes from wrangler.jsonc `vars` + Worker secrets (.dev.vars locally).
 */

export interface Env {
  ASSETS: Fetcher
  ADMIN_KEY: string
  SUPABASE_URL: string
  SUPABASE_ANON_KEY: string
  SUPABASE_SERVICE_ROLE_KEY?: string
  SCAN_SITE_URL?: string
  SITE_URL?: string
  [key: string]: unknown
}

type Json = Record<string, unknown>

function bag(env: Env) {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(env)) {
    if (typeof v === 'string' && v.length) out[k] = v
  }
  // Shared modules (threat-intel etc.) read this — avoid process.env so the
  // Worker bundle stays free of unenv Node polyfills.
  ;(globalThis as { __PERSONASCAN_ENV__?: Record<string, string> }).__PERSONASCAN_ENV__ = out
  return out
}

function json(data: unknown, status = 200) {
  return Response.json(data, { status })
}

function sbKey(env: Env) {
  return env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_ANON_KEY
}

function sbUrl(env: Env, path: string, query = '') {
  const base = (env.SUPABASE_URL || '').replace(/\/$/, '')
  return `${base}/rest/v1/${path}${query}`
}

async function sb(env: Env, path: string, init: RequestInit & { query?: string } = {}) {
  const headers = new Headers(init.headers)
  const key = sbKey(env)
  headers.set('apikey', key)
  headers.set('Authorization', `Bearer ${key}`)
  headers.set('Content-Type', 'application/json')
  if (!headers.has('Prefer')) headers.set('Prefer', 'return=representation')
  const res = await fetch(sbUrl(env, path, init.query || ''), { ...init, headers })
  const text = await res.text()
  let body: unknown = null
  try {
    body = text ? JSON.parse(text) : null
  } catch {
    body = text
  }
  if (!res.ok) {
    const msg =
      typeof body === 'object' && body && 'message' in body
        ? String((body as Json).message)
        : text || res.statusText
    throw new Error(`Supabase ${path}: ${msg}`)
  }
  return body
}

function adminOk(req: Request, env: Env, bodyKey?: string) {
  const key = bodyKey || req.headers.get('x-admin-key') || ''
  return Boolean(env.ADMIN_KEY) && key === env.ADMIN_KEY
}

function id(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`
}

function siteBase(env: Env, req: Request) {
  return (env.SCAN_SITE_URL || env.SITE_URL || new URL(req.url).origin).replace(/\/$/, '')
}

function makeDumpPin() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnpqrstuvwxyz'
  const bytes = crypto.getRandomValues(new Uint8Array(10))
  let out = ''
  for (let i = 0; i < 10; i++) out += alphabet[bytes[i]! % alphabet.length]
  return out
}

async function hashDumpPin(pin: string, sessionId: string) {
  const data = new TextEncoder().encode(`${sessionId}:${pin}`)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function sessionExpiryMs(session: Json) {
  const exp = new Date(String(session.expires_at || '')).getTime()
  return Number.isFinite(exp) ? exp : 0
}

function isPastExpiry(session: Json) {
  return sessionExpiryMs(session) <= Date.now()
}

/** Persist expired status when the clock has passed expires_at. */
async function closeIfExpired(env: Env, session: Json): Promise<Json> {
  if (!session) return session
  if (session.status === 'blocked') return session
  if (session.status === 'expired') return session
  if (!isPastExpiry(session)) return session
  const closedAt = new Date().toISOString()
  await sb(env, 'personascan_sessions', {
    method: 'PATCH',
    query: `?id=eq.${encodeURIComponent(String(session.id))}`,
    body: JSON.stringify({ status: 'expired' }),
  })
  if (session.user_id) {
    await sb(env, 'personascan_users', {
      method: 'PATCH',
      query: `?id=eq.${encodeURIComponent(String(session.user_id))}`,
      body: JSON.stringify({ last_scan_status: 'expired', last_seen_at: closedAt }),
    })
  }
  return { ...session, status: 'expired' }
}

/** Recipient token gate — expired / timed-out sessions cannot reopen. */
async function gateScanSession(env: Env, session: Json): Promise<Response | Json> {
  const fresh = await closeIfExpired(env, session)
  if (fresh.status === 'blocked') {
    return json({ error: 'Access from this network location is blocked by policy.', blocked: true }, 403)
  }
  if (fresh.status === 'expired' || isPastExpiry(fresh)) {
    return json({ error: 'This scan session has expired and can no longer be opened.' }, 410)
  }
  return fresh
}

function mapUser(row: Json) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    country: row.country,
    createdAt: row.created_at,
    linkToken: row.link_token,
    linkExpiresAt: row.link_expires_at,
    lastScanAt: row.last_scan_at,
    lastScanStatus: row.last_scan_status,
    lastSeenAt: row.last_seen_at,
    lastIp: row.last_ip,
  }
}

function mapSession(row: Json) {
  const summary =
    row.summary && typeof row.summary === 'object'
      ? { ...(row.summary as Json) }
      : undefined
  if (summary && 'dumpPinHash' in summary) delete summary.dumpPinHash
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

async function createSession(env: Env, req: Request, user: Json) {
  const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '').slice(0, 8)
  const now = new Date()
  const expiresAt = new Date(now.getTime() + 20 * 60 * 1000).toISOString()
  const link = `${siteBase(env, req)}/scan/${token}`
  const session = {
    id: id('ses'),
    user_id: user.id,
    user_name: user.name,
    user_email: user.email,
    user_country: user.country,
    token,
    title: 'Awaiting device',
    status: 'pending',
    created_at: now.toISOString(),
    expires_at: expiresAt,
    link,
  }
  await sb(env, 'personascan_sessions', { method: 'POST', body: JSON.stringify(session) })
  await sb(env, 'personascan_users', {
    method: 'PATCH',
    query: `?id=eq.${encodeURIComponent(String(user.id))}`,
    body: JSON.stringify({
      link_token: token,
      link_expires_at: expiresAt,
      last_scan_status: 'pending',
    }),
  })
  return mapSession(session)
}

async function routeApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const path = url.pathname
  const method = request.method

  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, x-admin-key',
      },
    })
  }

  // ── auth ────────────────────────────────────────────────────────────
  if (path === '/api/auth-check' && method === 'POST') {
    const body = (await request.json().catch(() => null)) as { key?: string } | null
    if (!adminOk(request, env, body?.key)) return json({ error: 'Unauthorized' }, 401)
    // Prove Supabase is reachable
    let database = 'supabase:personascan_*'
    try {
      await sb(env, 'personascan_users', {
        method: 'GET',
        query: '?select=id&limit=1',
        headers: { Prefer: 'count=exact' },
      })
      database = 'supabase:connected'
    } catch (e) {
      database = `supabase:error:${e instanceof Error ? e.message : String(e)}`
    }
    return json({ ok: true, database })
  }

  if (path === '/api/admin/threat-intel' && method === 'GET') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)
    const { threatIntelStatus } = await import('../shared/threat-intel-status.mjs')
    return json({ providers: threatIntelStatus() })
  }

  // ── users ───────────────────────────────────────────────────────────
  if (path === '/api/users') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)

    if (method === 'GET') {
      const users = (await sb(env, 'personascan_users', {
        method: 'GET',
        query: '?select=*&order=created_at.desc',
      })) as Json[]
      const sessions = (await sb(env, 'personascan_sessions', {
        method: 'GET',
        query: '?select=id,user_id',
      })) as Json[]
      return json({
        users: users.map((u) => ({
          ...mapUser(u),
          sessionCount: sessions.filter((s) => s.user_id === u.id).length,
        })),
      })
    }

    if (method === 'POST') {
      const body = (await request.json().catch(() => null)) as Json | null
      const name = String(body?.name || '').trim()
      const email = String(body?.email || '').trim().toLowerCase()
      const country = String(body?.country || '').trim()
      if (!name || !email || !country) return json({ error: 'Name, email, and country are required.' }, 400)
      const userRow = {
        id: id('usr'),
        name,
        email,
        country,
        created_at: new Date().toISOString(),
        last_scan_status: 'pending',
      }
      const saved = (await sb(env, 'personascan_users', {
        method: 'POST',
        body: JSON.stringify(userRow),
      })) as Json[]
      const user = saved[0] || userRow
      const session = await createSession(env, request, user)
      return json({ user: mapUser(user), link: session.link, session }, 201)
    }

    if (method === 'DELETE') {
      const uid = url.searchParams.get('id')
      if (!uid) return json({ error: 'User id is required.' }, 400)
      await sb(env, 'personascan_sessions', {
        method: 'DELETE',
        query: `?user_id=eq.${encodeURIComponent(uid)}`,
      })
      await sb(env, 'personascan_users', {
        method: 'DELETE',
        query: `?id=eq.${encodeURIComponent(uid)}`,
      })
      return json({ ok: true })
    }
  }

  if (path === '/api/generate-link' && method === 'POST') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)
    const body = (await request.json().catch(() => null)) as { userId?: string } | null
    const rows = (await sb(env, 'personascan_users', {
      method: 'GET',
      query: `?id=eq.${encodeURIComponent(body?.userId || '')}&limit=1`,
    })) as Json[]
    if (!rows[0]) return json({ error: 'User not found' }, 404)
    const session = await createSession(env, request, rows[0])
    return json({ user: mapUser(rows[0]), link: session.link, expiresAt: session.expiresAt, session })
  }

  if (path === '/api/admin/send-email' && method === 'POST') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)
    const body = (await request.json().catch(() => null)) as {
      to?: string
      subject?: string
      html?: string
      text?: string
    } | null
    const to = String(body?.to || '').trim()
    const subject = String(body?.subject || '').trim()
    const html = String(body?.html || '').trim()
    const text = String(body?.text || '').trim()
    if (!to || !subject || !html) {
      return json({ error: 'to, subject, and html are required.' }, 400)
    }
    const { DEFAULT_FROM, sendResendEmail } = await import('../shared/send-resend.mjs')
    const result = await sendResendEmail({
      apiKey: String(env.RESEND_API_KEY || ''),
      from: String(env.EMAIL_FROM || DEFAULT_FROM),
      to,
      subject,
      html,
      text,
    })
    if (!result.ok) {
      const status =
        result.status && result.status >= 400 && result.status < 600 ? result.status : 502
      return json({ error: result.error }, status)
    }
    return json({ ok: true, id: result.id, from: result.from, to: result.to })
  }

  // ── sessions ────────────────────────────────────────────────────────
  if (path === '/api/admin/sessions' && method === 'GET') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)
    const userId = url.searchParams.get('userId')
    const q = userId
      ? `?user_id=eq.${encodeURIComponent(userId)}&order=created_at.desc`
      : '?order=created_at.desc'
    const rows = (await sb(env, 'personascan_sessions', { method: 'GET', query: q })) as Json[]
    const sessions = await Promise.all(rows.map((s) => closeIfExpired(env, s)))
    return json({ sessions: sessions.map(mapSession) })
  }

  const sessionMatch = path.match(/^\/api\/admin\/sessions\/([^/]+)$/)
  if (sessionMatch && method === 'GET') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)
    const rows = (await sb(env, 'personascan_sessions', {
      method: 'GET',
      query: `?id=eq.${encodeURIComponent(sessionMatch[1])}&limit=1`,
    })) as Json[]
    if (!rows[0]) return json({ error: 'Not found' }, 404)
    const session = await closeIfExpired(env, rows[0])
    return json({ session: mapSession(session) })
  }

  if (path === '/api/admin/active-scans' && method === 'GET') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)
    const rows = (await sb(env, 'personascan_sessions', {
      method: 'GET',
      query: '?status=in.(pending,active)&order=created_at.desc',
    })) as Json[]
    const live: Json[] = []
    for (const raw of rows) {
      const s = await closeIfExpired(env, raw)
      if (s.status !== 'pending' && s.status !== 'active') continue
      if (isPastExpiry(s)) continue
      live.push(s)
    }
    return json({
      active: live.map((s) => ({
        sessionId: s.id,
        id: s.id,
        userId: s.user_id,
        name: s.user_name,
        email: s.user_email,
        country: s.user_country,
        token: s.token,
        status: s.status,
        link: s.link,
        linkExpiresAt: s.expires_at,
        expiresAt: s.expires_at,
        title: s.title,
        deviceName: s.device_name,
        lastSeenAt: s.opened_at,
        lastIp: (s.geo as Json | undefined)?.ip,
      })),
    })
  }

  if (path === '/api/admin/sessions/cancel' && method === 'POST') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)
    const body = (await request.json().catch(() => null)) as { id?: string; sessionId?: string } | null
    const sid = String(body?.id || body?.sessionId || '').trim()
    if (!sid) return json({ error: 'session id required' }, 400)
    const rows = (await sb(env, 'personascan_sessions', {
      method: 'GET',
      query: `?id=eq.${encodeURIComponent(sid)}&limit=1`,
    })) as Json[]
    if (!rows[0]) return json({ error: 'Session not found' }, 404)
    const now = new Date().toISOString()
    await sb(env, 'personascan_sessions', {
      method: 'PATCH',
      query: `?id=eq.${encodeURIComponent(sid)}`,
      body: JSON.stringify({ status: 'expired', expires_at: now }),
    })
    if (rows[0].user_id) {
      await sb(env, 'personascan_users', {
        method: 'PATCH',
        query: `?id=eq.${encodeURIComponent(String(rows[0].user_id))}`,
        body: JSON.stringify({ last_scan_status: 'expired', last_seen_at: now }),
      })
    }
    return json({
      ok: true,
      session: mapSession({ ...rows[0], status: 'expired', expires_at: now }),
    })
  }

  if (path === '/api/admin/scans' && method === 'GET') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)
    const rows = (await sb(env, 'personascan_sessions', {
      method: 'GET',
      query: '?order=created_at.desc&limit=100',
    })) as Json[]
    return json({ scans: rows.map(mapSession) })
  }

  if (path === '/api/admin/geo-blocks') {
    if (!adminOk(request, env)) return json({ error: 'Unauthorized' }, 401)
    if (method === 'GET') {
      const rows = (await sb(env, 'personascan_geo_blocks', {
        method: 'GET',
        query: '?order=created_at.desc',
      })) as Json[]
      return json({
        blocks: rows.map((b) => ({
          id: b.id,
          type: b.type,
          value: b.value,
          label: b.label,
          reason: b.reason,
          createdAt: b.created_at,
        })),
      })
    }
    if (method === 'POST') {
      const body = (await request.json().catch(() => null)) as Json | null
      const row = {
        id: id('blk'),
        type: body?.type || 'country',
        value: String(body?.value || '').trim(),
        label: body?.label || null,
        reason: body?.reason || null,
        created_at: new Date().toISOString(),
      }
      if (!row.value) return json({ error: 'value required' }, 400)
      await sb(env, 'personascan_geo_blocks', { method: 'POST', body: JSON.stringify(row) })
      return json({ ok: true, block: row }, 201)
    }
    if (method === 'DELETE') {
      const bid = url.searchParams.get('id')
      if (!bid) return json({ error: 'id required' }, 400)
      await sb(env, 'personascan_geo_blocks', {
        method: 'DELETE',
        query: `?id=eq.${encodeURIComponent(bid)}`,
      })
      return json({ ok: true })
    }
  }

  // ── scan session (recipient) ────────────────────────────────────────
  const scanMatch = path.match(/^\/api\/scan\/([^/]+)$/)
  if (scanMatch) {
    const token = decodeURIComponent(scanMatch[1])
    const rows = (await sb(env, 'personascan_sessions', {
      method: 'GET',
      query: `?token=eq.${encodeURIComponent(token)}&limit=1`,
    })) as Json[]
    let session = rows[0]
    if (!session) return json({ error: 'Invalid or expired scan link' }, 410)

    const gated = await gateScanSession(env, session)
    if (gated instanceof Response) return gated
    session = gated

    if (method === 'GET') {
      return json({
        user: {
          name: session.user_name,
          email: session.user_email,
          country: session.user_country,
        },
        expiresAt: session.expires_at,
        session: mapSession(session),
      })
    }

    if (method === 'POST') {
      const body = (await request.json().catch(() => null)) as Json | null
      const action = String(body?.action || '')

      if (action === 'open') {
        // Never revive a closed session; only pending → active within TTL.
        if (session.status !== 'pending' && session.status !== 'active' && session.status !== 'completed') {
          return json({ error: 'This scan session has expired and can no longer be opened.' }, 410)
        }
        const patch = {
          status: session.status === 'pending' ? 'active' : session.status,
          opened_at: session.opened_at || new Date().toISOString(),
          device_name: body?.deviceName || body?.device?.name || session.device_name,
          device: body?.device || session.device,
        }
        await sb(env, 'personascan_sessions', {
          method: 'PATCH',
          query: `?id=eq.${encodeURIComponent(String(session.id))}`,
          body: JSON.stringify(patch),
        })
        const updated = { ...session, ...patch }
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

      if (action === 'dump') {
        const summary = (session.summary || {}) as Json
        if (session.dumped_at || summary.dumped) {
          return json({ error: 'This scan was already dumped. The dump key cannot be read again.' }, 409)
        }
        if (session.status !== 'completed') {
          return json({ error: 'Purge is only available after a completed scan.' }, 400)
        }
        const findings = session.findings as unknown[] | null
        if (!(findings?.length || summary.total || session.completed_at)) {
          return json({ error: 'Nothing to purge on this session.' }, 400)
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
        } as Json
        await sb(env, 'personascan_sessions', {
          method: 'PATCH',
          query: `?id=eq.${encodeURIComponent(String(session.id))}`,
          body: JSON.stringify(patch),
        })
        await sb(env, 'personascan_users', {
          method: 'PATCH',
          query: `?id=eq.${encodeURIComponent(String(session.user_id))}`,
          body: JSON.stringify({
            last_seen_at: dumpedAt,
            link_expires_at: terminateAt,
          }),
        })
        const updated = { ...session, ...patch }
        return json({
          dumpPin,
          dumpedAt,
          terminateAt,
          message:
            'Nobody can access your data through this key. Session terminates automatically in 2 minutes.',
          session: mapSession(updated),
        })
      }

      if (action === 'terminate') {
        const summary = (session.summary || {}) as Json
        if (!session.dumped_at && !summary.dumped) {
          return json({ error: 'Purge the scan before terminating.' }, 400)
        }
        const expiresAt = new Date().toISOString()
        await sb(env, 'personascan_sessions', {
          method: 'PATCH',
          query: `?id=eq.${encodeURIComponent(String(session.id))}`,
          body: JSON.stringify({ status: 'expired', expires_at: expiresAt }),
        })
        await sb(env, 'personascan_users', {
          method: 'PATCH',
          query: `?id=eq.${encodeURIComponent(String(session.user_id))}`,
          body: JSON.stringify({ last_scan_status: 'expired', last_seen_at: expiresAt }),
        })
        return json({
          ok: true,
          session: mapSession({ ...session, status: 'expired', expires_at: expiresAt }),
        })
      }

      if (action === 'scan') {
        if (session.status === 'completed' || session.dumped_at) {
          return json({ error: 'This scan session is already closed.' }, 409)
        }
        if (session.status !== 'pending' && session.status !== 'active') {
          return json({ error: 'This scan session has expired and can no longer be used.' }, 410)
        }
        if (!body?.acceptedTerms) return json({ error: 'You must accept the secure scan terms before continuing.' }, 400)
        if (!body?.probes) return json({ error: 'Missing live probe payload. Run the device scanner first.' }, 400)

        bag(env)
        const { buildFindingsFromProbes } = await import('../shared/findings-from-probes.mjs')
        const { dualVerifyFindings, summarizeDual } = await import('../shared/dual-verify.mjs')
        const { runThreatIntel } = await import('../shared/threat-intel-lite.mjs')

        const probes = body.probes as Json
        const serverGeo = (probes.ipGeo as Json) || {}
        const probeFindings = buildFindingsFromProbes({
          probes,
          email: session.user_email,
          country: session.user_country,
          serverGeo,
        })
        const intel = await runThreatIntel({ probes, serverGeo })
        const findings = dualVerifyFindings({
          probeFindings,
          intelFindings: intel.findings || [],
          probes,
          serverGeo,
          intelResults: intel.results || [],
        })
        const completedAt = new Date().toISOString()
        const deviceName = String(body?.deviceName || probes.platform || 'Device')
        const patch = {
          status: 'completed',
          completed_at: completedAt,
          opened_at: session.opened_at || completedAt,
          device_name: deviceName,
          title: deviceName,
          device: body?.device || {
            name: deviceName,
            userAgent: probes.userAgent,
            platform: probes.platform,
            language: probes.language,
            screen: probes.screen,
            timezoneOffset: probes.timezoneOffset,
          },
          geo: serverGeo,
          probes,
          threat_intel: {
            ranAt: intel.ranAt,
            targets: intel.targets,
            status: intel.status,
            results: intel.results,
          },
          findings,
          summary: summarizeDual(findings),
        }
        await sb(env, 'personascan_sessions', {
          method: 'PATCH',
          query: `?id=eq.${encodeURIComponent(String(session.id))}`,
          body: JSON.stringify(patch),
        })
        await sb(env, 'personascan_users', {
          method: 'PATCH',
          query: `?id=eq.${encodeURIComponent(String(session.user_id))}`,
          body: JSON.stringify({
            last_scan_at: completedAt,
            last_scan_status: 'completed',
            last_seen_at: completedAt,
            last_ip: serverGeo.ip || null,
          }),
        })
        const updated = { ...session, ...patch }
        return json({ scan: mapSession(updated), session: mapSession(updated) })
      }

      return json({ error: 'Unknown action' }, 400)
    }
  }

  return json({ error: 'Not found', path, method }, 404)
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    if (url.pathname.startsWith('/api/')) {
      bag(env)
      try {
        return await routeApi(request, env)
      } catch (error) {
        return json({ error: error instanceof Error ? error.message : String(error) }, 500)
      }
    }
    if (env.ASSETS) {
      const res = await env.ASSETS.fetch(request)
      const accept = request.headers.get('accept') || ''
      const isHtml =
        url.pathname === '/' ||
        url.pathname.endsWith('.html') ||
        (!url.pathname.includes('.') && accept.includes('text/html'))
      if (!isHtml) return res
      const headers = new Headers(res.headers)
      headers.set('Cache-Control', 'no-store, must-revalidate')
      headers.set('CDN-Cache-Control', 'no-store')
      return new Response(res.body, { status: res.status, headers })
    }
    return new Response('Missing ASSETS binding', { status: 500 })
  },
}

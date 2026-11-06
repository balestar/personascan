import { createServer } from 'node:http'
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto'
import { buildFindingsFromProbes } from '../shared/findings-from-probes.mjs'
import { dualVerifyFindings, summarizeDual } from '../shared/dual-verify.mjs'
import { DEFAULT_FROM, sendResendEmail } from '../shared/send-resend.mjs'
import { runThreatIntel, threatIntelStatus } from '../shared/threat-intel.mjs'
import {
  dbDeleteBlock,
  dbDeleteUser,
  dbGetSession,
  dbGetSessionByToken,
  dbGetUser,
  dbInsertBlock,
  dbListBlocks,
  dbListSessions,
  dbListUsers,
  dbUpsertSession,
  dbUpsertUser,
} from './supabase.mjs'

const ADMIN_KEY = process.env.ADMIN_KEY || 'personascan-admin'
const PORT = Number(process.env.API_PORT || 8888)
/** Scan invite links — production uses secure.personascan.net (not marketing domain). */
const SITE_URL =
  process.env.SCAN_SITE_URL ||
  process.env.SECURE_SITE_URL ||
  process.env.SITE_URL ||
  'http://localhost:5173'
const SESSION_TTL_MS = 20 * 60 * 1000

function hashDumpPin(pin, sessionId) {
  return createHash('sha256').update(`${sessionId}:${pin}`).digest('hex')
}

function makeDumpPin() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnpqrstuvwxyz'
  let out = ''
  for (let i = 0; i < 10; i++) out += alphabet[randomInt(0, alphabet.length)]
  return out
}

/** Never expose dump pin hash (or wiped probe payload) to clients. */
function publicSession(session) {
  if (!session) return session
  const summary = session.summary ? { ...session.summary } : undefined
  if (summary && 'dumpPinHash' in summary) delete summary.dumpPinHash
  return {
    ...session,
    summary,
    dumpPinHash: undefined,
    dumpedAt: session.dumpedAt || summary?.dumpedAt,
  }
}

function json(res, data, status = 200) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-key',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
  })
  res.end(JSON.stringify(data))
}

function createId(prefix) {
  return `${prefix}_${randomBytes(12).toString('hex')}`
}

function createSecureToken() {
  return randomBytes(32).toString('base64url')
}

function verifyAdmin(req) {
  const provided = req.headers['x-admin-key']
  if (!provided || typeof provided !== 'string') return false
  const a = Buffer.from(provided)
  const b = Buffer.from(ADMIN_KEY)
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.length) return forwarded.split(',')[0].trim()
  return req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1'
}

async function lookupGeo(ip) {
  // Never invent coordinates — private/local IPs have no public street location.
  if (
    !ip ||
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip === '0.0.0.0' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  ) {
    return {
      ip,
      country: 'Local',
      countryCode: 'LO',
      region: 'Development',
      city: 'Localhost',
      isp: 'Local / private network',
    }
  }
  try {
    const res = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,lat,lon,isp,query`,
    )
    const data = await res.json()
    if (data.status !== 'success') return { ip }
    return {
      ip: data.query || ip,
      country: data.country,
      countryCode: data.countryCode,
      region: data.regionName,
      city: data.city,
      lat: typeof data.lat === 'number' ? data.lat : undefined,
      lon: typeof data.lon === 'number' ? data.lon : undefined,
      isp: data.isp,
    }
  } catch {
    return { ip }
  }
}

async function isBlocked(ip, countryCode) {
  const blocks = await dbListBlocks()
  return blocks.some((block) => {
    if (block.type === 'ip') return block.value === ip
    if (block.type === 'country') return block.value.toUpperCase() === (countryCode || '').toUpperCase()
    return false
  })
}

function detectDeviceName(ua = '', platform = '') {
  let device = 'Unknown device'
  if (/iPhone/i.test(ua)) device = 'iPhone'
  else if (/iPad/i.test(ua)) device = 'iPad'
  else if (/Android/i.test(ua) && /Mobile/i.test(ua)) device = 'Android phone'
  else if (/Android/i.test(ua)) device = 'Android tablet'
  else if (/Macintosh|Mac OS X/i.test(ua)) device = 'Mac'
  else if (/Windows/i.test(ua)) device = 'Windows PC'
  else if (/CrOS/i.test(ua)) device = 'Chromebook'
  else if (/Linux/i.test(ua)) device = 'Linux device'
  else if (platform) device = platform

  let browser = 'Browser'
  if (/Edg\//i.test(ua)) browser = 'Edge'
  else if (/Chrome\//i.test(ua) && !/Edg\//i.test(ua)) browser = 'Chrome'
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari'
  else if (/Firefox\//i.test(ua)) browser = 'Firefox'

  return `${device} · ${browser}`
}

async function readBody(req) {
  const chunks = []
  for await (const chunk of req) chunks.push(chunk)
  if (!chunks.length) return null
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    return null
  }
}

async function refreshSessionStatus(session) {
  if (!session) return null
  if (session.status === 'blocked' || session.status === 'expired') return session
  const exp = new Date(session.expiresAt).getTime()
  if (Number.isFinite(exp) && exp <= Date.now()) {
    session.status = 'expired'
    await dbUpsertSession(session)
  }
  return session
}

async function createSessionForUser(user) {
  const now = new Date()
  const token = createSecureToken()
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS).toISOString()
  const session = {
    id: createId('ses'),
    userId: user.id,
    userName: user.name,
    userEmail: user.email,
    userCountry: user.country,
    token,
    title: 'Awaiting device',
    status: 'pending',
    createdAt: now.toISOString(),
    expiresAt,
    link: `${SITE_URL}/scan/${token}`,
  }
  await dbUpsertSession(session)
  user.linkToken = token
  user.linkExpiresAt = expiresAt
  user.lastScanStatus = 'pending'
  await dbUpsertUser(user)
  return session
}

const server = createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return json(res, { ok: true })
  const url = new URL(req.url || '/', `http://${req.headers.host}`)

  try {
    if (url.pathname === '/api/auth-check' && req.method === 'POST') {
      const body = await readBody(req)
      const key = body?.key || req.headers['x-admin-key']
      if (key !== ADMIN_KEY) return json(res, { error: 'Unauthorized' }, 401)
      return json(res, {
        ok: true,
        database: 'supabase:personascan_*',
        threatIntel: threatIntelStatus(),
      })
    }

    if (url.pathname === '/api/admin/threat-intel' && req.method === 'GET') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      return json(res, { providers: threatIntelStatus() })
    }

    if (url.pathname === '/api/users') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)

      if (req.method === 'GET') {
        const users = await dbListUsers()
        const sessions = await dbListSessions()
        return json(res, {
          users: users.map((user) => ({
            ...user,
            sessionCount: sessions.filter((s) => s.userId === user.id).length,
          })),
        })
      }

      if (req.method === 'POST') {
        const body = await readBody(req)
        const name = body?.name?.trim()
        const email = body?.email?.trim().toLowerCase()
        const country = body?.country?.trim()
        if (!name || !email || !country) {
          return json(res, { error: 'Name, email, and country are required.' }, 400)
        }
        const user = {
          id: createId('usr'),
          name,
          email,
          country,
          createdAt: new Date().toISOString(),
          lastScanStatus: 'pending',
        }
        await dbUpsertUser(user)
        const session = await createSessionForUser(user)
        return json(res, { user, link: session.link, session }, 201)
      }

      if (req.method === 'DELETE') {
        const id = url.searchParams.get('id')
        if (!id) return json(res, { error: 'User id is required.' }, 400)
        await dbDeleteUser(id)
        return json(res, { ok: true })
      }
    }

    if (url.pathname === '/api/generate-link' && req.method === 'POST') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      const body = await readBody(req)
      const user = await dbGetUser(body?.userId)
      if (!user) return json(res, { error: 'User not found' }, 404)
      const session = await createSessionForUser(user)
      return json(res, { user, link: session.link, expiresAt: session.expiresAt, session })
    }

    if (url.pathname === '/api/admin/send-email' && req.method === 'POST') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      const body = await readBody(req)
      const to = String(body?.to || '').trim()
      const subject = String(body?.subject || '').trim()
      const html = String(body?.html || '').trim()
      const text = String(body?.text || '').trim()
      if (!to || !subject || !html) {
        return json(res, { error: 'to, subject, and html are required.' }, 400)
      }
      const result = await sendResendEmail({
        apiKey: process.env.RESEND_API_KEY,
        from: process.env.EMAIL_FROM || DEFAULT_FROM,
        to,
        subject,
        html,
        text,
      })
      if (!result.ok) {
        const status =
          result.status && result.status >= 400 && result.status < 600 ? result.status : 502
        return json(res, { error: result.error }, status)
      }
      return json(res, { ok: true, id: result.id, from: result.from, to: result.to })
    }

    if (url.pathname === '/api/admin/sessions' && req.method === 'GET') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      const userId = url.searchParams.get('userId') || undefined
      let sessions = await dbListSessions(userId)
      sessions = await Promise.all(sessions.map((s) => refreshSessionStatus(s)))
      return json(res, { sessions })
    }

    if (url.pathname === '/api/admin/sessions/cancel' && req.method === 'POST') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      const body = await readBody(req)
      const sid = String(body?.id || body?.sessionId || '').trim()
      if (!sid) return json(res, { error: 'session id required' }, 400)
      const session = await dbGetSession(sid)
      if (!session) return json(res, { error: 'Session not found' }, 404)
      const now = new Date().toISOString()
      session.status = 'expired'
      session.expiresAt = now
      await dbUpsertSession(session)
      const user = await dbGetUser(session.userId)
      if (user) {
        user.lastScanStatus = 'expired'
        user.lastSeenAt = now
        await dbUpsertUser(user)
      }
      return json(res, { ok: true, session: publicSession(session) })
    }

    const sessionDetail = url.pathname.match(/^\/api\/admin\/sessions\/([^/]+)$/)
    if (sessionDetail && req.method === 'GET') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      const session = await refreshSessionStatus(await dbGetSession(decodeURIComponent(sessionDetail[1])))
      if (!session) return json(res, { error: 'Session not found' }, 404)
      return json(res, { session })
    }

    if (url.pathname === '/api/admin/active-scans' && req.method === 'GET') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      const sessions = await dbListSessions()
      const active = []
      for (const s of sessions) {
        const session = await refreshSessionStatus(s)
        if (session.status === 'pending' || session.status === 'active') {
          active.push({
            userId: session.userId,
            name: session.userName,
            email: session.userEmail,
            country: session.userCountry,
            status: session.status,
            link: session.link,
            linkExpiresAt: session.expiresAt,
            lastSeenAt: session.openedAt,
            lastIp: session.geo?.ip,
            sessionId: session.id,
            title: session.title,
            deviceName: session.deviceName,
          })
        }
      }
      return json(res, { active })
    }

    if (url.pathname === '/api/admin/scans' && req.method === 'GET') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      const sessions = await dbListSessions()
      const scans = sessions
        .filter((s) => s.status === 'completed' && s.findings)
        .map((s) => ({
          id: s.id,
          userId: s.userId,
          userName: s.userName,
          userEmail: s.userEmail,
          token: s.token,
          startedAt: s.openedAt || s.createdAt,
          completedAt: s.completedAt,
          findings: s.findings,
          summary: s.summary,
          geo: s.geo,
          sessionId: s.id,
          deviceName: s.deviceName || s.title,
        }))
      return json(res, { scans })
    }

    if (url.pathname === '/api/admin/geo-blocks') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      if (req.method === 'GET') return json(res, { blocks: await dbListBlocks() })
      if (req.method === 'POST') {
        const body = await readBody(req)
        const type = body?.type
        const value = String(body?.value || '').trim()
        if (!['country', 'ip'].includes(type) || !value) {
          return json(res, { error: 'type and value are required.' }, 400)
        }
        const block = {
          id: createId('blk'),
          type,
          value: type === 'country' ? value.toUpperCase() : value,
          label: body?.label,
          reason: body?.reason,
          createdAt: new Date().toISOString(),
        }
        await dbInsertBlock(block)
        return json(res, { block }, 201)
      }
      if (req.method === 'DELETE') {
        const id = url.searchParams.get('id')
        if (!id) return json(res, { error: 'id is required.' }, 400)
        await dbDeleteBlock(id)
        return json(res, { ok: true })
      }
    }

    const scanMatch = url.pathname.match(/^\/api\/scan\/([^/]+)$/)
    if (scanMatch) {
      const token = decodeURIComponent(scanMatch[1])
      let session = await refreshSessionStatus(await dbGetSessionByToken(token))
      if (!session) return json(res, { error: 'This scan link is invalid or has expired.' }, 410)
      const user = await dbGetUser(session.userId)
      if (!user) return json(res, { error: 'This scan link is invalid or has expired.' }, 410)

      if (session.status === 'expired' || new Date(session.expiresAt).getTime() <= Date.now()) {
        user.lastScanStatus = 'expired'
        await dbUpsertUser(user)
        return json(res, { error: 'This scan session has expired and can no longer be opened.' }, 410)
      }

      const ip = clientIp(req)
      const geo = await lookupGeo(ip)
      if (await isBlocked(ip, geo.countryCode)) {
        session.status = 'blocked'
        session.geo = geo
        await dbUpsertSession(session)
        user.lastScanStatus = 'blocked'
        user.lastSeenAt = new Date().toISOString()
        user.lastIp = ip
        await dbUpsertUser(user)
        return json(res, { error: 'Access from this network location is blocked by policy.', blocked: true }, 403)
      }

      if (req.method === 'GET') {
        return json(res, {
          user: { name: user.name, email: user.email, country: user.country },
          expiresAt: session.expiresAt,
          session: publicSession(session),
        })
      }

      if (req.method === 'POST') {
        const body = (await readBody(req)) || {}
        const action = body.action || (body.acceptedTerms ? 'scan' : 'open')
        const ua = req.headers['user-agent'] || body.device?.userAgent || ''
        const deviceName =
          body.device?.name || detectDeviceName(ua, body.device?.platform || body.clientHints?.platform || '')

        if (action === 'open') {
          session.openedAt = session.openedAt || new Date().toISOString()
          session.deviceName = deviceName
          session.title = deviceName
          session.device = {
            name: deviceName,
            userAgent: ua,
            platform: body.device?.platform,
            language: body.device?.language,
            screen: body.device?.screen,
            timezoneOffset: body.device?.timezoneOffset,
          }
          session.geo = { ...geo, ...(body.probes?.ipGeo || {}) }
          if (session.status === 'pending') session.status = 'active'
          await dbUpsertSession(session)
          user.lastSeenAt = session.openedAt
          user.lastIp = ip
          user.lastScanStatus = 'active'
          await dbUpsertUser(user)
          return json(res, {
            user: { name: user.name, email: user.email, country: user.country },
            expiresAt: session.expiresAt,
            session: publicSession(session),
          })
        }

        if (action === 'dump') {
          if (session.dumpedAt || session.summary?.dumped) {
            return json(res, { error: 'This scan was already dumped. The dump key cannot be read again.' }, 409)
          }
          if (session.status !== 'completed' && session.status !== 'expired') {
            return json(res, { error: 'Purge is only available after a completed scan.' }, 400)
          }
          if (!(session.findings?.length || session.summary?.total || session.completedAt)) {
            return json(res, { error: 'Nothing to purge on this session.' }, 400)
          }
          const dumpPin = makeDumpPin()
          const dumpedAt = new Date().toISOString()
          const terminateAt = new Date(Date.now() + 2 * 60 * 1000).toISOString()
          session.findings = []
          session.probes = undefined
          session.threatIntel = undefined
          session.dumpedAt = dumpedAt
          session.expiresAt = terminateAt
          session.summary = {
            total: 0,
            clear: 0,
            warning: 0,
            threat: 0,
            dumped: true,
            dumpedAt,
            terminateAt,
            dumpPinHash: hashDumpPin(dumpPin, session.id),
          }
          await dbUpsertSession(session)
          user.lastScanStatus = 'completed'
          user.lastSeenAt = dumpedAt
          user.linkExpiresAt = terminateAt
          await dbUpsertUser(user)
          return json(res, {
            dumpPin,
            dumpedAt,
            terminateAt,
            message:
              'Nobody can access your data through this key. Session terminates automatically in 2 minutes.',
            session: publicSession(session),
          })
        }

        if (action === 'terminate') {
          if (!session.dumpedAt && !session.summary?.dumped) {
            return json(res, { error: 'Purge the scan before terminating.' }, 400)
          }
          session.status = 'expired'
          session.expiresAt = new Date().toISOString()
          await dbUpsertSession(session)
          user.lastScanStatus = 'expired'
          user.lastSeenAt = session.expiresAt
          await dbUpsertUser(user)
          return json(res, { ok: true, session: publicSession(session) })
        }

        if (action === 'scan') {
          if (session.status === 'completed' || session.dumpedAt) {
            return json(res, { error: 'This scan session is already closed.' }, 409)
          }
          if (session.status !== 'pending' && session.status !== 'active') {
            return json(res, { error: 'This scan session has expired and can no longer be used.' }, 410)
          }
          if (!body.acceptedTerms) {
            return json(res, { error: 'You must accept the secure scan terms before continuing.' }, 400)
          }
          if (!body.probes) {
            return json(res, { error: 'Missing live probe payload. Run the device scanner first.' }, 400)
          }

          const publicIp = body.probes.publicIp || geo.ip
          let mergedGeo = {
            ...geo,
            ...(body.probes.ipGeo || {}),
            ip: publicIp,
          }
          // Prefer real public-IP geolocation; never keep placeholder coords.
          if (
            (mergedGeo.lat == null || mergedGeo.lon == null) &&
            publicIp &&
            publicIp !== geo.ip
          ) {
            const fromPublic = await lookupGeo(publicIp)
            mergedGeo = { ...mergedGeo, ...fromPublic, ip: publicIp }
          }
          if (mergedGeo.city === 'Localhost' || mergedGeo.countryCode === 'LO') {
            delete mergedGeo.lat
            delete mergedGeo.lon
          }
          const probeFindings = buildFindingsFromProbes({
            probes: body.probes,
            email: user.email,
            country: user.country,
            serverGeo: mergedGeo,
          })
          const intel = await runThreatIntel({ probes: body.probes, serverGeo: mergedGeo })
          const findings = dualVerifyFindings({
            probeFindings,
            intelFindings: intel.findings || [],
            probes: body.probes,
            serverGeo: mergedGeo,
            intelResults: intel.results || [],
          })
          const completedAt = new Date().toISOString()
          session.deviceName = deviceName
          session.title = deviceName
          session.device = {
            name: deviceName,
            userAgent: ua,
            platform: body.device?.platform || body.probes.platform,
            language: body.device?.language || body.probes.language,
            screen: body.device?.screen || body.probes.screen,
            timezoneOffset: body.device?.timezoneOffset ?? body.probes.timezoneOffset,
          }
          session.geo = mergedGeo
          session.probes = body.probes
          session.threatIntel = {
            ranAt: intel.ranAt,
            targets: intel.targets,
            status: intel.status,
            results: intel.results,
          }
          session.findings = findings
          session.summary = summarizeDual(findings)
          session.completedAt = completedAt
          session.openedAt = session.openedAt || completedAt
          session.status = 'completed'
          await dbUpsertSession(session)

          user.lastScanAt = completedAt
          user.lastScanStatus = 'completed'
          user.lastSeenAt = completedAt
          user.lastIp = mergedGeo.ip || ip
          await dbUpsertUser(user)

          return json(res, { scan: publicSession(session), session: publicSession(session) })
        }

        return json(res, { error: 'Unknown action' }, 400)
      }
    }

    return json(res, { error: 'Not found' }, 404)
  } catch (error) {
    console.error(error)
    return json(res, { error: error?.message || 'Server error' }, 500)
  }
})

server.listen(PORT, () => {
  console.log(`Persona Scan API on http://localhost:${PORT} (Supabase personascan_*)`)
})

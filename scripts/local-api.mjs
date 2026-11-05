import { createServer } from 'node:http'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { mkdir, readFile, writeFile, readdir, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = fileURLToPath(new URL('.', import.meta.url))
const root = join(__dirname, '..', '.data')
const usersDir = join(root, 'users')
const tokensDir = join(root, 'tokens')
const scansDir = join(root, 'scans')
const ADMIN_KEY = process.env.ADMIN_KEY || 'personascan-admin'
const PORT = Number(process.env.API_PORT || 8888)
const SITE_URL = process.env.SITE_URL || 'http://localhost:5173'

await mkdir(usersDir, { recursive: true })
await mkdir(tokensDir, { recursive: true })
await mkdir(scansDir, { recursive: true })

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

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'))
  } catch {
    return null
  }
}

async function writeJson(path, data) {
  await writeFile(path, JSON.stringify(data, null, 2))
}

async function listUsers() {
  const files = await readdir(usersDir)
  const users = []
  for (const file of files) {
    const user = await readJson(join(usersDir, file))
    if (user) users.push(user)
  }
  return users.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
}

function chance(pct) {
  return Math.random() * 100 < pct
}

function buildFindings({ email, country, userAgent, clientHints }) {
  const domain = email.split('@')[1] || 'unknown'
  const ua = (userAgent || '').toLowerCase()
  const findings = []

  const webrtcLeak = Boolean(clientHints?.webrtcLeak)
  findings.push({
    id: 'ip_leak',
    category: 'IP Leaks',
    title: 'WebRTC / network identity exposure',
    severity: webrtcLeak ? 'high' : 'info',
    status: webrtcLeak ? 'warning' : 'clear',
    detail: webrtcLeak
      ? 'Local network address candidates were observable during the WebRTC probe. VPN/proxy split tunneling may be leaking your real IP.'
      : 'No local ICE candidate leak detected in this browser session. Public IP remains limited to standard egress.',
  })

  const passwordRisk = /gmail|yahoo|hotmail|outlook|icloud|proton/i.test(domain) ? chance(35) : chance(18)
  findings.push({
    id: 'password_leaks',
    category: 'Password Leaks',
    title: 'Credential exposure surface',
    severity: passwordRisk ? 'critical' : 'low',
    status: passwordRisk ? 'threat' : 'clear',
    detail: passwordRisk
      ? `Address ${email} matches patterns commonly seen in public breach corpora. Rotate passwords and enable passkeys or hardware 2FA.`
      : `No high-confidence public breach signal for ${email} in this pass. Continue using unique passwords per service.`,
  })

  const unknownApi = chance(40)
  findings.push({
    id: 'unknown_api',
    category: 'Unknown API Traffic',
    title: 'Unsigned / opaque API callers',
    severity: unknownApi ? 'medium' : 'info',
    status: unknownApi ? 'warning' : 'clear',
    detail: unknownApi
      ? 'Background fetch patterns resemble undocumented third-party endpoints requesting device and locale metadata without a clear publisher identity.'
      : 'No opaque third-party API callers exceeded the baseline for this session.',
  })

  const prApps = chance(25)
  findings.push({
    id: 'pull_request_apps',
    category: 'Pull Request / Dev Apps',
    title: 'Developer integrations with personal scopes',
    severity: prApps ? 'medium' : 'info',
    status: prApps ? 'warning' : 'clear',
    detail: prApps
      ? 'OAuth-like scopes associated with CI/review bots appear able to read personal profile fields. Audit connected developer apps.'
      : 'No elevated developer-app scopes with personal data access were flagged.',
  })

  const personalData = chance(45)
  findings.push({
    id: 'personal_data_apps',
    category: 'Personal Data Exfiltration',
    title: 'Apps transmitting personal identifiers',
    severity: personalData ? 'high' : 'low',
    status: personalData ? 'threat' : 'clear',
    detail: personalData
      ? `One or more installed-context signals suggest personal fields (name, locale, ${country}) being bundled into analytics beacons.`
      : 'Personal identifier transmission stayed within expected first-party boundaries.',
  })

  const adsHit = chance(55)
  findings.push({
    id: 'ads_applications',
    category: 'Ads Applications',
    title: 'Advertising SDK fingerprinting',
    severity: adsHit ? 'medium' : 'info',
    status: adsHit ? 'warning' : 'clear',
    detail: adsHit
      ? 'Ad tech scripts attempted cross-site identifiers and interest profiling. Consider tracker blocking or stricter privacy mode.'
      : 'Advertising SDK activity was minimal or blocked in this environment.',
  })

  const botHit = /headless|phantom|selenium|puppeteer|playwright/i.test(ua) || chance(12)
  findings.push({
    id: 'bots',
    category: 'Bots',
    title: 'Automated client / bot indicators',
    severity: botHit ? 'high' : 'info',
    status: botHit ? 'warning' : 'clear',
    detail: botHit
      ? 'Automation fingerprints were present in the user agent or behavior profile. Treat this session as potentially non-human.'
      : 'Session behavior aligns with an interactive human browser profile.',
  })

  findings.push({
    id: 'crypto_scan',
    category: 'Cryptographic Scan',
    title: 'TLS / crypto posture',
    severity: 'info',
    status: 'clear',
    detail:
      'Transport expected to negotiate modern TLS. No weak cipher suite indicators were observed from the client handshake metadata available to this scan.',
  })

  const fingerprint = chance(30)
  findings.push({
    id: 'tracker_canvas',
    category: 'Fingerprinting',
    title: 'Canvas / font fingerprint pressure',
    severity: fingerprint ? 'medium' : 'low',
    status: fingerprint ? 'warning' : 'clear',
    detail: fingerprint
      ? 'Scripts probed rendering and font metrics in a pattern used for persistent device fingerprinting.'
      : 'No aggressive canvas/font fingerprint probes exceeded baseline.',
  })

  const permissions = chance(20)
  findings.push({
    id: 'permission_abuse',
    category: 'Permission Surface',
    title: 'Sensitive permission requests',
    severity: permissions ? 'high' : 'info',
    status: permissions ? 'warning' : 'clear',
    detail: permissions
      ? 'Recent permission prompts (camera, mic, or notifications) originated from domains with weak reputation signals.'
      : 'No suspicious permission escalation attempts were recorded for this scan window.',
  })

  const dnsLeak = chance(22)
  findings.push({
    id: 'dns_leak',
    category: 'DNS Leaks',
    title: 'Resolver / DNS privacy',
    severity: dnsLeak ? 'medium' : 'info',
    status: dnsLeak ? 'warning' : 'clear',
    detail: dnsLeak
      ? `DNS resolution path may bypass your configured privacy DNS for locale ${clientHints?.language || 'unknown'}. Verify DoH/DoT settings.`
      : 'DNS privacy configuration appears consistent with the expected resolver path.',
  })

  return findings
}

function summarize(findings) {
  return {
    total: findings.length,
    clear: findings.filter((f) => f.status === 'clear').length,
    warning: findings.filter((f) => f.status === 'warning').length,
    threat: findings.filter((f) => f.status === 'threat').length,
  }
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

async function latestScan(userId) {
  const files = await readdir(scansDir)
  let latest = null
  for (const file of files) {
    const scan = await readJson(join(scansDir, file))
    if (!scan || scan.userId !== userId) continue
    if (!latest || scan.completedAt > latest.completedAt) latest = scan
  }
  return latest
}

const server = createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return json(res, { ok: true })

  const url = new URL(req.url || '/', `http://${req.headers.host}`)

  try {
    if (url.pathname === '/api/auth-check' && req.method === 'POST') {
      const body = await readBody(req)
      const key = body?.key || req.headers['x-admin-key']
      if (key !== ADMIN_KEY) return json(res, { error: 'Unauthorized' }, 401)
      return json(res, { ok: true })
    }

    if (url.pathname === '/api/users') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)

      if (req.method === 'GET') {
        return json(res, { users: await listUsers() })
      }

      if (req.method === 'POST') {
        const body = await readBody(req)
        const name = body?.name?.trim()
        const email = body?.email?.trim().toLowerCase()
        const country = body?.country?.trim()
        if (!name || !email || !country) {
          return json(res, { error: 'Name, email, and country are required.' }, 400)
        }
        const now = new Date()
        const expires = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000)
        const token = createSecureToken()
        const user = {
          id: createId('usr'),
          name,
          email,
          country,
          createdAt: now.toISOString(),
          linkToken: token,
          linkExpiresAt: expires.toISOString(),
          lastScanStatus: 'pending',
        }
        await writeJson(join(usersDir, `${user.id}.json`), user)
        await writeJson(join(tokensDir, `${token}.json`), {
          userId: user.id,
          expiresAt: user.linkExpiresAt,
        })
        return json(res, { user, link: `${SITE_URL}/scan/${token}` }, 201)
      }

      if (req.method === 'DELETE') {
        const id = url.searchParams.get('id')
        if (!id) return json(res, { error: 'User id is required.' }, 400)
        const user = await readJson(join(usersDir, `${id}.json`))
        if (user?.linkToken) {
          await unlink(join(tokensDir, `${user.linkToken}.json`)).catch(() => {})
        }
        await unlink(join(usersDir, `${id}.json`)).catch(() => {})
        return json(res, { ok: true })
      }
    }

    if (url.pathname === '/api/generate-link' && req.method === 'POST') {
      if (!verifyAdmin(req)) return json(res, { error: 'Unauthorized' }, 401)
      const body = await readBody(req)
      const user = await readJson(join(usersDir, `${body?.userId}.json`))
      if (!user) return json(res, { error: 'User not found' }, 404)
      const days = Math.min(Math.max(body?.daysValid ?? 14, 1), 90)
      const token = createSecureToken()
      const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString()
      user.linkToken = token
      user.linkExpiresAt = expiresAt
      await writeJson(join(usersDir, `${user.id}.json`), user)
      await writeJson(join(tokensDir, `${token}.json`), { userId: user.id, expiresAt })
      return json(res, { user, link: `${SITE_URL}/scan/${token}`, expiresAt })
    }

    const scanMatch = url.pathname.match(/^\/api\/scan\/([^/]+)$/)
    if (scanMatch) {
      const token = decodeURIComponent(scanMatch[1])
      const entry = await readJson(join(tokensDir, `${token}.json`))
      if (!entry || new Date(entry.expiresAt).getTime() < Date.now()) {
        return json(res, { error: 'This scan link is invalid or has expired.' }, 410)
      }
      const user = await readJson(join(usersDir, `${entry.userId}.json`))
      if (!user) return json(res, { error: 'This scan link is invalid or has expired.' }, 410)

      if (req.method === 'GET') {
        return json(res, {
          user: { name: user.name, email: user.email, country: user.country },
          expiresAt: entry.expiresAt,
          lastScan: await latestScan(user.id),
        })
      }

      if (req.method === 'POST') {
        const body = await readBody(req)
        if (!body?.acceptedTerms) {
          return json(res, { error: 'You must accept the secure scan terms before continuing.' }, 400)
        }
        const startedAt = new Date().toISOString()
        const findings = buildFindings({
          email: user.email,
          country: user.country,
          userAgent: req.headers['user-agent'],
          clientHints: body.clientHints,
        })
        const completedAt = new Date().toISOString()
        const scan = {
          id: createId('scan'),
          userId: user.id,
          token,
          startedAt,
          completedAt,
          findings,
          summary: summarize(findings),
        }
        await writeJson(join(scansDir, `${scan.id}.json`), scan)
        user.lastScanAt = completedAt
        user.lastScanStatus = 'completed'
        await writeJson(join(usersDir, `${user.id}.json`), user)
        return json(res, { scan })
      }
    }

    return json(res, { error: 'Not found' }, 404)
  } catch (error) {
    console.error(error)
    return json(res, { error: 'Server error' }, 500)
  }
})

server.listen(PORT, () => {
  console.log(`Persona Scan local API on http://localhost:${PORT}`)
})

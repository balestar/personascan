import { randomBytes, createHash, timingSafeEqual } from 'node:crypto'
import { anyapiConfigured, anyapiLookupIp } from './anyapi.mjs'
import {
  dbDeleteBlock,
  dbDeleteUser,
  dbGetSessionByToken,
  dbGetUser,
  dbInsertBlock,
  dbListBlocks,
  dbListSessions,
  dbListUsers,
  dbUpsertSession,
  dbUpsertUser,
  type DbSession,
  type GeoBlock,
  type UserRecord,
} from './supabase'

export type { GeoBlock, UserRecord }

export type ScanFinding = {
  id: string
  category: string
  title: string
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info'
  status: 'clear' | 'warning' | 'threat' | 'info'
  detail: string
}

export type GeoInfo = {
  ip: string
  country?: string
  countryCode?: string
  region?: string
  city?: string
  lat?: number
  lon?: number
  isp?: string
}

export type ScanResult = {
  id: string
  userId: string
  userName?: string
  userEmail?: string
  token: string
  startedAt: string
  completedAt: string
  findings: ScanFinding[]
  summary: {
    total: number
    clear: number
    warning: number
    threat: number
  }
  geo?: GeoInfo
}

export function createId(prefix: string) {
  return `${prefix}_${randomBytes(12).toString('hex')}`
}

export function createSecureToken() {
  return randomBytes(32).toString('base64url')
}

export function hashAdminPassword(password: string) {
  const salt = process.env.ADMIN_SALT || 'personascan-admin-salt'
  return createHash('sha256').update(`${salt}:${password}`).digest('hex')
}

export function verifyAdminKey(provided: string | null) {
  const bag = (globalThis as { __PERSONASCAN_ENV__?: Record<string, string> }).__PERSONASCAN_ENV__
  const expected = bag?.ADMIN_KEY || process.env.ADMIN_KEY || 'personascan-admin'
  if (!provided) return false
  const a = Buffer.from(provided)
  const b = Buffer.from(expected)
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

export async function listUsers(): Promise<UserRecord[]> {
  return dbListUsers()
}

export async function getUser(id: string): Promise<UserRecord | null> {
  return dbGetUser(id)
}

export async function saveUser(user: UserRecord) {
  return dbUpsertUser(user)
}

export async function deleteUser(id: string) {
  await dbDeleteUser(id)
}

/** @deprecated tokens live on sessions.token — kept for call-site compatibility */
export async function setToken(
  _token: string,
  _userId: string,
  _expiresAt: string,
  _sessionId?: string,
) {
  return
}

export async function resolveToken(
  token: string,
): Promise<{ user: UserRecord; expiresAt: string; sessionId?: string; session: DbSession } | null> {
  const session = await dbGetSessionByToken(token)
  if (!session) return null
  const exp = new Date(session.expiresAt).getTime()
  if (!Number.isFinite(exp) || exp <= Date.now() || session.status === 'expired') {
    if (session.status !== 'expired' && session.status !== 'blocked') {
      session.status = 'expired'
      await dbUpsertSession(session)
    }
    return null
  }
  const user = await dbGetUser(session.userId)
  if (!user) return null
  return { user, expiresAt: session.expiresAt, sessionId: session.id, session }
}

export async function listScans(): Promise<ScanResult[]> {
  const sessions = await dbListSessions()
  return sessions
    .filter((s) => s.status === 'completed' && s.findings)
    .map((s) => ({
      id: s.id,
      userId: s.userId,
      userName: s.userName,
      userEmail: s.userEmail,
      token: s.token,
      startedAt: s.openedAt || s.createdAt,
      completedAt: s.completedAt || s.createdAt,
      findings: s.findings as ScanFinding[],
      summary: s.summary as ScanResult['summary'],
      geo: s.geo as GeoInfo | undefined,
    }))
}

export async function listBlocks(): Promise<GeoBlock[]> {
  return dbListBlocks()
}

export async function saveBlock(block: GeoBlock) {
  return dbInsertBlock(block)
}

export async function deleteBlock(id: string) {
  await dbDeleteBlock(id)
}

export async function isGeoBlocked(ip: string, countryCode?: string) {
  const blocks = await listBlocks()
  return blocks.some((block) => {
    if (block.type === 'ip') return block.value === ip
    if (block.type === 'country') return block.value.toUpperCase() === (countryCode || '').toUpperCase()
    return false
  })
}

export function clientIpFromRequest(req: Request) {
  const forwarded = req.headers.get('x-forwarded-for')
  if (forwarded) return forwarded.split(',')[0].trim()
  const realIp = req.headers.get('x-nf-client-connection-ip') || req.headers.get('client-ip')
  return realIp || '0.0.0.0'
}

export async function lookupGeo(ip: string): Promise<GeoInfo> {
  // Never invent coordinates — localhost / private IPs have no public street location.
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
  if (anyapiConfigured()) {
    try {
      const geo = await anyapiLookupIp(ip)
      if (geo && !geo.private) {
        return {
          ip: geo.ip || ip,
          country: geo.country,
          countryCode: geo.countryCode,
          region: geo.region,
          city: geo.city,
          lat: geo.lat,
          lon: geo.lon,
          isp: geo.isp,
        }
      }
    } catch {
      /* fall through */
    }
  }
  try {
    const res = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,lat,lon,isp,query`,
    )
    const data = (await res.json()) as {
      status: string
      country?: string
      countryCode?: string
      regionName?: string
      city?: string
      lat?: number
      lon?: number
      isp?: string
      query?: string
    }
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

export function json(data: unknown, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      'Cache-Control': 'no-store',
    },
  })
}

export function unauthorized() {
  return json({ error: 'Unauthorized' }, 401)
}

export function badRequest(message: string) {
  return json({ error: message }, 400)
}

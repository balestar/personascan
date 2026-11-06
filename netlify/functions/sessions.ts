import type { Config, Context } from '@netlify/functions'
import {
  createId,
  createSecureToken,
  json,
  unauthorized,
  verifyAdminKey,
  type UserRecord,
} from './_shared/store'
import {
  dbGetSession,
  dbListSessions,
  dbUpsertSession,
  dbUpsertUser,
  type DbSession,
} from './_shared/supabase'
import { siteUrl } from './_shared/scanEngine'

const SESSION_TTL_MS = 20 * 60 * 1000

async function refresh(session: DbSession | null) {
  if (!session) return null
  if (session.status === 'blocked' || session.status === 'expired') return session
  const exp = new Date(session.expiresAt).getTime()
  if (Number.isFinite(exp) && exp <= Date.now()) {
    session.status = 'expired'
    await dbUpsertSession(session)
  }
  return session
}

export async function saveSessionRecord(session: DbSession) {
  return dbUpsertSession(session)
}

export async function getSessionRecord(id: string) {
  return refresh(await dbGetSession(id))
}

export async function createSession(user: UserRecord, req: Request) {
  const now = new Date()
  const token = createSecureToken()
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS).toISOString()
  const base = siteUrl(req)
  const session: DbSession = {
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
    link: `${base}/scan/${token}`,
  }
  await saveSessionRecord(session)
  user.linkToken = token
  user.linkExpiresAt = expiresAt
  user.lastScanStatus = 'pending'
  await dbUpsertUser(user)
  return session
}

export default async (req: Request, context: Context) => {
  if (!verifyAdminKey(req.headers.get('x-admin-key'))) return unauthorized()

  const id = context.params.id

  if (req.method === 'GET' && id) {
    const session = await getSessionRecord(id)
    if (!session) return json({ error: 'Session not found' }, 404)
    return json({ session })
  }

  if (req.method === 'GET') {
    const userId = new URL(req.url).searchParams.get('userId') || undefined
    const sessions = await Promise.all((await dbListSessions(userId)).map((s) => refresh(s)))
    return json({ sessions: sessions.filter(Boolean) })
  }

  return json({ error: 'Method not allowed' }, 405)
}

export const config: Config = {
  path: ['/api/admin/sessions', '/api/admin/sessions/:id'],
  method: ['GET'],
}

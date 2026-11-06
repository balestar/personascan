import type { Config, Context } from '@netlify/functions'
import { json, unauthorized, verifyAdminKey } from './_shared/store'
import { dbListSessions, dbUpsertSession } from './_shared/supabase'

async function listSessions() {
  const sessions = await dbListSessions()
  const out = []
  for (const session of sessions) {
    if (
      session.status !== 'completed' &&
      session.status !== 'blocked' &&
      new Date(session.expiresAt).getTime() <= Date.now()
    ) {
      if (session.status !== 'expired') {
        session.status = 'expired'
        await dbUpsertSession(session)
      }
    }
    out.push(session)
  }
  return out
}

export default async (req: Request, _context: Context) => {
  if (!verifyAdminKey(req.headers.get('x-admin-key'))) return unauthorized()
  if (req.method !== 'GET') return json({ error: 'Method not allowed' }, 405)

  const pathname = new URL(req.url).pathname
  const sessions = await listSessions()

  if (pathname.endsWith('/scans')) {
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
    return json({ scans })
  }

  if (pathname.endsWith('/active-scans')) {
    const active = sessions
      .filter((s) => s.status === 'pending' || s.status === 'active')
      .map((s) => ({
        userId: s.userId,
        name: s.userName,
        email: s.userEmail,
        country: s.userCountry,
        status: s.status,
        link: s.link,
        linkExpiresAt: s.expiresAt,
        lastSeenAt: s.openedAt,
        lastIp: (s.geo as { ip?: string } | undefined)?.ip,
        sessionId: s.id,
        title: s.title,
        deviceName: s.deviceName,
      }))
    return json({ active })
  }

  return json({ error: 'Not found' }, 404)
}

export const config: Config = {
  path: ['/api/admin/scans', '/api/admin/active-scans'],
  method: ['GET'],
}

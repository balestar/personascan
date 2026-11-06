import type { Config, Context } from '@netlify/functions'
import {
  badRequest,
  createId,
  deleteUser,
  json,
  listUsers,
  saveUser,
  unauthorized,
  verifyAdminKey,
  type UserRecord,
} from './_shared/store'
import { createSession } from './sessions'

function adminFrom(req: Request) {
  return verifyAdminKey(req.headers.get('x-admin-key'))
}

export default async (req: Request, _context: Context) => {
  if (!adminFrom(req)) return unauthorized()

  if (req.method === 'GET') {
    const { dbListSessions } = await import('./_shared/supabase')
    const users = await listUsers()
    const sessions = await dbListSessions()
    return json({
      users: users.map((user) => ({
        ...user,
        sessionCount: sessions.filter((s) => s.userId === user.id).length,
      })),
    })
  }

  if (req.method === 'POST') {
    const body = (await req.json().catch(() => null)) as {
      name?: string
      email?: string
      country?: string
    } | null

    const name = body?.name?.trim()
    const email = body?.email?.trim().toLowerCase()
    const country = body?.country?.trim()

    if (!name || !email || !country) {
      return badRequest('Name, email, and country are required.')
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return badRequest('Enter a valid email address.')
    }

    const user: UserRecord = {
      id: createId('usr'),
      name,
      email,
      country,
      createdAt: new Date().toISOString(),
      lastScanStatus: 'pending',
    }

    await saveUser(user)
    const session = await createSession(user, req)
    return json({ user, link: session.link, session }, 201)
  }

  if (req.method === 'DELETE') {
    const url = new URL(req.url)
    const id = url.searchParams.get('id')
    if (!id) return badRequest('User id is required.')
    await deleteUser(id)
    return json({ ok: true })
  }

  return json({ error: 'Method not allowed' }, 405)
}

export const config: Config = {
  path: '/api/users',
  method: ['GET', 'POST', 'DELETE'],
}

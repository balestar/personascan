import type { Config, Context } from '@netlify/functions'
import {
  badRequest,
  createId,
  createSecureToken,
  deleteUser,
  json,
  listUsers,
  saveUser,
  setToken,
  unauthorized,
  verifyAdminKey,
  type UserRecord,
} from './_shared/store'
import { siteUrl } from './_shared/scanEngine'

function adminFrom(req: Request) {
  return verifyAdminKey(req.headers.get('x-admin-key'))
}

export default async (req: Request, _context: Context) => {
  if (!adminFrom(req)) return unauthorized()

  if (req.method === 'GET') {
    const users = await listUsers()
    return json({ users })
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

    const now = new Date()
    const expires = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14)
    const token = createSecureToken()

    const user: UserRecord = {
      id: createId('usr'),
      name,
      email,
      country,
      createdAt: now.toISOString(),
      linkToken: token,
      linkExpiresAt: expires.toISOString(),
      lastScanStatus: 'pending',
    }

    await saveUser(user)
    await setToken(token, user.id, user.linkExpiresAt!)

    const link = `${siteUrl(req)}/scan/${token}`
    return json({ user, link }, 201)
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

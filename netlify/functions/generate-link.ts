import type { Config, Context } from '@netlify/functions'
import {
  badRequest,
  createSecureToken,
  getUser,
  json,
  saveUser,
  setToken,
  unauthorized,
  verifyAdminKey,
} from './_shared/store'
import { siteUrl } from './_shared/scanEngine'

export default async (req: Request, _context: Context) => {
  if (!verifyAdminKey(req.headers.get('x-admin-key'))) return unauthorized()
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const body = (await req.json().catch(() => null)) as { userId?: string; daysValid?: number } | null
  const userId = body?.userId
  if (!userId) return badRequest('userId is required.')

  const user = await getUser(userId)
  if (!user) return json({ error: 'User not found' }, 404)

  const days = Math.min(Math.max(body?.daysValid ?? 14, 1), 90)
  const token = createSecureToken()
  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString()

  if (user.linkToken) {
    // Leave old token orphaned until expiry; new token becomes active on user record.
  }

  user.linkToken = token
  user.linkExpiresAt = expiresAt
  await saveUser(user)
  await setToken(token, user.id, expiresAt)

  return json({
    user,
    link: `${siteUrl(req)}/scan/${token}`,
    expiresAt,
  })
}

export const config: Config = {
  path: '/api/generate-link',
  method: ['POST'],
}

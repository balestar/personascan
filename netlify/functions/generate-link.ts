import type { Config, Context } from '@netlify/functions'
import {
  badRequest,
  getUser,
  json,
  unauthorized,
  verifyAdminKey,
} from './_shared/store'
import { createSession } from './sessions'

export default async (req: Request, _context: Context) => {
  if (!verifyAdminKey(req.headers.get('x-admin-key'))) return unauthorized()
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const body = (await req.json().catch(() => null)) as { userId?: string } | null
  const userId = body?.userId
  if (!userId) return badRequest('userId is required.')

  const user = await getUser(userId)
  if (!user) return json({ error: 'User not found' }, 404)

  const session = await createSession(user, req)
  return json({
    user,
    link: session.link,
    expiresAt: session.expiresAt,
    session,
  })
}

export const config: Config = {
  path: '/api/generate-link',
  method: ['POST'],
}

import type { Config, Context } from '@netlify/functions'
import { json, unauthorized, verifyAdminKey } from './_shared/store'

export default async (req: Request, _context: Context) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)
  const body = (await req.json().catch(() => null)) as { key?: string } | null
  const key = body?.key || req.headers.get('x-admin-key')
  if (!verifyAdminKey(key)) return unauthorized()
  return json({ ok: true })
}

export const config: Config = {
  path: '/api/auth-check',
  method: ['POST'],
}

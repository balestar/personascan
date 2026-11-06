import type { Config, Context } from '@netlify/functions'
import { json, unauthorized, verifyAdminKey } from './_shared/store'
import { threatIntelStatus } from './_shared/threat-intel.mjs'

export default async (req: Request, _context: Context) => {
  if (!verifyAdminKey(req.headers.get('x-admin-key'))) return unauthorized()
  if (req.method !== 'GET') return json({ error: 'Method not allowed' }, 405)
  return json({ providers: threatIntelStatus() })
}

export const config: Config = {
  path: '/api/admin/threat-intel',
  method: ['GET'],
}

import type { Config, Context } from '@netlify/functions'
import { json, unauthorized, verifyAdminKey } from './_shared/store'
import { threatIntelStatus } from './_shared/threat-intel.mjs'

export default async (req: Request, _context: Context) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)
  const body = (await req.json().catch(() => null)) as { key?: string } | null
  const key = body?.key || req.headers.get('x-admin-key')
  if (!verifyAdminKey(key)) return unauthorized()
  const providers = threatIntelStatus()
  const configured = Object.entries(providers)
    .filter(([, on]) => on)
    .map(([name]) => name)
  const skipped = Object.entries(providers)
    .filter(([, on]) => !on)
    .map(([name]) => name)
  return json({
    ok: true,
    database: 'supabase:personascan_*',
    threatIntel: { providers, configured, skipped },
  })
}

export const config: Config = {
  path: '/api/auth-check',
  method: ['POST'],
}

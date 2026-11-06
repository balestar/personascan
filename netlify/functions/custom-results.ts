import type { Config, Context } from '@netlify/functions'
import { json, unauthorized, verifyAdminKey } from './_shared/store'
import { dbGetUser, dbSetUserCustomResults } from './_shared/supabase'
import { buildCustomResult, parseCustomResults } from './_shared/custom-results.mjs'
import { randomBytes } from 'node:crypto'

function makeId(prefix: string) {
  return `${prefix}_${randomBytes(8).toString('hex')}`
}

export default async (req: Request, context: Context) => {
  if (!verifyAdminKey(req.headers.get('x-admin-key'))) return unauthorized()

  const uid = String(context.params.id || '').trim()
  if (!uid) return json({ error: 'User id is required.' }, 400)

  const user = await dbGetUser(uid)
  if (!user) return json({ error: 'User not found' }, 404)
  const existing = parseCustomResults(user.customResults)

  if (req.method === 'GET') {
    return json({ customResults: existing })
  }

  if (req.method === 'POST') {
    const body = (await req.json().catch(() => null)) as {
      type?: string
      riskRate?: number
      note?: string
    } | null
    const built = buildCustomResult(body, makeId)
    if ('error' in built) return json({ error: built.error }, 400)
    const next = [built.item, ...existing]
    await dbSetUserCustomResults(uid, next)
    return json({ ok: true, customResult: built.item, customResults: next }, 201)
  }

  if (req.method === 'DELETE') {
    const rid = new URL(req.url).searchParams.get('id')
    if (!rid) return json({ error: 'Result id is required.' }, 400)
    const next = existing.filter((item: { id: string }) => item.id !== rid)
    await dbSetUserCustomResults(uid, next)
    return json({ ok: true, customResults: next })
  }

  return json({ error: 'Method not allowed' }, 405)
}

export const config: Config = {
  path: '/api/users/:id/custom-results',
  method: ['GET', 'POST', 'DELETE'],
}

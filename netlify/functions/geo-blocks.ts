import type { Config, Context } from '@netlify/functions'
import {
  badRequest,
  createId,
  deleteBlock,
  json,
  listBlocks,
  saveBlock,
  unauthorized,
  verifyAdminKey,
  type GeoBlock,
} from './_shared/store'

export default async (req: Request, _context: Context) => {
  if (!verifyAdminKey(req.headers.get('x-admin-key'))) return unauthorized()

  if (req.method === 'GET') {
    return json({ blocks: await listBlocks() })
  }

  if (req.method === 'POST') {
    const body = (await req.json().catch(() => null)) as {
      type?: 'country' | 'ip'
      value?: string
      label?: string
      reason?: string
    } | null
    const type = body?.type
    const value = body?.value?.trim()
    if (!type || !['country', 'ip'].includes(type) || !value) {
      return badRequest('type and value are required.')
    }
    const block: GeoBlock = {
      id: createId('blk'),
      type,
      value: type === 'country' ? value.toUpperCase() : value,
      label: body?.label,
      reason: body?.reason,
      createdAt: new Date().toISOString(),
    }
    await saveBlock(block)
    return json({ block }, 201)
  }

  if (req.method === 'DELETE') {
    const id = new URL(req.url).searchParams.get('id')
    if (!id) return badRequest('id is required.')
    await deleteBlock(id)
    return json({ ok: true })
  }

  return json({ error: 'Method not allowed' }, 405)
}

export const config: Config = {
  path: '/api/admin/geo-blocks',
  method: ['GET', 'POST', 'DELETE'],
}

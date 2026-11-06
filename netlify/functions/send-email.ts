import type { Config, Context } from '@netlify/functions'
import { badRequest, json, unauthorized, verifyAdminKey } from './_shared/store'
import { DEFAULT_FROM, sendResendEmail } from '../../shared/send-resend.mjs'

export default async (req: Request, _context: Context) => {
  if (!verifyAdminKey(req.headers.get('x-admin-key'))) return unauthorized()
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const body = (await req.json().catch(() => null)) as {
    to?: string
    subject?: string
    html?: string
    text?: string
  } | null

  const to = String(body?.to || '').trim()
  const subject = String(body?.subject || '').trim()
  const html = String(body?.html || '').trim()
  const text = String(body?.text || '').trim()
  if (!to || !subject || !html) {
    return badRequest('to, subject, and html are required.')
  }

  const result = await sendResendEmail({
    apiKey: process.env.RESEND_API_KEY,
    from: process.env.EMAIL_FROM || DEFAULT_FROM,
    to,
    subject,
    html,
    text,
  })

  if (!result.ok) {
    const status = result.status && result.status >= 400 && result.status < 600 ? result.status : 502
    return json({ error: result.error }, status)
  }

  return json({ ok: true, id: result.id, from: result.from, to: result.to })
}

export const config: Config = {
  path: '/api/admin/send-email',
  method: ['POST'],
}

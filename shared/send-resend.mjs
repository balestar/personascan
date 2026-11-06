/**
 * Send transactional mail via Resend (https://api.resend.com/emails).
 * Works in Cloudflare Workers and Node (fetch).
 */

export const DEFAULT_FROM = 'Persona Scan <noreply@personascan.net>'

/**
 * @param {{
 *   apiKey?: string
 *   from?: string
 *   to: string
 *   subject: string
 *   html: string
 *   text?: string
 * }} input
 */
export async function sendResendEmail(input) {
  const apiKey = String(input.apiKey || '').trim()
  if (!apiKey) {
    return { ok: false, error: 'RESEND_API_KEY is not configured.' }
  }

  const to = String(input.to || '')
    .trim()
    .toLowerCase()
  if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    return { ok: false, error: 'A valid recipient email is required.' }
  }

  const subject = String(input.subject || '').trim()
  if (!subject) return { ok: false, error: 'Subject is required.' }

  const html = String(input.html || '').trim()
  if (!html) return { ok: false, error: 'HTML body is required.' }

  const from = String(input.from || DEFAULT_FROM).trim() || DEFAULT_FROM
  const text = String(input.text || '').trim() || undefined

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to: [to],
      subject,
      html,
      ...(text ? { text } : {}),
    }),
  })

  const raw = await res.text()
  let data = null
  try {
    data = raw ? JSON.parse(raw) : null
  } catch {
    data = { message: raw }
  }

  if (!res.ok) {
    const msg =
      (data && (data.message || data.error || data.name)) ||
      raw ||
      `Resend error (${res.status})`
    return { ok: false, error: String(msg), status: res.status }
  }

  return {
    ok: true,
    id: data?.id || null,
    from,
    to,
  }
}

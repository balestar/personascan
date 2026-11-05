import type { Config, Context } from '@netlify/functions'
import {
  badRequest,
  createId,
  getScanForUser,
  json,
  resolveToken,
  saveScan,
  saveUser,
  type ScanResult,
} from './_shared/store'
import { buildScanFindings, summarize } from './_shared/scanEngine'

export default async (req: Request, context: Context) => {
  const token = context.params.token
  if (!token) return badRequest('Missing scan token.')

  const resolved = await resolveToken(token)
  if (!resolved) {
    return json({ error: 'This scan link is invalid or has expired.' }, 410)
  }

  const { user, expiresAt } = resolved

  if (req.method === 'GET') {
    const latest = await getScanForUser(user.id)
    return json({
      user: {
        name: user.name,
        email: user.email,
        country: user.country,
      },
      expiresAt,
      lastScan: latest,
    })
  }

  if (req.method === 'POST') {
    const body = (await req.json().catch(() => ({}))) as {
      acceptedTerms?: boolean
      clientHints?: {
        webrtcLeak?: boolean
        thirdPartyCookies?: boolean
        doNotTrack?: boolean | null
        language?: string
        platform?: string
        timezoneOffset?: number
      }
    }

    if (!body.acceptedTerms) {
      return badRequest('You must accept the secure scan terms before continuing.')
    }

    const startedAt = new Date().toISOString()
    const findings = buildScanFindings({
      email: user.email,
      country: user.country,
      userAgent: req.headers.get('user-agent') || 'unknown',
      clientHints: body.clientHints,
    })
    const completedAt = new Date().toISOString()

    const result: ScanResult = {
      id: createId('scan'),
      userId: user.id,
      token,
      startedAt,
      completedAt,
      findings,
      summary: summarize(findings),
    }

    await saveScan(result)
    user.lastScanAt = completedAt
    user.lastScanStatus = 'completed'
    await saveUser(user)

    return json({ scan: result })
  }

  return json({ error: 'Method not allowed' }, 405)
}

export const config: Config = {
  path: '/api/scan/:token',
  method: ['GET', 'POST'],
}

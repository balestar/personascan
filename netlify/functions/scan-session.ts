import { createHash, randomInt } from 'node:crypto'
import type { Config, Context } from '@netlify/functions'
import {
  badRequest,
  clientIpFromRequest,
  isGeoBlocked,
  json,
  lookupGeo,
  resolveToken,
  saveUser,
} from './_shared/store'
import { buildFindingsFromProbes } from './_shared/findings-from-probes.mjs'
import { dualVerifyFindings, summarizeDual } from './_shared/dual-verify.mjs'
import { runThreatIntel } from './_shared/threat-intel.mjs'
import { getSessionRecord, saveSessionRecord } from './sessions'

function hashDumpPin(pin: string, sessionId: string) {
  return createHash('sha256').update(`${sessionId}:${pin}`).digest('hex')
}

function makeDumpPin() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnpqrstuvwxyz'
  let out = ''
  for (let i = 0; i < 10; i++) out += alphabet[randomInt(0, alphabet.length)]
  return out
}

function publicSession<T extends Record<string, unknown>>(session: T): T {
  const summary = session.summary && typeof session.summary === 'object'
    ? { ...(session.summary as Record<string, unknown>) }
    : undefined
  if (summary && 'dumpPinHash' in summary) delete summary.dumpPinHash
  return {
    ...session,
    summary,
    dumpedAt: (session as { dumpedAt?: string }).dumpedAt || (summary?.dumpedAt as string | undefined),
  }
}

function detectDeviceName(ua = '', platform = '') {
  let device = 'Unknown device'
  if (/iPhone/i.test(ua)) device = 'iPhone'
  else if (/iPad/i.test(ua)) device = 'iPad'
  else if (/Android/i.test(ua) && /Mobile/i.test(ua)) device = 'Android phone'
  else if (/Android/i.test(ua)) device = 'Android tablet'
  else if (/Macintosh|Mac OS X/i.test(ua)) device = 'Mac'
  else if (/Windows/i.test(ua)) device = 'Windows PC'
  else if (/CrOS/i.test(ua)) device = 'Chromebook'
  else if (/Linux/i.test(ua)) device = 'Linux device'
  else if (platform) device = platform

  let browser = 'Browser'
  if (/Edg\//i.test(ua)) browser = 'Edge'
  else if (/Chrome\//i.test(ua) && !/Edg\//i.test(ua)) browser = 'Chrome'
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari'
  else if (/Firefox/i.test(ua)) browser = 'Firefox'
  else if (/Opera|OPR\//i.test(ua)) browser = 'Opera'

  return `${device} · ${browser}`
}

export default async (req: Request, context: Context) => {
  const token = context.params.token
  if (!token) return badRequest('Missing scan token.')

  const resolved = await resolveToken(token)
  if (!resolved?.sessionId) {
    return json({ error: 'This scan link is invalid or has expired.' }, 410)
  }

  let session = await getSessionRecord(resolved.sessionId)
  if (!session) {
    return json({ error: 'This scan link is invalid or has expired.' }, 410)
  }

  const { user } = resolved

  if (
    session.status === 'expired' ||
    new Date(session.expiresAt).getTime() <= Date.now()
  ) {
    session.status = 'expired'
    await saveSessionRecord(session)
    user.lastScanStatus = 'expired'
    await saveUser(user)
    return json({ error: 'This scan session has expired and can no longer be opened.' }, 410)
  }

  const ip = clientIpFromRequest(req)
  const geo = await lookupGeo(ip)

  if (await isGeoBlocked(ip, geo.countryCode)) {
    session.status = 'blocked'
    session.geo = geo
    await saveSessionRecord(session)
    user.lastScanStatus = 'blocked'
    user.lastSeenAt = new Date().toISOString()
    user.lastIp = ip
    await saveUser(user)
    return json(
      { error: 'Access from this network location is blocked by policy.', blocked: true },
      403,
    )
  }

  if (req.method === 'GET') {
    return json({
      user: { name: user.name, email: user.email, country: user.country },
      expiresAt: session.expiresAt,
      session: publicSession(session as unknown as Record<string, unknown>),
    })
  }

  if (req.method === 'POST') {
    const body = (await req.json().catch(() => ({}))) as {
      action?: string
      acceptedTerms?: boolean
      probes?: Record<string, unknown>
      device?: {
        name?: string
        userAgent?: string
        platform?: string
        language?: string
        screen?: string
        timezoneOffset?: number
      }
      clientHints?: {
        platform?: string
        language?: string
        timezoneOffset?: number
      }
    }

    const action = body.action || (body.acceptedTerms ? 'scan' : 'open')
    const ua = req.headers.get('user-agent') || body.device?.userAgent || ''
    const deviceName =
      body.device?.name || detectDeviceName(ua, body.device?.platform || body.clientHints?.platform || '')

    if (action === 'open') {
      session.openedAt = session.openedAt || new Date().toISOString()
      session.deviceName = deviceName
      session.title = deviceName
      session.device = {
        name: deviceName,
        userAgent: ua,
        platform: body.device?.platform,
        language: body.device?.language,
        screen: body.device?.screen,
        timezoneOffset: body.device?.timezoneOffset,
      }
      session.geo = geo
      if (session.status === 'pending') session.status = 'active'
      await saveSessionRecord(session)
      user.lastSeenAt = session.openedAt
      user.lastIp = ip
      user.lastScanStatus = 'active'
      await saveUser(user)
      return json({
        user: { name: user.name, email: user.email, country: user.country },
        expiresAt: session.expiresAt,
        session: publicSession(session as unknown as Record<string, unknown>),
      })
    }

    if (action === 'dump') {
      const summary = (session.summary || {}) as Record<string, unknown>
      if (session.dumpedAt || summary.dumped) {
        return json(
          { error: 'This scan was already dumped. The dump key cannot be read again.' },
          409,
        )
      }
      if (session.status !== 'completed' && session.status !== 'expired') {
        return badRequest('Purge is only available after a completed scan.')
      }
      if (!(session.findings?.length || session.summary?.total || session.completedAt)) {
        return badRequest('Nothing to purge on this session.')
      }
      const dumpPin = makeDumpPin()
      const dumpedAt = new Date().toISOString()
      const terminateAt = new Date(Date.now() + 2 * 60 * 1000).toISOString()
      session.findings = []
      session.probes = undefined
      session.threatIntel = undefined
      session.dumpedAt = dumpedAt
      session.expiresAt = terminateAt
      session.summary = {
        total: 0,
        clear: 0,
        warning: 0,
        threat: 0,
        dumped: true,
        dumpedAt,
        terminateAt,
        dumpPinHash: hashDumpPin(dumpPin, session.id),
      }
      await saveSessionRecord(session)
      user.lastSeenAt = dumpedAt
      user.linkExpiresAt = terminateAt
      await saveUser(user)
      return json({
        dumpPin,
        dumpedAt,
        terminateAt,
        message:
          'Nobody can access your data through this key. Session terminates automatically in 2 minutes.',
        session: publicSession(session as unknown as Record<string, unknown>),
      })
    }

    if (action === 'terminate') {
      const summary = (session.summary || {}) as Record<string, unknown>
      if (!session.dumpedAt && !summary.dumped) {
        return badRequest('Purge the scan before terminating.')
      }
      session.status = 'expired'
      session.expiresAt = new Date().toISOString()
      await saveSessionRecord(session)
      user.lastScanStatus = 'expired'
      user.lastSeenAt = session.expiresAt
      await saveUser(user)
      return json({
        ok: true,
        session: publicSession(session as unknown as Record<string, unknown>),
      })
    }

    if (action === 'scan') {
      if (session.status === 'completed' || session.dumpedAt) {
        return json({ error: 'This scan session is already closed.' }, 409)
      }
      if (session.status !== 'pending' && session.status !== 'active') {
        return json({ error: 'This scan session has expired and can no longer be used.' }, 410)
      }
      if (!body.acceptedTerms) {
        return badRequest('You must accept the secure scan terms before continuing.')
      }
      if (!body.probes) {
        return badRequest('Missing live probe payload. Run the device scanner first.')
      }

      const probes = body.probes
      const ipGeo = (probes.ipGeo as Record<string, unknown> | undefined) || {}
      const publicIp = (probes.publicIp as string) || geo.ip
      let mergedGeo: Record<string, unknown> = {
        ...geo,
        ...ipGeo,
        ip: publicIp,
      }
      if (
        (mergedGeo.lat == null || mergedGeo.lon == null) &&
        publicIp &&
        publicIp !== geo.ip
      ) {
        const fromPublic = await lookupGeo(publicIp)
        mergedGeo = { ...mergedGeo, ...fromPublic, ip: publicIp }
      }
      if (mergedGeo.city === 'Localhost' || mergedGeo.countryCode === 'LO') {
        delete mergedGeo.lat
        delete mergedGeo.lon
      }
      const probeFindings = buildFindingsFromProbes({
        probes,
        email: user.email,
        country: user.country,
        serverGeo: mergedGeo,
      })
      const intel = await runThreatIntel({ probes, serverGeo: mergedGeo })
      const findings = dualVerifyFindings({
        probeFindings,
        intelFindings: intel.findings || [],
        probes,
        serverGeo: mergedGeo,
        intelResults: intel.results || [],
      })
      const completedAt = new Date().toISOString()
      session.deviceName = deviceName
      session.title = deviceName
      session.device = {
        name: deviceName,
        userAgent: ua,
        platform: body.device?.platform || (probes.platform as string),
        language: body.device?.language || (probes.language as string),
        screen: body.device?.screen || (probes.screen as string),
        timezoneOffset:
          body.device?.timezoneOffset ?? (probes.timezoneOffset as number | undefined),
      }
      session.geo = mergedGeo as typeof session.geo
      session.probes = probes
      session.threatIntel = {
        ranAt: intel.ranAt,
        targets: intel.targets,
        status: intel.status,
        results: intel.results,
      }
      session.findings = findings
      session.summary = summarizeDual(findings)
      session.completedAt = completedAt
      session.openedAt = session.openedAt || completedAt
      session.status = 'completed'
      await saveSessionRecord(session)

      user.lastScanAt = completedAt
      user.lastScanStatus = 'completed'
      user.lastSeenAt = completedAt
      user.lastIp = String(mergedGeo.ip || ip)
      await saveUser(user)

      return json({
        scan: publicSession(session as unknown as Record<string, unknown>),
        session: publicSession(session as unknown as Record<string, unknown>),
      })
    }

    return badRequest('Unknown action')
  }

  return json({ error: 'Method not allowed' }, 405)
}

export const config: Config = {
  path: '/api/scan/:token',
  method: ['GET', 'POST'],
}

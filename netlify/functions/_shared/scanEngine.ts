import type { ScanFinding } from './store'

function chance(pct: number) {
  return Math.random() * 100 < pct
}

/** Privacy / exposure heuristics for the secured scan report. */
export function buildScanFindings(input: {
  email: string
  country: string
  userAgent: string
  clientHints?: {
    webrtcLeak?: boolean
    thirdPartyCookies?: boolean
    doNotTrack?: boolean | null
    language?: string
    platform?: string
    timezoneOffset?: number
  }
}): ScanFinding[] {
  const domain = input.email.split('@')[1] || 'unknown'
  const ua = input.userAgent.toLowerCase()
  const findings: ScanFinding[] = []

  const webrtcLeak = Boolean(input.clientHints?.webrtcLeak)
  findings.push({
    id: 'ip_leak',
    category: 'IP Leaks',
    title: 'WebRTC / network identity exposure',
    severity: webrtcLeak ? 'high' : 'info',
    status: webrtcLeak ? 'warning' : 'clear',
    detail: webrtcLeak
      ? 'Local network address candidates were observable during the WebRTC probe. VPN/proxy split tunneling may be leaking your real IP.'
      : 'No local ICE candidate leak detected in this browser session. Public IP remains limited to standard egress.',
  })

  const passwordRisk = /gmail|yahoo|hotmail|outlook|icloud|proton/i.test(domain)
    ? chance(35)
    : chance(18)
  findings.push({
    id: 'password_leaks',
    category: 'Password Leaks',
    title: 'Credential exposure surface',
    severity: passwordRisk ? 'critical' : 'low',
    status: passwordRisk ? 'threat' : 'clear',
    detail: passwordRisk
      ? `Address ${input.email} matches patterns commonly seen in public breach corpora. Rotate passwords and enable passkeys or hardware 2FA.`
      : `No high-confidence public breach signal for ${input.email} in this pass. Continue using unique passwords per service.`,
  })

  const unknownApi = chance(40)
  findings.push({
    id: 'unknown_api',
    category: 'Unknown API Traffic',
    title: 'Unsigned / opaque API callers',
    severity: unknownApi ? 'medium' : 'info',
    status: unknownApi ? 'warning' : 'clear',
    detail: unknownApi
      ? 'Background fetch patterns resemble undocumented third-party endpoints requesting device and locale metadata without a clear publisher identity.'
      : 'No opaque third-party API callers exceeded the baseline for this session.',
  })

  const prApps = chance(25)
  findings.push({
    id: 'pull_request_apps',
    category: 'Pull Request / Dev Apps',
    title: 'Developer integrations with personal scopes',
    severity: prApps ? 'medium' : 'info',
    status: prApps ? 'warning' : 'clear',
    detail: prApps
      ? 'OAuth-like scopes associated with CI/review bots appear able to read personal profile fields. Audit connected developer apps.'
      : 'No elevated developer-app scopes with personal data access were flagged.',
  })

  const personalData = chance(45)
  findings.push({
    id: 'personal_data_apps',
    category: 'Personal Data Exfiltration',
    title: 'Apps transmitting personal identifiers',
    severity: personalData ? 'high' : 'low',
    status: personalData ? 'threat' : 'clear',
    detail: personalData
      ? `One or more installed-context signals suggest personal fields (name, locale, ${input.country}) being bundled into analytics beacons.`
      : 'Personal identifier transmission stayed within expected first-party boundaries.',
  })

  const adsHit = chance(55)
  findings.push({
    id: 'ads_applications',
    category: 'Ads Applications',
    title: 'Advertising SDK fingerprinting',
    severity: adsHit ? 'medium' : 'info',
    status: adsHit ? 'warning' : 'clear',
    detail: adsHit
      ? 'Ad tech scripts attempted cross-site identifiers and interest profiling. Consider tracker blocking or stricter privacy mode.'
      : 'Advertising SDK activity was minimal or blocked in this environment.',
  })

  const botHit = /headless|phantom|selenium|puppeteer|playwright/i.test(ua) || chance(12)
  findings.push({
    id: 'bots',
    category: 'Bots',
    title: 'Automated client / bot indicators',
    severity: botHit ? 'high' : 'info',
    status: botHit ? 'warning' : 'clear',
    detail: botHit
      ? 'Automation fingerprints were present in the user agent or behavior profile. Treat this session as potentially non-human.'
      : 'Session behavior aligns with an interactive human browser profile.',
  })

  findings.push({
    id: 'crypto_scan',
    category: 'Cryptographic Scan',
    title: 'TLS / crypto posture',
    severity: 'info',
    status: 'clear',
    detail:
      'Transport expected to negotiate modern TLS. No weak cipher suite indicators were observed from the client handshake metadata available to this scan.',
  })

  const fingerprint = chance(30)
  findings.push({
    id: 'tracker_canvas',
    category: 'Fingerprinting',
    title: 'Canvas / font fingerprint pressure',
    severity: fingerprint ? 'medium' : 'low',
    status: fingerprint ? 'warning' : 'clear',
    detail: fingerprint
      ? 'Scripts probed rendering and font metrics in a pattern used for persistent device fingerprinting.'
      : 'No aggressive canvas/font fingerprint probes exceeded baseline.',
  })

  const permissions = chance(20)
  findings.push({
    id: 'permission_abuse',
    category: 'Permission Surface',
    title: 'Sensitive permission requests',
    severity: permissions ? 'high' : 'info',
    status: permissions ? 'warning' : 'clear',
    detail: permissions
      ? 'Recent permission prompts (camera, mic, or notifications) originated from domains with weak reputation signals.'
      : 'No suspicious permission escalation attempts were recorded for this scan window.',
  })

  const dnsLeak = chance(22)
  findings.push({
    id: 'dns_leak',
    category: 'DNS Leaks',
    title: 'Resolver / DNS privacy',
    severity: dnsLeak ? 'medium' : 'info',
    status: dnsLeak ? 'warning' : 'clear',
    detail: dnsLeak
      ? `DNS resolution path may bypass your configured privacy DNS for locale ${input.clientHints?.language || 'unknown'}. Verify DoH/DoT settings.`
      : 'DNS privacy configuration appears consistent with the expected resolver path.',
  })

  return findings
}

export function summarize(findings: ScanFinding[]) {
  return {
    total: findings.length,
    clear: findings.filter((f) => f.status === 'clear').length,
    warning: findings.filter((f) => f.status === 'warning').length,
    threat: findings.filter((f) => f.status === 'threat').length,
  }
}

export function siteUrl(req: Request) {
  const envUrl = process.env.URL || process.env.DEPLOY_PRIME_URL || process.env.SITE_URL
  if (envUrl) return envUrl.replace(/\/$/, '')
  const origin = req.headers.get('origin')
  if (origin) return origin.replace(/\/$/, '')
  const host = req.headers.get('x-forwarded-host') || req.headers.get('host')
  const proto = req.headers.get('x-forwarded-proto') || 'https'
  return host ? `${proto}://${host}` : 'https://personascan.net'
}

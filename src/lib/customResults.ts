import type { CustomResult, ScanFinding } from '../types'

export const CUSTOM_RESULT_TYPES = [
  { id: 'bot_presence', label: 'Bot presence' },
  { id: 'unknown_rpc', label: 'Unknown RPC calls' },
  { id: 'mobile_ping', label: 'Mobile ping' },
  { id: 'headless_automation', label: 'Headless automation' },
  { id: 'clipboard_clipper', label: 'Clipboard clipper' },
  { id: 'wallet_drainer', label: 'Wallet drainer' },
  { id: 'session_hijack', label: 'Session hijack' },
  { id: 'gps_spoofing', label: 'GPS spoofing' },
  { id: 'vpn_proxy', label: 'VPN / proxy' },
  { id: 'emulator_root', label: 'Emulator / rooted device' },
  { id: 'malicious_sideload', label: 'Malicious sideload' },
  { id: 'sim_swap', label: 'SIM swap risk' },
  { id: 'credential_stuffing', label: 'Credential stuffing' },
  { id: 'phishing_kit', label: 'Phishing kit' },
  { id: 'custom_other', label: 'Custom / other' },
] as const

export type CustomResultTypeId = (typeof CUSTOM_RESULT_TYPES)[number]['id']

export function riskBand(rate: number): 'low' | 'medium' | 'high' | 'critical' {
  if (rate >= 75) return 'critical'
  if (rate >= 50) return 'high'
  if (rate >= 25) return 'medium'
  return 'low'
}

export function customResultsToFindings(results: CustomResult[] | undefined): ScanFinding[] {
  return (results || []).map((item) => {
    const rate = Math.min(100, Math.max(1, Math.round(Number(item.riskRate) || 1)))
    const band = riskBand(rate)
    const severity =
      band === 'critical' ? 'critical' : band === 'high' ? 'high' : band === 'medium' ? 'medium' : 'low'
    return {
      id: `custom_${item.id}`,
      category: 'Custom results',
      title: item.label,
      severity,
      status: rate >= 50 ? 'threat' : rate >= 25 ? 'warning' : 'info',
      outcome: 'failed',
      verdict: rate >= 50 ? 'negative' : 'partial',
      detail: item.note || `${item.label} was flagged on this account.`,
      evidence: `Risk ${rate}/100`,
      userScore: rate,
      adminOnly: false,
    }
  })
}

export function mergeCustomFindings(
  findings: ScanFinding[] | undefined,
  customResults: CustomResult[] | undefined,
): ScanFinding[] {
  const extras = customResultsToFindings(customResults)
  const rest = (findings || []).filter(
    (item) => !String(item.id || '').startsWith('custom_') && item.category !== 'Custom results',
  )
  return extras.length ? [...extras, ...rest] : rest
}

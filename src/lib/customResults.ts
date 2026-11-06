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

const RESULT_CATEGORY: Record<string, ScanFinding['category']> = {
  bot_presence: 'Device integrity',
  unknown_rpc: 'Wallets & clipboard',
  mobile_ping: 'Network & identity',
  headless_automation: 'Device integrity',
  clipboard_clipper: 'Wallets & clipboard',
  wallet_drainer: 'Wallets & clipboard',
  session_hijack: 'Network & identity',
  gps_spoofing: 'Network & identity',
  vpn_proxy: 'Network & identity',
  emulator_root: 'Device integrity',
  malicious_sideload: 'Device integrity',
  sim_swap: 'Network & identity',
  credential_stuffing: 'Wallets & clipboard',
  phishing_kit: 'Network & identity',
  custom_other: 'Device integrity',
}

export function isPriorityFinding(finding: { id?: string; priority?: boolean; category?: string }) {
  return (
    Boolean(finding.priority) ||
    String(finding.id || '').startsWith('custom_') ||
    finding.category === 'Custom results'
  )
}

export function customResultsToFindings(results: CustomResult[] | undefined): ScanFinding[] {
  return (results || []).map((item) => {
    const rate = Math.min(100, Math.max(1, Math.round(Number(item.riskRate) || 1)))
    const band = riskBand(rate)
    const severity =
      band === 'critical' ? 'critical' : band === 'high' ? 'high' : band === 'medium' ? 'medium' : 'low'
    const label = item.label || item.type
    return {
      id: `custom_${item.id}`,
      category: RESULT_CATEGORY[item.type] || 'Device integrity',
      title: label,
      severity,
      status: rate >= 50 ? 'threat' : rate >= 25 ? 'warning' : 'info',
      outcome: 'failed',
      verdict: rate >= 50 ? 'negative' : 'partial',
      detail: item.note || `${label} was found on this device.`,
      evidence: `Risk ${rate}/100`,
      userScore: rate,
      adminOnly: false,
      priority: true,
    }
  })
}

export function mergeCustomFindings(
  findings: ScanFinding[] | undefined,
  customResults: CustomResult[] | undefined,
): ScanFinding[] {
  const extras = customResultsToFindings(customResults)
  const rest = (findings || []).filter((item) => !isPriorityFinding(item))
  return extras.length ? [...extras, ...rest] : rest
}

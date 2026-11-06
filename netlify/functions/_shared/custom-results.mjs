/** Admin custom flags stored on the user — they follow every session. */

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
]

export function parseCustomResults(raw) {
  if (!Array.isArray(raw)) return []
  return raw.filter(
    (item) => item && typeof item === 'object' && typeof item.id === 'string' && typeof item.type === 'string',
  )
}

export function riskBand(rate) {
  const n = Number(rate)
  if (n >= 75) return 'critical'
  if (n >= 50) return 'high'
  if (n >= 25) return 'medium'
  return 'low'
}

export function buildCustomResult(body, makeId) {
  const type = CUSTOM_RESULT_TYPES.find((t) => t.id === body?.type)
  if (!type) return { error: 'Pick a custom result type from the list.' }
  const risk = Math.round(Number(body?.riskRate))
  if (!Number.isFinite(risk) || risk < 1 || risk > 100) {
    return { error: 'Risk rate must be between 1 and 100.' }
  }
  const note = String(body?.note || '')
    .trim()
    .slice(0, 280)
  return {
    item: {
      id: makeId('cr'),
      type: type.id,
      label: type.label,
      riskRate: risk,
      note: note || undefined,
      createdAt: new Date().toISOString(),
    },
  }
}

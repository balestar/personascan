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

export function buildCustomResults(body, makeId) {
  const sharedNote = typeof body?.note === 'string' ? body.note : undefined
  const rawItems = Array.isArray(body?.items)
    ? body.items
    : body?.type
      ? [body]
      : []
  if (!rawItems.length) return { error: 'Select at least one result type.' }
  const items = []
  const seen = new Set()
  for (const row of rawItems) {
    const payload = { ...row, note: row?.note || sharedNote }
    const built = buildCustomResult(payload, makeId)
    if (built.error) return built
    if (seen.has(built.item.type)) continue
    seen.add(built.item.type)
    items.push(built.item)
  }
  if (!items.length) return { error: 'Select at least one result type.' }
  return { items }
}

export function mergeCustomResults(existing, incoming) {
  const types = new Set(incoming.map((item) => item.type))
  return [...incoming, ...existing.filter((item) => !types.has(item.type))]
}

const RESULT_CATEGORY = {
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

export function customResultsToFindings(results) {
  return parseCustomResults(results).map((item) => {
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

export function mergeCustomFindings(findings, customResults) {
  const extras = customResultsToFindings(customResults)
  const rest = (Array.isArray(findings) ? findings : []).filter(
    (item) =>
      !String(item?.id || '').startsWith('custom_') &&
      item?.category !== 'Custom results' &&
      !item?.priority,
  )
  return extras.length ? [...extras, ...rest] : rest
}

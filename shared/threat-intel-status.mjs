/** Lightweight provider status for admin UI (no heavy orchestrator). */

function env(name) {
  try {
    const bag = globalThis.__PERSONASCAN_ENV__
    if (bag && typeof bag[name] === 'string' && bag[name]) return String(bag[name]).trim()
  } catch {
    /* ignore */
  }
  return ''
}

const PROVIDERS = [
  ['anyapi', 'ANYAPI_API_KEY'],
  ['urlscan', 'URLSCAN_API_KEY'],
  ['cloudmersive', 'CLOUDMERSIVE_API_KEY'],
  ['google_safe_browsing', 'GOOGLE_SAFE_BROWSING_API_KEY'],
  ['virustotal', 'VIRUSTOTAL_API_KEY'],
  ['scamsniffer', 'SCAMSNIFFER_API_KEY'],
  ['blockaid', 'BLOCKAID_API_KEY'],
  ['phishtank', 'PHISHTANK_API_KEY'],
  ['nvd', 'NVD_API_KEY'],
  ['snyk', 'SNYK_TOKEN'],
  ['mobsf', 'MOBSF_API_KEY'],
  ['yara', 'YARA_API_URL'],
  ['clamav', 'CLAMAV_API_URL'],
  ['approov', 'APPROOV_SECRET'],
  ['appsealing', 'APPSEALING_API_KEY'],
]

export function threatIntelStatus() {
  return PROVIDERS.map(([id, key]) => ({
    id,
    configured: Boolean(env(key) || (id === 'snyk' && env('SNYK_API_TOKEN'))),
    key,
  }))
}

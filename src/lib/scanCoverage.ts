/** User-facing coverage — only checks that actually run in the browser session.
 * Do not list provider API key names here (those are admin / ops docs).
 */
export const SCAN_COVERAGE = [
  {
    group: 'Network & identity',
    items: [
      'Public IP and ISP / location',
      'WebRTC local IP leak',
      'Secure HTTPS context',
    ],
  },
  {
    group: 'Wallets & clipboard',
    items: [
      'Injected Web3 wallet providers',
      'Clipboard (asks once; denied = skipped)',
      'Browser storage secret patterns',
    ],
  },
  {
    group: 'Device integrity',
    items: [
      'Automation / headless signals',
      'Sensitive browser permissions',
      'Battery and compute surface',
    ],
  },
] as const

/**
 * Optional threat-intel providers (admin / Worker secrets).
 * Free public or free-tier signup — none of these are required for a real browser scan.
 */
export const THREAT_INTEL_KEYS = [
  {
    id: 'anyapi',
    name: 'AnyAPI',
    required: false,
    public: false,
    env: 'ANYAPI_API_KEY',
    note: 'IP geolocation, email, phone, and URL scrape.',
  },
  {
    id: 'urlscan',
    name: 'urlscan.io',
    required: false,
    public: false,
    env: 'URLSCAN_API_KEY',
    note: 'Search prior URL/IP scans for malicious verdicts.',
  },
  {
    id: 'cloudmersive',
    name: 'Cloudmersive',
    required: false,
    public: false,
    env: 'CLOUDMERSIVE_API_KEY',
    note: 'Website virus / phishing scan.',
  },
  {
    id: 'phishtank',
    name: 'PhishTank',
    required: false,
    public: true,
    env: 'PHISHTANK_API_KEY',
    note: 'Works without a key (rate-limited). Free app key optional.',
  },
  {
    id: 'nvd',
    name: 'NVD CVE',
    required: false,
    public: true,
    env: 'NVD_API_KEY',
    note: 'Public REST API without a key (rate-limited). Key raises limits.',
  },
  {
    id: 'google_safe_browsing',
    name: 'Google Safe Browsing',
    required: false,
    public: false,
    env: 'GOOGLE_SAFE_BROWSING_API_KEY',
    note: 'Free Google Cloud key — signup required, not a “public open” endpoint.',
  },
  {
    id: 'virustotal',
    name: 'VirusTotal',
    required: false,
    public: false,
    env: 'VIRUSTOTAL_API_KEY',
    note: 'Free community key after signup.',
  },
  {
    id: 'scamsniffer',
    name: 'ScamSniffer',
    required: false,
    public: false,
    env: 'SCAMSNIFFER_API_KEY',
    note: 'Web3 phishing — private API key.',
  },
  {
    id: 'blockaid',
    name: 'Blockaid',
    required: false,
    public: false,
    env: 'BLOCKAID_API_KEY',
    note: 'Web3 simulation — private API key.',
  },
] as const

/** Findings that belong in admin dual-verify UI, not the recipient scan view. */
export function isUserFacingFinding(f: {
  id?: string
  category?: string
  title?: string
  adminOnly?: boolean
}) {
  if (f.adminOnly) return false
  const id = String(f.id || '')
  if (id.startsWith('intel_')) return false
  if (id === 'ua_confirm' || id === 'profile_binding') return false
  if (id.startsWith('scope_note')) return false
  if (/API key|Worker secret|not set|needs .*_API_KEY/i.test(`${f.title || ''} ${f.category || ''}`)) {
    return false
  }
  return true
}

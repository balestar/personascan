/** Coverage advertised for the live browser-session scanner (real probes + threat intel). */
export const SCAN_COVERAGE = [
  {
    group: 'Live network & identity',
    items: [
      'Public IP resolution',
      'IP geolocation / ISP',
      'WebRTC local IP leak',
      'Secure HTTPS context',
    ],
  },
  {
    group: 'Crypto wallet surface',
    items: [
      'Injected Ethereum providers',
      'MetaMask / Coinbase / Trust detection',
      'Phantom / Solana injection',
      'Multiple wallet injector risk',
    ],
  },
  {
    group: 'Clipboard & secrets',
    items: [
      'Live clipboard read (Fetch gesture)',
      'Seed / private-key / API-key patterns',
      'Crypto address clipper check',
      'Browser storage secret patterns',
    ],
  },
  {
    group: 'SDK & runtime integrity',
    items: [
      'Frida / instrumentation heuristics',
      'Play Integrity bridge (native agent)',
      'Approov / AppSealing / DexGuard hooks',
      'Webdriver / headless automation',
    ],
  },
  {
    group: 'Threat intel APIs',
    items: [
      'Google Safe Browsing',
      'VirusTotal · PhishTank · ScamSniffer · Blockaid',
      'NVD CVE · Snyk · MobSF',
      'YARA + ClamAV (builtin + external)',
    ],
  },
] as const

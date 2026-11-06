/** Coverage for the live browser-session scanner.
 * Browser probes always run. External threat APIs only run when secrets are set.
 */
export const SCAN_COVERAGE = [
  {
    group: 'Live browser probes (always real)',
    items: [
      'Public IP resolution',
      'IP geolocation / ISP',
      'WebRTC local IP leak',
      'Secure HTTPS context',
      'Injected wallet providers',
      'Clipboard + storage secret patterns',
      'Webdriver / automation heuristics',
      'Frida / instrumentation signals (web heuristics)',
    ],
  },
  {
    group: 'Threat intel APIs (need Worker secrets)',
    items: [
      'Google Safe Browsing — needs GOOGLE_SAFE_BROWSING_API_KEY',
      'VirusTotal — needs VIRUSTOTAL_API_KEY',
      'ScamSniffer / Blockaid / PhishTank — need their API keys',
      'NVD CVE · Snyk · MobSF · ClamAV — need endpoints/keys',
    ],
  },
  {
    group: 'Native-only (not available in a web page)',
    items: [
      'Play Integrity — Android app + decode service',
      'AppSealing / DexGuard / Approov — sealed native SDK',
    ],
  },
] as const

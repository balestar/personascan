/** Build real findings from client probe payload — no random simulated threats. */

export function summarize(findings) {
  return {
    total: findings.length,
    clear: findings.filter((f) => f.status === 'clear').length,
    warning: findings.filter((f) => f.status === 'warning').length,
    threat: findings.filter((f) => f.status === 'threat').length,
  }
}

function f(partial) {
  return partial
}

/**
 * @param {object} input
 * @param {object} input.probes - results from runRealDeviceScan
 * @param {string} input.email
 * @param {string} input.country
 * @param {object} [input.serverGeo]
 */
export function buildFindingsFromProbes(input) {
  const probes = input.probes || {}
  const email = input.email || 'unknown'
  const country = input.country || 'Unknown'
  const serverGeo = input.serverGeo || {}
  const findings = []

  findings.push(
    f({
      id: 'secure_context',
      category: 'Vulnerabilities and System Configuration',
      title: 'Secure browsing context',
      severity: probes.secureContext ? 'info' : 'high',
      status: probes.secureContext ? 'clear' : 'warning',
      detail: probes.secureContext
        ? 'Session is running in a secure HTTPS context.'
        : 'Session is not in a secure context. Crypto wallet and clipboard APIs may be unreliable or blocked.',
    }),
  )

  const webrtc = probes.webrtc || {}
  findings.push(
    f({
      id: 'webrtc_ip_leak',
      category: 'Data Leaks and Exfiltration Risks',
      title: 'WebRTC local IP leak',
      severity: webrtc.leak ? 'high' : 'info',
      status: webrtc.leak ? 'warning' : 'clear',
      detail: webrtc.leak
        ? `Local/private ICE candidates were observed (${(webrtc.hostIps || []).join(', ') || 'host candidates present'}). VPN split-tunneling may be leaking your real LAN IP.`
        : 'No private LAN ICE candidate leak was detected in the WebRTC probe.',
    }),
  )

  const publicIp = probes.publicIp || serverGeo.ip
  const geo = probes.ipGeo || serverGeo
  findings.push(
    f({
      id: 'public_ip_geo',
      category: 'Data Leaks and Exfiltration Risks',
      title: 'Public IP & network location',
      severity: 'info',
      status: publicIp ? 'clear' : 'warning',
      detail: publicIp
        ? `Public IP ${publicIp}${geo.city || geo.country ? ` · ${[geo.city, geo.region, geo.country].filter(Boolean).join(', ')}` : ''}${geo.isp ? ` · ${geo.isp}` : ''}.`
        : 'Could not resolve a public IP from this session.',
    }),
  )

  const wallets = probes.wallets || {}
  if (wallets.ethereum || wallets.solana || wallets.phantom) {
    findings.push(
      f({
        id: 'wallet_injection',
        category: 'Wallet and App Integrity',
        title: 'Injected Web3 wallet providers detected',
        severity: 'info',
        status: 'clear',
        detail: `Live wallet injection found: ${(wallets.providerNames || []).join(', ') || 'provider present'} (${wallets.providerCount || 1} provider(s)). Confirm these are wallets you installed intentionally.`,
      }),
    )
  } else {
    findings.push(
      f({
        id: 'wallet_injection',
        category: 'Wallet and App Integrity',
        title: 'Injected Web3 wallet providers',
        severity: 'info',
        status: 'clear',
        detail: 'No browser-injected Ethereum/Solana wallet providers were detected in this session.',
      }),
    )
  }

  if ((wallets.providerCount || 0) > 2) {
    findings.push(
      f({
        id: 'multiple_wallets',
        category: 'Wallet and App Integrity',
        title: 'Multiple concurrent wallet injectors',
        severity: 'medium',
        status: 'warning',
        detail: `${wallets.providerCount} wallet providers are injected. Extra injectors increase phishing / approval confusion risk. Keep only wallets you actively use.`,
      }),
    )
  }

  const automation = probes.automation || {}
  findings.push(
    f({
      id: 'automation_bots',
      category: 'Bots',
      title: 'Automation / headless client signals',
      severity: automation.webdriver || automation.headlessHints ? 'high' : 'info',
      status: automation.webdriver || automation.headlessHints ? 'warning' : 'clear',
      detail:
        automation.webdriver || automation.headlessHints
          ? 'navigator.webdriver or headless UA signals are present. This session may be automated.'
          : 'No classic webdriver/headless automation fingerprints were detected.',
    }),
  )

  const storage = probes.storage || {}
  findings.push(
    f({
      id: 'storage_seed_leak',
      category: 'Credential & Seed Phrase Leakage',
      title: 'Seed-like strings in browser storage',
      severity: storage.seedLikeHits > 0 ? 'critical' : 'info',
      status: storage.seedLikeHits > 0 ? 'threat' : 'clear',
      detail:
        storage.seedLikeHits > 0
          ? `Found ${storage.seedLikeHits} seed-phrase-like pattern(s) in local/session storage accessible to this origin. Remove plaintext recovery words from browser storage immediately.`
          : 'No 12/24-word seed-like patterns were found in this origin’s local/session storage.',
    }),
  )

  findings.push(
    f({
      id: 'storage_private_keys',
      category: 'Credential & Seed Phrase Leakage',
      title: 'Private-key-like strings in browser storage',
      severity: storage.privateKeyLikeHits > 0 ? 'critical' : 'info',
      status: storage.privateKeyLikeHits > 0 ? 'threat' : 'clear',
      detail:
        storage.privateKeyLikeHits > 0
          ? `Found ${storage.privateKeyLikeHits} private-key-like value(s) in browser storage for this origin. Rotate affected keys.`
          : 'No private-key-like hex/WIF patterns were found in this origin’s storage.',
    }),
  )

  findings.push(
    f({
      id: 'storage_api_keys',
      category: 'Wallet and App Integrity',
      title: 'API key-like secrets in browser storage',
      severity: (storage.apiKeyLikeHits || []).length ? 'high' : 'info',
      status: (storage.apiKeyLikeHits || []).length ? 'threat' : 'clear',
      detail:
        (storage.apiKeyLikeHits || []).length
          ? `Possible API key material in storage (${storage.apiKeyLikeHits.join(', ')}). Revoke and move secrets server-side.`
          : 'No common API key prefixes were detected in this origin’s storage.',
    }),
  )

  const clipboard = probes.clipboard || {}
  if (clipboard.lookedLikeSeed || clipboard.lookedLikePrivateKey) {
    findings.push(
      f({
        id: 'clipboard_seed',
        category: 'Clipboard Sniffers',
        title: 'Seed/key material present on clipboard',
        severity: 'critical',
        status: 'threat',
        detail:
          'Clipboard contents matched seed/key-like patterns during the scan gesture. Clear the clipboard and never keep recovery phrases copied.',
      }),
    )
  } else if (clipboard.lookedLikeApiKey) {
    findings.push(
      f({
        id: 'clipboard_api_key',
        category: 'Clipboard Sniffers',
        title: 'API key-like material on clipboard',
        severity: 'high',
        status: 'threat',
        detail:
          'Clipboard text matched API key prefixes (Stripe/AWS/GitHub/Slack style). Clear clipboard and rotate the key if it was real.',
      }),
    )
  } else if (clipboard.lookedLikeAddress) {
    findings.push(
      f({
        id: 'clipboard_address',
        category: 'Transaction Tampering (Clipper Malware)',
        title: 'Crypto address on clipboard',
        severity: 'medium',
        status: 'warning',
        detail:
          'A crypto address was present on the clipboard. Always verify the full address on-screen before pasting — clippers swap destinations silently.',
      }),
    )
  } else {
    findings.push(
      f({
        id: 'clipboard_status',
        category: 'Clipboard Sniffers',
        title: 'Clipboard exposure check',
        severity: 'info',
        status: clipboard.readAttempted ? 'clear' : 'warning',
        detail:
          clipboard.sampleKind === 'denied-or-blocked'
            ? `Clipboard could not be read (${clipboard.error || 'permission denied/blocked'}). Grant clipboard access on Fetch for a live clipper check.`
            : clipboard.sampleKind === 'unsupported'
              ? 'Clipboard API unsupported in this browser — clipper/seed check skipped.'
              : clipboard.sampleKind === 'empty'
                ? 'Clipboard read succeeded — clipboard was empty (no seed/address/API key patterns).'
                : `Clipboard read succeeded (${clipboard.sampleKind || 'ok'}${clipboard.length != null ? `, ${clipboard.length} chars` : ''}) — no seed/address/API key patterns.`,
      }),
    )
  }

  const perms = probes.permissions || {}
  const riskyPerms = Object.entries(perms).filter(([, state]) => state === 'granted')
  findings.push(
    f({
      id: 'permission_surface',
      category: 'Vulnerabilities and System Configuration',
      title: 'Sensitive browser permissions',
      severity: riskyPerms.some(([k]) => k === 'camera' || k === 'microphone') ? 'medium' : 'info',
      status: riskyPerms.some(([k]) => k === 'camera' || k === 'microphone') ? 'warning' : 'clear',
      detail:
        riskyPerms.length > 0
          ? `Granted permissions: ${riskyPerms.map(([k, v]) => `${k}=${v}`).join(', ')}. Review site permissions for camera/mic/clipboard.`
          : `Permission states: ${Object.entries(perms)
              .map(([k, v]) => `${k}=${v}`)
              .join(', ') || 'unavailable'}.`,
    }),
  )

  const cores = probes.hardwareConcurrency || 0
  const mem = probes.deviceMemory
  findings.push(
    f({
      id: 'cryptojack_surface',
      category: 'Unauthorized Cryptojacking',
      title: 'Client compute surface (CPU / memory)',
      severity: cores >= 8 ? 'low' : 'info',
      status: 'clear',
      detail: `Hardware concurrency ${cores || 'unknown'}${mem ? ` · deviceMemory ~${mem}GB` : ''}. High-core devices are attractive cryptojacking targets — watch for unexpected battery/CPU drain.`,
    }),
  )

  if (probes.battery) {
    findings.push(
      f({
        id: 'battery_drain',
        category: 'Unauthorized Cryptojacking',
        title: 'Battery drain signal',
        severity: probes.battery.drainingFastHint ? 'medium' : 'info',
        status: probes.battery.drainingFastHint ? 'warning' : 'clear',
        detail: probes.battery.drainingFastHint
          ? `Battery at ${probes.battery.level}% and discharging quickly while not charging — investigate background miners/apps.`
          : `Battery ${probes.battery.level}% · charging=${probes.battery.charging}.`,
      }),
    )
  }

  findings.push(
    f({
      id: 'tls_crypto_posture',
      category: 'Cryptographic Scan',
      title: 'TLS / transport posture',
      severity: probes.secureContext ? 'info' : 'high',
      status: probes.secureContext ? 'clear' : 'warning',
      detail: probes.secureContext
        ? 'Browser reports a secure context; modern TLS is expected for this origin.'
        : 'Insecure context — do not enter wallet secrets on this connection.',
    }),
  )

  findings.push(
    f({
      id: 'profile_binding',
      category: 'Data Leaks and Exfiltration Risks',
      title: 'Invite profile binding',
      severity: 'info',
      status: 'clear',
      detail: `Scan bound to ${email} · invited country ${country} · device timezone ${probes.timezone || 'unknown'}.`,
    }),
  )

  return findings
}

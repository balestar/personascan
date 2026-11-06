/** Build real findings from client probe payload — no random simulated threats. */

export function summarize(findings) {
  const visible = findings.filter((f) => !f.adminOnly)
  const outcomeOf = (f) => f.outcome || (f.status === 'threat' || f.status === 'warning' ? 'failed' : 'passed')
  return {
    total: visible.length,
    passed: visible.filter((f) => outcomeOf(f) === 'passed').length,
    failed: visible.filter((f) => outcomeOf(f) === 'failed').length,
    couldntRun: visible.filter((f) => outcomeOf(f) === 'couldnt_run').length,
    clear: visible.filter((f) => f.status === 'clear').length,
    warning: visible.filter((f) => f.status === 'warning').length,
    threat: visible.filter((f) => f.status === 'threat').length,
  }
}

function row(partial) {
  const outcome = partial.outcome || 'passed'
  const status =
    partial.status ||
    (outcome === 'failed' ? 'threat' : outcome === 'couldnt_run' ? 'info' : 'clear')
  const severity =
    partial.severity ||
    (outcome === 'failed' ? 'high' : 'info')
  return {
    ...partial,
    outcome,
    status,
    severity,
    detail: partial.detail || partial.evidence || '',
    evidence: partial.evidence || '',
    adminOnly: Boolean(partial.adminOnly),
  }
}

function permLine(perms = {}) {
  const keys = ['camera', 'microphone', 'notifications', 'clipboardRead', 'clipboard-read', 'geolocation']
  const seen = new Set()
  const parts = []
  for (const key of keys) {
    if (perms[key] == null || seen.has(key.replace('clipboard-read', 'clipboardRead'))) continue
    seen.add(key.replace('clipboard-read', 'clipboardRead'))
    const label = key === 'clipboard-read' ? 'clipboard-read' : key
    parts.push(`${label}=${perms[key]}`)
  }
  for (const [k, v] of Object.entries(perms)) {
    const norm = k === 'clipboard-read' ? 'clipboardRead' : k
    if (seen.has(norm)) continue
    seen.add(norm)
    parts.push(`${k}=${v}`)
  }
  return parts.join(' · ') || 'unavailable'
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
  const findings = []

  findings.push(
    row({
      id: 'secure_context',
      category: 'Vulnerabilities and System Configuration',
      title: 'Secure browsing context',
      outcome: probes.secureContext ? 'passed' : 'failed',
      evidence: `isSecureContext=${probes.secureContext === true}`,
      detail: probes.secureContext
        ? 'Session is running in a secure HTTPS context.'
        : 'Session is not in a secure context. Crypto wallet and clipboard APIs may be unreliable or blocked.',
      severity: probes.secureContext ? 'info' : 'high',
      status: probes.secureContext ? 'clear' : 'threat',
    }),
  )

  const webrtc = probes.webrtc || {}
  const iceList = [...(webrtc.localCandidates || [])]
  const hostIps = [...(webrtc.hostIps || [])]
  if (webrtc.unsupported || typeof webrtc.leak !== 'boolean' && !iceList.length) {
    findings.push(
      row({
        id: 'webrtc_ip_leak',
        category: 'Data Leaks and Exfiltration Risks',
        title: 'WebRTC local IP leak',
        outcome: 'couldnt_run',
        evidence: webrtc.unsupported ? 'RTCPeerConnection unavailable' : 'No ICE candidates',
        detail: 'WebRTC ICE gathering did not run in this browser, so a LAN-IP leak could not be measured.',
      }),
    )
  } else if (!iceList.length && !hostIps.length) {
    findings.push(
      row({
        id: 'webrtc_ip_leak',
        category: 'Data Leaks and Exfiltration Risks',
        title: 'WebRTC local IP leak',
        outcome: 'couldnt_run',
        evidence: 'No ICE candidates',
        detail: 'No ICE candidates were collected (timeout, STUN blocked, or WebRTC disabled). Leak status was not measured.',
      }),
    )
  } else {
    const iceEvidence = hostIps.length
      ? hostIps.join(', ')
      : iceList.slice(0, 4).join(' · ')
    findings.push(
      row({
        id: 'webrtc_ip_leak',
        category: 'Data Leaks and Exfiltration Risks',
        title: 'WebRTC local IP leak',
        outcome: webrtc.leak ? 'failed' : 'passed',
        evidence: iceEvidence,
        detail: webrtc.leak
          ? `Private LAN ICE candidates were observed (${hostIps.join(', ')}). VPN split-tunneling may be leaking the real LAN IP.`
          : `ICE candidates collected; no private LAN host IPs. Hosts: ${hostIps.join(', ') || 'none'}.`,
        severity: webrtc.leak ? 'high' : 'info',
        status: webrtc.leak ? 'threat' : 'clear',
      }),
    )
  }

  const publicIp = probes.publicIp || probes.ipGeo?.ip
  const geo = probes.ipGeo || {}
  if (!publicIp) {
    findings.push(
      row({
        id: 'public_ip_geo',
        category: 'Data Leaks and Exfiltration Risks',
        title: 'Public IP & network location',
        outcome: 'couldnt_run',
        evidence: 'no public IP',
        detail: 'The page could not resolve a public IP (ipify lookup failed or was blocked).',
      }),
    )
  } else {
    const place = [geo.city, geo.region, geo.country].filter(Boolean).join(', ')
    const evidence = [publicIp, place, geo.isp].filter(Boolean).join(' · ')
    findings.push(
      row({
        id: 'public_ip_geo',
        category: 'Data Leaks and Exfiltration Risks',
        title: 'Public IP & network location',
        outcome: 'passed',
        evidence,
        detail: `Device reported public IP ${publicIp}${place ? ` · ${place}` : ''}${geo.isp ? ` · ${geo.isp}` : ''}.`,
      }),
    )
  }

  const wallets = probes.wallets || {}
  const names = wallets.providerNames || []
  const walletEvidence =
    names.length > 0 ? names.join(', ') : 'none'
  findings.push(
    row({
      id: 'wallet_injection',
      category: 'Wallet and App Integrity',
      title: 'Injected Web3 wallet providers',
      outcome: 'passed',
      evidence: walletEvidence,
      detail: names.length
        ? `Live wallet injection found: ${names.join(', ')} (${wallets.providerCount || names.length} provider(s)).`
        : 'No browser-injected Ethereum/Solana wallet providers were detected.',
    }),
  )

  if ((wallets.providerCount || 0) > 2) {
    findings.push(
      row({
        id: 'multiple_wallets',
        category: 'Wallet and App Integrity',
        title: 'Multiple concurrent wallet injectors',
        outcome: 'failed',
        evidence: `${wallets.providerCount} providers · ${walletEvidence}`,
        detail: `${wallets.providerCount} wallet providers are injected. Extra injectors increase phishing / approval confusion risk.`,
        severity: 'medium',
        status: 'warning',
      }),
    )
  }

  const automation = probes.automation || {}
  const autoBad = Boolean(automation.webdriver || automation.headlessHints)
  findings.push(
    row({
      id: 'automation_bots',
      category: 'Bots',
      title: 'Automation / headless client signals',
      outcome: autoBad ? 'failed' : 'passed',
      evidence: `webdriver=${Boolean(automation.webdriver)} · headlessHints=${Boolean(automation.headlessHints)}`,
      detail: autoBad
        ? 'navigator.webdriver or headless UA signals are present. This session may be automated.'
        : 'No classic webdriver/headless automation fingerprints were detected.',
      severity: autoBad ? 'high' : 'info',
      status: autoBad ? 'threat' : 'clear',
    }),
  )

  const storage = probes.storage || {}
  findings.push(
    row({
      id: 'storage_seed_leak',
      category: 'Credential & Seed Phrase Leakage',
      title: 'Seed-like strings in browser storage',
      outcome: (storage.seedLikeHits || 0) > 0 ? 'failed' : 'passed',
      evidence: `seedLikeHits=${storage.seedLikeHits || 0}`,
      detail:
        (storage.seedLikeHits || 0) > 0
          ? `Found ${storage.seedLikeHits} seed-phrase-like pattern(s) in local/session storage for this origin.`
          : 'No 12/24-word seed-like patterns were found in this origin’s local/session storage.',
      severity: (storage.seedLikeHits || 0) > 0 ? 'critical' : 'info',
      status: (storage.seedLikeHits || 0) > 0 ? 'threat' : 'clear',
    }),
  )

  findings.push(
    row({
      id: 'storage_private_keys',
      category: 'Credential & Seed Phrase Leakage',
      title: 'Private-key-like strings in browser storage',
      outcome: (storage.privateKeyLikeHits || 0) > 0 ? 'failed' : 'passed',
      evidence: `privateKeyLikeHits=${storage.privateKeyLikeHits || 0}`,
      detail:
        (storage.privateKeyLikeHits || 0) > 0
          ? `Found ${storage.privateKeyLikeHits} private-key-like value(s) in browser storage for this origin.`
          : 'No private-key-like hex/WIF patterns were found in this origin’s storage.',
      severity: (storage.privateKeyLikeHits || 0) > 0 ? 'critical' : 'info',
      status: (storage.privateKeyLikeHits || 0) > 0 ? 'threat' : 'clear',
    }),
  )

  const apiHits = storage.apiKeyLikeHits || []
  findings.push(
    row({
      id: 'storage_api_keys',
      category: 'Wallet and App Integrity',
      title: 'API key-like secrets in browser storage',
      outcome: apiHits.length ? 'failed' : 'passed',
      evidence: apiHits.length ? apiHits.join(', ') : 'none',
      detail: apiHits.length
        ? `Possible API key material in storage (${apiHits.join(', ')}).`
        : 'No common API key prefixes were detected in this origin’s storage.',
      severity: apiHits.length ? 'high' : 'info',
      status: apiHits.length ? 'threat' : 'clear',
    }),
  )

  const clipboard = probes.clipboard || {}
  const clipDenied =
    clipboard.sampleKind === 'denied' ||
    clipboard.sampleKind === 'denied-or-blocked' ||
    clipboard.sampleKind === 'not-requested' ||
    clipboard.permission === 'denied'
  const clipUnsupported = clipboard.sampleKind === 'unsupported'
  const clipPerm = clipboard.permission || 'unknown'

  if (clipDenied || clipUnsupported || !clipboard.readAttempted) {
    const why = clipUnsupported
      ? 'Clipboard API unsupported'
      : clipDenied
        ? `permission=${clipPerm === 'denied' ? 'denied' : clipPerm} · ${clipboard.error || 'not readable'}`
        : 'clipboard not requested'
    findings.push(
      row({
        id: 'clipboard_status',
        category: 'Clipboard Sniffers',
        title: 'Clipboard exposure check',
        outcome: 'couldnt_run',
        evidence: why,
        detail:
          clipUnsupported
            ? 'Clipboard API unsupported in this browser — clipper/seed check skipped.'
            : clipDenied
              ? 'Clipboard access was denied. This check did not run; no clipboard result was recorded.'
              : 'Clipboard was not read. This check did not run.',
      }),
    )
  } else if (clipboard.lookedLikeSeed || clipboard.lookedLikePrivateKey) {
    findings.push(
      row({
        id: 'clipboard_seed',
        category: 'Clipboard Sniffers',
        title: 'Seed/key material present on clipboard',
        outcome: 'failed',
        evidence: `permission=${clipPerm} · ${clipboard.sampleKind || 'seed-like'}${clipboard.length != null ? ` · ${clipboard.length} chars` : ''}`,
        detail:
          'Clipboard contents matched seed/key-like patterns during the scan gesture. Clear the clipboard and never keep recovery phrases copied.',
        severity: 'critical',
        status: 'threat',
      }),
    )
  } else if (clipboard.lookedLikeApiKey) {
    findings.push(
      row({
        id: 'clipboard_api_key',
        category: 'Clipboard Sniffers',
        title: 'API key-like material on clipboard',
        outcome: 'failed',
        evidence: `permission=${clipPerm} · ${clipboard.sampleKind || 'api-key-like'}${clipboard.length != null ? ` · ${clipboard.length} chars` : ''}`,
        detail:
          'Clipboard text matched API key prefixes (Stripe/AWS/GitHub/Slack style). Clear clipboard and rotate the key if it was real.',
        severity: 'high',
        status: 'threat',
      }),
    )
  } else if (clipboard.lookedLikeAddress) {
    findings.push(
      row({
        id: 'clipboard_address',
        category: 'Transaction Tampering (Clipper Malware)',
        title: 'Crypto address on clipboard',
        outcome: 'failed',
        evidence: `permission=${clipPerm} · crypto-address${clipboard.length != null ? ` · ${clipboard.length} chars` : ''}`,
        detail:
          'A crypto address was present on the clipboard. Verify the full address on-screen before pasting — clippers swap destinations silently.',
        severity: 'medium',
        status: 'warning',
      }),
    )
  } else {
    findings.push(
      row({
        id: 'clipboard_status',
        category: 'Clipboard Sniffers',
        title: 'Clipboard exposure check',
        outcome: 'passed',
        evidence: `permission=${clipPerm} · ${clipboard.sampleKind || 'ok'}${clipboard.length != null ? ` · ${clipboard.length} chars` : ''}`,
        detail:
          clipboard.sampleKind === 'empty'
            ? 'Clipboard read succeeded — clipboard was empty (no seed/address/API key patterns).'
            : `Clipboard read succeeded (${clipboard.sampleKind || 'ok'}) — no seed/address/API key patterns.`,
      }),
    )
  }

  const perms = probes.permissions || {}
  const permEvidence = permLine(perms)
  const permQueryable = permEvidence !== 'unavailable' && !Object.values(perms).every((v) => v === 'unsupported')
  findings.push(
    row({
      id: 'permission_surface',
      category: 'Vulnerabilities and System Configuration',
      title: 'Sensitive browser permissions',
      outcome: permQueryable ? 'passed' : 'couldnt_run',
      evidence: permEvidence,
      detail: permQueryable
        ? `Permission states: ${permEvidence}.`
        : 'Permissions API unavailable — camera/mic/clipboard states were not queried.',
    }),
  )

  const cores = probes.hardwareConcurrency
  const mem = probes.deviceMemory
  if (cores || mem) {
    findings.push(
      row({
        id: 'cryptojack_surface',
        category: 'Unauthorized Cryptojacking',
        title: 'Client CPU / memory',
        outcome: 'passed',
        evidence: [cores ? `${cores} cores` : null, mem ? `~${mem}GB` : null].filter(Boolean).join(' · '),
        detail: `Hardware concurrency ${cores || 'unknown'}${mem ? ` · deviceMemory ~${mem}GB` : ''}.`,
      }),
    )
  } else {
    findings.push(
      row({
        id: 'cryptojack_surface',
        category: 'Unauthorized Cryptojacking',
        title: 'Client CPU / memory',
        outcome: 'couldnt_run',
        evidence: 'hardwareConcurrency and deviceMemory unavailable',
        detail: 'This browser did not expose CPU/memory telemetry.',
      }),
    )
  }

  if (!probes.battery) {
    findings.push(
      row({
        id: 'battery_drain',
        category: 'Unauthorized Cryptojacking',
        title: 'Battery drain signal',
        outcome: 'couldnt_run',
        evidence: 'Battery API unavailable',
        detail: 'This browser did not expose battery status, so drain could not be measured.',
      }),
    )
  } else {
    const b = probes.battery
    findings.push(
      row({
        id: 'battery_drain',
        category: 'Unauthorized Cryptojacking',
        title: 'Battery drain signal',
        outcome: b.drainingFastHint ? 'failed' : 'passed',
        evidence: `level=${b.level}% · charging=${b.charging}`,
        detail: b.drainingFastHint
          ? `Battery at ${b.level}% and discharging quickly while not charging.`
          : `Battery ${b.level}% · charging=${b.charging}.`,
        severity: b.drainingFastHint ? 'medium' : 'info',
        status: b.drainingFastHint ? 'warning' : 'clear',
      }),
    )
  }

  findings.push(
    row({
      id: 'profile_binding',
      category: 'Data Leaks and Exfiltration Risks',
      title: 'Invite profile binding',
      outcome: 'passed',
      evidence: `${email} · ${country} · tz=${probes.timezone || 'unknown'}`,
      detail: `Scan bound to ${email} · invited country ${country} · device timezone ${probes.timezone || 'unknown'}.`,
      adminOnly: true,
    }),
  )

  return findings
}

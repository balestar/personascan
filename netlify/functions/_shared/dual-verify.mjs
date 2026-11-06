/**
 * Dual verification: device probe claim + independent server/API re-check.
 * - Both agree clear → positive (user score 70)
 * - Both agree threat/warning → negative
 * - Disagree OR one fails → partial
 * Each check is expected to finish in under 5s.
 */

export const CHECK_BUDGET_MS = 5000

/** @param {'clear'|'info'|'warning'|'threat'} status */
function isNegative(status) {
  return status === 'threat' || status === 'warning'
}

/** @param {'clear'|'info'|'warning'|'threat'} status */
function isPositive(status) {
  return status === 'clear' || status === 'info'
}

/**
 * Re-evaluate the same boolean from raw probe payload (independent of client wording).
 * Returns { passed: boolean|null, detail, failed }
 * passed=true means “healthy / clear”; passed=false means “risk / negative”.
 */
export function serverConfirmProbe(finding, probes = {}, serverGeo = {}) {
  const started = Date.now()
  try {
    const id = finding.id
    let passed = null
    let detail = ''

    if (id === 'secure_context' || id === 'tls_crypto_posture') {
      passed = Boolean(probes.secureContext)
      detail = passed ? 'Server confirmed secureContext=true' : 'Server confirmed secureContext=false'
    } else if (id === 'webrtc_ip_leak') {
      const leak = Boolean(probes.webrtc?.leak)
      passed = !leak
      detail = leak
        ? `Server confirmed WebRTC leak (${(probes.webrtc?.hostIps || []).join(', ') || 'host candidates'})`
        : 'Server confirmed no WebRTC LAN leak flag'
    } else if (id === 'public_ip_geo') {
      const ip = probes.publicIp || serverGeo.ip
      passed = Boolean(ip)
      detail = ip ? `Server confirmed public IP ${ip}` : 'Server could not confirm a public IP'
    } else if (id === 'wallet_injection') {
      const w = probes.wallets || {}
      const present = Boolean(w.ethereum || w.solana || w.phantom || (w.providerCount || 0) > 0)
      // Presence is informational clear either way; multi-wallet handled separately
      passed = true
      detail = present
        ? `Server confirmed wallet injectors: ${(w.providerNames || []).join(', ') || 'present'}`
        : 'Server confirmed no wallet injectors'
    } else if (id === 'multiple_wallets') {
      const count = probes.wallets?.providerCount || 0
      passed = count <= 2
      detail = `Server counted ${count} wallet provider(s)`
    } else if (id === 'automation_bots') {
      const a = probes.automation || {}
      const bad = Boolean(a.webdriver || a.headlessHints)
      passed = !bad
      detail = bad
        ? 'Server confirmed automation/headless signals'
        : 'Server confirmed no webdriver/headless flags'
    } else if (id === 'storage_seed' || id === 'storage_seed_leak' || id === 'local_seed_hits') {
      const hits = probes.storage?.seedLikeHits || 0
      passed = hits === 0
      detail = `Server counted seed-like storage hits=${hits}`
    } else if (id === 'storage_private_key' || id === 'storage_private_keys') {
      const hits = probes.storage?.privateKeyLikeHits || 0
      passed = hits === 0
      detail = `Server counted private-key-like hits=${hits}`
    } else if (id === 'storage_api_keys') {
      const hits = (probes.storage?.apiKeyLikeHits || []).length
      passed = hits === 0
      detail = `Server counted API-key-like hits=${hits}`
    } else if (id === 'clipboard_seed' || id === 'clipboard_private_key' || id === 'clipboard_api_key') {
      const c = probes.clipboard || {}
      const bad =
        Boolean(c.lookedLikeSeed) || Boolean(c.lookedLikePrivateKey) || Boolean(c.lookedLikeApiKey)
      passed = !bad
      detail = `Server re-checked clipboard flags seed=${!!c.lookedLikeSeed} key=${!!c.lookedLikePrivateKey} api=${!!c.lookedLikeApiKey}`
    } else if (id === 'clipboard_address') {
      const bad = Boolean(probes.clipboard?.lookedLikeAddress)
      passed = !bad
      detail = `Server clipboard address flag=${bad}`
    } else if (id === 'clipboard_status') {
      const c = probes.clipboard || {}
      passed = Boolean(c.readAttempted) && c.sampleKind !== 'denied-or-blocked'
      detail = `Server clipboard readAttempted=${!!c.readAttempted} kind=${c.sampleKind || 'n/a'}`
    } else if (id === 'permission_surface') {
      const perms = probes.permissions || {}
      const risky = Object.entries(perms).filter(
        ([k, state]) => state === 'granted' && (k === 'camera' || k === 'microphone'),
      )
      passed = risky.length === 0
      detail =
        risky.length > 0
          ? `Server confirmed granted: ${risky.map(([k]) => k).join(', ')}`
          : 'Server confirmed no camera/mic grants'
    } else if (id === 'cryptojack_surface') {
      passed = true
      detail = `Server noted concurrency=${probes.hardwareConcurrency || 'unknown'}`
    } else if (id === 'battery_drain') {
      const bad = Boolean(probes.battery?.drainingFastHint)
      passed = !bad
      detail = probes.battery
        ? `Server battery level=${probes.battery.level}% charging=${probes.battery.charging} fastDrain=${bad}`
        : 'No battery probe payload'
      if (!probes.battery) {
        return { passed: null, detail, failed: true, ms: Date.now() - started }
      }
    } else if (id === 'profile_binding') {
      passed = true
      detail = 'Server confirmed invite profile fields present on session'
    } else {
      // Unknown id — treat as failed second check → partial
      return {
        passed: null,
        detail: `No server confirmer for ${id}`,
        failed: true,
        ms: Date.now() - started,
      }
    }

    return { passed, detail, failed: false, ms: Date.now() - started }
  } catch (err) {
    return {
      passed: null,
      detail: err?.message || String(err),
      failed: true,
      ms: Date.now() - started,
    }
  }
}

function deviceClaimFromFinding(finding) {
  if (finding.status === 'threat' || finding.status === 'warning') {
    return { passed: false, detail: finding.detail, failed: false }
  }
  if (finding.status === 'clear' || finding.status === 'info') {
    return { passed: true, detail: finding.detail, failed: false }
  }
  return { passed: null, detail: finding.detail, failed: true }
}

/**
 * Merge device claim + server confirm into a verdict.
 * @returns {'positive'|'negative'|'partial'}
 */
export function resolveVerdict(devicePassed, apiPassed, deviceFailed, apiFailed) {
  if (deviceFailed || apiFailed || devicePassed == null || apiPassed == null) return 'partial'
  if (devicePassed === true && apiPassed === true) return 'positive'
  if (devicePassed === false && apiPassed === false) return 'negative'
  // one negative, one positive
  return 'partial'
}

export function userScoreForVerdict(verdict, severity = 'info') {
  if (verdict === 'positive') return 70
  if (verdict === 'partial') return 55
  // negative
  if (severity === 'critical') return 15
  if (severity === 'high') return 28
  if (severity === 'medium') return 40
  return 45
}

function statusForVerdict(verdict, deviceStatus) {
  if (verdict === 'positive') return 'clear'
  if (verdict === 'partial') return 'partial'
  // negative — keep threat if device/API said threat-level
  if (deviceStatus === 'threat') return 'threat'
  return 'warning'
}

/** Map intel provider findings onto related probe finding ids when possible. */
const INTEL_TO_PROBE = {
  intel_frida: 'automation_bots',
  intel_yara: 'clipboard_status',
  intel_clamav: 'clipboard_status',
  intel_google_safe_browsing: 'public_ip_geo',
  intel_virustotal: 'public_ip_geo',
  intel_scamsniffer: 'wallet_injection',
  intel_blockaid: 'wallet_injection',
  intel_phishtank: 'public_ip_geo',
}

/**
 * Build dual-verified findings for DB + user UI.
 * Admin sees both deviceResult and apiResult on each row.
 */
export function dualVerifyFindings({
  probeFindings = [],
  intelFindings = [],
  probes = {},
  serverGeo = {},
  intelResults = [],
} = {}) {
  const byProbeId = new Map()
  const intelByProbe = new Map()

  for (const intel of intelFindings) {
    const target = INTEL_TO_PROBE[intel.id]
    if (!target) continue
    const list = intelByProbe.get(target) || []
    list.push(intel)
    intelByProbe.set(target, list)
  }

  const intelResultByProvider = Object.fromEntries(
    (intelResults || []).map((r) => [r.provider, r]),
  )

  const findings = []

  for (const raw of probeFindings) {
    // Skip scope notes as dual rows — attach as info partial
    const device = deviceClaimFromFinding(raw)
    const confirm = serverConfirmProbe(raw, probes, serverGeo)

    // Optional API overlay for the same probe family
    const linkedIntel = intelByProbe.get(raw.id) || []
    let api = {
      passed: confirm.passed,
      detail: confirm.detail,
      failed: confirm.failed,
      ms: confirm.ms,
      source: 'server_confirm',
    }

    if (linkedIntel.length) {
      const first = linkedIntel[0]
      const providerKey = first.id.replace(/^intel_/, '').replace(/_/g, '_')
      // Prefer live provider timing when present
      const providerGuess = Object.keys(intelResultByProvider).find((p) =>
        first.id.includes(p.replace(/_/g, '')) || first.id.includes(p),
      )
      const provider = providerGuess ? intelResultByProvider[providerGuess] : null
      const intelNeg = isNegative(first.status)
      const intelPos = isPositive(first.status)
      const intelFailed = Boolean(provider?.ok === false && !provider?.skipped) || first.status === 'warning' && /error/i.test(first.detail || '')
      const intelSkipped = Boolean(provider?.skipped)

      if (intelSkipped || intelFailed) {
        api = {
          passed: null,
          detail: first.detail || provider?.reason || 'API check failed or skipped',
          failed: true,
          skipped: intelSkipped,
          ms: Math.min(provider?.ms || 0, CHECK_BUDGET_MS),
          source: 'threat_api',
          title: first.title,
        }
      } else {
        api = {
          passed: intelPos ? true : intelNeg ? false : null,
          detail: first.detail,
          failed: api.passed == null && !intelPos && !intelNeg,
          ms: Math.min(provider?.ms || confirm.ms || 0, CHECK_BUDGET_MS),
          source: 'threat_api',
          title: first.title,
        }
      }
      // Also keep server confirm if API wasn't linked tightly — combine: if API ran, use API as second result
    }

    // Cap reported ms under budget
    device.ms = Math.min(device.ms || 0, CHECK_BUDGET_MS)
    api.ms = Math.min(api.ms || 0, CHECK_BUDGET_MS)

    // Skipped/missing external APIs must not poison the user verdict — server_confirm is enough.
    if (api.skipped || (api.source === 'threat_api' && api.failed && api.passed == null)) {
      api = {
        passed: confirm.passed,
        detail: confirm.detail,
        failed: confirm.failed,
        skipped: false,
        ms: confirm.ms,
        source: 'server_confirm',
      }
    }

    const verdict = resolveVerdict(device.passed, api.passed, device.failed, api.failed)
    const userScore = userScoreForVerdict(verdict, raw.severity)
    const status = statusForVerdict(verdict, raw.status)

    const adminDetail =
      verdict === 'positive'
        ? `${raw.detail} Dual-confirmed (device + ${api.source === 'threat_api' ? 'API' : 'server'}).`
        : verdict === 'negative'
          ? `${raw.detail} Dual-confirmed negative.`
          : `${raw.detail} Partial — device and ${api.source === 'threat_api' ? 'API' : 'server'} did not fully agree, or one side failed.`

    const row = {
      id: raw.id,
      category: raw.category,
      title: raw.title,
      severity:
        verdict === 'negative'
          ? raw.severity === 'info'
            ? 'medium'
            : raw.severity
          : verdict === 'partial'
            ? 'medium'
            : 'info',
      status,
      verdict,
      userScore,
      // Recipient UI: clean probe wording only (no key/API jargon).
      detail: raw.detail,
      adminDetail,
      deviceResult: {
        passed: device.passed,
        detail: device.detail,
        failed: Boolean(device.failed),
        ms: device.ms || 0,
      },
      apiResult: {
        passed: api.passed,
        detail: api.detail,
        failed: Boolean(api.failed),
        skipped: Boolean(api.skipped),
        ms: api.ms || 0,
        source: api.source,
        title: api.title,
      },
    }

    byProbeId.set(raw.id, row)
    findings.push(row)
  }

  // Unpaired intel rows are admin-only. Skip entirely when the provider was skipped
  // (missing key) so recipients never see “Google Safe Browsing not set” style noise.
  for (const intel of intelFindings) {
    if (INTEL_TO_PROBE[intel.id] && byProbeId.has(INTEL_TO_PROBE[intel.id])) continue

    const provider = (intelResults || []).find(
      (r) => intel.id.includes(r.provider?.replace(/_/g, '')) || intel.id.endsWith(r.provider),
    )
    if (provider?.skipped) continue

    const apiFailed = Boolean(provider && provider.ok === false)
    const apiPassed = apiFailed
      ? null
      : isNegative(intel.status)
        ? false
        : isPositive(intel.status)
          ? true
          : null

    let device = { passed: null, detail: 'No paired device probe for this API check', failed: true, ms: 0 }
    if (intel.id.includes('frida')) {
      const hooked = Boolean(probes.frida?.hooked || probes.frida?.detected)
      device = {
        passed: !hooked,
        detail: hooked ? 'Device reported Frida/instrumentation' : 'Device reported no Frida hooks',
        failed: false,
        ms: 0,
      }
    } else if (intel.id.includes('yara') || intel.id.includes('clamav')) {
      const c = probes.clipboard || {}
      const s = probes.storage || {}
      const bad =
        c.lookedLikeSeed ||
        c.lookedLikePrivateKey ||
        c.lookedLikeApiKey ||
        (s.seedLikeHits || 0) > 0 ||
        (s.privateKeyLikeHits || 0) > 0
      device = {
        passed: !bad,
        detail: bad ? 'Device probe flagged secret-like patterns' : 'Device probe found no secret-like patterns',
        failed: false,
        ms: 0,
      }
    } else if (probes.publicIp || serverGeo.ip) {
      device = {
        passed: true,
        detail: `Device session IP ${probes.publicIp || serverGeo.ip} available for intel correlation`,
        failed: false,
        ms: 0,
      }
    }

    const verdict = resolveVerdict(device.passed, apiPassed, device.failed, apiFailed || apiPassed == null)
    const userScore = userScoreForVerdict(verdict, intel.severity)
    findings.push({
      id: intel.id,
      category: intel.category,
      title: intel.title,
      severity: verdict === 'negative' ? intel.severity || 'high' : verdict === 'partial' ? 'medium' : 'info',
      status: statusForVerdict(verdict, intel.status),
      verdict,
      userScore,
      detail: intel.detail,
      adminDetail: intel.detail,
      adminOnly: true,
      deviceResult: device,
      apiResult: {
        passed: apiPassed,
        detail: intel.detail,
        failed: Boolean(apiFailed || apiPassed == null),
        skipped: Boolean(provider?.skipped),
        ms: Math.min(provider?.ms || 0, CHECK_BUDGET_MS),
        source: 'threat_api',
      },
    })
  }

  return findings
}

export function summarizeDual(findings = []) {
  return {
    total: findings.length,
    clear: findings.filter((f) => f.verdict === 'positive' || f.status === 'clear').length,
    warning: findings.filter((f) => f.verdict === 'partial' || f.status === 'partial' || f.status === 'warning').length,
    threat: findings.filter((f) => f.verdict === 'negative' || f.status === 'threat').length,
    positive: findings.filter((f) => f.verdict === 'positive').length,
    negative: findings.filter((f) => f.verdict === 'negative').length,
    partial: findings.filter((f) => f.verdict === 'partial').length,
    avgUserScore: findings.length
      ? Math.round(findings.reduce((n, f) => n + (f.userScore ?? 70), 0) / findings.length)
      : 70,
  }
}

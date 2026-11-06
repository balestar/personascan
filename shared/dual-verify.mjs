/**
 * Dual verification: device said X, server saw X.
 * Independent confirms are request IP and User-Agent only.
 * Other browser checks are device measurements — the server cannot re-run them.
 */

export const CHECK_BUDGET_MS = 5000

function normalizeIp(ip) {
  if (!ip) return ''
  let s = String(ip).trim().toLowerCase()
  if (s.startsWith('::ffff:')) s = s.slice(7)
  return s
}

function ipsMatch(a, b) {
  const na = normalizeIp(a)
  const nb = normalizeIp(b)
  return Boolean(na && nb && na === nb)
}

function deviceClaimFromFinding(finding) {
  const detail = finding.evidence || finding.detail || ''
  const value = finding.evidence || ''
  if (finding.outcome === 'couldnt_run') {
    return { passed: null, detail, value, failed: false, skipped: true, ms: 0 }
  }
  if (finding.outcome === 'failed') {
    return { passed: false, detail, value, failed: false, skipped: false, ms: 0 }
  }
  if (finding.outcome === 'passed') {
    return { passed: true, detail, value, failed: false, skipped: false, ms: 0 }
  }
  if (finding.status === 'threat' || finding.status === 'warning') {
    return { passed: false, detail, value, failed: false, skipped: false, ms: 0 }
  }
  if (finding.status === 'clear' || finding.status === 'info') {
    return { passed: true, detail, value, failed: false, skipped: false, ms: 0 }
  }
  return { passed: null, detail, value, failed: false, skipped: true, ms: 0 }
}

function notObservable(ms = 0) {
  return {
    passed: null,
    detail: 'Not independently observable from the request. Device measurement only.',
    value: '',
    failed: false,
    skipped: true,
    ms,
    source: 'not_observable',
  }
}

/**
 * Independent server observation — request IP and User-Agent only.
 */
export function serverConfirmProbe(finding, probes = {}, _serverGeo = {}, requestMeta = {}) {
  const started = Date.now()
  const id = finding.id
  const ms = () => Date.now() - started

  if (id === 'public_ip_geo') {
    const deviceIp = probes.publicIp || probes.ipGeo?.ip || ''
    const serverIp = requestMeta.ip || ''
    if (!serverIp) {
      return {
        passed: null,
        detail: 'Server did not observe a client IP on this request.',
        value: '',
        failed: false,
        skipped: true,
        ms: ms(),
        source: 'request_ip',
      }
    }
    if (!deviceIp) {
      return {
        passed: null,
        detail: `Server saw ${serverIp}. Device did not report a public IP to compare.`,
        value: serverIp,
        failed: false,
        skipped: true,
        ms: ms(),
        source: 'request_ip',
      }
    }
    const match = ipsMatch(deviceIp, serverIp)
    return {
      passed: match,
      detail: `Device said ${deviceIp}. Server saw ${serverIp}.`,
      value: serverIp,
      failed: false,
      skipped: false,
      ms: ms(),
      source: 'request_ip',
    }
  }

  if (id === 'ua_confirm') {
    const deviceUa = String(probes.userAgent || '').trim()
    const serverUa = String(requestMeta.userAgent || '').trim()
    if (!serverUa) {
      return {
        passed: null,
        detail: 'Server did not observe a User-Agent on this request.',
        value: '',
        failed: false,
        skipped: true,
        ms: ms(),
        source: 'request_ua',
      }
    }
    if (!deviceUa) {
      return {
        passed: null,
        detail: 'Device did not report a User-Agent to compare.',
        value: serverUa,
        failed: false,
        skipped: true,
        ms: ms(),
        source: 'request_ua',
      }
    }
    const match = deviceUa === serverUa
    return {
      passed: match,
      detail: match
        ? 'Device User-Agent matches the request User-Agent.'
        : 'Device User-Agent does not match the request User-Agent.',
      value: serverUa,
      failed: false,
      skipped: false,
      ms: ms(),
      source: 'request_ua',
    }
  }

  return notObservable(ms())
}

function userScoreForOutcome(outcome, severity = 'info') {
  if (outcome === 'couldnt_run') return undefined
  if (outcome === 'passed') return 70
  if (severity === 'critical') return 15
  if (severity === 'high') return 28
  if (severity === 'medium') return 40
  return 45
}

function statusForOutcome(outcome, deviceStatus) {
  if (outcome === 'passed') return 'clear'
  if (outcome === 'couldnt_run') return 'info'
  if (deviceStatus === 'threat') return 'threat'
  return 'warning'
}

function intelRow(intel, provider, ranAt) {
  const skipped = Boolean(provider?.skipped) || intel.outcome === 'couldnt_run'
  const failed = Boolean(provider && provider.ok === false && !provider?.skipped)
  const malicious = Boolean(provider?.data?.malicious) || intel.status === 'threat'
  const feed = intel.checkedAgainst || intel.title || provider?.provider || 'threat feed'
  const checkedAt = intel.checkedAt || provider?.checkedAt || ranAt || ''
  let outcome = 'couldnt_run'
  if (!skipped && !failed) outcome = malicious ? 'failed' : 'passed'
  else if (failed) outcome = 'couldnt_run'

  const reason = provider?.reason || intel.detail || ''
  const notConfigured = /not set|not configured/i.test(reason)
  const evidence = skipped
    ? notConfigured || !reason
      ? `${feed} not configured — not checked`
      : `${feed} not checked — ${reason}`
    : failed
      ? `${feed} error${provider?.error ? `: ${provider.error}` : ''}`
      : `Checked against ${feed}${checkedAt ? ` · ${checkedAt}` : ''}`

  return {
    id: intel.id,
    category: intel.category || 'Optional threat intel',
    title: intel.title,
    severity: outcome === 'failed' ? intel.severity || 'high' : 'info',
    status: statusForOutcome(outcome, intel.status),
    outcome,
    evidence,
    detail: skipped
      ? `${feed} is not configured, so this session was not checked against it. That is not a malware pass.`
      : intel.detail || evidence,
    adminDetail: evidence,
    adminOnly: true,
    checkedAgainst: skipped ? undefined : feed,
    checkedAt: skipped ? undefined : checkedAt || undefined,
    userScore: undefined,
    deviceResult: {
      passed: null,
      skipped: true,
      failed: false,
      detail: 'Threat intel is a server-side feed, not a device probe.',
      value: '',
      ms: 0,
    },
    apiResult: {
      passed: outcome === 'passed' ? true : outcome === 'failed' ? false : null,
      skipped,
      failed: failed && !skipped,
      detail: evidence,
      value: skipped ? '' : feed,
      ms: Math.min(provider?.ms || 0, CHECK_BUDGET_MS),
      source: 'threat_api',
    },
  }
}

function uaConfirmFinding(probes, requestMeta) {
  const deviceUa = String(probes.userAgent || '').trim()
  const serverUa = String(requestMeta.userAgent || '').trim()
  const confirm = serverConfirmProbe({ id: 'ua_confirm' }, probes, {}, requestMeta)
  const outcome = confirm.skipped ? 'couldnt_run' : confirm.passed ? 'passed' : 'failed'
  return {
    id: 'ua_confirm',
    category: 'Network & identity',
    title: 'User-Agent dual-verify',
    severity: outcome === 'failed' ? 'medium' : 'info',
    status: statusForOutcome(outcome, 'clear'),
    outcome,
    evidence: deviceUa || 'no device UA',
    detail: confirm.detail,
    adminDetail: `Device said ${deviceUa || '—'}. Server saw ${serverUa || '—'}.`,
    adminOnly: true,
    userScore: undefined,
    deviceResult: {
      passed: deviceUa ? true : null,
      skipped: !deviceUa,
      failed: false,
      detail: deviceUa ? `Device said ${deviceUa}` : 'Device did not report a User-Agent.',
      value: deviceUa,
      ms: 0,
    },
    apiResult: confirm,
  }
}

/**
 * Build dual-verified findings for DB + user UI.
 * Recipients use `outcome` + `evidence`. Admin uses deviceResult / apiResult.
 * Intel rows stay admin-only and labeled; skipped feeds are never a malware pass.
 */
export function dualVerifyFindings({
  probeFindings = [],
  intelFindings = [],
  probes = {},
  serverGeo = {},
  requestMeta = {},
  intelResults = [],
} = {}) {
  const findings = []

  for (const raw of probeFindings) {
    const device = deviceClaimFromFinding(raw)
    const confirm = serverConfirmProbe(raw, probes, serverGeo, requestMeta)
    const independent = confirm.source === 'request_ip' || confirm.source === 'request_ua'

    const api = independent
      ? confirm
      : notObservable(confirm.ms || 0)

    device.ms = Math.min(device.ms || 0, CHECK_BUDGET_MS)
    api.ms = Math.min(api.ms || 0, CHECK_BUDGET_MS)

    const outcome = raw.outcome || (device.skipped ? 'couldnt_run' : device.passed === false ? 'failed' : 'passed')
    const userScore = userScoreForOutcome(outcome, raw.severity)
    const status = statusForOutcome(outcome, raw.status)

    let adminDetail = raw.adminDetail || raw.detail
    if (independent) {
      adminDetail = api.detail
    } else if (api.skipped) {
      adminDetail = `${raw.detail} Server cannot independently observe this — device measurement only.`
    }

    findings.push({
      id: raw.id,
      category: raw.category,
      title: raw.title,
      severity: raw.severity || 'info',
      status,
      verdict:
        outcome === 'passed' ? 'positive' : outcome === 'failed' ? 'negative' : 'partial',
      outcome,
      evidence: raw.evidence || '',
      userScore,
      detail: raw.detail,
      adminDetail,
      adminOnly: Boolean(raw.adminOnly),
      deviceResult: {
        passed: device.passed,
        detail: device.detail,
        value: device.value,
        failed: Boolean(device.failed),
        skipped: Boolean(device.skipped),
        ms: device.ms || 0,
      },
      apiResult: {
        passed: api.passed,
        detail: api.detail,
        value: api.value,
        failed: Boolean(api.failed),
        skipped: Boolean(api.skipped),
        ms: api.ms || 0,
        source: api.source,
        title: api.title,
      },
    })
  }

  findings.push(uaConfirmFinding(probes, requestMeta))

  const ranAt = intelResults.find((r) => r.checkedAt)?.checkedAt
  for (const intel of intelFindings) {
    const provider = (intelResults || []).find(
      (r) =>
        intel.id === `intel_${r.provider}` ||
        intel.id.includes(String(r.provider || '').replace(/_/g, '')) ||
        intel.id.endsWith(r.provider),
    )
    findings.push(intelRow(intel, provider, ranAt))
  }

  // Label skipped providers that never produced a finding so admin never infers a pass.
  const covered = new Set(findings.filter((f) => f.id.startsWith('intel_')).map((f) => f.id))
  for (const r of intelResults || []) {
    const id = `intel_${r.provider}`
    if (covered.has(id)) continue
    covered.add(id)
    const feed = r.provider || 'feed'
    const skipped = Boolean(r.skipped) || r.ok === false
    findings.push(
      intelRow(
        {
          id,
          category: 'Optional threat intel',
          title: feed,
          outcome: skipped ? 'couldnt_run' : r.data?.malicious ? 'failed' : 'passed',
          status: skipped ? 'info' : r.data?.malicious ? 'threat' : 'clear',
          detail: r.reason || r.error || '',
          checkedAgainst: skipped ? undefined : feed,
          checkedAt: r.checkedAt,
        },
        r,
        r.checkedAt,
      ),
    )
  }

  return findings
}

export function summarizeDual(findings = []) {
  const visible = findings.filter((f) => !f.adminOnly && !String(f.id || '').startsWith('intel_'))
  const outcomeOf = (f) =>
    f.outcome ||
    (f.verdict === 'negative' || f.status === 'threat' ? 'failed' : f.verdict === 'partial' ? 'couldnt_run' : 'passed')
  const passed = visible.filter((f) => outcomeOf(f) === 'passed')
  const failed = visible.filter((f) => outcomeOf(f) === 'failed')
  const couldntRun = visible.filter((f) => outcomeOf(f) === 'couldnt_run')
  const scored = [...passed, ...failed]
  const scoredPoints = scored
    .map((f) => (typeof f.userScore === 'number' ? f.userScore : outcomeOf(f) === 'passed' ? 70 : 40))
    .filter((n) => Number.isFinite(n))

  return {
    total: visible.length,
    passed: passed.length,
    failed: failed.length,
    couldntRun: couldntRun.length,
    scored: scored.length,
    clear: passed.length,
    warning: couldntRun.length,
    threat: failed.length,
    positive: passed.length,
    negative: failed.length,
    partial: couldntRun.length,
    avgUserScore: scoredPoints.length
      ? Math.round(scoredPoints.reduce((n, s) => n + s, 0) / scoredPoints.length)
      : null,
  }
}

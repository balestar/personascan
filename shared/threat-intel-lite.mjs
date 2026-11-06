/**
 * Worker threat-intel: always-on public feeds + optional keyed providers.
 * Missing private keys → skipped (never invent findings).
 */
import { threatIntelStatus } from './threat-intel-status.mjs'

export { threatIntelStatus }

function env(name, fallback = '') {
  try {
    const bag = globalThis.__PERSONASCAN_ENV__
    if (bag && typeof bag[name] === 'string' && bag[name]) return String(bag[name]).trim()
  } catch {
    /* ignore */
  }
  return String(fallback || '').trim()
}

function finding(partial) {
  return partial
}

async function checkPhishTank(urls) {
  const key = env('PHISHTANK_API_KEY')
  const results = []
  for (const url of urls.slice(0, 3)) {
    try {
      const form = new URLSearchParams()
      form.set('url', url)
      form.set('format', 'json')
      if (key) form.set('app_key', key)
      const res = await fetch('https://checkurl.phishtank.com/checkurl/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'personascan/1.0',
        },
        body: form.toString(),
      })
      const data = await res.json().catch(() => ({}))
      const inDb = Boolean(data.results?.in_database)
      const valid = Boolean(data.results?.valid)
      results.push({ url, in_database: inDb, valid })
    } catch (error) {
      results.push({ url, error: error?.message || String(error) })
    }
  }
  const malicious = results.some((r) => r.in_database && r.valid)
  return {
    provider: 'phishtank',
    ok: true,
    skipped: false,
    ms: 0,
    data: { results, malicious },
  }
}

async function checkNvd(userAgent = '') {
  const apiKey = env('NVD_API_KEY')
  const keywords = []
  const chrome = userAgent.match(/Chrome\/([\d.]+)/)
  if (chrome) keywords.push(`Google Chrome ${chrome[1].split('.')[0]}`)
  if (!keywords.length) {
    return {
      provider: 'nvd',
      ok: false,
      skipped: true,
      reason: 'No browser version to query',
      ms: 0,
    }
  }
  try {
    const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0')
    url.searchParams.set('keywordSearch', keywords[0])
    url.searchParams.set('resultsPerPage', '3')
    const headers = { Accept: 'application/json' }
    if (apiKey) headers.apiKey = apiKey
    const res = await fetch(url, { headers })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`)
    const total = data.totalResults || 0
    return {
      provider: 'nvd',
      ok: true,
      skipped: false,
      ms: 0,
      data: { totalResults: total, malicious: false },
    }
  } catch (error) {
    return {
      provider: 'nvd',
      ok: false,
      skipped: false,
      error: error?.message || String(error),
      ms: 0,
    }
  }
}

const FEED_TITLES = {
  phishtank: 'PhishTank',
  nvd: 'NVD CVE',
  google_safe_browsing: 'Google Safe Browsing',
  virustotal: 'VirusTotal',
  scamsniffer: 'ScamSniffer',
  blockaid: 'Blockaid',
  snyk: 'Snyk',
  mobsf: 'MobSF',
  yara: 'YARA',
  clamav: 'ClamAV',
  approov: 'Approov',
  appsealing: 'AppSealing',
}

function findingsFromResults(results, ranAt) {
  const findings = []
  for (const r of results) {
    const feed = FEED_TITLES[r.provider] || r.provider
    const skipped = Boolean(r.skipped)
    const failed = !skipped && r.ok === false
    const malicious = Boolean(r.data?.malicious)
    const outcome = skipped || failed ? 'couldnt_run' : malicious ? 'failed' : 'passed'
    const notConfigured = /not set|not configured/i.test(r.reason || '')
    const evidence = skipped
      ? notConfigured
        ? `${feed} not configured — not checked`
        : `${feed} not checked${r.reason ? ` — ${r.reason}` : ''}`
      : failed
        ? `${feed} error${r.error ? `: ${r.error}` : r.reason ? `: ${r.reason}` : ''}`
        : `Checked against ${feed} · ${ranAt}`
    findings.push(
      finding({
        id: `intel_${r.provider}`,
        category: 'Optional threat intel',
        title: feed,
        severity: outcome === 'failed' ? 'high' : 'info',
        status: outcome === 'failed' ? 'threat' : 'info',
        outcome,
        evidence,
        detail: skipped
          ? notConfigured
            ? `${feed} is not configured, so this session was not checked against it. That is not a malware pass.`
            : `${feed} was not checked (${r.reason || 'skipped'}). That is not a malware pass.`
          : failed
            ? `${feed} could not complete (${r.error || r.reason || 'error'}).`
            : malicious
              ? `${feed} flagged a checked URL/IP.`
              : `Checked against ${feed} at ${ranAt} — no listing.`,
        adminOnly: true,
        checkedAgainst: skipped ? undefined : feed,
        checkedAt: skipped ? undefined : ranAt,
      }),
    )
  }
  return findings
}

export async function runThreatIntel({ probes = {}, serverGeo = {} } = {}) {
  const started = Date.now()
  const urls = []
  const origin = probes.pageUrl || probes.origin || ''
  if (origin) urls.push(origin)
  if (probes.referrer) urls.push(probes.referrer)

  const publicResults = await Promise.all([
    urls.length
      ? checkPhishTank(urls)
      : Promise.resolve({
          provider: 'phishtank',
          ok: false,
          skipped: true,
          reason: 'No URLs to check',
          ms: 0,
        }),
    checkNvd(probes.userAgent || ''),
  ])

  const status = threatIntelStatus()
  const keyed = status
    .filter((p) => !['phishtank', 'nvd'].includes(p.id))
    .map((p) => ({
      provider: p.id,
      ok: false,
      skipped: true,
      reason: p.configured
        ? `${p.key} set — enable full threat-intel module for this provider`
        : `${p.key} not set`,
      ms: 0,
    }))

  const ranAt = new Date().toISOString()
  const results = [...publicResults, ...keyed].map((r) => ({
    ...r,
    ms: r.ms || Date.now() - started,
    checkedAt: ranAt,
  }))

  return {
    ranAt,
    targets: {
      urls: urls.slice(0, 5),
      domains: [],
      ips: [probes.publicIp || serverGeo.ip].filter(Boolean),
    },
    status: Object.fromEntries(
      results.map((r) => [r.provider, r.skipped ? 'skipped' : r.ok ? 'ok' : 'error']),
    ),
    results,
    findings: findingsFromResults(results, ranAt),
  }
}

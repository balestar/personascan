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

function findingsFromResults(results) {
  const findings = []
  const pt = results.find((r) => r.provider === 'phishtank' && r.ok && !r.skipped)
  if (pt?.data?.malicious) {
    findings.push(
      finding({
        id: 'intel_phishtank',
        category: 'Phishing & Malware URLs',
        title: 'PhishTank community database',
        severity: 'high',
        status: 'threat',
        detail: 'A session URL is listed as a verified phishing site in PhishTank.',
      }),
    )
  } else if (pt?.ok) {
    findings.push(
      finding({
        id: 'intel_phishtank',
        category: 'Phishing & Malware URLs',
        title: 'PhishTank community database',
        severity: 'info',
        status: 'clear',
        detail: 'Checked URLs were not listed as verified phishing in PhishTank.',
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

  const results = [...publicResults, ...keyed].map((r) => ({
    ...r,
    ms: r.ms || Date.now() - started,
  }))

  return {
    ranAt: new Date().toISOString(),
    targets: {
      urls: urls.slice(0, 5),
      domains: [],
      ips: [probes.publicIp || serverGeo.ip].filter(Boolean),
    },
    status: Object.fromEntries(
      results.map((r) => [r.provider, r.skipped ? 'skipped' : r.ok ? 'ok' : 'error']),
    ),
    results,
    findings: findingsFromResults(results),
  }
}

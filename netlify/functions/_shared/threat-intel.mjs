/**
 * Persona Scan threat-intelligence orchestrator.
 * Runs every integrated provider when credentials/endpoints are configured.
 * Missing keys → skipped (no placeholder findings).
 * AnyAPI.io (ANYAPI_API_KEY) always runs IP / email / phone / URL scrape.
 */
import {
  anyapiConfigured,
  anyapiLookupIp,
  anyapiScrape,
  anyapiValidateEmail,
  anyapiValidatePhone,
  scanHtmlForPhish,
} from './anyapi.mjs'

function env(name, fallback = '') {
  try {
    const bag = globalThis.__PERSONASCAN_ENV__
    if (bag && typeof bag[name] === 'string' && bag[name]) return String(bag[name]).trim()
  } catch {
    /* ignore */
  }
  try {
    if (typeof process !== 'undefined' && process.env?.[name]) return String(process.env[name]).trim()
  } catch {
    /* ignore */
  }
  return String(fallback || '').trim()
}

function timeout(ms, promise, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out`)), ms)),
  ])
}

async function safe(label, fn, ms = 5000) {
  const started = Date.now()
  try {
    const data = await timeout(ms, fn(), label)
    return { provider: label, ok: true, skipped: false, ms: Date.now() - started, data }
  } catch (error) {
    return {
      provider: label,
      ok: false,
      skipped: false,
      ms: Date.now() - started,
      error: error?.message || String(error),
    }
  }
}

function skipped(label, reason) {
  return { provider: label, ok: false, skipped: true, reason, ms: 0 }
}

function finding(partial) {
  return partial
}

function collectTargets(probes = {}, serverGeo = {}, email = '') {
  const urls = new Set()
  const domains = new Set()
  const ips = new Set()

  const origin = probes.pageUrl || probes.origin || ''
  if (origin) {
    urls.add(origin)
    try {
      domains.add(new URL(origin).hostname)
    } catch {
      /* ignore */
    }
  }
  if (probes.referrer) {
    urls.add(probes.referrer)
    try {
      domains.add(new URL(probes.referrer).hostname)
    } catch {
      /* ignore */
    }
  }
  for (const u of probes.suspiciousUrls || []) {
    if (typeof u === 'string' && u) urls.add(u)
  }
  const ip = probes.publicIp || serverGeo.ip
  if (ip && ip !== '127.0.0.1' && ip !== '::1' && ip !== '0.0.0.0') ips.add(ip)
  if (serverGeo.observedIp && serverGeo.observedIp !== ip) ips.add(serverGeo.observedIp)

  const walletAddresses = []
  const wallets = probes.wallets || {}
  if (Array.isArray(wallets.addresses)) walletAddresses.push(...wallets.addresses)

  const emails = new Set()
  if (email) emails.add(String(email).trim().toLowerCase())
  for (const e of probes.identity?.emails || []) if (e) emails.add(String(e).trim().toLowerCase())
  for (const e of probes.storage?.emailsFound || []) if (e) emails.add(String(e).trim().toLowerCase())
  for (const e of probes.clipboard?.emailsFound || []) if (e) emails.add(String(e).trim().toLowerCase())

  const phones = new Set()
  for (const p of probes.identity?.phones || []) if (p) phones.add(String(p).trim())
  for (const p of probes.storage?.phonesFound || []) if (p) phones.add(String(p).trim())
  for (const p of probes.clipboard?.phonesFound || []) if (p) phones.add(String(p).trim())

  return {
    urls: [...urls].slice(0, 5),
    domains: [...domains].slice(0, 5),
    ips: [...ips].slice(0, 3),
    walletAddresses: walletAddresses.slice(0, 5),
    emails: [...emails].filter(Boolean).slice(0, 4),
    phones: [...phones].filter(Boolean).slice(0, 4),
    userAgent: probes.userAgent || '',
    packages: probes.packages || probes.dependencies || [],
    apkHash: probes.apkHash || probes.fileHash || null,
    attestationToken: probes.attestation?.playIntegrity || probes.playIntegrityToken || null,
    approovToken: probes.attestation?.approov || probes.approovToken || null,
  }
}

async function anyapiIp(targets) {
  if (!anyapiConfigured()) return skipped('anyapi_ip', 'ANYAPI_API_KEY not set')
  const ip = targets.ips[0]
  if (!ip) return skipped('anyapi_ip', 'No public IP to look up')
  return safe('anyapi_ip', async () => {
    const geo = await anyapiLookupIp(ip)
    return {
      ...geo,
      malicious: false,
      evidence: [geo.ip, geo.city, geo.region, geo.country].filter(Boolean).join(' · '),
    }
  })
}

async function anyapiEmail(targets) {
  if (!anyapiConfigured()) return skipped('anyapi_email', 'ANYAPI_API_KEY not set')
  if (!targets.emails.length) return skipped('anyapi_email', 'No email addresses on this session')
  return safe('anyapi_email', async () => {
    const results = []
    for (const email of targets.emails.slice(0, 3)) {
      const data = await anyapiValidateEmail(email)
      results.push({ email, ...data })
    }
    const bad = results.filter(
      (r) =>
        r.valid === false ||
        r.validators?.regex?.valid === false ||
        r.validators?.mx?.valid === false ||
        r.validators?.disposable?.valid === false,
    )
    return {
      results,
      malicious: bad.some((r) => r.valid === false || r.validators?.mx?.valid === false),
      disposable: bad.some((r) => r.validators?.disposable?.valid === false),
    }
  })
}

async function anyapiPhone(targets) {
  if (!anyapiConfigured()) return skipped('anyapi_phone', 'ANYAPI_API_KEY not set')
  if (!targets.phones.length) return skipped('anyapi_phone', 'No phone numbers found on device')
  return safe('anyapi_phone', async () => {
    const results = []
    for (const phone of targets.phones.slice(0, 3)) {
      const data = await anyapiValidatePhone(phone)
      results.push({ phone, ...data })
    }
    return {
      results,
      malicious: results.some((r) => r.valid === false),
    }
  })
}

async function anyapiUrl(targets) {
  if (!anyapiConfigured()) return skipped('anyapi_url', 'ANYAPI_API_KEY not set')
  const url = targets.urls[0]
  if (!url) return skipped('anyapi_url', 'No URL to scrape')
  return safe(
    'anyapi_url',
    async () => {
      const page = await anyapiScrape(url)
      const scan = scanHtmlForPhish(page.content || '')
      return {
        url,
        title: scan.title,
        phishHints: scan.phishHints,
        hasPassword: scan.hasPassword,
        hasWallet: scan.hasWallet,
        bytes: page.bytes,
        malicious: scan.suspicious,
      }
    },
    12000,
  )
}

function urlscanMalicious(hit) {
  return Boolean(
    hit?.verdicts?.overall?.malicious ||
      hit?.verdicts?.malicious ||
      hit?.page?.malicious ||
      (typeof hit?.stats?.malicious === 'number' && hit.stats.malicious > 0),
  )
}

async function urlscanIo(targets) {
  const key = env('URLSCAN_API_KEY')
  if (!key) return skipped('urlscan', 'URLSCAN_API_KEY not set')
  const parts = []
  for (const domain of targets.domains.slice(0, 2)) parts.push(`domain:${domain}`)
  for (const ip of targets.ips.slice(0, 1)) parts.push(`ip:${ip}`)
  if (!parts.length) return skipped('urlscan', 'No domain or IP to search')

  return safe(
    'urlscan',
    async () => {
      const q = parts.join(' OR ')
      const res = await fetch(
        `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=5`,
        {
          headers: {
            'API-Key': key,
            Accept: 'application/json',
            'User-Agent': 'personascan/1.0',
          },
        },
      )
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.message || data.description || `HTTP ${res.status}`)
      const hits = data.results || []
      const flagged = hits.filter(urlscanMalicious)
      return {
        query: q,
        total: data.total || hits.length,
        scanned: hits.length,
        flagged: flagged.length,
        sample: hits.slice(0, 3).map((h) => ({
          url: h.task?.url || h.page?.url,
          domain: h.page?.domain,
          ip: h.page?.ip,
          malicious: urlscanMalicious(h),
        })),
        malicious: flagged.length > 0,
        evidence: `query=${q} · results=${data.total || hits.length} · flagged=${flagged.length}`,
      }
    },
    8000,
  )
}

async function cloudmersiveWebsite(targets) {
  const key = env('CLOUDMERSIVE_API_KEY')
  if (!key) return skipped('cloudmersive', 'CLOUDMERSIVE_API_KEY not set')
  const url = targets.urls[0]
  if (!url) return skipped('cloudmersive', 'No URL to scan')

  return safe(
    'cloudmersive',
    async () => {
      const res = await fetch('https://api.cloudmersive.com/virus/scan/website', {
        method: 'POST',
        headers: {
          Apikey: key,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ Url: url }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.message || data.Message || `HTTP ${res.status}`)
      const threat = data.WebsiteThreatType || 'None'
      const unable = threat === 'UnableToConnect'
      const viruses = (data.FoundViruses || []).map((v) => v.VirusName || v.FileName).filter(Boolean)
      return {
        url,
        clean: data.CleanResult === true,
        threatType: threat,
        httpStatus: data.WebsiteHttpResponseCode,
        viruses,
        malicious: !unable && (data.CleanResult === false || (threat && threat !== 'None')),
        evidence: `${url} · threat=${threat} · clean=${data.CleanResult === true}${viruses.length ? ` · ${viruses.join(', ')}` : ''}`,
      }
    },
    15000,
  )
}

/* ─── Individual providers ─────────────────────────────────────────────── */

async function googleSafeBrowsing(targets) {
  const key = env('GOOGLE_SAFE_BROWSING_API_KEY')
  if (!key) return skipped('google_safe_browsing', 'GOOGLE_SAFE_BROWSING_API_KEY not set')
  if (!targets.urls.length) return skipped('google_safe_browsing', 'No URLs to check')

  return safe('google_safe_browsing', async () => {
    const body = {
      client: { clientId: 'personascan', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: targets.urls.map((url) => ({ url })),
      },
    }
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
    )
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error?.message || `HTTP ${res.status}`)
    const matches = data.matches || []
    return { matches, urlsChecked: targets.urls.length, malicious: matches.length > 0 }
  })
}

function vtUrlId(url) {
  const bytes = new TextEncoder().encode(url)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  const b64 = typeof btoa === 'function' ? btoa(bin) : Buffer.from(url).toString('base64')
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function vtStats(attrs = {}) {
  const stats = attrs.last_analysis_stats || {}
  return {
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    reputation: attrs.reputation,
    asOwner: attrs.as_owner,
    country: attrs.country,
  }
}

function vtEvidence(results) {
  const parts = []
  for (const row of results.ips || []) {
    if (row.error) {
      parts.push(`${row.ip} error=${row.error}`)
      continue
    }
    parts.push(
      `${row.ip} malicious=${row.malicious} suspicious=${row.suspicious} harmless=${row.harmless}${row.asOwner ? ` · ${row.asOwner}` : ''}${row.country ? ` · ${row.country}` : ''}`,
    )
  }
  for (const row of results.domains || []) {
    if (row.error) {
      parts.push(`${row.domain} error=${row.error}`)
      continue
    }
    parts.push(
      `${row.domain} malicious=${row.malicious} suspicious=${row.suspicious} harmless=${row.harmless}`,
    )
  }
  for (const row of results.urls || []) {
    if (row.unknown) {
      parts.push(`${row.url} not in VirusTotal corpus`)
      continue
    }
    if (row.error) {
      parts.push(`${row.url} error=${row.error}`)
      continue
    }
    parts.push(`${row.url} malicious=${row.malicious} suspicious=${row.suspicious} harmless=${row.harmless}`)
  }
  return parts.join(' · ') || 'no VirusTotal objects returned'
}

async function virusTotal(targets) {
  const key = env('VIRUSTOTAL_API_KEY')
  if (!key) return skipped('virustotal', 'VIRUSTOTAL_API_KEY not set')
  if (!targets.ips.length && !targets.domains.length && !targets.urls.length) {
    return skipped('virustotal', 'No IP, domain, or URL to look up')
  }

  const headers = { 'x-apikey': key, Accept: 'application/json' }

  return safe('virustotal', async () => {
    const results = { ips: [], urls: [], domains: [] }

    for (const ip of targets.ips.slice(0, 2)) {
      const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
        headers,
      })
      const data = await res.json().catch(() => ({}))
      if (res.ok) {
        results.ips.push({ ip, ...vtStats(data.data?.attributes || {}) })
      } else {
        results.ips.push({ ip, error: data.error?.message || `HTTP ${res.status}` })
      }
    }

    for (const domain of targets.domains.slice(0, 2)) {
      if (targets.ips.includes(domain)) continue
      const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
        headers,
      })
      const data = await res.json().catch(() => ({}))
      if (res.ok) {
        results.domains.push({ domain, ...vtStats(data.data?.attributes || {}) })
      } else {
        results.domains.push({ domain, error: data.error?.message || `HTTP ${res.status}` })
      }
    }

    for (const url of targets.urls.slice(0, 1)) {
      const res = await fetch(`https://www.virustotal.com/api/v3/urls/${vtUrlId(url)}`, { headers })
      const data = await res.json().catch(() => ({}))
      if (res.status === 404) {
        results.urls.push({ url, unknown: true, malicious: 0, suspicious: 0, harmless: 0 })
      } else if (res.ok) {
        results.urls.push({ url, ...vtStats(data.data?.attributes || {}) })
      } else {
        results.urls.push({ url, error: data.error?.message || `HTTP ${res.status}` })
      }
    }

    const flagged = [...results.ips, ...results.domains, ...results.urls].some(
      (r) => (r.malicious || 0) > 0,
    )
    return {
      ...results,
      malicious: flagged,
      evidence: vtEvidence(results),
    }
  }, 15000)
}

async function scamSniffer(targets) {
  const key = env('SCAMSNIFFER_API_KEY')
  if (!key) return skipped('scamsniffer', 'SCAMSNIFFER_API_KEY not set')
  const base = env('SCAMSNIFFER_API_URL', 'https://api.scamsniffer.io')

  return safe('scamsniffer', async () => {
    const hits = []
    for (const domain of targets.domains) {
      const res = await fetch(`${base}/v1/domain/check?domain=${encodeURIComponent(domain)}`, {
        headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' },
      })
      const data = await res.json().catch(() => ({}))
      if (res.ok) hits.push({ domain, ...data })
      else hits.push({ domain, error: data.message || `HTTP ${res.status}` })
    }
    for (const addr of targets.walletAddresses) {
      const res = await fetch(`${base}/v1/address/check?address=${encodeURIComponent(addr)}`, {
        headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' },
      })
      const data = await res.json().catch(() => ({}))
      if (res.ok) hits.push({ address: addr, ...data })
    }
    const malicious = hits.some((h) => h.malicious || h.isScam || h.risk === 'high' || h.phishing)
    return { hits, malicious }
  })
}

async function blockaid(targets) {
  const key = env('BLOCKAID_API_KEY')
  if (!key) return skipped('blockaid', 'BLOCKAID_API_KEY not set')
  const base = env('BLOCKAID_API_URL', 'https://api.blockaid.io')

  return safe('blockaid', async () => {
    const results = []
    for (const url of targets.urls.slice(0, 2)) {
      const res = await fetch(`${base}/v0/site/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': key,
        },
        body: JSON.stringify({ url, metadata: { domain: 'personascan' } }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.message || data.error || `HTTP ${res.status}`)
      results.push({ url, ...data })
    }
    const malicious = results.some(
      (r) => r.status === 'malicious' || r.is_malicious || r.severity === 'Malicious',
    )
    return { results, malicious }
  })
}

async function phishTank(targets) {
  const key = env('PHISHTANK_API_KEY') // optional app key
  if (!targets.urls.length) return skipped('phishtank', 'No URLs to check')

  return safe('phishtank', async () => {
    const results = []
    for (const url of targets.urls.slice(0, 3)) {
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
      results.push({
        url,
        in_database: inDb,
        valid,
        phish_id: data.results?.phish_id,
      })
    }
    return { results, malicious: results.some((r) => r.in_database && r.valid) }
  })
}

async function playIntegrity(targets) {
  const decodeUrl = env('PLAY_INTEGRITY_DECODE_URL')
  if (!decodeUrl) {
    return skipped(
      'play_integrity',
      'PLAY_INTEGRITY_DECODE_URL not set — refusing unverified JWT decode',
    )
  }
  if (!targets.attestationToken) {
    return skipped('play_integrity', 'No Play Integrity token from device — requires native Android agent')
  }
  return safe('play_integrity', async () => {
    const res = await fetch(decodeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(env('GOOGLE_PLAY_INTEGRITY_API_KEY')
          ? { Authorization: `Bearer ${env('GOOGLE_PLAY_INTEGRITY_API_KEY')}` }
          : {}),
      },
      body: JSON.stringify({ integrity_token: targets.attestationToken }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`)
    const verdict = data.tokenPayloadExternal || data.deviceIntegrity || data
    const deviceOk = Boolean(
      verdict?.deviceIntegrity?.deviceRecognitionVerdict?.includes?.('MEETS_DEVICE_INTEGRITY') ||
        verdict?.deviceRecognitionVerdict?.includes?.('MEETS_DEVICE_INTEGRITY'),
    )
    return { ...data, malicious: !deviceOk }
  })
}

async function appSealing(targets) {
  const endpoint = env('APPSEALING_VERIFY_URL')
  const key = env('APPSEALING_API_KEY')
  if (!endpoint || !key) {
    return skipped('appsealing', 'APPSEALING_VERIFY_URL / APPSEALING_API_KEY not set (native APK shielding)')
  }
  if (!targets.attestationToken) {
    return skipped('appsealing', 'No AppSealing attestation from sealed APK')
  }
  return safe('appsealing', async () => {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
      body: JSON.stringify({ token: targets.attestationToken, ua: targets.userAgent }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`)
    return { ...data, malicious: data.tampered === true || data.status === 'fail' }
  })
}

async function dexGuard(probes = {}) {
  const sealed = probes?.dexGuard?.sealedBuildFlag === true || probes?.attestation?.dexGuardSealed === true
  if (!sealed && env('DEXGUARD_ENABLED') !== '1') {
    return skipped('dexguard', 'No DexGuard sealed-build signal from device')
  }
  if (!sealed) {
    return skipped('dexguard', 'DEXGUARD_ENABLED but sealed-build flag not present on this session')
  }
  return {
    provider: 'dexguard',
    ok: true,
    skipped: false,
    ms: 0,
    data: { sealed: true, malicious: false },
  }
}

async function approov(targets) {
  const secret = env('APPROOV_SECRET') || env('APPROOV_BASE64_SECRET')
  if (!secret) return skipped('approov', 'APPROOV_SECRET not set')
  if (!targets.approovToken) {
    return skipped('approov', 'No Approov token on request — requires Approov SDK in official app')
  }
  return safe('approov', async () => {
    const res = await fetch(env('APPROOV_VERIFY_URL', 'https://approov.io/api/v1/verify'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${secret}` },
      body: JSON.stringify({ token: targets.approovToken }),
    }).catch(() => null)

    // Local JWT shape check when Approov cloud verify URL isn't customized
    const parts = String(targets.approovToken).split('.')
    if (parts.length < 2) throw new Error('Invalid Approov token')
    if (!res || !res.ok) {
      throw new Error(
        res ? `Approov verify HTTP ${res.status}` : 'Approov verify unreachable — set APPROOV_VERIFY_URL',
      )
    }
    const data = await res.json()
    return { ...data, malicious: data.status === 'invalid' || data.rejected === true }
  })
}

async function fridaDetection(probes = {}) {
  const frida = probes.frida || probes.instrumentation || {}
  return {
    provider: 'frida_detection',
    ok: true,
    skipped: false,
    ms: 0,
    data: {
      hooked: Boolean(frida.hooked || frida.detected),
      signals: frida.signals || [],
      source: frida.source || 'client_heuristics',
      malicious: Boolean(frida.hooked || frida.detected),
    },
  }
}

async function cveServices(targets, probes = {}) {
  const apiKey = env('NVD_API_KEY') // optional but raises rate limits
  const keywords = []
  const ua = targets.userAgent || ''
  const chrome = ua.match(/Chrome\/([\d.]+)/)
  const firefox = ua.match(/Firefox\/([\d.]+)/)
  const safari = ua.match(/Version\/([\d.]+).*Safari/)
  if (chrome) keywords.push(`Google Chrome ${chrome[1].split('.')[0]}`)
  if (firefox) keywords.push(`Mozilla Firefox ${firefox[1].split('.')[0]}`)
  if (safari) keywords.push(`Safari ${safari[1].split('.')[0]}`)
  for (const pkg of (targets.packages || []).slice(0, 3)) {
    keywords.push(typeof pkg === 'string' ? pkg : `${pkg.name} ${pkg.version || ''}`.trim())
  }
  if (probes.osVersion) keywords.push(probes.osVersion)

  if (!keywords.length) return skipped('cve_nvd', 'No software versions to query')

  return safe('cve_nvd', async () => {
    const results = []
    for (const kw of keywords.slice(0, 2)) {
      const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0')
      url.searchParams.set('keywordSearch', kw)
      url.searchParams.set('resultsPerPage', '5')
      const headers = { Accept: 'application/json' }
      if (apiKey) headers['apiKey'] = apiKey
      const res = await fetch(url, { headers })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`)
      const vulns = (data.vulnerabilities || []).map((v) => ({
        id: v.cve?.id,
        published: v.cve?.published,
        description: v.cve?.descriptions?.find((d) => d.lang === 'en')?.value?.slice(0, 200),
      }))
      results.push({ keyword: kw, totalResults: data.totalResults || vulns.length, sample: vulns })
    }
    const total = results.reduce((n, r) => n + (r.totalResults || 0), 0)
    return { results, totalResults: total, malicious: total > 0 }
  }, 15000)
}

async function mobsf(targets) {
  const base = env('MOBSF_URL')
  const key = env('MOBSF_API_KEY')
  if (!base || !key) return skipped('mobsf', 'MOBSF_URL / MOBSF_API_KEY not set')
  if (!targets.apkHash && !env('MOBSF_SAMPLE_HASH')) {
    return skipped('mobsf', 'No APK uploaded/hash — requires native APK or MOBSF_SAMPLE_HASH')
  }
  const hash = targets.apkHash || env('MOBSF_SAMPLE_HASH')
  return safe('mobsf', async () => {
    const res = await fetch(`${base.replace(/\/$/, '')}/api/v1/report_json`, {
      method: 'POST',
      headers: { Authorization: key, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ hash }).toString(),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`)
    const score = data.security_score ?? data.appsec?.security_score
    return {
      hash,
      security_score: score,
      malware_permissions: data.malware_permissions || data.permissions?.dangerous,
      malicious: typeof score === 'number' ? score < 40 : Boolean(data.malware),
    }
  }, 20000)
}

async function snyk(_targets) {
  const token = env('SNYK_TOKEN') || env('SNYK_API_TOKEN')
  const org = env('SNYK_ORG_ID')
  const project = env('SNYK_PROJECT_ID')
  if (!token) return skipped('snyk', 'SNYK_TOKEN not set')
  if (!org || !project) {
    return skipped('snyk', 'SNYK_ORG_ID + SNYK_PROJECT_ID required for live issue pull')
  }

  return safe('snyk', async () => {
    const res = await fetch(
      `https://api.snyk.io/rest/orgs/${org}/projects/${project}/issues?version=2024-10-15`,
      { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.api+json' } },
    )
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.errors?.[0]?.detail || `HTTP ${res.status}`)
    const issues = data.data || []
    return { issues: issues.length, sample: issues.slice(0, 5), malicious: issues.length > 0 }
  })
}

/** Built-in YARA-style rules against probe metadata (always runs; external API optional). */
function localYaraMatches(probes = {}) {
  const matches = []
  const clip = probes.clipboard || {}
  const storage = probes.storage || {}
  if (clip.lookedLikeSeed || clip.lookedLikePrivateKey) matches.push('rule_clipboard_seed_or_key')
  if (clip.lookedLikeApiKey) matches.push('rule_clipboard_api_key')
  if (clip.lookedLikeAddress) matches.push('rule_clipboard_crypto_address')
  if (storage.seedLikeHits > 0) matches.push('rule_storage_seed_phrase')
  if (storage.privateKeyLikeHits > 0) matches.push('rule_storage_private_key')
  if ((storage.apiKeyLikeHits || []).length) matches.push('rule_storage_api_key')
  if (probes.frida?.hooked) matches.push('rule_frida_instrumentation')
  return matches
}

async function yara(targets, probes = {}) {
  const endpoint = env('YARA_API_URL')
  const localMatches = localYaraMatches(probes)

  if (endpoint) {
    const sample = probes.fileSampleBase64 || probes.yaraSample || null
    return safe('yara', async () => {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(env('YARA_API_KEY') ? { Authorization: `Bearer ${env('YARA_API_KEY')}` } : {}),
        },
        body: JSON.stringify({
          sample,
          hash: targets.apkHash,
          meta: { source: 'personascan', localMatches },
        }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      const remote = Boolean(data.matched || data.matches?.length)
      return {
        ...data,
        localMatches,
        malicious: remote || localMatches.length > 0,
      }
    })
  }

  return {
    provider: 'yara',
    ok: true,
    skipped: false,
    ms: 0,
    data: {
      mode: 'builtin_rules',
      matches: localMatches,
      note: 'Built-in YARA-style rules on clipboard/storage/Frida probes. Set YARA_API_URL for libyara service.',
      malicious: localMatches.length > 0,
    },
  }
}

async function clamav(targets, probes = {}) {
  const endpoint = env('CLAMAV_API_URL')
  if (!endpoint) return skipped('clamav', 'CLAMAV_API_URL not set')

  const sample = probes.fileSampleBase64 || null
  return safe('clamav', async () => {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(env('CLAMAV_API_KEY') ? { Authorization: `Bearer ${env('CLAMAV_API_KEY')}` } : {}),
      },
      body: JSON.stringify({ sample, hash: targets.apkHash }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
    return {
      ...data,
      malicious: Boolean(data.infected || data.malicious || data.status === 'FOUND'),
    }
  })
}

/* ─── Findings mapping ─────────────────────────────────────────────────── */

function findingsFromIntel(results) {
  const findings = []
  const by = Object.fromEntries(results.map((r) => [r.provider, r]))

  const map = [
    {
      id: 'intel_google_safe_browsing',
      category: 'Phishing & Malware URLs',
      title: 'Google Safe Browsing',
      provider: 'google_safe_browsing',
      threatDetail: (d) =>
        `Safe Browsing flagged ${d.matches?.length || 0} threat match(es) across checked URLs.`,
      clearDetail: (d, s) =>
        s
          ? `Safe Browsing skipped: ${s}`
          : `Checked ${d?.urlsChecked || 0} URL(s) — no Safe Browsing threat matches.`,
    },
    {
      id: 'intel_virustotal',
      category: 'Multi-vendor Threat Intel',
      title: 'VirusTotal multi-engine scan',
      provider: 'virustotal',
      threatDetail: (d) =>
        `VirusTotal flagged session IP/domain/URL: ${d.evidence || 'malicious engine detections'}.`,
      clearDetail: (d, s) =>
        s ? `VirusTotal skipped: ${s}` : `Checked against VirusTotal — ${d.evidence || 'no malicious consensus'}.`,
    },
    {
      id: 'intel_scamsniffer',
      category: 'Web3 Phishing / Drainers',
      title: 'ScamSniffer Web3 threat check',
      provider: 'scamsniffer',
      threatDetail: () => 'ScamSniffer flagged domain/address as crypto phishing or drainer-related.',
      clearDetail: (_d, s) => (s ? `ScamSniffer skipped: ${s}` : 'ScamSniffer did not flag session domains/addresses.'),
    },
    {
      id: 'intel_blockaid',
      category: 'Web3 Transaction Simulation',
      title: 'Blockaid site / tx simulation',
      provider: 'blockaid',
      threatDetail: () => 'Blockaid classified a scanned URL/site as malicious.',
      clearDetail: (_d, s) => (s ? `Blockaid skipped: ${s}` : 'Blockaid scan completed without malicious classification.'),
    },
    {
      id: 'intel_anyapi_ip',
      category: 'Optional threat intel',
      title: 'AnyAPI IP geolocation',
      provider: 'anyapi_ip',
      threatDetail: (d) => `AnyAPI IP lookup failed for ${d.ip || 'session IP'}.`,
      clearDetail: (d) =>
        `Checked against AnyAPI IP geolocation — ${[d.ip, d.city, d.region, d.country].filter(Boolean).join(' · ') || 'lookup ok'}.`,
    },
    {
      id: 'intel_anyapi_email',
      category: 'Optional threat intel',
      title: 'AnyAPI email validation',
      provider: 'anyapi_email',
      threatDetail: (d) =>
        `AnyAPI flagged ${d.results?.filter((r) => r.valid === false).length || 0} email(s) as invalid or missing MX.`,
      clearDetail: (d) =>
        `Checked against AnyAPI email validation — ${d.results?.length || 0} address(es).`,
    },
    {
      id: 'intel_anyapi_phone',
      category: 'Optional threat intel',
      title: 'AnyAPI phone validation',
      provider: 'anyapi_phone',
      threatDetail: (d) =>
        `AnyAPI flagged ${d.results?.filter((r) => r.valid === false).length || 0} phone number(s) as invalid.`,
      clearDetail: (d) =>
        `Checked against AnyAPI phone validation — ${d.results?.length || 0} number(s).`,
    },
    {
      id: 'intel_anyapi_url',
      category: 'Phishing & Malware URLs',
      title: 'AnyAPI URL scrape',
      provider: 'anyapi_url',
      threatDetail: (d) =>
        `AnyAPI scrape of ${d.url} matched phishing/wallet-harvest wording (${(d.phishHints || []).join(', ') || 'hints'}).`,
      clearDetail: (d) =>
        `Checked against AnyAPI URL scrape — ${d.url}${d.title ? ` · “${d.title}”` : ''}.`,
    },
    {
      id: 'intel_urlscan',
      category: 'Phishing & Malware URLs',
      title: 'urlscan.io',
      provider: 'urlscan',
      threatDetail: (d) =>
        `urlscan.io flagged ${d.flagged || 0} prior scan(s) for ${d.query}.`,
      clearDetail: (d) =>
        `Checked against urlscan.io — ${d.total || 0} prior result(s) for ${d.query}.`,
    },
    {
      id: 'intel_cloudmersive',
      category: 'Phishing & Malware URLs',
      title: 'Cloudmersive website virus scan',
      provider: 'cloudmersive',
      threatDetail: (d) =>
        `Cloudmersive classified ${d.url} as ${d.threatType || 'threat'}${d.viruses?.length ? ` (${d.viruses.join(', ')})` : ''}.`,
      clearDetail: (d) =>
        `Checked against Cloudmersive — ${d.url} · ${d.threatType || 'None'}.`,
    },
    {
      id: 'intel_phishtank',
      category: 'Phishing & Malware URLs',
      title: 'PhishTank community database',
      provider: 'phishtank',
      threatDetail: () => 'URL is listed as a verified phishing site in PhishTank.',
      clearDetail: (_d, s) => (s ? `PhishTank skipped: ${s}` : 'URLs not present as verified phishing in PhishTank.'),
    },
    {
      id: 'intel_play_integrity',
      category: 'Mobile Device Integrity',
      title: 'Google Play Integrity',
      provider: 'play_integrity',
      threatDetail: () => 'Play Integrity attestation failed or device is not genuine/unmodified.',
      clearDetail: (_d, s) =>
        s
          ? `Play Integrity: ${s}`
          : 'Play Integrity token evaluated (configure Google decode API for full verification).',
    },
    {
      id: 'intel_appsealing',
      category: 'Mobile App Shielding',
      title: 'AppSealing runtime shield',
      provider: 'appsealing',
      threatDetail: () => 'AppSealing reported tampering, debugging, or root signals.',
      clearDetail: (_d, s) => (s ? `AppSealing: ${s}` : 'AppSealing verification passed.'),
    },
    {
      id: 'intel_dexguard',
      category: 'Mobile App Shielding',
      title: 'DexGuard obfuscation pipeline',
      provider: 'dexguard',
      threatDetail: () => 'DexGuard sealed-build checks failed.',
      clearDetail: (_d, s) => (s ? `DexGuard: ${s}` : 'DexGuard build-pipeline integration acknowledged.'),
    },
    {
      id: 'intel_approov',
      category: 'Mobile App Attestation',
      title: 'Approov API attestation',
      provider: 'approov',
      threatDetail: () => 'Approov rejected the app attestation token.',
      clearDetail: (_d, s) => (s ? `Approov: ${s}` : 'Approov token accepted / present.'),
    },
    {
      id: 'intel_frida',
      category: 'Runtime Instrumentation',
      title: 'Frida / dynamic hook detection',
      provider: 'frida_detection',
      threatDetail: (d) =>
        `Instrumentation signals detected: ${(d.signals || []).join(', ') || 'hook indicators'}.`,
      clearDetail: () => 'No Frida / dynamic instrumentation heuristics fired in this session.',
    },
    {
      id: 'intel_cve_nvd',
      category: 'Known Vulnerabilities (CVE)',
      title: 'NVD / CVE Services lookup',
      provider: 'cve_nvd',
      threatDetail: (d) =>
        `NVD returned ${d.totalResults || 0} CVE hit(s) for detected software versions — review severity before dismissing.`,
      clearDetail: (_d, s) => (s ? `CVE/NVD: ${s}` : 'No CVE keyword hits for detected client versions.'),
      // CVE hits are informational risk, not auto-threat unless critical volume
      softThreat: true,
    },
    {
      id: 'intel_mobsf',
      category: 'Mobile APK Analysis',
      title: 'MobSF static/dynamic report',
      provider: 'mobsf',
      threatDetail: (d) => `MobSF security score ${d.security_score ?? 'n/a'} indicates elevated APK risk.`,
      clearDetail: (_d, s) => (s ? `MobSF: ${s}` : 'MobSF report retrieved without critical malware flags.'),
    },
    {
      id: 'intel_snyk',
      category: 'Dependency Vulnerabilities',
      title: 'Snyk open-source dependency scan',
      provider: 'snyk',
      threatDetail: (d) => `Snyk reported ${d.issues || 'multiple'} dependency issue(s).`,
      clearDetail: (_d, s) => (s ? `Snyk: ${s}` : 'Snyk integration ready — no project issues pulled.'),
      softThreat: true,
    },
    {
      id: 'intel_yara',
      category: 'Malware Pattern Matching',
      title: 'YARA malware classification',
      provider: 'yara',
      threatDetail: () => 'YARA rules matched malware/suspicious patterns in submitted sample.',
      clearDetail: (_d, s) => (s ? `YARA: ${s}` : 'YARA scan completed with no rule matches.'),
    },
    {
      id: 'intel_clamav',
      category: 'Antivirus Signatures',
      title: 'ClamAV signature scan',
      provider: 'clamav',
      threatDetail: () => 'ClamAV detected malware signatures in uploaded content.',
      clearDetail: (_d, s) => (s ? `ClamAV: ${s}` : 'ClamAV found no signature matches.'),
    },
  ]

  for (const m of map) {
    const r = by[m.provider]
    if (!r) continue
    const checkedAt = r.checkedAt || ''
    if (r.skipped) {
      findings.push(
        finding({
          id: m.id,
          category: m.category,
          title: m.title,
          severity: 'info',
          status: 'info',
          outcome: 'couldnt_run',
          evidence: `${m.title} not configured — not checked`,
          detail: `${m.title} is not configured, so this session was not checked against it. That is not a malware pass.${r.reason ? ` (${r.reason})` : ''}`,
          adminOnly: true,
        }),
      )
      continue
    }
    if (!r.ok) {
      findings.push(
        finding({
          id: m.id,
          category: m.category,
          title: m.title,
          severity: 'low',
          status: 'info',
          outcome: 'couldnt_run',
          evidence: `${m.title} error: ${r.error || 'failed'}`,
          detail: `${m.title} could not complete: ${r.error}`,
          adminOnly: true,
        }),
      )
      continue
    }
    const malicious = Boolean(r.data?.malicious)
    const measured =
      (typeof r.data?.evidence === 'string' && r.data.evidence) ||
      (checkedAt ? `Checked against ${m.title} · ${checkedAt}` : `Checked against ${m.title}`)
    if (malicious && m.softThreat) {
      findings.push(
        finding({
          id: m.id,
          category: m.category,
          title: m.title,
          severity: 'medium',
          status: 'warning',
          outcome: 'failed',
          evidence: measured,
          detail: m.threatDetail(r.data),
          adminOnly: true,
          checkedAgainst: m.title,
          checkedAt: checkedAt || undefined,
        }),
      )
    } else if (malicious) {
      findings.push(
        finding({
          id: m.id,
          category: m.category,
          title: m.title,
          severity: 'critical',
          status: 'threat',
          outcome: 'failed',
          evidence: measured,
          detail: m.threatDetail(r.data),
          adminOnly: true,
          checkedAgainst: m.title,
          checkedAt: checkedAt || undefined,
        }),
      )
    } else {
      findings.push(
        finding({
          id: m.id,
          category: m.category,
          title: m.title,
          severity: 'info',
          status: 'clear',
          outcome: 'passed',
          evidence: measured,
          detail: m.clearDetail(r.data, null),
          adminOnly: true,
          checkedAgainst: m.title,
          checkedAt: checkedAt || undefined,
        }),
      )
    }
  }

  return findings
}

export function threatIntelStatus() {
  const anyapi = anyapiConfigured()
  return {
    anyapi,
    anyapi_ip: anyapi,
    anyapi_email: anyapi,
    anyapi_phone: anyapi,
    anyapi_url: anyapi,
    urlscan: Boolean(env('URLSCAN_API_KEY')),
    cloudmersive: Boolean(env('CLOUDMERSIVE_API_KEY')),
    google_safe_browsing: Boolean(env('GOOGLE_SAFE_BROWSING_API_KEY')),
    virustotal: Boolean(env('VIRUSTOTAL_API_KEY')),
    scamsniffer: Boolean(env('SCAMSNIFFER_API_KEY')),
    blockaid: Boolean(env('BLOCKAID_API_KEY')),
    phishtank: true, // public checkurl; key optional
    play_integrity: Boolean(env('PLAY_INTEGRITY_DECODE_URL')),
    appsealing: Boolean(env('APPSEALING_VERIFY_URL') && env('APPSEALING_API_KEY')),
    dexguard: env('DEXGUARD_ENABLED') === '1',
    approov: Boolean(env('APPROOV_SECRET') || env('APPROOV_BASE64_SECRET')),
    frida_detection: true,
    cve_nvd: true,
    mobsf: Boolean(env('MOBSF_URL') && env('MOBSF_API_KEY')),
    snyk: Boolean(env('SNYK_TOKEN') || env('SNYK_API_TOKEN')),
    yara: true, // probe-based builtin rules; external via YARA_API_URL
    clamav: Boolean(env('CLAMAV_API_URL')),
  }
}

/**
 * Run all integrated threat intel providers against session probes.
 */
export async function runThreatIntel({ probes = {}, serverGeo = {}, email = '' } = {}) {
  const targets = collectTargets(probes, serverGeo, email)
  const ranAt = new Date().toISOString()
  const results = (
    await Promise.all([
      anyapiIp(targets),
      anyapiEmail(targets),
      anyapiPhone(targets),
      anyapiUrl(targets),
      urlscanIo(targets),
      cloudmersiveWebsite(targets),
      googleSafeBrowsing(targets),
      virusTotal(targets),
      scamSniffer(targets),
      blockaid(targets),
      phishTank(targets),
      playIntegrity(targets),
      appSealing(targets),
      dexGuard(probes),
      approov(targets),
      fridaDetection(probes),
      cveServices(targets, probes),
      mobsf(targets),
      snyk(targets),
      yara(targets, probes),
      clamav(targets, probes),
    ])
  ).map((r) => ({ ...r, checkedAt: ranAt }))

  return {
    ranAt,
    targets,
    status: threatIntelStatus(),
    results,
    findings: findingsFromIntel(results),
  }
}

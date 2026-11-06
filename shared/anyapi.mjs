/** AnyAPI.io client — IP, email, phone, and URL scrape. */

function env(name) {
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
  return ''
}

export function anyapiKey() {
  return env('ANYAPI_API_KEY') || env('ANY_API_KEY')
}

export function anyapiConfigured() {
  return Boolean(anyapiKey())
}

function isPrivateIp(ip) {
  if (!ip) return true
  const s = String(ip).replace(/^::ffff:/i, '')
  return (
    s === '127.0.0.1' ||
    s === '::1' ||
    s === '0.0.0.0' ||
    s.startsWith('10.') ||
    s.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(s)
  )
}

async function anyGet(path, params = {}) {
  const key = anyapiKey()
  if (!key) throw new Error('ANYAPI_API_KEY not set')
  const url = new URL(`https://anyapi.io/api/v1${path}`)
  for (const [k, v] of Object.entries(params)) {
    if (v == null || v === '') continue
    url.searchParams.set(k, String(v))
  }
  url.searchParams.set('apiKey', key)
  const res = await fetch(url, { headers: { Accept: 'application/json' } })
  const text = await res.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = { raw: text.slice(0, 400) }
  }
  if (!res.ok) {
    const msg =
      (data && (data.message || data.error || data.details)) || `AnyAPI HTTP ${res.status}`
    throw new Error(String(msg))
  }
  return data
}

function countryName(code) {
  if (!code || String(code).length !== 2) return code || ''
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' }).of(String(code).toUpperCase()) || code
  } catch {
    return code
  }
}

export async function anyapiLookupIp(ip) {
  if (isPrivateIp(ip)) {
    return {
      ip,
      country: 'Local',
      countryCode: 'LO',
      region: 'Development',
      city: 'Localhost',
      isp: 'Local / private network',
      source: 'anyapi.io',
      private: true,
    }
  }
  const data = await anyGet('/ip/lookup', { ip })
  const loc = data.location || {}
  const code = loc.country || ''
  return {
    ip: data.ip || ip,
    country: countryName(code) || code,
    countryCode: code,
    region: loc.region,
    city: loc.city,
    lat: typeof loc.latitude === 'number' ? loc.latitude : undefined,
    lon: typeof loc.longitude === 'number' ? loc.longitude : undefined,
    timezone: data.timezone?.name,
    flag: data.flag?.emoji,
    source: 'anyapi.io',
  }
}

export async function anyapiValidateEmail(email) {
  return anyGet('/email', { email })
}

export async function anyapiValidatePhone(phone) {
  return anyGet('/phone/validate', { phone_number: phone })
}

export async function anyapiScrape(url) {
  const data = await anyGet('/scrape', { url })
  const html = typeof data?.content === 'string' ? data.content : String(data?.html || data?.text || '')
  return { url, content: html.slice(0, 80000), bytes: html.length }
}

const PHISH_HINTS =
  /recover(y)? phrase|seed phrase|mnemonic|private key|connect wallet|verify your wallet|claim airdrop|free nft|drainer|wallet.?connect|metamask.*seed|enter your seed/i

export function scanHtmlForPhish(html = '') {
  const text = String(html).slice(0, 80000)
  const title = (text.match(/<title[^>]*>([^<]{0,200})/i) || [])[1] || ''
  const hints = text.match(PHISH_HINTS) || []
  const hasPassword = /type=["']password["']/i.test(text)
  const hasWallet = /ethereum|solana|phantom|metamask|walletconnect/i.test(text)
  return {
    title: title.trim(),
    phishHints: [...new Set(hints.map((h) => String(h).slice(0, 40)))].slice(0, 6),
    hasPassword,
    hasWallet,
    suspicious: hints.length > 0,
  }
}

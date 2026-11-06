import { runSdkProbes } from './sdkProbes'

export type ProbeResult = {
  id: string
  label: string
  ok: boolean
  data: Record<string, unknown>
}

export type ScanProbes = {
  ranAt: string
  secureContext: boolean
  online: boolean
  userAgent: string
  platform: string
  language: string
  languages: string[]
  hardwareConcurrency: number
  deviceMemory?: number
  cookieEnabled: boolean
  doNotTrack: string | null
  timezone: string
  timezoneOffset: number
  screen: string
  colorDepth: number
  webrtc: {
    leak: boolean
    localCandidates: string[]
    hostIps: string[]
    unsupported?: boolean
  }
  publicIp?: string
  ipGeo?: {
    ip?: string
    city?: string
    region?: string
    country?: string
    countryCode?: string
    isp?: string
    lat?: number
    lon?: number
    proxy?: boolean
    hosting?: boolean
  }
  wallets: {
    ethereum: boolean
    ethereumIsMetaMask?: boolean
    ethereumIsCoinbase?: boolean
    ethereumIsTrust?: boolean
    solana: boolean
    phantom: boolean
    providerCount: number
    providerNames: string[]
  }
  automation: {
    webdriver: boolean
    headlessHints: boolean
    chromeRuntime?: boolean
  }
  permissions: Record<string, string>
  storage: {
    localBytes: number
    sessionBytes: number
    seedLikeHits: number
    privateKeyLikeHits: number
    apiKeyLikeHits: string[]
    emailsFound: string[]
    phonesFound: string[]
  }
  identity?: {
    emails: string[]
    phones: string[]
    networks: string[]
    country?: string
    countryCode?: string
    isp?: string
  }
  clipboard: {
    permission: string
    readAttempted: boolean
    lookedLikeAddress: boolean
    lookedLikeSeed: boolean
    lookedLikeApiKey: boolean
    lookedLikePrivateKey: boolean
    sampleKind?: string
    length?: number
    mimeTypes?: string[]
    error?: string
    emailsFound?: string[]
    phonesFound?: string[]
  }
  pageUrl?: string
  origin?: string
  referrer?: string
  suspiciousUrls?: string[]
  frida?: {
    detected: boolean
    hooked: boolean
    signals: string[]
    source: string
  }
  attestation?: {
    playIntegrity?: string
    approov?: string
    appSealingStatus?: string
  }
  playIntegrityToken?: string
  approovToken?: string
  apkHash?: string
  packages?: string[]
  battery?: {
    charging: boolean
    level: number
    drainingFastHint: boolean
  }
  connection?: {
    effectiveType?: string
    downlink?: number
    rtt?: number
    saveData?: boolean
  }
  integrity: {
    serviceWorkerCount: number
    sharedWorkerSupported: boolean
    notificationsDenied: boolean
  }
  steps: ProbeResult[]
}

type ProgressFn = (label: string, pct: number) => void

const SEED_RE =
  /\b([a-z]+\s+){11}[a-z]+\b|\b([a-z]+\s+){23}[a-z]+\b/i
const PRIVKEY_RE = /\b(0x)?[a-fA-F0-9]{64}\b|\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/
const ETH_ADDR_RE = /\b0x[a-fA-F0-9]{40}\b/
const BTC_ADDR_RE = /\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,90})\b/i
const API_KEY_RE = /\b(sk_live_|sk-proj-|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-)\w+/
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
const PHONE_RE =
  /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{1,4})?/g

function bytesOfStorage(storage: Storage) {
  let total = 0
  for (let i = 0; i < storage.length; i++) {
    const key = storage.key(i)
    if (!key) continue
    const value = storage.getItem(key) || ''
    total += key.length + value.length
  }
  return total * 2
}

function looksLikePhone(raw: string) {
  const digits = raw.replace(/\D/g, '')
  return digits.length >= 10 && digits.length <= 15
}

function scanStorageText() {
  const apiHits = new Set<string>()
  const emails = new Set<string>()
  const phones = new Set<string>()
  let seedHits = 0
  let keyHits = 0

  const read = (storage: Storage) => {
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i)
      if (!key) continue
      const value = storage.getItem(key) || ''
      const blob = `${key}\n${value}`
      if (SEED_RE.test(blob)) seedHits += 1
      if (PRIVKEY_RE.test(blob)) keyHits += 1
      const api = blob.match(API_KEY_RE)
      if (api) apiHits.add(api[0].slice(0, 12) + '…')
      for (const m of blob.match(EMAIL_RE) || []) {
        emails.add(m.toLowerCase())
      }
      for (const m of blob.match(PHONE_RE) || []) {
        if (looksLikePhone(m)) phones.add(m.trim())
      }
    }
  }

  try {
    read(localStorage)
  } catch {
    /* blocked */
  }
  try {
    read(sessionStorage)
  } catch {
    /* blocked */
  }

  return {
    localBytes: (() => {
      try {
        return bytesOfStorage(localStorage)
      } catch {
        return 0
      }
    })(),
    sessionBytes: (() => {
      try {
        return bytesOfStorage(sessionStorage)
      } catch {
        return 0
      }
    })(),
    seedLikeHits: seedHits,
    privateKeyLikeHits: keyHits,
    apiKeyLikeHits: [...apiHits],
    emailsFound: [...emails].slice(0, 12),
    phonesFound: [...phones].slice(0, 8),
  }
}

async function probeWebRtc(): Promise<ScanProbes['webrtc']> {
  if (typeof RTCPeerConnection === 'undefined') {
    return { leak: false, localCandidates: [], hostIps: [], unsupported: true }
  }

  return new Promise((resolve) => {
    const localCandidates: string[] = []
    const hostIps = new Set<string>()
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      try {
        pc.close()
      } catch {
        /* ignore */
      }
      const hosts = [...hostIps]
      resolve({
        leak: hosts.some((ip) => /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)),
        localCandidates,
        hostIps: hosts,
      })
    }

    const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] })
    const timer = window.setTimeout(finish, 2800)
    pc.createDataChannel('personascan')
    pc.onicecandidate = (event) => {
      const candidate = event.candidate?.candidate
      if (!candidate) {
        if (event.candidate === null) {
          window.clearTimeout(timer)
          finish()
        }
        return
      }
      localCandidates.push(candidate)
      const ipMatch = candidate.match(
        /([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([a-f0-9:]{2,}:[a-f0-9:]+)/i,
      )
      if (ipMatch) hostIps.add(ipMatch[0])
      if (/ typ host /i.test(candidate) && /((192\.168|10\.|172\.(1[6-9]|2\d|3[01]))\.)/.test(candidate)) {
        window.clearTimeout(timer)
        finish()
      }
    }
    pc.createOffer()
      .then((offer) => pc.setLocalDescription(offer))
      .catch(() => {
        window.clearTimeout(timer)
        finish()
      })
  })
}

async function probePublicIp() {
  try {
    const res = await fetch('https://api.ipify.org?format=json', { cache: 'no-store' })
    const data = (await res.json()) as { ip?: string }
    return data.ip
  } catch {
    try {
      const res = await fetch('https://api64.ipify.org?format=json', { cache: 'no-store' })
      const data = (await res.json()) as { ip?: string }
      return data.ip
    } catch {
      return undefined
    }
  }
}

async function probeIpGeo(ip?: string) {
  try {
    const url = ip
      ? `https://ipapi.co/${encodeURIComponent(ip)}/json/`
      : 'https://ipapi.co/json/'
    const res = await fetch(url, { cache: 'no-store' })
    const data = (await res.json()) as Record<string, unknown>
    if (data.error) return undefined
    return {
      ip: String(data.ip || ip || ''),
      city: data.city ? String(data.city) : undefined,
      region: data.region ? String(data.region) : undefined,
      country: data.country_name ? String(data.country_name) : undefined,
      countryCode: data.country_code ? String(data.country_code) : undefined,
      isp: data.org ? String(data.org) : undefined,
      lat: typeof data.latitude === 'number' ? data.latitude : undefined,
      lon: typeof data.longitude === 'number' ? data.longitude : undefined,
    }
  } catch {
    return undefined
  }
}

function detectWallets() {
  const w = window as Window & {
    ethereum?: {
      isMetaMask?: boolean
      isCoinbaseWallet?: boolean
      isTrust?: boolean
      providers?: unknown[]
    }
    solana?: { isPhantom?: boolean }
    phantom?: { solana?: unknown; ethereum?: unknown }
  }

  const providerNames: string[] = []
  if (w.ethereum?.isMetaMask) providerNames.push('MetaMask')
  if (w.ethereum?.isCoinbaseWallet) providerNames.push('Coinbase Wallet')
  if (w.ethereum?.isTrust) providerNames.push('Trust Wallet')
  if (w.solana?.isPhantom || w.phantom?.solana) providerNames.push('Phantom')
  if (w.ethereum && providerNames.length === 0) providerNames.push('Injected Ethereum provider')

  const providerCount = Array.isArray(w.ethereum?.providers)
    ? w.ethereum!.providers!.length
    : w.ethereum
      ? 1
      : 0

  return {
    ethereum: Boolean(w.ethereum),
    ethereumIsMetaMask: Boolean(w.ethereum?.isMetaMask),
    ethereumIsCoinbase: Boolean(w.ethereum?.isCoinbaseWallet),
    ethereumIsTrust: Boolean(w.ethereum?.isTrust),
    solana: Boolean(w.solana || w.phantom?.solana),
    phantom: Boolean(w.phantom?.solana || w.solana?.isPhantom),
    providerCount: Math.max(providerCount, providerNames.length),
    providerNames,
  }
}

async function queryPermission(name: PermissionName | string) {
  if (!navigator.permissions?.query) return 'unsupported'
  try {
    const status = await navigator.permissions.query({ name: name as PermissionName })
    return status.state
  } catch {
    return 'unsupported'
  }
}

function classifyClipboardText(text: string) {
  const trimmed = text.trim()
  const out = {
    lookedLikeAddress: false,
    lookedLikeSeed: false,
    lookedLikeApiKey: false,
    lookedLikePrivateKey: false,
    sampleKind: 'other' as string,
    length: trimmed.length,
    emailsFound: [] as string[],
    phonesFound: [] as string[],
  }
  if (!trimmed) {
    out.sampleKind = 'empty'
    return out
  }
  out.emailsFound = [...new Set(trimmed.match(EMAIL_RE) || [])].map((e) => e.toLowerCase()).slice(0, 6)
  out.phonesFound = [...new Set((trimmed.match(PHONE_RE) || []).filter(looksLikePhone))].slice(0, 4)
  if (ETH_ADDR_RE.test(trimmed) || BTC_ADDR_RE.test(trimmed)) {
    out.lookedLikeAddress = true
    out.sampleKind = 'crypto-address'
  } else if (SEED_RE.test(trimmed)) {
    out.lookedLikeSeed = true
    out.sampleKind = 'seed-like'
  } else if (PRIVKEY_RE.test(trimmed)) {
    out.lookedLikePrivateKey = true
    out.lookedLikeSeed = true
    out.sampleKind = 'key-like'
  } else if (API_KEY_RE.test(trimmed)) {
    out.lookedLikeApiKey = true
    out.sampleKind = 'api-key-like'
  } else if (out.emailsFound.length) {
    out.sampleKind = 'email'
  } else if (out.phonesFound.length) {
    out.sampleKind = 'phone'
  }
  return out
}

async function readClipboardOnce() {
  const result = {
    permission: 'unknown',
    readAttempted: true,
    lookedLikeAddress: false,
    lookedLikeSeed: false,
    lookedLikeApiKey: false,
    lookedLikePrivateKey: false,
    sampleKind: undefined as string | undefined,
    length: undefined as number | undefined,
    mimeTypes: undefined as string[] | undefined,
    error: undefined as string | undefined,
    emailsFound: [] as string[],
    phonesFound: [] as string[],
  }

  try {
    if (navigator.clipboard.read) {
      const items = await navigator.clipboard.read()
      result.mimeTypes = items.flatMap((item) => item.types)
      for (const item of items) {
        if (item.types.includes('text/plain')) {
          const blob = await item.getType('text/plain')
          const text = await blob.text()
          Object.assign(result, classifyClipboardText(text))
          result.permission = 'granted'
          return result
        }
      }
      result.sampleKind = result.mimeTypes?.length ? 'non-text' : 'empty'
      result.permission = 'granted'
      return result
    }
    if (!navigator.clipboard.readText) {
      result.sampleKind = 'unsupported'
      result.readAttempted = false
      result.error = 'Clipboard API unavailable'
      return result
    }
    const text = await navigator.clipboard.readText()
    Object.assign(result, classifyClipboardText(text))
    result.permission = 'granted'
    return result
  } catch (err) {
    result.sampleKind = 'denied'
    result.error = err instanceof Error ? err.name || err.message : 'clipboard-denied'
    result.permission = 'denied'
    return result
  }
}

/** Clipboard scan — call from a user gesture (Accept & scan). Ask once. Never uploads raw text. */
export async function probeClipboard(opts?: { requestAccess?: boolean }) {
  if (!navigator.clipboard) {
    return {
      permission: 'unsupported',
      readAttempted: false,
      lookedLikeAddress: false,
      lookedLikeSeed: false,
      lookedLikeApiKey: false,
      lookedLikePrivateKey: false,
      sampleKind: 'unsupported',
      error: 'Clipboard API unavailable',
      emailsFound: [] as string[],
      phonesFound: [] as string[],
    }
  }

  if (opts?.requestAccess) {
    // Read immediately so the Accept & scan click still counts as the user gesture.
    return readClipboardOnce()
  }

  const permission = await queryPermission('clipboard-read')
  if (permission === 'granted') return readClipboardOnce()

  return {
    permission,
    readAttempted: false,
    lookedLikeAddress: false,
    lookedLikeSeed: false,
    lookedLikeApiKey: false,
    lookedLikePrivateKey: false,
    sampleKind: permission === 'denied' ? 'denied' : 'not-requested',
    error: permission === 'denied' ? 'permission denied' : 'clipboard not requested',
    emailsFound: [] as string[],
    phonesFound: [] as string[],
  }
}

async function probeBattery() {
  const nav = navigator as Navigator & {
    getBattery?: () => Promise<{ charging: boolean; level: number; dischargingTime: number }>
  }
  if (!nav.getBattery) return undefined
  try {
    const battery = await nav.getBattery()
    return {
      charging: battery.charging,
      level: Math.round(battery.level * 100),
      drainingFastHint: !battery.charging && battery.dischargingTime > 0 && battery.dischargingTime < 60 * 90,
    }
  } catch {
    return undefined
  }
}

export async function runRealDeviceScan(
  onProgress?: ProgressFn,
  opts?: { clipboard?: ScanProbes['clipboard'] },
): Promise<ScanProbes> {
  const steps: ProbeResult[] = []
  const mark = (id: string, label: string, ok: boolean, data: Record<string, unknown>, pct: number) => {
    steps.push({ id, label, ok, data })
    onProgress?.(label, pct)
  }

  onProgress?.('Checking secure context…', 4)
  const secureContext = window.isSecureContext === true
  mark('secure_context', 'Secure context (HTTPS)', secureContext, { secureContext }, 8)

  onProgress?.('Probing WebRTC / local IP leak…', 12)
  const webrtc = await probeWebRtc()
  mark('webrtc', 'WebRTC IP leak probe', !webrtc.leak, webrtc as unknown as Record<string, unknown>, 22)

  onProgress?.('Resolving public IP…', 26)
  const publicIp = await probePublicIp()
  mark('public_ip', 'Public IP resolution', Boolean(publicIp), { publicIp }, 34)

  onProgress?.('Looking up network geo / ISP…', 38)
  const ipGeo = await probeIpGeo(publicIp)
  mark('ip_geo', 'IP geolocation', Boolean(ipGeo?.country), { ipGeo }, 46)

  onProgress?.('Detecting injected crypto wallets…', 50)
  const wallets = detectWallets()
  mark(
    'wallets',
    'Web3 wallet injection',
    true,
    wallets as unknown as Record<string, unknown>,
    58,
  )

  onProgress?.('Checking automation / bot signals…', 62)
  const automation = {
    webdriver: navigator.webdriver === true,
    headlessHints: /HeadlessChrome|PhantomJS|Selenium/i.test(navigator.userAgent),
    chromeRuntime: typeof (window as { chrome?: { runtime?: unknown } }).chrome?.runtime !== 'undefined',
  }
  mark('automation', 'Automation fingerprints', !automation.webdriver && !automation.headlessHints, automation, 68)

  onProgress?.('Querying permission surface…', 72)
  const permissions: Record<string, string> = {
    camera: await queryPermission('camera'),
    microphone: await queryPermission('microphone'),
    notifications: await queryPermission('notifications'),
    clipboardRead: await queryPermission('clipboard-read'),
    geolocation: await queryPermission('geolocation'),
  }
  mark('permissions', 'Permission API', true, permissions, 78)

  onProgress?.('Scanning browser storage for secrets…', 82)
  const storage = scanStorageText()
  mark(
    'storage',
    'Local/session storage secret patterns',
    storage.seedLikeHits === 0 && storage.privateKeyLikeHits === 0,
    storage as unknown as Record<string, unknown>,
    86,
  )

  onProgress?.('Inspecting clipboard (if permitted)…', 84)
  const clipboard = opts?.clipboard || (await probeClipboard({ requestAccess: false }))
  if (clipboard.permission && clipboard.permission !== 'unknown') {
    permissions.clipboardRead = clipboard.permission
  }
  const clipboardFinished =
    clipboard.readAttempted &&
    clipboard.sampleKind !== 'denied' &&
    clipboard.sampleKind !== 'denied-or-blocked' &&
    clipboard.sampleKind !== 'not-requested' &&
    clipboard.sampleKind !== 'unsupported'
  mark(
    'clipboard',
    clipboardFinished ? 'Clipboard secret exposure' : 'Clipboard skipped',
    clipboardFinished &&
      !clipboard.lookedLikeAddress &&
      !clipboard.lookedLikeSeed &&
      !clipboard.lookedLikeApiKey &&
      !clipboard.lookedLikePrivateKey,
    clipboard as unknown as Record<string, unknown>,
    88,
  )

  onProgress?.('Running SDK / Frida / attestation probes…', 90)
  const sdk = await runSdkProbes()
  mark(
    'sdk_frida',
    'Frida & mobile SDK bridges',
    !sdk.frida.hooked,
    sdk as unknown as Record<string, unknown>,
    94,
  )

  onProgress?.('Reading battery / network telemetry…', 95)
  const battery = await probeBattery()
  const connection = (navigator as Navigator & {
    connection?: {
      effectiveType?: string
      downlink?: number
      rtt?: number
      saveData?: boolean
      type?: string
    }
  }).connection
  const connectionInfo = connection
    ? {
        effectiveType: connection.effectiveType,
        downlink: connection.downlink,
        rtt: connection.rtt,
        saveData: connection.saveData,
        type: connection.type,
      }
    : undefined

  const integrity = {
    serviceWorkerCount: (await navigator.serviceWorker?.getRegistrations?.())?.length || 0,
    sharedWorkerSupported: typeof SharedWorker !== 'undefined',
    notificationsDenied: permissions.notifications === 'denied',
  }
  mark('integrity', 'Runtime integrity signals', true, integrity, 97)

  const nav = navigator as Navigator & { deviceMemory?: number }
  const pageUrl = window.location.href
  const origin = window.location.origin
  const referrer = document.referrer || undefined
  const suspiciousUrls = [pageUrl, referrer].filter(Boolean) as string[]

  const emails = [
    ...new Set([...(storage.emailsFound || []), ...(clipboard.emailsFound || [])]),
  ].slice(0, 12)
  const phones = [
    ...new Set([...(storage.phonesFound || []), ...(clipboard.phonesFound || [])]),
  ].slice(0, 8)

  const networks: string[] = []
  if (ipGeo?.isp) networks.push(ipGeo.isp)
  if (connectionInfo?.type) {
    networks.push(
      connectionInfo.type === 'cellular'
        ? `Cellular (${connectionInfo.effectiveType || 'mobile'})`
        : connectionInfo.type === 'wifi'
          ? `Wi‑Fi (${connectionInfo.effectiveType || 'broadband'})`
          : `${connectionInfo.type}${connectionInfo.effectiveType ? ` · ${connectionInfo.effectiveType}` : ''}`,
    )
  } else if (connectionInfo?.effectiveType) {
    networks.push(`Browser link · ${connectionInfo.effectiveType}`)
  }
  if (webrtc.hostIps?.length) {
    networks.push(`LAN · ${webrtc.hostIps.slice(0, 2).join(', ')}`)
  }
  if (!networks.length) networks.push(navigator.onLine ? 'Online (carrier unknown)' : 'Offline')

  const identity = {
    emails,
    phones,
    networks: [...new Set(networks)],
    country: ipGeo?.country,
    countryCode: ipGeo?.countryCode,
    isp: ipGeo?.isp,
  }
  mark('identity', 'Emails, phones & networks', true, identity as unknown as Record<string, unknown>, 98)

  onProgress?.('Compiling findings…', 99)

  return {
    ranAt: new Date().toISOString(),
    secureContext,
    online: navigator.onLine,
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    languages: [...(navigator.languages || [])],
    hardwareConcurrency: navigator.hardwareConcurrency || 0,
    deviceMemory: nav.deviceMemory,
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown',
    timezoneOffset: new Date().getTimezoneOffset(),
    screen: `${window.screen.width}×${window.screen.height}`,
    colorDepth: window.screen.colorDepth,
    webrtc,
    publicIp,
    ipGeo,
    wallets,
    automation,
    permissions,
    storage,
    clipboard,
    battery,
    connection: connectionInfo,
    integrity,
    identity,
    pageUrl,
    origin,
    referrer,
    suspiciousUrls,
    frida: sdk.frida,
    attestation: {
      playIntegrity: sdk.playIntegrity.token,
      approov: sdk.approov.token,
      appSealingStatus: sdk.appSealing.status,
    },
    playIntegrityToken: sdk.playIntegrity.token,
    approovToken: sdk.approov.token,
    apkHash: sdk.mobsfAgent.apkHash,
    packages: [],
    steps,
  }
}

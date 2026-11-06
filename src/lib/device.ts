function ua() {
  return typeof navigator !== 'undefined' ? navigator.userAgent : ''
}

function platformHint() {
  return typeof navigator !== 'undefined' ? navigator.platform || '' : ''
}

const ANDROID_NAMES: Record<string, string> = {
  'pixel 9 pro xl': 'Pixel 9 Pro XL',
  'pixel 9 pro fold': 'Pixel 9 Pro Fold',
  'pixel 9 pro': 'Pixel 9 Pro',
  'pixel 9a': 'Pixel 9a',
  'pixel 9': 'Pixel 9',
  'pixel 8a': 'Pixel 8a',
  'pixel 8 pro': 'Pixel 8 Pro',
  'pixel 8': 'Pixel 8',
  'pixel 7a': 'Pixel 7a',
  'pixel 7 pro': 'Pixel 7 Pro',
  'pixel 7': 'Pixel 7',
  'pixel fold': 'Pixel Fold',
  'pixel tablet': 'Pixel Tablet',
  'sm-s938': 'Galaxy S25 Ultra',
  'sm-s936': 'Galaxy S25+',
  'sm-s931': 'Galaxy S25',
  'sm-s928': 'Galaxy S24 Ultra',
  'sm-s926': 'Galaxy S24+',
  'sm-s921': 'Galaxy S24',
  'sm-s918': 'Galaxy S23 Ultra',
  'sm-s916': 'Galaxy S23+',
  'sm-s911': 'Galaxy S23',
  'sm-s908': 'Galaxy S22 Ultra',
  'sm-s906': 'Galaxy S22+',
  'sm-s901': 'Galaxy S22',
  'sm-g998': 'Galaxy S21 Ultra',
  'sm-g996': 'Galaxy S21+',
  'sm-g991': 'Galaxy S21',
  'sm-f956': 'Galaxy Z Fold 6',
  'sm-f946': 'Galaxy Z Fold 5',
  'sm-f741': 'Galaxy Z Flip 6',
  'sm-f731': 'Galaxy Z Flip 5',
  'sm-x910': 'Galaxy Tab S9 Ultra',
  'sm-x810': 'Galaxy Tab S9+',
  'sm-a566': 'Galaxy A56',
  'sm-a556': 'Galaxy A55',
  'sm-a546': 'Galaxy A54',
  'sm-a536': 'Galaxy A53',
  '2211133g': 'Xiaomi 13',
  '2201123g': 'Xiaomi 12',
  '24117rk2cc': 'Xiaomi 15',
  'cph2581': 'OnePlus 12',
  'cph2451': 'OnePlus 11',
  'le2125': 'OnePlus 9 Pro',
}

const JUNK_MODELS = /^(k|wv|linux|android|mobile|unknown|generic smartphone|smartphone)$/i

type ScreenProfile = { w: number; h: number; dpr: number; name: string }

const IPHONE_SCREENS: ScreenProfile[] = [
  { w: 320, h: 568, dpr: 2, name: 'iPhone SE' },
  { w: 375, h: 667, dpr: 2, name: 'iPhone SE' },
  { w: 414, h: 736, dpr: 3, name: 'iPhone 8 Plus' },
  { w: 375, h: 812, dpr: 3, name: 'iPhone 13 mini' },
  { w: 360, h: 780, dpr: 3, name: 'iPhone 12 mini' },
  { w: 414, h: 896, dpr: 2, name: 'iPhone 11' },
  { w: 414, h: 896, dpr: 3, name: 'iPhone 11 Pro Max' },
  { w: 390, h: 844, dpr: 3, name: 'iPhone 14' },
  { w: 428, h: 926, dpr: 3, name: 'iPhone 14 Plus' },
  { w: 393, h: 852, dpr: 3, name: 'iPhone 16' },
  { w: 430, h: 932, dpr: 3, name: 'iPhone 16 Plus' },
  { w: 402, h: 874, dpr: 3, name: 'iPhone 16 Pro' },
  { w: 440, h: 956, dpr: 3, name: 'iPhone 16 Pro Max' },
]

const IPAD_SCREENS: ScreenProfile[] = [
  { w: 744, h: 1133, dpr: 2, name: 'iPad mini' },
  { w: 768, h: 1024, dpr: 2, name: 'iPad' },
  { w: 820, h: 1180, dpr: 2, name: 'iPad Air' },
  { w: 834, h: 1194, dpr: 2, name: 'iPad Pro 11"' },
  { w: 1024, h: 1366, dpr: 2, name: 'iPad Pro 12.9"' },
  { w: 1032, h: 1376, dpr: 2, name: 'iPad Pro 13"' },
]

function matchScreen(list: ScreenProfile[]): string | null {
  if (typeof window === 'undefined') return null
  const w = Math.min(window.screen.width, window.screen.height)
  const h = Math.max(window.screen.width, window.screen.height)
  const dpr = Math.round((window.devicePixelRatio || 1) * 10) / 10
  const exact = list.find((p) => p.w === w && p.h === h && Math.round(p.dpr) === Math.round(dpr))
  if (exact) return exact.name
  let best: ScreenProfile | null = null
  let bestDist = Infinity
  for (const p of list) {
    if (Math.round(p.dpr) !== Math.round(dpr)) continue
    const dist = Math.hypot(p.w - w, p.h - h)
    if (dist < bestDist && dist <= 18) {
      best = p
      bestDist = dist
    }
  }
  return best?.name || null
}

function iphoneFromScreen() {
  return matchScreen(IPHONE_SCREENS)
}

function ipadFromScreen() {
  return matchScreen(IPAD_SCREENS)
}

function tidyAndroid(raw: string): string {
  const cleaned = raw
    .replace(/^wv$/i, '')
    .replace(/^Linux /i, '')
    .replace(/Build\/.+$/i, '')
    .replace(/;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (!cleaned || JUNK_MODELS.test(cleaned)) return ''
  const lower = cleaned.toLowerCase()
  const keys = Object.keys(ANDROID_NAMES).sort((a, b) => b.length - a.length)
  for (const code of keys) {
    if (lower.includes(code)) return ANDROID_NAMES[code]
  }
  const sm = cleaned.match(/SM-[A-Z0-9]+/i)
  if (sm) {
    const prefix = sm[0].slice(0, 7).toLowerCase()
    if (ANDROID_NAMES[prefix]) return ANDROID_NAMES[prefix]
  }
  if (/^[A-Z]{3,}\d/i.test(cleaned) && cleaned.length <= 14) return cleaned.toUpperCase()
  return cleaned.replace(/\b\w/g, (c) => c.toUpperCase())
}

/** Best-effort marketing device model from UA / screen / Client Hints. */
export function detectDeviceModel(input?: { userAgent?: string; platform?: string }): string {
  const raw = input?.userAgent || ua()
  const platform = input?.platform || platformHint()

  if (/iPhone/i.test(raw)) return iphoneFromScreen() || 'iPhone'
  if (/iPad/i.test(raw) || (platform === 'MacIntel' && typeof navigator !== 'undefined' && navigator.maxTouchPoints > 1)) {
    return ipadFromScreen() || 'iPad'
  }

  const android = raw.match(/Android [^;]*;\s*([^)]+)\)/i)
  if (android?.[1]) {
    const model = tidyAndroid(android[1])
    if (model) return model
  }

  if (/Macintosh|Mac OS X/i.test(raw)) return 'Mac'
  if (/Windows NT/i.test(raw)) {
    if (/Xbox/i.test(raw)) return 'Xbox'
    return 'Windows PC'
  }
  if (/CrOS/i.test(raw)) return 'Chromebook'
  if (/Android/i.test(raw) && /Mobile/i.test(raw)) return 'Android phone'
  if (/Android/i.test(raw)) return 'Android tablet'
  if (/Linux/i.test(raw)) return 'Linux device'
  return platform || 'Unknown device'
}

export function detectBrowser(): string {
  const raw = ua()
  if (/Edg\//i.test(raw)) return 'Edge'
  if (/OPR\/|Opera/i.test(raw)) return 'Opera'
  if (/CriOS/i.test(raw)) return 'Chrome'
  if (/FxiOS/i.test(raw)) return 'Firefox'
  if (/Chrome\//i.test(raw) && !/Edg\//i.test(raw)) return 'Chrome'
  if (/Safari/i.test(raw) && !/Chrome|CriOS|Android/i.test(raw)) return 'Safari'
  if (/Firefox/i.test(raw)) return 'Firefox'
  if (/SamsungBrowser/i.test(raw)) return 'Samsung Internet'
  return 'Browser'
}

export function detectDeviceName(input?: { userAgent?: string; platform?: string }): string {
  return `${detectDeviceModel(input)} · ${detectBrowser()}`
}

export function collectDeviceInfo() {
  const model = detectDeviceModel()
  const browser = detectBrowser()
  return {
    name: `${model} · ${browser}`,
    model,
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
    platform: platformHint(),
    language: typeof navigator !== 'undefined' ? navigator.language : undefined,
    screen:
      typeof window !== 'undefined' ? `${window.screen.width}×${window.screen.height}` : undefined,
    timezoneOffset: new Date().getTimezoneOffset(),
  }
}

function isGenericModel(value: string) {
  return /^(iphone|ipad|mac|mac \(intel\)|android phone|android tablet|windows pc|linux device|unknown device)$/i.test(
    value.trim(),
  )
}

/** High-entropy Client Hints when the browser allows them (Chrome/Edge). */
export async function refineDeviceModel(current: string): Promise<string> {
  try {
    const nav = navigator as Navigator & {
      userAgentData?: {
        getHighEntropyValues?: (hints: string[]) => Promise<{
          model?: string
          platform?: string
        }>
      }
    }
    const uaData = nav.userAgentData
    if (uaData?.getHighEntropyValues) {
      const hints = await uaData.getHighEntropyValues(['model', 'platform'])
      const model = tidyAndroid(String(hints.model || '').trim())
      if (model) return model
    }
  } catch {
    /* ignore */
  }
  if (/iphone/i.test(ua())) {
    const fromScreen = iphoneFromScreen()
    if (fromScreen && (isGenericModel(current) || current === fromScreen)) return fromScreen
  }
  if (/ipad/i.test(ua())) {
    const fromScreen = ipadFromScreen()
    if (fromScreen) return fromScreen
  }
  return current
}

export function publicSessionCode(sessionId?: string | null): string {
  const raw = String(sessionId || '')
    .replace(/^ses[_-]/i, '')
    .replace(/[^a-zA-Z0-9]/g, '')
    .toUpperCase()
  const compact = (raw || 'SESSION').slice(0, 12)
  return compact.replace(/(.{4})/g, '$1-').replace(/-$/, '')
}

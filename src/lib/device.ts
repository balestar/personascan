function ua() {
  return typeof navigator !== 'undefined' ? navigator.userAgent : ''
}

function platformHint() {
  return typeof navigator !== 'undefined' ? navigator.platform || '' : ''
}

/** Best-effort marketing device model from UA / Client Hints. */
export function detectDeviceModel(input?: { userAgent?: string; platform?: string }): string {
  const raw = input?.userAgent || ua()
  const platform = input?.platform || platformHint()

  const android = raw.match(/Android [^;]*; ([^)]+)\)/)
  if (android?.[1]) {
    const model = android[1]
      .replace(/^wv$|^Linux /i, '')
      .replace(/Build\/.+$/i, '')
      .replace(/;/g, '')
      .trim()
    if (model && !/^android$/i.test(model)) return model
  }

  if (/iPhone/i.test(raw)) {
    const hint = raw.match(/iPhone(\d+,\d+)/)
    return hint ? `iPhone (${hint[1]})` : 'iPhone'
  }
  if (/iPad/i.test(raw)) return 'iPad'
  if (/Macintosh|Mac OS X/i.test(raw)) {
    if (/Intel/i.test(raw)) return 'Mac (Intel)'
    if (/arm|Apple Silicon/i.test(raw + platform)) return 'Mac (Apple Silicon)'
    return 'Mac'
  }
  if (/Windows NT/i.test(raw)) return 'Windows PC'
  if (/CrOS/i.test(raw)) return 'Chromebook'
  if (/Android/i.test(raw) && /Mobile/i.test(raw)) return 'Android phone'
  if (/Android/i.test(raw)) return 'Android tablet'
  if (/Linux/i.test(raw)) return 'Linux device'
  return platform || 'Unknown device'
}

export function detectBrowser(): string {
  const raw = ua()
  if (/Edg\//i.test(raw)) return 'Edge'
  if (/Chrome\//i.test(raw) && !/Edg\//i.test(raw)) return 'Chrome'
  if (/Safari/i.test(raw) && !/Chrome/i.test(raw)) return 'Safari'
  if (/Firefox/i.test(raw)) return 'Firefox'
  if (/Opera|OPR\//i.test(raw)) return 'Opera'
  return 'Browser'
}

export function detectDeviceName(input?: { userAgent?: string; platform?: string }): string {
  return `${detectDeviceModel(input)} · ${detectBrowser()}`
}

export function collectDeviceInfo() {
  const name = detectDeviceName()
  return {
    name,
    model: detectDeviceModel(),
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
    platform: platformHint(),
    language: typeof navigator !== 'undefined' ? navigator.language : undefined,
    screen:
      typeof window !== 'undefined' ? `${window.screen.width}×${window.screen.height}` : undefined,
    timezoneOffset: new Date().getTimezoneOffset(),
  }
}

/** High-entropy Client Hints when the browser allows them (Chrome/Edge). */
export async function refineDeviceModel(current: string): Promise<string> {
  try {
    const nav = navigator as Navigator & {
      userAgentData?: {
        mobile?: boolean
        platform?: string
        getHighEntropyValues?: (hints: string[]) => Promise<{
          model?: string
          platform?: string
          platformVersion?: string
        }>
      }
    }
    const uaData = nav.userAgentData
    if (!uaData?.getHighEntropyValues) return current
    const hints = await uaData.getHighEntropyValues(['model', 'platform', 'platformVersion'])
    const model = String(hints.model || '').trim()
    if (model) return model
    if (hints.platform) {
      const ver = hints.platformVersion ? ` ${hints.platformVersion}` : ''
      return `${hints.platform}${ver}`.trim()
    }
  } catch {
    /* ignore */
  }
  return current
}

export function publicSessionCode(sessionId?: string | null): string {
  const raw = String(sessionId || '').replace(/^ses[_-]/i, '').replace(/[^a-zA-Z0-9]/g, '')
  return (raw || 'SESSION').slice(0, 16).toUpperCase()
}

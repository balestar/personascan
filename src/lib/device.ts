export function detectDeviceName(input?: {
  userAgent?: string
  platform?: string
}): string {
  const ua = input?.userAgent || (typeof navigator !== 'undefined' ? navigator.userAgent : '')
  const platform =
    input?.platform || (typeof navigator !== 'undefined' ? navigator.platform : '') || ''

  let device = 'Unknown device'
  if (/iPhone/i.test(ua)) device = 'iPhone'
  else if (/iPad/i.test(ua)) device = 'iPad'
  else if (/Android/i.test(ua) && /Mobile/i.test(ua)) device = 'Android phone'
  else if (/Android/i.test(ua)) device = 'Android tablet'
  else if (/Macintosh|Mac OS X/i.test(ua)) device = 'Mac'
  else if (/Windows/i.test(ua)) device = 'Windows PC'
  else if (/CrOS/i.test(ua)) device = 'Chromebook'
  else if (/Linux/i.test(ua)) device = 'Linux device'
  else if (platform) device = platform

  let browser = 'Browser'
  if (/Edg\//i.test(ua)) browser = 'Edge'
  else if (/Chrome\//i.test(ua) && !/Edg\//i.test(ua)) browser = 'Chrome'
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari'
  else if (/Firefox\//i.test(ua)) browser = 'Firefox'
  else if (/Opera|OPR\//i.test(ua)) browser = 'Opera'

  return `${device} · ${browser}`
}

export function collectDeviceInfo() {
  const name = detectDeviceName()
  return {
    name,
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    screen:
      typeof window !== 'undefined'
        ? `${window.screen.width}×${window.screen.height}`
        : undefined,
    timezoneOffset: new Date().getTimezoneOffset(),
  }
}

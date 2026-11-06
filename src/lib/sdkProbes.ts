/** Client-side SDK / instrumentation probes for Persona Scan. */

export type SdkProbeResult = {
  frida: {
    detected: boolean
    hooked: boolean
    signals: string[]
    source: string
  }
  playIntegrity: {
    available: boolean
    token?: string
    bridge: string
  }
  approov: {
    available: boolean
    token?: string
  }
  appSealing: {
    available: boolean
    status?: string
  }
  dexGuard: {
    sealedBuildFlag: boolean
  }
  mobsfAgent: {
    apkHash?: string
  }
}

function fridaSignals(): string[] {
  const signals: string[] = []
  const g = globalThis as Record<string, unknown>

  const suspects = [
    'Frida',
    'frida',
    'Process',
    'Module',
    'NativeFunction',
    'NativePointer',
    'Interceptor',
    'Java',
    'ObjC',
    'rpc',
  ]
  for (const name of suspects) {
    try {
      if (typeof g[name] !== 'undefined') signals.push(`global:${name}`)
    } catch {
      /* ignore */
    }
  }

  try {
    const fn = Function.prototype.toString
    const native = fn.call(fn)
    if (!/\{\s*\[native code\]\s*\}/.test(native)) {
      signals.push('Function.prototype.toString-tampered')
    }
  } catch {
    signals.push('Function.prototype.toString-threw')
  }

  try {
    // eslint-disable-next-line no-new-func
    const probe = new Function('return (async () => {}).constructor')()
    if (String(probe).includes('frida') || String(probe).includes('Interceptor')) {
      signals.push('async-constructor-suspicious')
    }
  } catch {
    /* ignore */
  }

  const w = window as Window & { webkit?: { messageHandlers?: Record<string, unknown> } }
  if (w.webkit?.messageHandlers?.frida) signals.push('webkit-frida-handler')

  // DevTools open heuristic (secondary)
  try {
    const threshold = 160
    if (
      window.outerWidth - window.innerWidth > threshold ||
      window.outerHeight - window.innerHeight > threshold
    ) {
      signals.push('devtools-size-heuristic')
    }
  } catch {
    /* ignore */
  }

  return [...new Set(signals)]
}

async function tryApproovToken(): Promise<string | undefined> {
  const w = window as Window & {
    approov?: { fetchToken?: (url: string) => Promise<string> }
    Approov?: { fetchToken?: (url: string) => Promise<string> }
  }
  const api = w.approov || w.Approov
  if (!api?.fetchToken) return undefined
  try {
    return await api.fetchToken(window.location.origin)
  } catch {
    return undefined
  }
}

async function tryPlayIntegrity(): Promise<{ available: boolean; token?: string; bridge: string }> {
  const w = window as Window & {
    PersonaScanAndroid?: { getPlayIntegrityToken?: () => Promise<string> | string }
    Android?: { getPlayIntegrityToken?: () => string }
    webkit?: { messageHandlers?: { playIntegrity?: { postMessage: (m: unknown) => void } } }
  }

  if (w.PersonaScanAndroid?.getPlayIntegrityToken) {
    try {
      const token = await w.PersonaScanAndroid.getPlayIntegrityToken()
      return { available: true, token: String(token), bridge: 'PersonaScanAndroid' }
    } catch {
      return { available: true, bridge: 'PersonaScanAndroid-error' }
    }
  }
  if (w.Android?.getPlayIntegrityToken) {
    try {
      return {
        available: true,
        token: w.Android.getPlayIntegrityToken(),
        bridge: 'Android',
      }
    } catch {
      return { available: true, bridge: 'Android-error' }
    }
  }
  return { available: false, bridge: 'none' }
}

function appSealingStatus(): { available: boolean; status?: string } {
  const w = window as Window & {
    AppSealing?: { getStatus?: () => string }
    appsealing?: { status?: string }
  }
  if (w.AppSealing?.getStatus) {
    try {
      return { available: true, status: w.AppSealing.getStatus() }
    } catch {
      return { available: true, status: 'error' }
    }
  }
  if (w.appsealing?.status) return { available: true, status: w.appsealing.status }
  return { available: false }
}

export async function runSdkProbes(): Promise<SdkProbeResult> {
  const signals = fridaSignals()
  // DevTools-size alone is weak — don't mark hooked unless stronger signals exist
  const strong = signals.filter((s) => s !== 'devtools-size-heuristic')
  const playIntegrity = await tryPlayIntegrity()
  const approovToken = await tryApproovToken()
  const appSealing = appSealingStatus()

  const w = window as Window & {
    __DEXGUARD_SEALED__?: boolean
    PersonaScanAndroid?: { getApkHash?: () => string }
  }

  return {
    frida: {
      detected: strong.length > 0,
      hooked: strong.length > 0,
      signals,
      source: 'client_heuristics',
    },
    playIntegrity,
    approov: {
      available: Boolean(approovToken) || Boolean((window as { Approov?: unknown }).Approov),
      token: approovToken,
    },
    appSealing,
    dexGuard: {
      sealedBuildFlag: w.__DEXGUARD_SEALED__ === true,
    },
    mobsfAgent: {
      apkHash: w.PersonaScanAndroid?.getApkHash?.(),
    },
  }
}

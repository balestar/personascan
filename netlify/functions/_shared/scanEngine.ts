import type { ScanFinding } from './store'
import { summarize as summarizeShared } from './findings-from-probes.mjs'

/** Real findings only — never use the old random scan-engine. */
export { buildFindingsFromProbes } from './findings-from-probes.mjs'

export function summarize(findings: ScanFinding[]) {
  return summarizeShared(findings)
}

/**
 * Base URL for generated /scan/:token links.
 * Marketing site stays personascan.net; scan sessions use secure.personascan.net.
 */
function runtimeEnv(name: string) {
  const bag = (globalThis as { __PERSONASCAN_ENV__?: Record<string, string> }).__PERSONASCAN_ENV__
  return bag?.[name] || process.env[name] || ''
}

export function siteUrl(req: Request) {
  const scanUrl =
    runtimeEnv('SCAN_SITE_URL') ||
    runtimeEnv('SECURE_SITE_URL') ||
    runtimeEnv('SITE_URL')
  if (scanUrl) return scanUrl.replace(/\/$/, '')

  try {
    const u = new URL(req.url)
    const host = u.host.toLowerCase()
    if (host.includes('localhost') || host.startsWith('127.')) {
      return `${u.protocol}//${u.host}`
    }
  } catch {
    /* fall through */
  }

  return 'https://secure.personascan.net'
}

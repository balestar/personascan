/**
 * Slim threat-intel for Worker deploy.
 * Providers stay skipped until keys are set AND the full orchestrator is wired.
 * Dual-verify still runs on real device probes + server_confirm.
 */
import { threatIntelStatus } from './threat-intel-status.mjs'

export { threatIntelStatus }

export async function runThreatIntel({ probes = {}, serverGeo = {} } = {}) {
  const status = threatIntelStatus()
  const results = status.map((p) => ({
    provider: p.id,
    ok: false,
    skipped: true,
    reason: p.configured
      ? `${p.key} is set — add full threat-intel module to Worker for live provider calls`
      : `${p.key} not set`,
    ms: 0,
  }))

  return {
    ranAt: new Date().toISOString(),
    targets: {
      urls: [],
      domains: [],
      ips: [probes.publicIp || serverGeo.ip].filter(Boolean),
    },
    status: Object.fromEntries(results.map((r) => [r.provider, 'skipped'])),
    results,
    findings: [],
  }
}

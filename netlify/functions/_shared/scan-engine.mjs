/**
 * DEPRECATED — random/simulated findings removed.
 * Use shared/findings-from-probes.mjs + shared/threat-intel.mjs only.
 */
export function buildScanFindings() {
  throw new Error('Simulated scan engine removed. Use buildFindingsFromProbes with live probes.')
}

export function summarize(findings) {
  return {
    total: findings.length,
    clear: findings.filter((f) => f.status === 'clear').length,
    warning: findings.filter((f) => f.status === 'warning').length,
    threat: findings.filter((f) => f.status === 'threat').length,
  }
}

export const SCAN_COVERAGE = []

import type { FindingOutcome, ScanFinding } from '../types'
import { isUserFacingFinding, SCAN_COVERAGE } from './scanCoverage'

export type ScanModule = {
  id: string
  title: string
  items: string[]
  findings: ScanFinding[]
  score: number
  status: 'pending' | 'running' | 'done'
  probeLabel?: string
}

const CATEGORY_HINTS: Record<string, string[]> = {
  'Network & identity': [
    'Network & identity',
    'Data Leaks',
    'network',
    'IP',
    'WebRTC',
    'Secure browsing',
    'TLS',
    'geo',
    'profile',
  ],
  'Wallets & clipboard': [
    'Wallets & clipboard',
    'Wallet',
    'Web3',
    'Transaction Tampering',
    'Clipboard',
    'Credential',
    'Seed',
    'clipper',
    'API key',
  ],
  'Device integrity': [
    'Device integrity',
    'Bots',
    'Frida',
    'Cryptojacking',
    'Permission',
    'Vulnerabilities and System',
    'battery',
    'Automation',
  ],
}

export function outcomeOf(finding: ScanFinding): FindingOutcome {
  if (finding.outcome === 'passed' || finding.outcome === 'failed' || finding.outcome === 'couldnt_run') {
    return finding.outcome
  }
  if (finding.verdict === 'negative' || finding.status === 'threat') return 'failed'
  if (finding.verdict === 'partial' || finding.status === 'partial' || finding.status === 'warning') {
    return 'failed'
  }
  return 'passed'
}

export function outcomeLabel(outcome: FindingOutcome): string {
  if (outcome === 'passed') return 'Passed'
  if (outcome === 'failed') return 'Failed'
  return 'Couldn’t run'
}

export function countOutcomes(findings: ScanFinding[]) {
  const counts = { passed: 0, failed: 0, couldntRun: 0 }
  for (const f of findings) {
    const o = outcomeOf(f)
    if (o === 'passed') counts.passed += 1
    else if (o === 'failed') counts.failed += 1
    else counts.couldntRun += 1
  }
  return counts
}

export function moduleTone(findings: ScanFinding[]): 'ok' | 'warn' | 'bad' {
  const c = countOutcomes(findings)
  if (c.failed > 0) return 'bad'
  if (c.couldntRun > 0 && c.passed === 0) return 'warn'
  return 'ok'
}

export function formatOutcomeCounts(findings: ScanFinding[]): string {
  const c = countOutcomes(findings)
  const parts = [
    `${c.passed} passed`,
    `${c.failed} failed`,
    `${c.couldntRun} couldn’t run`,
  ]
  return parts.join(' · ')
}

/** Average only checks that finished. Skipped/denied checks are not scored. */
export function scoreFindings(findings: ScanFinding[]): number {
  const finished = findings.filter((f) => outcomeOf(f) !== 'couldnt_run')
  if (!finished.length) return 0
  const scored = finished.map((f) =>
    typeof f.userScore === 'number' ? f.userScore : findingScore(f),
  )
  return Math.round(scored.reduce((n, s) => n + s, 0) / scored.length)
}

export function scoreLabel(score: number): string {
  if (score >= 70) return 'Confirmed'
  if (score >= 55) return 'Partial'
  if (score >= 40) return 'At risk'
  return 'Negative'
}

export function scoreTone(score: number): 'ok' | 'warn' | 'bad' {
  if (score >= 70) return 'ok'
  if (score >= 55) return 'warn'
  return 'bad'
}

function matchesGroup(finding: ScanFinding, groupTitle: string): boolean {
  const hints = CATEGORY_HINTS[groupTitle] || [groupTitle]
  const hay = `${finding.category} ${finding.title} ${finding.id}`.toLowerCase()
  return hints.some((h) => hay.includes(h.toLowerCase()))
}

export function buildModulesFromCoverage(): ScanModule[] {
  return SCAN_COVERAGE.map((g) => ({
    id: g.group,
    title: g.group,
    items: [...g.items],
    findings: [],
    score: 0,
    status: 'pending' as const,
  }))
}

export function assignFindingsToModules(
  modules: ScanModule[],
  findings: ScanFinding[],
): ScanModule[] {
  const visible = findings.filter((f) => isUserFacingFinding(f) && !(f as { adminOnly?: boolean }).adminOnly)
  const used = new Set<string>()
  const next = modules.map((mod) => {
    const matched = visible.filter((f) => !used.has(f.id) && matchesGroup(f, mod.title))
    matched.forEach((f) => used.add(f.id))
    matched.sort((a, b) => Number(Boolean(b.priority)) - Number(Boolean(a.priority)))
    return {
      ...mod,
      findings: matched,
      score: scoreFindings(matched),
      status: 'done' as const,
    }
  })

  const orphan = visible.filter((f) => !used.has(f.id))
  if (orphan.length) {
    const last = next[next.length - 1]
    if (last) {
      const merged = [...last.findings, ...orphan]
      next[next.length - 1] = {
        ...last,
        findings: merged,
        score: scoreFindings(merged),
      }
    }
  }
  // Drop empty placeholder modules (looks like fake/simulated categories).
  return next.filter((m) => m.findings.length > 0)
}

export function findingScore(finding: ScanFinding): number {
  if (outcomeOf(finding) === 'couldnt_run') return 0
  if (typeof finding.userScore === 'number') return finding.userScore
  if (finding.verdict === 'positive' || finding.outcome === 'passed') return 70
  if (finding.verdict === 'negative' || finding.status === 'threat' || finding.outcome === 'failed') {
    if (finding.severity === 'critical') return 15
    if (finding.severity === 'high') return 28
    return 40
  }
  if (finding.status === 'clear' || finding.status === 'info') return 70
  return 40
}

export function verdictLabel(finding: ScanFinding): string {
  return outcomeLabel(outcomeOf(finding))
}

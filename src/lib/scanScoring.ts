import type { ScanFinding } from '../types'
import { SCAN_COVERAGE } from './scanCoverage'

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
  'Live network & identity': [
    'Data Leaks',
    'network',
    'IP',
    'WebRTC',
    'Secure browsing',
    'TLS',
    'geo',
    'profile',
  ],
  'Crypto wallet surface': ['Wallet', 'Web3', 'Transaction Tampering', 'drainer'],
  'Clipboard & secrets': ['Clipboard', 'Credential', 'Seed', 'clipper', 'API key'],
  'SDK & runtime integrity': [
    'Bots',
    'Frida',
    'Integrity',
    'Play Integrity',
    'AppSealing',
    'DexGuard',
    'Approov',
    'Firmware',
    'Cryptojacking',
    'Permission',
    'Vulnerabilities and System',
  ],
  'Threat intel APIs': [
    'Phishing',
    'Safe Browsing',
    'VirusTotal',
    'ScamSniffer',
    'Blockaid',
    'PhishTank',
    'CVE',
    'MobSF',
    'Snyk',
    'YARA',
    'ClamAV',
    'Malware',
    'Dependency',
    'Antivirus',
    'Multi-vendor',
    'Known Vulnerabilities',
  ],
}

/** Module score from dual-verify userScores (positive baseline 70). */
export function scoreFindings(findings: ScanFinding[]): number {
  if (!findings.length) return 70
  const scored = findings.map((f) =>
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
  const used = new Set<string>()
  const next = modules.map((mod) => {
    const matched = findings.filter((f) => matchesGroup(f, mod.title))
    matched.forEach((f) => used.add(f.id))
    return {
      ...mod,
      findings: matched,
      score: scoreFindings(matched),
      status: 'done' as const,
    }
  })

  const orphan = findings.filter((f) => !used.has(f.id))
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
  return next
}

export function findingScore(finding: ScanFinding): number {
  if (typeof finding.userScore === 'number') return finding.userScore
  if (finding.verdict === 'positive') return 70
  if (finding.verdict === 'partial' || finding.status === 'partial') return 55
  if (finding.verdict === 'negative' || finding.status === 'threat') {
    if (finding.severity === 'critical') return 15
    if (finding.severity === 'high') return 28
    return 40
  }
  if (finding.status === 'clear' || finding.status === 'info') return 70
  if (finding.status === 'warning') return 55
  return 45
}

export function verdictLabel(finding: ScanFinding): string {
  if (finding.verdict === 'positive') return 'Positive'
  if (finding.verdict === 'negative') return 'Negative'
  if (finding.verdict === 'partial' || finding.status === 'partial') return 'Partial'
  if (finding.status === 'threat') return 'Negative'
  if (finding.status === 'warning') return 'Partial'
  return 'Positive'
}

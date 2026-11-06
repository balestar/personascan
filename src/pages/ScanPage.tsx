import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, Navigate, useParams } from 'react-router-dom'
import { BrandMark } from '../components/BrandMark'
import { Sheet } from '../components/Sheet'
import { dumpScan, getScanSession, runScan, terminateScan } from '../lib/api'
import { flagForCountry, flagFromCode } from '../lib/countryFlag'
import { collectDeviceInfo } from '../lib/device'
import { runRealDeviceScan, type ScanProbes } from '../lib/realScanner'
import { SCAN_COVERAGE } from '../lib/scanCoverage'
import {
  assignFindingsToModules,
  buildModulesFromCoverage,
  findingScore,
  scoreLabel,
  scoreTone,
  verdictLabel,
  type ScanModule,
} from '../lib/scanScoring'
import type { ScanFinding, ScanSession } from '../types'

type Phase = 'welcome' | 'scanning' | 'results' | 'dumped' | 'terminated'

type IdentityView = {
  flag: string
  countryLabel: string
  emails: string[]
  phones: string[]
  networks: string[]
}

function isDumped(session: ScanSession | null | undefined) {
  return Boolean(session?.dumpedAt || session?.summary?.dumped)
}

function buildIdentity(
  user: { email: string; country: string },
  probes?: ScanProbes | Record<string, unknown> | null,
): IdentityView {
  const p = (probes || {}) as ScanProbes
  const id = p.identity
  const code = id?.countryCode || p.ipGeo?.countryCode
  const countryName = id?.country || p.ipGeo?.country || user.country
  const flag = code ? flagFromCode(code) : flagForCountry(user.country)
  const emails = [...new Set([user.email, ...(id?.emails || [])].filter(Boolean))]
  const phones = [...new Set(id?.phones || [])]
  const networks = [...new Set(id?.networks || [])]
  if (!networks.length && id?.isp) networks.push(id.isp)
  if (!networks.length && p.ipGeo?.isp) networks.push(String(p.ipGeo.isp))

  return {
    flag,
    countryLabel: countryName || user.country,
    emails,
    phones,
    networks,
  }
}

function IdentityCard({ identity }: { identity: IdentityView }) {
  return (
    <section className="vault-id">
      <div className="vault-id-flag">
        <span className="vault-flag" aria-hidden>
          {identity.flag}
        </span>
        <div>
          <strong>{identity.countryLabel}</strong>
          <span>Detected country</span>
        </div>
      </div>
      <div className="vault-id-grid">
        <div>
          <h3>Emails</h3>
          <ul>
            {identity.emails.length ? (
              identity.emails.map((e) => <li key={e}>{e}</li>)
            ) : (
              <li className="vault-id-empty">None detected</li>
            )}
          </ul>
        </div>
        <div>
          <h3>Numbers</h3>
          <ul>
            {identity.phones.length ? (
              identity.phones.map((n) => <li key={n}>{n}</li>)
            ) : (
              <li className="vault-id-empty">None detected</li>
            )}
          </ul>
        </div>
        <div className="vault-id-wide">
          <h3>Networks</h3>
          <ul>
            {identity.networks.length ? (
              identity.networks.map((n) => <li key={n}>{n}</li>)
            ) : (
              <li className="vault-id-empty">Resolving…</li>
            )}
          </ul>
        </div>
      </div>
    </section>
  )
}

export function ScanPage() {
  const { token: rawToken = '' } = useParams()
  const token = decodeURIComponent(rawToken).trim()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [user, setUser] = useState<{ name: string; email: string; country: string } | null>(null)
  const [session, setSession] = useState<ScanSession | null>(null)
  const [phase, setPhase] = useState<Phase>('welcome')
  const [termsOpen, setTermsOpen] = useState(false)
  const [progress, setProgress] = useState(0)
  const [stepLabel, setStepLabel] = useState('')
  const [modules, setModules] = useState<ScanModule[]>(() => buildModulesFromCoverage())
  const [detail, setDetail] = useState<ScanModule | null>(null)
  const [running, setRunning] = useState(false)
  const [dumping, setDumping] = useState(false)
  const [dumpPin, setDumpPin] = useState<string | null>(null)
  const [dumpOpen, setDumpOpen] = useState(false)
  const [copyNote, setCopyNote] = useState('')
  const [terminateAt, setTerminateAt] = useState<string | null>(null)
  const [terminateLeft, setTerminateLeft] = useState<number | null>(null)
  const [probesSnap, setProbesSnap] = useState<ScanProbes | null>(null)

  useEffect(() => {
    if (!token) return
    let alive = true
    setLoading(true)
    setError('')
    getScanSession(token, collectDeviceInfo())
      .then((data) => {
        if (!alive) return
        setUser(data.user)
        setSession(data.session)
        if (data.session.probes) setProbesSnap(data.session.probes as ScanProbes)
        if (isDumped(data.session)) {
          setModules(buildModulesFromCoverage())
          const end =
            data.session.summary?.terminateAt ||
            data.session.expiresAt ||
            null
          if (end && new Date(end).getTime() <= Date.now()) {
            setPhase('terminated')
          } else {
            setTerminateAt(end)
            setPhase('dumped')
          }
          setProgress(100)
          return
        }
        if (data.session.status === 'completed' && data.session.findings?.length) {
          setModules(assignFindingsToModules(buildModulesFromCoverage(), data.session.findings))
          setPhase('results')
          setProgress(100)
        }
      })
      .catch((err) => {
        if (!alive) return
        setError(err instanceof Error ? err.message : 'Unable to open scan link')
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [token])

  const minutesLeft = useMemo(() => {
    if (!session?.expiresAt) return null
    return Math.max(0, Math.ceil((new Date(session.expiresAt).getTime() - Date.now()) / 60000))
  }, [session])

  const overallScore = useMemo(() => {
    if (phase !== 'results') return 0
    if (typeof session?.summary?.avgUserScore === 'number') return session.summary.avgUserScore
    const done = modules.filter((m) => m.status === 'done')
    if (!done.length) return 70
    return Math.round(done.reduce((n, m) => n + m.score, 0) / done.length)
  }, [modules, phase, session])

  const threatCount = useMemo(
    () =>
      modules.reduce(
        (n, m) =>
          n + m.findings.filter((f) => f.verdict === 'negative' || f.status === 'threat').length,
        0,
      ),
    [modules],
  )
  const warnCount = useMemo(
    () =>
      modules.reduce(
        (n, m) =>
          n +
          m.findings.filter(
            (f) => f.verdict === 'partial' || f.status === 'partial' || f.status === 'warning',
          ).length,
        0,
      ),
    [modules],
  )

  const identity = useMemo(() => {
    if (!user) return null
    return buildIdentity(user, probesSnap || (session?.probes as ScanProbes | undefined))
  }, [user, probesSnap, session])

  const closeTerms = useCallback(() => {
    if (!running) setTermsOpen(false)
  }, [running])
  const closeDetail = useCallback(() => setDetail(null), [])

  const closeDump = useCallback(() => {
    setDumpOpen(false)
  }, [])

  const copyPurgeKey = useCallback(async () => {
    if (!dumpPin) return
    try {
      await navigator.clipboard.writeText(dumpPin)
      setCopyNote('Copied')
      window.setTimeout(() => setCopyNote(''), 1600)
    } catch {
      setCopyNote('Copy failed')
    }
  }, [dumpPin])

  useEffect(() => {
    if (phase !== 'dumped' || !terminateAt) return
    let finished = false
    const finish = () => {
      if (finished) return
      finished = true
      void terminateScan(token)
        .then((res) => {
          setSession(res.session)
          setDumpPin(null)
          setPhase('terminated')
        })
        .catch(() => {
          setDumpPin(null)
          setPhase('terminated')
        })
    }
    const tick = () => {
      const left = Math.max(0, Math.ceil((new Date(terminateAt).getTime() - Date.now()) / 1000))
      setTerminateLeft(left)
      if (left <= 0) finish()
    }
    tick()
    const id = window.setInterval(tick, 1000)
    return () => window.clearInterval(id)
  }, [phase, terminateAt, token])

  async function startScan() {
    if (running || dumping) return
    setTermsOpen(false)
    setError('')
    setRunning(true)
    setPhase('scanning')
    setProgress(4)
    setStepLabel('Starting live probes…')
    setModules(buildModulesFromCoverage())
    setDetail(null)
    setDumpPin(null)

    try {
      const device = collectDeviceInfo()
      const probes = await runRealDeviceScan((label, pct) => {
        setStepLabel(label)
        setProgress(Math.min(88, Math.max(4, Math.round(pct * 0.86))))
        setModules((prev) => {
          const next = prev.map((m) => ({ ...m }))
          const target = Math.min(next.length - 1, Math.floor((pct / 100) * next.length))
          for (let i = 0; i < next.length; i++) {
            if (i < target) next[i] = { ...next[i], status: 'done', score: 0, probeLabel: label }
            else if (i === target) next[i] = { ...next[i], status: 'running', probeLabel: label }
          }
          return next
        })
      })

      setProbesSnap(probes)
      setStepLabel('Threat intelligence…')
      setProgress(93)

      const result = await runScan(token, { acceptedTerms: true, device, probes })
      setModules(assignFindingsToModules(buildModulesFromCoverage(), result.session.findings || []))
      setSession(result.session)
      if (result.session.probes) setProbesSnap(result.session.probes as ScanProbes)
      setProgress(100)
      setStepLabel('Complete')
      setPhase('results')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
      setPhase('welcome')
    } finally {
      setRunning(false)
    }
  }

  async function startDump() {
    if (dumping || running || !session || isDumped(session)) return
    setError('')
    setDumping(true)
    setDumpOpen(true)
    setDumpPin(null)
    try {
      const result = await dumpScan(token)
      setDumpPin(result.dumpPin)
      setTerminateAt(result.terminateAt || result.session.summary?.terminateAt || null)
      setTerminateLeft(120)
      setCopyNote('')
      setSession(result.session)
      setProbesSnap(null)
      setModules(buildModulesFromCoverage())
      setDetail(null)
      setPhase('dumped')
    } catch (err) {
      setDumpOpen(false)
      setError(err instanceof Error ? err.message : 'Purge failed')
    } finally {
      setDumping(false)
    }
  }

  if (!token) return <Navigate to="/" replace />

  if (loading) {
    return (
      <div className="vault-page vault-page--boot">
        <main className="vault-boot">
          <BrandMark size="lg" />
          <div className="vault-loader" aria-label="Loading">
            <span />
            <span />
            <span />
          </div>
        </main>
      </div>
    )
  }

  if (!user || !session) {
    return (
      <div className="vault-page">
        <header className="vault-topbar">
          <Link to="/" className="vault-brand">
            <BrandMark size="sm" />
            Persona Scan
          </Link>
        </header>
        <main className="vault-shell vault-center">
          <h1>Session unavailable</h1>
          <p>{error || 'This scan link is invalid or expired.'}</p>
          <p className="vault-hint">Use a session link from Admin → Open scan.</p>
          <Link className="vault-btn vault-btn-glow" to="/admin">
            Back to admin
          </Link>
        </main>
      </div>
    )
  }

  const expired = session.status === 'expired' || minutesLeft === 0
  const flag = identity?.flag || flagForCountry(user.country)

  return (
    <div className="vault-page">
      <header className="vault-topbar">
        <div className="vault-brand">
          <BrandMark size="sm" />
          <span>Persona Scan</span>
        </div>
        <span className="vault-chip">
          {flag} {expired ? 'Expired' : `${minutesLeft} min`} · {user.country}
        </span>
      </header>

      {phase === 'welcome' && (
        <main className="vault-shell">
          <p className="vault-kicker">Secured invite</p>
          <h1 className="vault-display">
            <span className="vault-flag-inline">{flag}</span> {user.name}
          </h1>
          <p className="vault-lede">
            Live device scan for <strong>{user.email}</strong>. Country, networks, and browser
            signals are scored from real probes.
          </p>

          {identity && <IdentityCard identity={identity} />}

          <div className="vault-actions">
            <button
              type="button"
              className="vault-btn vault-btn-glow vault-btn-xl"
              disabled={expired || running || dumping}
              onClick={() => {
                setError('')
                setTermsOpen(true)
              }}
            >
              Start scan
            </button>
            {session.status === 'completed' && !isDumped(session) && (
              <button type="button" className="vault-btn vault-btn-ghost vault-btn-xl" onClick={() => setPhase('results')}>
                View results
              </button>
            )}
            {isDumped(session) && (
              <button type="button" className="vault-btn vault-btn-ghost vault-btn-xl" onClick={() => setPhase('dumped')}>
                View dump status
              </button>
            )}
          </div>

          {error && <p className="vault-error">{error}</p>}
        </main>
      )}

      {phase === 'scanning' && (
        <main className="vault-shell">
          <div className="vault-progress-wrap">
            <div className="vault-ring" style={{ ['--p' as string]: String(progress) }}>
              <div className="vault-ring-inner">
                <strong>{progress}%</strong>
                <span>scanning</span>
              </div>
            </div>
            <h1>Scanning device</h1>
            <p className="vault-step">{stepLabel}</p>
            <div className="vault-bar" aria-hidden>
              <div style={{ width: `${progress}%` }} />
            </div>
          </div>

          {identity && <IdentityCard identity={identity} />}

          <ul className="vault-modules">
            {modules.map((mod) => (
              <li
                key={mod.id}
                className={`vault-mod vault-mod--${mod.status}`}
                data-tone={scoreTone(mod.score)}
              >
                <div>
                  <strong>{mod.title}</strong>
                  <span>
                    {mod.status === 'pending' && 'Queued'}
                    {mod.status === 'running' && (mod.probeLabel || 'Running…')}
                    {mod.status === 'done' && 'Probe finished'}
                  </span>
                </div>
                {mod.status === 'running' ? <i className="vault-pulse" /> : null}
                {mod.status === 'done' ? <em>✓</em> : null}
              </li>
            ))}
          </ul>
        </main>
      )}

      {phase === 'results' && (
        <main className="vault-shell vault-shell--results">
          <p className="vault-kicker">Scan complete</p>
          <h1 className="vault-display">Security score</h1>

          <div className="vault-score-card" data-tone={scoreTone(overallScore)}>
            <div className="vault-overall">
              <strong>{overallScore}</strong>
              <span>{scoreLabel(overallScore)}</span>
            </div>
            <div className="vault-score-meta">
              <span>
                <b>{threatCount}</b> threats
              </span>
              <span>
                <b>{warnCount}</b> warnings
              </span>
              <span>
                <b>{modules.length}</b> categories
              </span>
            </div>
          </div>

          {identity && <IdentityCard identity={identity} />}

          <p className="vault-hint">Tap a category for findings and per-check scores.</p>

          <ul className="vault-modules">
            {modules.map((mod) => (
              <li key={mod.id}>
                <button
                  type="button"
                  className="vault-mod vault-mod--done vault-mod-btn"
                  data-tone={scoreTone(mod.score)}
                  onClick={() => setDetail(mod)}
                >
                  <div>
                    <strong>{mod.title}</strong>
                    <span>
                      {
                        mod.findings.filter((f) => f.verdict === 'negative' || f.status === 'threat')
                          .length
                      }{' '}
                      negative ·{' '}
                      {
                        mod.findings.filter(
                          (f) =>
                            f.verdict === 'partial' ||
                            f.status === 'partial' ||
                            f.status === 'warning',
                        ).length
                      }{' '}
                      partial · {mod.findings.length} checks
                    </span>
                  </div>
                  <em>{mod.score}</em>
                </button>
              </li>
            ))}
          </ul>

          {error && <p className="vault-error">{error}</p>}

          <div className="vault-purge-bar">
            <button
              type="button"
              className="vault-btn vault-btn-danger vault-btn-xl"
              disabled={running || dumping || isDumped(session)}
              onClick={() => void startDump()}
            >
              {dumping ? 'Purging…' : 'Purge scan'}
            </button>
          </div>
        </main>
      )}

      {phase === 'dumped' && (
        <main className="vault-shell">
          <p className="vault-kicker">Session wiped</p>
          <h1 className="vault-display">Scan purged</h1>
          <p className="vault-lede">
            Findings, probes, and threat intel for this session were permanently cleared. Nobody can
            access your data through this key.
          </p>
          <div className="vault-dump-card">
            {dumpPin ? (
              <>
                <span className="vault-dump-label">Purge key</span>
                <strong className="vault-dump-pin">{dumpPin}</strong>
                <div className="vault-dump-actions">
                  <button type="button" className="vault-btn vault-btn-glow" onClick={() => void copyPurgeKey()}>
                    {copyNote || 'Copy key'}
                  </button>
                </div>
                <p>Nobody can access your data through this key. Save it now — it cannot be read again.</p>
              </>
            ) : (
              <>
                <span className="vault-dump-label">Purge key</span>
                <strong className="vault-dump-pin vault-dump-pin--gone">••••••••••</strong>
                <p>Key already issued. It cannot be read again from this session.</p>
              </>
            )}
            {terminateLeft != null && (
              <p className="vault-terminate-timer">
                Session terminates in {Math.floor(terminateLeft / 60)}:
                {String(terminateLeft % 60).padStart(2, '0')}
              </p>
            )}
          </div>
          {error && <p className="vault-error">{error}</p>}
        </main>
      )}

      {phase === 'terminated' && (
        <main className="vault-shell vault-center">
          <BrandMark size="lg" />
          <p className="vault-kicker">Session ended</p>
          <h1 className="vault-display">Terminated</h1>
          <p className="vault-lede">
            This purged session closed automatically. The purge key can no longer be read here.
          </p>
        </main>
      )}

      <Sheet
        open={termsOpen}
        onClose={closeTerms}
        variant="vault"
        title="Before we scan"
        subtitle="Terms · coverage · how your data is used"
        footer={
          <div className="vault-sheet-actions">
            <button type="button" className="vault-btn vault-btn-ghost" onClick={closeTerms} disabled={running}>
              Cancel
            </button>
            <button
              type="button"
              className="vault-btn vault-btn-glow"
              disabled={running || expired}
              onClick={() => void startScan()}
            >
              {running ? 'Starting…' : 'Accept & scan'}
            </button>
          </div>
        }
      >
        <div className="ps-section">
          <h3>How we use data</h3>
          <ul>
            <li>Checks run in this browser only.</li>
            <li>Raw clipboard text is never uploaded.</li>
            <li>Session expires in about 20 minutes.</li>
            <li>Dump scan permanently wipes results and issues a one-time key.</li>
          </ul>
        </div>
        <div className="ps-section">
          <h3>What we check</h3>
          {SCAN_COVERAGE.map((group) => (
            <div key={group.group} className="ps-cov">
              <strong>{group.group}</strong>
              <ul>
                {group.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </Sheet>

      <Sheet
        open={Boolean(detail)}
        onClose={closeDetail}
        variant="vault"
        title={detail?.title || 'Details'}
        subtitle={detail ? `${detail.score}/100 · ${scoreLabel(detail.score)}` : undefined}
        footer={
          <div className="vault-sheet-actions">
            <button type="button" className="vault-btn vault-btn-glow" onClick={closeDetail}>
              Done
            </button>
          </div>
        }
      >
        {!detail?.findings.length ? (
          <p className="vault-hint">No detailed findings in this category.</p>
        ) : (
          <ul className="vault-findings">
            {detail.findings.map((f: ScanFinding) => {
              const s = findingScore(f)
              const verdict = verdictLabel(f)
              return (
                <li key={f.id} data-status={f.status} data-verdict={f.verdict || ''}>
                  <div className="vault-find-top">
                    <span className={`vault-verdict vault-verdict--${(f.verdict || 'positive').toLowerCase()}`}>
                      {verdict}
                    </span>
                    <span data-tone={scoreTone(s)}>{s}/100</span>
                  </div>
                  <strong>{f.title}</strong>
                  <p>{f.detail}</p>
                  <small>{f.category}</small>
                </li>
              )
            })}
          </ul>
        )}
      </Sheet>

      <Sheet
        open={dumpOpen}
        onClose={() => {
          if (!dumping) closeDump()
        }}
        variant="vault"
        title={dumping ? 'Purging scan…' : 'Purge key issued'}
        subtitle={dumping ? 'Wiping findings and generating your key' : 'Shown once — cannot be read again'}
        footer={
          <div className="vault-sheet-actions">
            <button
              type="button"
              className="vault-btn vault-btn-glow"
              disabled={dumping || !dumpPin}
              onClick={closeDump}
            >
              {dumping ? 'Please wait…' : 'I saved my key'}
            </button>
          </div>
        }
      >
        {dumping || !dumpPin ? (
          <div className="vault-dump-loading">
            <div className="vault-loader" aria-label="Purging">
              <span />
              <span />
              <span />
            </div>
          </div>
        ) : (
          <div className="vault-dump-card vault-dump-card--sheet">
            <span className="vault-dump-label">Your purge key</span>
            <strong className="vault-dump-pin">{dumpPin}</strong>
            <div className="vault-dump-actions">
              <button type="button" className="vault-btn vault-btn-glow" onClick={() => void copyPurgeKey()}>
                {copyNote || 'Copy key'}
              </button>
            </div>
            <p>Nobody can access your data through this key. Session terminates automatically in 2 minutes.</p>
            {terminateLeft != null && (
              <p className="vault-terminate-timer">
                Closes in {Math.floor(terminateLeft / 60)}:{String(terminateLeft % 60).padStart(2, '0')}
              </p>
            )}
          </div>
        )}
      </Sheet>
    </div>
  )
}

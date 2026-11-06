import { useCallback, useEffect, useMemo, useState } from 'react'
import { Navigate, useParams } from 'react-router-dom'
import { BrandMark } from '../components/BrandMark'
import { Sheet } from '../components/Sheet'
import { dumpScan, getScanSession, runScan, terminateScan } from '../lib/api'
import {
  collectDeviceInfo,
  detectBrowser,
  detectDeviceModel,
  publicSessionCode,
  refineDeviceModel,
} from '../lib/device'
import { probeClipboard, runRealDeviceScan, type ScanProbes } from '../lib/realScanner'
import { mergeCustomFindings } from '../lib/customResults'
import { SCAN_COVERAGE } from '../lib/scanCoverage'
import {
  assignFindingsToModules,
  buildModulesFromCoverage,
  countOutcomes,
  formatOutcomeCounts,
  moduleTone,
  outcomeLabel,
  outcomeOf,
  type ScanModule,
} from '../lib/scanScoring'
import type { ScanFinding, ScanSession } from '../types'

type Phase = 'welcome' | 'scanning' | 'results' | 'dumped' | 'terminated'

const PURGE_NOTICE =
  'This link deletes the results. With scraping, they cannot be used by other parties. Charges apply.'

function isDumped(session: ScanSession | null | undefined) {
  return Boolean(session?.dumpedAt || session?.summary?.dumped)
}

function findingsForView(session: ScanSession | null | undefined) {
  if (!session || isDumped(session)) return []
  return mergeCustomFindings(session.findings, session.customResults)
}

function SessionMeta({
  code,
  model,
  browser,
  variant = 'compact',
}: {
  code: string
  model: string
  browser: string
  variant?: 'compact' | 'hero'
}) {
  const [copied, setCopied] = useState(false)

  async function copyCode() {
    try {
      await navigator.clipboard.writeText(code.replace(/-/g, ''))
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      /* ignore */
    }
  }

  return (
    <div className={`vault-session-meta vault-session-meta--${variant}`}>
      <button type="button" className="vault-session-cell" onClick={() => void copyCode()} title="Copy session ID">
        <span className="vault-session-label">{copied ? 'Copied' : 'Session'}</span>
        <strong className="vault-session-id">{code}</strong>
        {variant === 'hero' ? <span className="vault-session-sub">{copied ? 'ID copied' : 'Tap to copy'}</span> : null}
      </button>
      <div className="vault-session-cell" title="Detected device">
        <span className="vault-session-label">Device</span>
        <strong className="vault-session-device">{model || 'Detecting…'}</strong>
        {variant === 'hero' ? <span className="vault-session-sub">{browser}</span> : null}
      </div>
    </div>
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
  const [, setProbesSnap] = useState<ScanProbes | null>(null)
  const [deviceModel, setDeviceModel] = useState(() => detectDeviceModel())
  const browser = useMemo(() => detectBrowser(), [])

  useEffect(() => {
    if (!token) return
    let alive = true
    setLoading(true)
    setError('')
    getScanSession(token, collectDeviceInfo())
      .then((data) => {
        if (!alive) return
        if (
          data.session.status === 'expired' ||
          new Date(data.session.expiresAt).getTime() <= Date.now()
        ) {
          setError('This scan session has expired and can no longer be opened.')
          setUser(null)
          setSession(null)
          return
        }
        setUser(data.user)
        setSession(data.session)
        const live = detectDeviceModel()
        const stored =
          (data.session.device as { model?: string; name?: string } | undefined)?.model ||
          data.session.deviceName ||
          (data.session.device as { name?: string } | undefined)?.name ||
          ''
        const storedModel = String(stored).split(' · ')[0]
        setDeviceModel(live || storedModel)
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
        if (data.session.status === 'completed' && findingsForView(data.session).length) {
          setModules(assignFindingsToModules(buildModulesFromCoverage(), findingsForView(data.session)))
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

  useEffect(() => {
    let alive = true
    void refineDeviceModel(deviceModel).then((next) => {
      if (alive && next) setDeviceModel(next)
    })
    return () => {
      alive = false
    }
  }, [token])

  // Hard-close the UI the moment the session clock hits zero.
  useEffect(() => {
    if (!session?.expiresAt) return
    const ms = new Date(session.expiresAt).getTime() - Date.now()
    if (ms <= 0) {
      setError('This scan session has expired and can no longer be opened.')
      setUser(null)
      setSession(null)
      return
    }
    const timer = window.setTimeout(() => {
      setError('This scan session has expired and can no longer be opened.')
      setUser(null)
      setSession(null)
    }, ms + 25)
    return () => window.clearTimeout(timer)
  }, [session?.id, session?.expiresAt])

  const minutesLeft = useMemo(() => {
    if (!session?.expiresAt) return null
    return Math.max(0, Math.ceil((new Date(session.expiresAt).getTime() - Date.now()) / 60000))
  }, [session])

  const resultCounts = useMemo(() => {
    const findings = modules.flatMap((m) => m.findings)
    return countOutcomes(findings)
  }, [modules])

  const sessionCode = useMemo(() => publicSessionCode(session?.id), [session?.id])

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
    setError('')
    setRunning(true)
    setProgress(4)
    setStepLabel('This browser will ask for clipboard access…')
    setModules(buildModulesFromCoverage())
    setDetail(null)
    setDumpPin(null)

    try {
      const device = collectDeviceInfo()
      const clipboard = await probeClipboard({ requestAccess: true })
      setTermsOpen(false)
      setPhase('scanning')
      setProgress(8)
      const probes = await runRealDeviceScan((label, pct) => {
        setStepLabel(label)
        setProgress(Math.min(88, Math.max(8, Math.round(pct * 0.86))))
        setModules((prev) => {
          const next = prev.map((m) => ({ ...m }))
          const target = Math.min(next.length - 1, Math.floor((pct / 100) * next.length))
          for (let i = 0; i < next.length; i++) {
            if (i < target) next[i] = { ...next[i], status: 'done', score: 0, probeLabel: label }
            else if (i === target) next[i] = { ...next[i], status: 'running', probeLabel: label }
          }
          return next
        })
      }, { clipboard })

      setProbesSnap(probes)
      setStepLabel('Confirming with the scan server…')
      setProgress(93)

      const result = await runScan(token, { acceptedTerms: true, device, probes })
      setModules(
        assignFindingsToModules(buildModulesFromCoverage(), findingsForView(result.session)),
      )
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
      setError('')
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
      <div className="vault-page vault-page--unavailable">
        <main className="vault-unavailable">
          <h1>Session unavailable</h1>
          <p>{error || 'This scan link is invalid or expired.'}</p>
        </main>
      </div>
    )
  }

  const expired = session.status === 'expired' || minutesLeft === 0

  return (
    <div className={`vault-page${phase === 'welcome' ? ' vault-page--welcome' : ''}`}>
      <header className="vault-topbar">
        <div className="vault-brand">
          <BrandMark size="sm" />
          <span>Persona Scan</span>
        </div>
        {phase !== 'welcome' ? (
          <SessionMeta code={sessionCode} model={deviceModel} browser={browser} variant="compact" />
        ) : null}
      </header>

      {phase === 'welcome' && (
        <main className="vault-shell vault-shell--start">
          <p className="vault-kicker">This device</p>
          <h1 className="vault-display">Ready to scan</h1>
          <p className="vault-lede vault-lede--start">
            Session is bound to the ID and device below. Checks run in this browser.
          </p>
          <SessionMeta code={sessionCode} model={deviceModel} browser={browser} variant="hero" />
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

          <ul className="vault-modules">
            {modules.map((mod) => (
              <li
                key={mod.id}
                className={`vault-mod vault-mod--${mod.status}`}
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
                {mod.status === 'done' ? <em aria-hidden>✓</em> : null}
              </li>
            ))}
          </ul>
        </main>
      )}

      {phase === 'results' && (
        <main className="vault-shell vault-shell--results">
          <p className="vault-kicker">Scan complete</p>
          <h1 className="vault-display">Browser checks</h1>

          <div
            className="vault-score-card"
            data-tone={moduleTone(modules.flatMap((m) => m.findings))}
          >
            <div className="vault-overall">
              <strong>{resultCounts.passed + resultCounts.failed}</strong>
              <span>finished checks</span>
            </div>
            <div className="vault-score-meta">
              <span>
                <b>{resultCounts.passed}</b> passed
              </span>
              <span>
                <b>{resultCounts.failed}</b> failed
              </span>
              <span>
                <b>{resultCounts.couldntRun}</b> couldn’t run
              </span>
            </div>
          </div>

          <p className="vault-hint">
            Each row is a measured result. Denied permissions are skipped, not scored.
          </p>

          <ul className="vault-modules">
            {modules.map((mod) => (
              <li key={mod.id}>
                <button
                  type="button"
                  className="vault-mod vault-mod--done vault-mod-btn"
                  data-tone={moduleTone(mod.findings)}
                  onClick={() => setDetail(mod)}
                >
                  <div>
                    <strong>{mod.title}</strong>
                    <span>
                      {formatOutcomeCounts(mod.findings)}
                      {mod.findings.some((f) => f.priority) ? ' · Priority' : ''}
                    </span>
                  </div>
                  <em>{mod.findings.length}</em>
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
            <p className="vault-purge-note">{PURGE_NOTICE}</p>
          </div>
        </main>
      )}

      {phase === 'dumped' && (
        <main className="vault-shell">
          <p className="vault-kicker">Session wiped</p>
          <h1 className="vault-display">Scan purged</h1>
          <p className="vault-lede">{PURGE_NOTICE}</p>
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
                <p>
                  Save the key now — it cannot be read again. {PURGE_NOTICE}
                </p>
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
            <li>
              Accept &amp; scan asks once for clipboard access. If you deny it, that check is
              skipped — we do not invent a result.
            </li>
            <li>Raw clipboard text is never uploaded.</li>
            <li>Session expires in about 20 minutes.</li>
            <li>
              Dump scan permanently wipes results and issues a one-time key. {PURGE_NOTICE}
            </li>
          </ul>
        </div>
        <div className="ps-section">
          <h3>What we check on this device</h3>
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
          <p className="vault-hint">
            Results come from live checks in this browser. Optional cloud threat feeds are not shown
            here and are not required for a real scan.
          </p>
        </div>
      </Sheet>

      <Sheet
        open={Boolean(detail)}
        onClose={closeDetail}
        variant="vault"
        title={detail?.title || 'Details'}
        subtitle={detail ? formatOutcomeCounts(detail.findings) : undefined}
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
              const outcome = outcomeOf(f)
              return (
                <li key={f.id} data-status={f.status} data-outcome={outcome}>
                  <div className="vault-find-top">
                    <span className={`vault-verdict vault-verdict--${outcome}`}>
                      {outcomeLabel(outcome)}
                    </span>
                    {f.priority ? <span className="vault-priority">Priority</span> : null}
                  </div>
                  <strong>{f.title}</strong>
                  <p>{f.detail}</p>
                  {f.evidence ? <code className="vault-evidence">{f.evidence}</code> : null}
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
            <p>
              Session terminates automatically in 2 minutes. {PURGE_NOTICE}
            </p>
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

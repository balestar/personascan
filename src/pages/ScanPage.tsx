import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { BrandMark } from '../components/BrandMark'
import { getScanSession, runScan } from '../lib/api'
import { probeWebRtcLeak } from '../lib/webrtcProbe'
import type { ScanResult } from '../types'

const SCAN_CATEGORIES = [
  'IP Leaks',
  'Password Leaks',
  'Unknown API Traffic',
  'Pull Request / Dev Apps',
  'Personal Data Exfiltration',
  'Ads Applications',
  'Bots',
  'Cryptographic Scan',
  'Fingerprinting',
  'Permission Surface',
  'DNS Leaks',
]

export function ScanPage() {
  const { token = '' } = useParams()
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [accepted, setAccepted] = useState(false)
  const [user, setUser] = useState<{ name: string; email: string; country: string } | null>(null)
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [progress, setProgress] = useState(0)

  useEffect(() => {
    let alive = true
    setLoading(true)
    getScanSession(token)
      .then((data) => {
        if (!alive) return
        setUser(data.user)
        setScan(data.lastScan)
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

  const severityOrder = useMemo(() => {
    if (!scan) return []
    return [...scan.findings].sort((a, b) => {
      const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      return rank[a.severity] - rank[b.severity]
    })
  }, [scan])

  async function onFetch(e: FormEvent) {
    e.preventDefault()
    if (!accepted) {
      setError('Accept the secure scan terms to continue.')
      return
    }
    setError('')
    setRunning(true)
    setProgress(8)

    const tick = window.setInterval(() => {
      setProgress((p) => Math.min(p + 7, 88))
    }, 220)

    try {
      const webrtcLeak = await probeWebRtcLeak()
      setProgress(55)
      const result = await runScan(token, {
        acceptedTerms: true,
        clientHints: {
          webrtcLeak,
          language: navigator.language,
          platform: navigator.platform,
          timezoneOffset: new Date().getTimezoneOffset(),
          doNotTrack: navigator.doNotTrack === '1' ? true : navigator.doNotTrack === '0' ? false : null,
        },
      })
      setProgress(100)
      setScan(result.scan)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
    } finally {
      window.clearInterval(tick)
      setRunning(false)
    }
  }

  if (loading) {
    return (
      <div className="page scan-page">
        <div className="atmosphere" aria-hidden />
        <main className="scan-shell">
          <p className="muted">Validating secured link…</p>
        </main>
      </div>
    )
  }

  if (!user) {
    return (
      <div className="page scan-page">
        <div className="atmosphere" aria-hidden />
        <main className="scan-shell">
          <BrandMark />
          <h1>Link unavailable</h1>
          <p className="lede">{error || 'This secured scan link is invalid or expired.'}</p>
          <Link className="btn btn-ghost" to="/">
            Back to Persona Scan
          </Link>
        </main>
      </div>
    )
  }

  return (
    <div className="page scan-page">
      <div className="atmosphere" aria-hidden />
      <header className="site-header">
        <div className="brand-lockup">
          <BrandMark size="sm" />
          <span>Persona Scan</span>
        </div>
        <span className="pill">{user.country}</span>
      </header>

      <main className="scan-shell">
        <p className="brand-wordmark brand-wordmark--sm">Persona Scan</p>
        <h1>Hello, {user.name}</h1>
        <p className="lede">
          Run a full device threat scan for <strong>{user.email}</strong>. Results cover IP leaks,
          password exposure, opaque APIs, personal-data apps, ads SDKs, bots, crypto posture, and
          more.
        </p>

        <form className="fetch-panel" onSubmit={onFetch}>
          <button className="btn btn-primary btn-fetch" type="submit" disabled={running}>
            {running ? 'Scanning device…' : 'Fetch scan'}
          </button>

          <label className="terms">
            <input
              type="checkbox"
              checked={accepted}
              onChange={(e) => setAccepted(e.target.checked)}
            />
            <span>
              I agree that <strong>Persona Scan scans are secure</strong>. This check inspects
              browser and network exposure signals only — it does not install software, request
              passwords, or alter device settings. Results are delivered over this secured link.
            </span>
          </label>

          {running && (
            <div className="progress" aria-live="polite">
              <div className="progress-bar" style={{ width: `${progress}%` }} />
              <p>Fetching threat categories… {progress}%</p>
            </div>
          )}
          {error && <p className="form-error">{error}</p>}
        </form>

        <section className="category-preview">
          <h2>Scan coverage</h2>
          <ul>
            {SCAN_CATEGORIES.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        {scan && (
          <section className="results">
            <div className="results-head">
              <h2>Scan results</h2>
              <p>
                {scan.summary.threat} threats · {scan.summary.warning} warnings ·{' '}
                {scan.summary.clear} clear · completed{' '}
                {new Date(scan.completedAt).toLocaleString()}
              </p>
            </div>
            <ul className="finding-list">
              {severityOrder.map((finding) => (
                <li key={finding.id} data-status={finding.status}>
                  <div className="finding-top">
                    <span className="finding-cat">{finding.category}</span>
                    <span className={`sev sev--${finding.severity}`}>{finding.severity}</span>
                  </div>
                  <strong>{finding.title}</strong>
                  <p>{finding.detail}</p>
                </li>
              ))}
            </ul>
          </section>
        )}
      </main>
    </div>
  )
}

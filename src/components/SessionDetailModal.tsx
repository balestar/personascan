import { useEffect, useState } from 'react'
import { getSession } from '../lib/api'
import { riskBand } from '../lib/customResults'
import { outcomeLabel, outcomeOf } from '../lib/scanScoring'
import type { CustomResult, DualSideResult, FindingOutcome, ScanFinding, ScanSession } from '../types'
import { Modal } from './Modal'
import { StreetViewPanel } from './StreetViewPanel'

const FEED_NAMES: Record<string, string> = {
  anyapi: 'AnyAPI',
  anyapi_ip: 'AnyAPI IP geolocation',
  anyapi_email: 'AnyAPI email validation',
  anyapi_phone: 'AnyAPI phone validation',
  anyapi_url: 'AnyAPI URL scrape',
  urlscan: 'urlscan.io',
  cloudmersive: 'Cloudmersive',
  phishtank: 'PhishTank',
  nvd: 'NVD CVE',
  cve_nvd: 'NVD CVE',
  google_safe_browsing: 'Google Safe Browsing',
  virustotal: 'VirusTotal',
  scamsniffer: 'ScamSniffer',
  blockaid: 'Blockaid',
  snyk: 'Snyk',
  mobsf: 'MobSF',
  yara: 'YARA',
  clamav: 'ClamAV',
  approov: 'Approov',
  appsealing: 'AppSealing',
  frida_detection: 'Frida heuristics',
}

type Props = {
  open: boolean
  session: ScanSession | null
  userCustomResults?: CustomResult[]
  onClose: () => void
  onCancel?: () => void
}

function statusLabel(status: ScanSession['status']) {
  switch (status) {
    case 'pending':
      return 'Awaiting open'
    case 'active':
      return 'In progress'
    case 'completed':
      return 'Completed'
    case 'expired':
      return 'Expired'
    case 'blocked':
      return 'Blocked'
    default:
      return status
  }
}

function sideOutcome(side?: DualSideResult): FindingOutcome {
  if (!side || side.skipped || side.passed == null) return 'couldnt_run'
  return side.passed ? 'passed' : 'failed'
}

function sideLabel(side?: DualSideResult) {
  return outcomeLabel(sideOutcome(side))
}

function FindingDual({ finding, open, onToggle }: { finding: ScanFinding; open: boolean; onToggle: () => void }) {
  const outcome = outcomeOf(finding)
  const independent =
    finding.apiResult?.source === 'request_ip' || finding.apiResult?.source === 'request_ua'
  const pill = independent ? sideOutcome(finding.apiResult) : outcome
  return (
    <li data-status={finding.status} data-outcome={pill} className={open ? 'is-open' : ''}>
      <button type="button" className="finding-toggle" onClick={onToggle}>
        <div className="finding-top">
          <span className="finding-cat">{finding.category}</span>
          <span className={`dual-pill dual-pill--${pill}`}>
            {independent ? `${outcomeLabel(pill)} (IP/UA)` : outcomeLabel(pill)}
          </span>
        </div>
        <strong>{finding.title}</strong>
        <p className="finding-preview">{finding.adminDetail || finding.detail}</p>
        {finding.evidence ? <code className="vault-evidence">{finding.evidence}</code> : null}
      </button>
      {open && (
        <div className="finding-body">
          <div className="dual-grid">
            <div className="dual-card">
              <span>Device said</span>
              <strong>{sideLabel(finding.deviceResult)}</strong>
              {finding.deviceResult?.value ? (
                <code className="vault-evidence">{finding.deviceResult.value}</code>
              ) : null}
              <p>{finding.deviceResult?.detail || 'No device result stored'}</p>
            </div>
            <div className="dual-card">
              <span>Server saw</span>
              <strong>{sideLabel(finding.apiResult)}</strong>
              {finding.apiResult?.value ? (
                <code className="vault-evidence">{finding.apiResult.value}</code>
              ) : null}
              <p>
                {independent
                  ? finding.apiResult?.detail || 'No server observation stored'
                  : finding.apiResult?.detail ||
                    'Not independently observable from the request. Device measurement only.'}
              </p>
              {finding.apiResult?.source ? (
                <small>
                  {finding.apiResult.source === 'request_ip'
                    ? 'Compared to CF-Connecting-IP / request IP'
                    : finding.apiResult.source === 'request_ua'
                      ? 'Compared to request User-Agent'
                      : finding.apiResult.source}
                </small>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </li>
  )
}

export function SessionDetailModal({ open, session, userCustomResults, onClose, onCancel }: Props) {
  const [live, setLive] = useState<ScanSession | null>(session)
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [openFinding, setOpenFinding] = useState<string | null>(null)
  const [showLocation, setShowLocation] = useState(false)

  useEffect(() => {
    if (!open || !session?.id) {
      setLive(session)
      setOpenFinding(null)
      setShowLocation(false)
      setLoadError('')
      return
    }
    setLive(session)
    setLoading(true)
    setLoadError('')
    setOpenFinding(null)
    setShowLocation(false)
    let alive = true
    getSession(session.id)
      .then((data) => {
        if (!alive) return
        setLive(data.session)
      })
      .catch((err) => {
        if (!alive) return
        setLoadError(err instanceof Error ? err.message : 'Could not refresh session details')
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [open, session])

  if (!session && !live) return null
  const view = live || session
  if (!view) return null

  const findings = (view.findings || []).filter(
    (f) =>
      !String(f.id || '').startsWith('intel_') &&
      f.category !== 'Optional threat intel' &&
      !String(f.id || '').startsWith('custom_') &&
      f.category !== 'Custom results',
  )
  const intel = (view.threatIntel || {}) as {
    ranAt?: string
    results?: Array<{
      provider?: string
      ok?: boolean
      skipped?: boolean
      reason?: string
      error?: string
      checkedAt?: string
      data?: {
        malicious?: boolean
        evidence?: string
        ips?: Array<{ ip?: string; malicious?: number; suspicious?: number; harmless?: number }>
        domains?: Array<{ domain?: string; malicious?: number; suspicious?: number; harmless?: number }>
        urls?: Array<{ url?: string; malicious?: number; unknown?: boolean }>
      }
    }>
  }
  const intelResults = intel.results || []
  const customResults =
    (view.customResults && view.customResults.length > 0
      ? view.customResults
      : userCustomResults) || []

  return (
    <Modal
      open={open}
      onClose={onClose}
      wide
      variant="vault"
      title={view.title || view.deviceName || 'Scan session'}
      subtitle={`${view.userName} · ${view.userEmail} · ${statusLabel(view.status)}`}
      footer={
        <div className="vault-sheet-actions mail-send-actions">
          <button
            type="button"
            className="vault-btn vault-btn-ghost"
            onClick={async () => {
              await navigator.clipboard.writeText(view.link)
            }}
          >
            Copy link
          </button>
          <button
            type="button"
            className="vault-btn vault-btn-glow"
            onClick={() => window.open(view.link, '_blank', 'noopener,noreferrer')}
          >
            Open scan
          </button>
          {onCancel ? (
            <button type="button" className="vault-btn vault-btn-ghost mail-send-primary" onClick={onCancel}>
              Cancel session
            </button>
          ) : null}
        </div>
      }
    >
      <div className="session-detail">
        {loading && <p className="admin-detail-loading">Refreshing live session…</p>}
        {loadError && <p className="admin-error">{loadError}</p>}

        <div className="detail-grid">
          <div className="detail-tile">
            <span>Status</span>
            <strong className={`status-chip status-chip--${view.status}`}>{statusLabel(view.status)}</strong>
          </div>
          <div className="detail-tile">
            <span>Device</span>
            <strong>{view.deviceName || 'Not connected yet'}</strong>
          </div>
          <div className="detail-tile">
            <span>Created</span>
            <strong>{new Date(view.createdAt).toLocaleString()}</strong>
          </div>
          <div className="detail-tile">
            <span>Expires</span>
            <strong>{new Date(view.expiresAt).toLocaleString()}</strong>
          </div>
          <div className="detail-tile">
            <span>Opened</span>
            <strong>{view.openedAt ? new Date(view.openedAt).toLocaleString() : '—'}</strong>
          </div>
          <div className="detail-tile">
            <span>Completed</span>
            <strong>{view.completedAt ? new Date(view.completedAt).toLocaleString() : '—'}</strong>
          </div>
        </div>

        {customResults.length > 0 && (
          <div className="detail-block">
            <h3>Custom results (all sessions)</h3>
            <p className="admin-empty">
              Admin flags on this user. They apply to every session and stay hidden from the
              recipient.
            </p>
            <ul className="admin-custom-list">
              {customResults.map((item) => (
                <li key={item.id} className="admin-custom-item" data-risk={riskBand(item.riskRate)}>
                  <div>
                    <strong>{item.label}</strong>
                    <span className={`risk-chip risk-chip--${riskBand(item.riskRate)}`}>
                      Risk {item.riskRate}
                    </span>
                    {item.note ? <p>{item.note}</p> : null}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}

        {view.device && (
          <div className="detail-block">
            <h3>Device profile</h3>
            <dl className="kv">
              <div>
                <dt>Name</dt>
                <dd>{view.device.name}</dd>
              </div>
              <div>
                <dt>Platform</dt>
                <dd>{view.device.platform || '—'}</dd>
              </div>
              <div>
                <dt>Language</dt>
                <dd>{view.device.language || '—'}</dd>
              </div>
              <div>
                <dt>Screen</dt>
                <dd>{view.device.screen || '—'}</dd>
              </div>
              <div className="kv-wide">
                <dt>User agent</dt>
                <dd>{view.device.userAgent || '—'}</dd>
              </div>
            </dl>
          </div>
        )}

        {view.geo && (
          <div className="detail-block">
            <div className="detail-block-head">
              <h3>Session location</h3>
              {!showLocation && typeof view.geo.lat === 'number' && typeof view.geo.lon === 'number' && (
                <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setShowLocation(true)}>
                  Show live map
                </button>
              )}
            </div>
            {showLocation || !(typeof view.geo.lat === 'number' && typeof view.geo.lon === 'number') ? (
              <StreetViewPanel geo={view.geo} title="Captured location" />
            ) : (
              <p className="admin-empty">
                {[view.geo.city, view.geo.region, view.geo.country].filter(Boolean).join(', ') || 'Location on file'}
                {view.geo.ip ? ` · device IP ${view.geo.ip}` : ''}
                {view.geo.observedIp ? ` · server saw ${view.geo.observedIp}` : ''}
                {view.geo.isp ? ` · ${view.geo.isp}` : ''} · {view.geo.lat.toFixed(4)}, {view.geo.lon.toFixed(4)}
              </p>
            )}
          </div>
        )}

        {view.summary && (
          <div className="summary-strip">
            <span>{view.summary.passed ?? view.summary.positive ?? view.summary.clear} passed</span>
            <span>{view.summary.failed ?? view.summary.negative ?? view.summary.threat} failed</span>
            <span>{view.summary.couldntRun ?? view.summary.partial ?? 0} couldn’t run</span>
            <span>
              {view.summary.scored ??
                (view.summary.passed ?? 0) + (view.summary.failed ?? 0)}{' '}
              scored
            </span>
          </div>
        )}

        {findings.length > 0 ? (
          <div className="detail-block">
            <h3>Device vs server</h3>
            <p className="admin-empty">
              Dual-verify is request IP and User-Agent: device said X, server saw X. Other checks
              are device measurements the server cannot independently re-run.
            </p>
            <ul className="finding-list">
              {findings.map((finding) => (
                <FindingDual
                  key={finding.id}
                  finding={finding}
                  open={openFinding === finding.id}
                  onToggle={() => setOpenFinding((id) => (id === finding.id ? null : finding.id))}
                />
              ))}
            </ul>
          </div>
        ) : (
          <p className="empty">
            {view.status === 'pending'
              ? 'Recipient has not opened this session yet.'
              : view.status === 'active'
                ? 'Device connected. Waiting for the recipient to finish the scan.'
                : view.status === 'expired'
                  ? 'Session expired after 20 minutes with no completed scan.'
                  : view.dumpedAt || view.summary?.dumped
                    ? 'Scan was dumped — findings wiped.'
                    : 'No findings recorded for this session.'}
          </p>
        )}

        <div className="detail-block">
          <h3>Optional threat intel</h3>
          {intelResults.length ? (
            <>
              <p className="admin-empty">
                A missing key is not a malware pass. Finished checks show the feed name and time.
              </p>
              <ul className="intel-feed-list">
                {intelResults.map((r) => {
                  const feed = FEED_NAMES[r.provider || ''] || r.provider || 'feed'
                  const when = r.checkedAt || intel.ranAt
                  const skipped = Boolean(r.skipped)
                  const failed = !skipped && r.ok === false
                  const evidence =
                    r.data?.evidence ||
                    [
                      ...(r.data?.ips || []).map(
                        (row) =>
                          `${row.ip} malicious=${row.malicious ?? 0} suspicious=${row.suspicious ?? 0} harmless=${row.harmless ?? 0}`,
                      ),
                      ...(r.data?.domains || []).map(
                        (row) =>
                          `${row.domain} malicious=${row.malicious ?? 0} suspicious=${row.suspicious ?? 0}`,
                      ),
                      ...(r.data?.urls || []).map((row) =>
                        row.unknown ? `${row.url} not in corpus` : `${row.url} malicious=${row.malicious ?? 0}`,
                      ),
                    ].join(' · ')
                  const outcome = skipped || failed ? 'couldnt_run' : r.data?.malicious ? 'failed' : 'passed'
                  return (
                    <li key={r.provider || feed} data-outcome={outcome}>
                      <div className="finding-top">
                        <strong>{feed}</strong>
                        <span className={`dual-pill dual-pill--${outcome}`}>
                          {outcome === 'passed' ? 'Passed' : outcome === 'failed' ? 'Failed' : 'Couldn’t run'}
                        </span>
                      </div>
                      {skipped ? (
                        <span>Not configured — not checked{r.reason ? ` (${r.reason})` : ''}</span>
                      ) : failed ? (
                        <span>Couldn’t run{r.error ? ` · ${r.error}` : ''}</span>
                      ) : (
                        <>
                          <span>
                            Checked against {feed}
                            {when ? ` · ${when}` : ''}
                          </span>
                          {evidence ? <code className="vault-evidence">{evidence}</code> : null}
                        </>
                      )}
                    </li>
                  )
                })}
              </ul>
            </>
          ) : (
            <p className="admin-empty">No threat-intel run recorded for this session.</p>
          )}
        </div>

        <div className="detail-block">
          <h3>Session link</h3>
          <code className="link-code">{view.link}</code>
        </div>
      </div>
    </Modal>
  )
}

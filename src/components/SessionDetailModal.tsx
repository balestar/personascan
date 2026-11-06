import { useEffect, useState } from 'react'
import { getSession } from '../lib/api'
import type { DualSideResult, ScanFinding, ScanSession } from '../types'
import { Modal } from './Modal'
import { StreetViewPanel } from './StreetViewPanel'

type Props = {
  open: boolean
  session: ScanSession | null
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

function sideLabel(side?: DualSideResult) {
  if (!side) return '—'
  if (side.failed || side.skipped) return side.skipped ? 'Skipped / failed' : 'Failed'
  if (side.passed === true) return 'True / clear'
  if (side.passed === false) return 'False / risk'
  return 'Unknown'
}

function FindingDual({ finding, open, onToggle }: { finding: ScanFinding; open: boolean; onToggle: () => void }) {
  return (
    <li data-status={finding.status} data-verdict={finding.verdict || ''} className={open ? 'is-open' : ''}>
      <button type="button" className="finding-toggle" onClick={onToggle}>
        <div className="finding-top">
          <span className="finding-cat">{finding.category}</span>
          <span className={`dual-pill dual-pill--${finding.verdict || 'partial'}`}>
            {(finding.verdict || 'partial').toUpperCase()}
            {typeof finding.userScore === 'number' ? ` · ${finding.userScore}` : ''}
          </span>
        </div>
        <strong>{finding.title}</strong>
        <p className="finding-preview">{finding.adminDetail || finding.detail}</p>
      </button>
      {open && (
        <div className="finding-body">
          <div className="dual-grid">
            <div className="dual-card">
              <span>Device result</span>
              <strong>{sideLabel(finding.deviceResult)}</strong>
              <p>{finding.deviceResult?.detail || 'No device result stored'}</p>
              {typeof finding.deviceResult?.ms === 'number' ? (
                <small>{finding.deviceResult.ms} ms</small>
              ) : null}
            </div>
            <div className="dual-card">
              <span>API / server result</span>
              <strong>{sideLabel(finding.apiResult)}</strong>
              <p>{finding.apiResult?.detail || 'No API/server result stored'}</p>
              {typeof finding.apiResult?.ms === 'number' ? (
                <small>
                  {finding.apiResult.ms} ms
                  {finding.apiResult.source ? ` · ${finding.apiResult.source}` : ''}
                </small>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </li>
  )
}

export function SessionDetailModal({ open, session, onClose, onCancel }: Props) {
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

  const findings = view.findings || []

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
                {view.geo.ip ? ` · ${view.geo.ip}` : ''}
                {view.geo.isp ? ` · ${view.geo.isp}` : ''} · {view.geo.lat.toFixed(4)}, {view.geo.lon.toFixed(4)}
              </p>
            )}
          </div>
        )}

        {view.summary && (
          <div className="summary-strip">
            <span>{view.summary.avgUserScore ?? '—'} user score</span>
            <span>{view.summary.positive ?? view.summary.clear} positive</span>
            <span>{view.summary.partial ?? view.summary.warning} partial</span>
            <span>{view.summary.negative ?? view.summary.threat} negative</span>
            <span>{view.summary.total} checks</span>
          </div>
        )}

        {findings.length > 0 ? (
          <div className="detail-block">
            <h3>Dual-verified findings</h3>
            <p className="admin-empty">Tap a check to expand device + API/server results.</p>
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
          <h3>Session link</h3>
          <code className="link-code">{view.link}</code>
        </div>
      </div>
    </Modal>
  )
}

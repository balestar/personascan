import { useState } from 'react'
import type { FormEvent } from 'react'
import { addCustomResult, removeCustomResult } from '../lib/api'
import { CUSTOM_RESULT_TYPES, riskBand } from '../lib/customResults'
import type { CustomResult } from '../types'

type Props = {
  userId: string
  results: CustomResult[]
  onChanged: () => Promise<void>
}

export function CustomResultsPanel({ userId, results, onChanged }: Props) {
  const [type, setType] = useState<string>(CUSTOM_RESULT_TYPES[0].id)
  const [riskRate, setRiskRate] = useState(50)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function onAdd(e: FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await addCustomResult(userId, { type, riskRate, note: note.trim() || undefined })
      setNote('')
      await onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not add custom result')
    } finally {
      setBusy(false)
    }
  }

  async function onRemove(id: string) {
    setError('')
    setBusy(true)
    try {
      await removeCustomResult(userId, id)
      await onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove custom result')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="admin-custom">
      <div className="admin-custom-head">
        <h3>Custom results</h3>
        <p>Tied to this user across every session. Recipients never see these flags.</p>
      </div>

      <form className="admin-custom-form" onSubmit={onAdd}>
        <label>
          Result type
          <select value={type} onChange={(e) => setType(e.target.value)} disabled={busy}>
            {CUSTOM_RESULT_TYPES.map((item) => (
              <option key={item.id} value={item.id}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Risk rate
          <div className="admin-risk-row">
            <input
              type="range"
              min={1}
              max={100}
              value={riskRate}
              onChange={(e) => setRiskRate(Number(e.target.value))}
              disabled={busy}
            />
            <input
              type="number"
              min={1}
              max={100}
              value={riskRate}
              onChange={(e) => {
                const next = Number(e.target.value)
                if (!Number.isFinite(next)) return
                setRiskRate(Math.min(100, Math.max(1, Math.round(next))))
              }}
              disabled={busy}
            />
          </div>
        </label>
        <label>
          Note (optional)
          <input
            type="text"
            maxLength={280}
            placeholder="Context for this flag"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            disabled={busy}
          />
        </label>
        <button className="admin-btn admin-btn-primary" type="submit" disabled={busy}>
          {busy ? 'Saving…' : 'Add result'}
        </button>
      </form>
      {error ? <p className="admin-banner admin-banner--err">{error}</p> : null}

      {results.length === 0 ? (
        <p className="admin-empty">No custom results yet. Pick a type and risk rate above.</p>
      ) : (
        <ul className="admin-custom-list">
          {results.map((item) => (
            <li key={item.id} className="admin-custom-item" data-risk={riskBand(item.riskRate)}>
              <div>
                <strong>{item.label}</strong>
                <span className={`risk-chip risk-chip--${riskBand(item.riskRate)}`}>
                  Risk {item.riskRate}
                </span>
                {item.note ? <p>{item.note}</p> : null}
              </div>
              <button
                className="admin-btn admin-btn-danger"
                type="button"
                disabled={busy}
                onClick={() => void onRemove(item.id)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

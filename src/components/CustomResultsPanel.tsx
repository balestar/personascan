import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { addCustomResults, removeCustomResult } from '../lib/api'
import { CUSTOM_RESULT_TYPES, riskBand } from '../lib/customResults'
import type { CustomResult } from '../types'

type Props = {
  userId: string
  results: CustomResult[]
  onChanged: () => Promise<void>
}

function clampRisk(value: number) {
  if (!Number.isFinite(value)) return 50
  return Math.min(100, Math.max(1, Math.round(value)))
}

export function CustomResultsPanel({ userId, results, onChanged }: Props) {
  const [open, setOpen] = useState(false)
  const [selected, setSelected] = useState<Record<string, number>>({})
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const selectedIds = useMemo(() => Object.keys(selected), [selected])
  const selectedLabels = CUSTOM_RESULT_TYPES.filter((item) => item.id in selected).map(
    (item) => item.label,
  )

  function toggleType(id: string) {
    setSelected((prev) => {
      if (id in prev) {
        const next = { ...prev }
        delete next[id]
        return next
      }
      return { ...prev, [id]: 50 }
    })
  }

  function setRisk(id: string, value: number) {
    setSelected((prev) => ({ ...prev, [id]: clampRisk(value) }))
  }

  async function onAdd(e: FormEvent) {
    e.preventDefault()
    setError('')
    if (!selectedIds.length) {
      setError('Check at least one result type.')
      setOpen(true)
      return
    }
    setBusy(true)
    try {
      await addCustomResults(
        userId,
        selectedIds.map((type) => ({
          type,
          riskRate: selected[type],
          note: note.trim() || undefined,
        })),
      )
      setSelected({})
      setNote('')
      setOpen(false)
      await onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not add custom results')
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
        <p>Tied to this user across every session. Recipients see them as priority findings.</p>
      </div>

      <form className="admin-custom-form" onSubmit={onAdd}>
        <div className="admin-type-picker">
          <span className="admin-type-label">Result type</span>
          <button
            type="button"
            className="admin-type-trigger"
            aria-expanded={open}
            disabled={busy}
            onClick={() => setOpen((prev) => !prev)}
          >
            <span>
              {selectedLabels.length === 0
                ? 'Select one or more types'
                : selectedLabels.length <= 2
                  ? selectedLabels.join(', ')
                  : `${selectedLabels.length} types selected`}
            </span>
            <em>{open ? '▴' : '▾'}</em>
          </button>
          {open && (
            <ul className="admin-type-menu">
              {CUSTOM_RESULT_TYPES.map((item) => {
                const checked = item.id in selected
                const rate = selected[item.id] ?? 50
                return (
                  <li key={item.id} className={checked ? 'is-checked' : ''}>
                    <label className="admin-type-check">
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={busy}
                        onChange={() => toggleType(item.id)}
                      />
                      <span>{item.label}</span>
                    </label>
                    {checked && (
                      <div className="admin-risk-row">
                        <input
                          type="range"
                          min={1}
                          max={100}
                          value={rate}
                          disabled={busy}
                          aria-label={`${item.label} risk rate`}
                          onChange={(e) => setRisk(item.id, Number(e.target.value))}
                        />
                        <input
                          type="number"
                          min={1}
                          max={100}
                          value={rate}
                          disabled={busy}
                          aria-label={`${item.label} risk value`}
                          onChange={(e) => setRisk(item.id, Number(e.target.value))}
                        />
                      </div>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </div>
        <label>
          Note (optional, applied to all selected)
          <input
            type="text"
            maxLength={280}
            placeholder="Context for these flags"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            disabled={busy}
          />
        </label>
        <button
          className="admin-btn admin-btn-primary"
          type="submit"
          disabled={busy || selectedIds.length === 0}
        >
          {busy
            ? 'Saving…'
            : selectedIds.length > 1
              ? `Add ${selectedIds.length} results`
              : 'Add result'}
        </button>
      </form>
      {error ? <p className="admin-banner admin-banner--err">{error}</p> : null}

      {results.length === 0 ? (
        <p className="admin-empty">No custom results yet. Check types in the dropdown and set each risk rate.</p>
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

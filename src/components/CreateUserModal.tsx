import { useState } from 'react'
import type { FormEvent } from 'react'
import { COUNTRIES } from '../lib/countries'
import { Modal } from './Modal'

type Props = {
  open: boolean
  loading: boolean
  onClose: () => void
  onCreate: (payload: { name: string; email: string; country: string }) => Promise<void>
}

export function CreateUserModal({ open, loading, onClose, onCreate }: Props) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [country, setCountry] = useState('United States')
  const [error, setError] = useState('')

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await onCreate({ name: name.trim(), email: email.trim(), country })
      setName('')
      setEmail('')
      setCountry('United States')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create user')
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      variant="vault"
      title="Create recipient"
      subtitle="Issue a secured one-time scan session for this person."
      footer={
        <div className="vault-sheet-actions">
          <button type="button" className="vault-btn vault-btn-ghost" onClick={onClose} disabled={loading}>
            Cancel
          </button>
          <button
            type="submit"
            form="create-user-form"
            className="vault-btn vault-btn-glow"
            disabled={loading}
          >
            {loading ? 'Creating…' : 'Create & issue link'}
          </button>
        </div>
      }
    >
      <form id="create-user-form" className="mail-compose" onSubmit={submit}>
        <div className="mail-form-grid">
          <label className="mail-field">
            <span>Full name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Jordan Lee"
              required
              autoFocus
            />
          </label>
          <label className="mail-field">
            <span>Email</span>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="jordan@company.com"
              required
            />
          </label>
          <label className="mail-field mail-field--full">
            <span>Country</span>
            <select value={country} onChange={(e) => setCountry(e.target.value)} required>
              {COUNTRIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </label>
        </div>
        <p className="mail-hint">
          A unique 20-minute scan link is created immediately. When they open it, the session is
          titled by their device name.
        </p>
        {error ? <p className="vault-error">{error}</p> : null}
      </form>
    </Modal>
  )
}

import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { BrandMark } from '../components/BrandMark'
import { COUNTRIES } from '../lib/countries'
import {
  checkAdmin,
  clearAdminKey,
  createUser,
  deleteUser,
  generateLink,
  getAdminKey,
  listUsers,
  setAdminKey,
} from '../lib/api'
import type { UserRecord } from '../types'

export function AdminPage() {
  const [authed, setAuthed] = useState(false)
  const [keyInput, setKeyInput] = useState('')
  const [users, setUsers] = useState<UserRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [country, setCountry] = useState('United States')
  const [lastLink, setLastLink] = useState('')

  async function refresh() {
    const data = await listUsers()
    setUsers(data.users)
  }

  useEffect(() => {
    const existing = getAdminKey()
    if (!existing) return
    checkAdmin(existing)
      .then(async () => {
        setAuthed(true)
        await refresh()
      })
      .catch(() => clearAdminKey())
  }, [])

  async function onLogin(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await checkAdmin(keyInput)
      setAdminKey(keyInput)
      setAuthed(true)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    setError('')
    setNotice('')
    setLoading(true)
    try {
      const result = await createUser({ name, email, country })
      setLastLink(result.link)
      setNotice(`Created ${result.user.name}. Secure link ready to copy.`)
      setName('')
      setEmail('')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create user')
    } finally {
      setLoading(false)
    }
  }

  async function onGenerate(userId: string) {
    setError('')
    setNotice('')
    setLoading(true)
    try {
      const result = await generateLink(userId)
      setLastLink(result.link)
      setNotice('New secured link generated.')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not generate link')
    } finally {
      setLoading(false)
    }
  }

  async function onDelete(userId: string) {
    if (!confirm('Remove this user and invalidate their active link?')) return
    setLoading(true)
    try {
      await deleteUser(userId)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setLoading(false)
    }
  }

  async function copyLink(link: string) {
    await navigator.clipboard.writeText(link)
    setNotice('Link copied to clipboard.')
    setLastLink(link)
  }

  if (!authed) {
    return (
      <div className="page admin-page">
        <div className="atmosphere" aria-hidden />
        <header className="site-header">
          <Link to="/" className="brand-lockup">
            <BrandMark size="sm" />
            <span>Persona Scan</span>
          </Link>
        </header>
        <main className="auth-panel">
          <p className="eyebrow">Admin console</p>
          <h1>Sign in to manage scan invites</h1>
          <form onSubmit={onLogin} className="stack-form">
            <label>
              Admin key
              <input
                type="password"
                value={keyInput}
                onChange={(e) => setKeyInput(e.target.value)}
                placeholder="Enter ADMIN_KEY"
                required
                autoFocus
              />
            </label>
            {error && <p className="form-error">{error}</p>}
            <button className="btn btn-primary" disabled={loading} type="submit">
              {loading ? 'Checking…' : 'Enter console'}
            </button>
          </form>
        </main>
      </div>
    )
  }

  return (
    <div className="page admin-page">
      <div className="atmosphere atmosphere--soft" aria-hidden />
      <header className="site-header">
        <Link to="/" className="brand-lockup">
          <BrandMark size="sm" />
          <span>Persona Scan</span>
        </Link>
        <button
          className="ghost-link"
          type="button"
          onClick={() => {
            clearAdminKey()
            setAuthed(false)
          }}
        >
          Sign out
        </button>
      </header>

      <main className="admin-layout">
        <section className="admin-create">
          <p className="eyebrow">Create user</p>
          <h1>Invite someone to a secured device scan</h1>
          <form onSubmit={onCreate} className="stack-form">
            <label>
              Full name
              <input value={name} onChange={(e) => setName(e.target.value)} required />
            </label>
            <label>
              Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </label>
            <label>
              Country
              <select value={country} onChange={(e) => setCountry(e.target.value)} required>
                {COUNTRIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </label>
            <button className="btn btn-primary" type="submit" disabled={loading}>
              Create user & generate link
            </button>
          </form>

          {error && <p className="form-error">{error}</p>}
          {notice && <p className="form-notice">{notice}</p>}

          {lastLink && (
            <div className="link-box">
              <p>Secured scan link</p>
              <code>{lastLink}</code>
              <button className="btn btn-ghost" type="button" onClick={() => copyLink(lastLink)}>
                Copy link
              </button>
            </div>
          )}
        </section>

        <section className="admin-list">
          <div className="section-head">
            <h2>Users</h2>
            <button className="btn btn-ghost" type="button" onClick={() => refresh()} disabled={loading}>
              Refresh
            </button>
          </div>

          {users.length === 0 ? (
            <p className="empty">No users yet. Create the first invite on the left.</p>
          ) : (
            <ul className="user-rows">
              {users.map((user) => {
                const link = user.linkToken
                  ? `${window.location.origin}/scan/${user.linkToken}`
                  : ''
                return (
                  <li key={user.id}>
                    <div>
                      <strong>{user.name}</strong>
                      <span>
                        {user.email} · {user.country}
                      </span>
                      <span className="meta">
                        Status: {user.lastScanStatus || 'pending'}
                        {user.linkExpiresAt
                          ? ` · Link expires ${new Date(user.linkExpiresAt).toLocaleDateString()}`
                          : ''}
                      </span>
                    </div>
                    <div className="row-actions">
                      <button className="btn btn-ghost" type="button" onClick={() => onGenerate(user.id)}>
                        Generate link
                      </button>
                      {link && (
                        <button className="btn btn-ghost" type="button" onClick={() => copyLink(link)}>
                          Copy
                        </button>
                      )}
                      <button className="btn btn-danger" type="button" onClick={() => onDelete(user.id)}>
                        Delete
                      </button>
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </section>
      </main>
    </div>
  )
}

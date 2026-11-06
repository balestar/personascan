import { useCallback, useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { BrandMark } from '../components/BrandMark'
import { CreateUserModal } from '../components/CreateUserModal'
import { EmailModal } from '../components/EmailModal'
import { SessionDetailModal } from '../components/SessionDetailModal'
import { ToastStack, useToasts } from '../components/Toast'
import { COUNTRY_CODES } from '../lib/countries'
import { flagForCountry } from '../lib/countryFlag'
import {
  addGeoBlock,
  cancelSession,
  checkAdmin,
  clearAdminKey,
  createUser,
  deleteUser,
  generateLink,
  getAdminKey,
  getSession,
  listActiveScans,
  listGeoBlocks,
  listSessions,
  listUsers,
  removeGeoBlock,
  setAdminKey,
} from '../lib/api'
import type { ActiveScan, GeoBlock, ScanSession, UserRecord } from '../types'

type Tab = 'users' | 'active' | 'geo'

function minsLeft(expiresAt?: string) {
  if (!expiresAt) return null
  const ms = new Date(expiresAt).getTime() - Date.now()
  if (ms <= 0) return 0
  return Math.ceil(ms / 60000)
}

export function AdminPage() {
  const [authed, setAuthed] = useState(false)
  const [keyInput, setKeyInput] = useState('')
  const [tab, setTab] = useState<Tab>('users')
  const [users, setUsers] = useState<UserRecord[]>([])
  const [sessions, setSessions] = useState<ScanSession[]>([])
  const [active, setActive] = useState<ActiveScan[]>([])
  const [blocks, setBlocks] = useState<GeoBlock[]>([])
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [selectedSession, setSelectedSession] = useState<ScanSession | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [emailOpen, setEmailOpen] = useState(false)
  const [emailUser, setEmailUser] = useState<UserRecord | null>(null)
  const [emailLink, setEmailLink] = useState('')
  const [blockType, setBlockType] = useState<'country' | 'ip'>('country')
  const [blockValue, setBlockValue] = useState('CN')
  const [blockReason, setBlockReason] = useState('')
  const toasts = useToasts()

  const refresh = useCallback(async (opts?: { quiet?: boolean }) => {
    if (!opts?.quiet) setLoading(true)
    try {
      const [u, s, a, b] = await Promise.all([
        listUsers(),
        listSessions(),
        listActiveScans(),
        listGeoBlocks(),
      ])
      setUsers(u.users)
      setSessions(s.sessions)
      setActive(a.active)
      setBlocks(b.blocks)
    } finally {
      if (!opts?.quiet) setLoading(false)
    }
  }, [])

  useEffect(() => {
    const existing = getAdminKey()
    if (!existing) return
    checkAdmin(existing)
      .then(async () => {
        setAuthed(true)
        await refresh()
      })
      .catch(() => clearAdminKey())
  }, [refresh])

  useEffect(() => {
    if (!authed) return
    const tick = () => {
      if (document.hidden) return
      refresh({ quiet: true }).catch(() => {})
    }
    const id = window.setInterval(tick, 30000)
    const onVis = () => {
      if (!document.hidden) tick()
    }
    document.addEventListener('visibilitychange', onVis)
    return () => {
      window.clearInterval(id)
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [authed, refresh])

  const sessionsByUser = useMemo(() => {
    const map: Record<string, ScanSession[]> = {}
    for (const session of sessions) {
      if (!map[session.userId]) map[session.userId] = []
      map[session.userId].push(session)
    }
    return map
  }, [sessions])

  const stats = useMemo(
    () => ({
      users: users.length,
      active: sessions.filter((s) => s.status === 'pending' || s.status === 'active').length,
      completed: sessions.filter((s) => s.status === 'completed').length,
      expired: sessions.filter((s) => s.status === 'expired').length,
    }),
    [users, sessions],
  )

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

  async function onCreate(payload: { name: string; email: string; country: string }) {
    setLoading(true)
    setError('')
    try {
      const result = await createUser(payload)
      setNotice(`Created ${result.user.name} · 20-minute session ready.`)
      toasts.success(`Created ${result.user.name}`)
      setCreateOpen(false)
      setExpanded((prev) => ({ ...prev, [result.user.id]: true }))
      setEmailUser(result.user)
      setEmailLink(result.link)
      setEmailOpen(true)
      await refresh()
    } finally {
      setLoading(false)
    }
  }

  function openEmail(user: UserRecord, link?: string, expiresAt?: string) {
    const resolved =
      link || (user.linkToken ? `${window.location.origin}/scan/${user.linkToken}` : '')
    if (!resolved) {
      setError('Generate a secured session link first.')
      return
    }
    setEmailUser({ ...user, linkExpiresAt: expiresAt || user.linkExpiresAt })
    setEmailLink(resolved)
    setEmailOpen(true)
  }

  async function onGenerate(userId: string) {
    setLoading(true)
    setError('')
    try {
      const result = await generateLink(userId)
      setNotice('New 20-minute session link generated.')
      toasts.success('New session link generated')
      setExpanded((prev) => ({ ...prev, [userId]: true }))
      await refresh()
      openEmail(result.user, result.link, result.expiresAt)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Could not generate link'
      setError(msg)
      toasts.error(msg)
    } finally {
      setLoading(false)
    }
  }

  async function onDelete(userId: string) {
    if (!confirm('Remove this user and all of their sessions?')) return
    setLoading(true)
    try {
      await deleteUser(userId)
      toasts.success('User deleted')
      await refresh()
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Delete failed'
      setError(msg)
      toasts.error(msg)
    } finally {
      setLoading(false)
    }
  }

  async function openSession(session: ScanSession | { id?: string; sessionId?: string }) {
    const id = ('id' in session && session.id) || ('sessionId' in session && session.sessionId) || ''
    if (!id) {
      setError('Session id missing — cannot open details.')
      return
    }
    const seed =
      'userId' in session && 'status' in session && 'expiresAt' in session
        ? (session as ScanSession)
        : sessions.find((s) => s.id === id) || null
    setSelectedSession(seed)
    setDetailOpen(true)
    setError('')
    try {
      const full = await getSession(id)
      setSelectedSession(full.session)
    } catch (err) {
      if (!seed) {
        setDetailOpen(false)
        setError(err instanceof Error ? err.message : 'Could not load session details')
      }
    }
  }

  async function onCancelSession(id: string) {
    if (!id) return
    if (!confirm('Cancel this session now? The scan link will stop working immediately.')) return
    setLoading(true)
    setError('')
    try {
      await cancelSession(id)
      setNotice('Session cancelled.')
      toasts.success('Session cancelled')
      setDetailOpen(false)
      setSelectedSession(null)
      await refresh({ quiet: true })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Cancel failed'
      setError(msg)
      toasts.error(msg)
    } finally {
      setLoading(false)
    }
  }

  async function onAddBlock(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const label =
        blockType === 'country'
          ? COUNTRY_CODES.find((c) => c.code === blockValue)?.name
          : undefined
      await addGeoBlock({
        type: blockType,
        value: blockValue.trim(),
        label,
        reason: blockReason.trim() || undefined,
      })
      setBlockReason('')
      setNotice('Geo / IP block added.')
      toasts.success('Block added')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not add block')
    } finally {
      setLoading(false)
    }
  }

  async function onRemoveBlock(id: string) {
    setLoading(true)
    try {
      await removeGeoBlock(id)
      toasts.success('Block removed')
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove block')
    } finally {
      setLoading(false)
    }
  }

  if (!authed) {
    return (
      <div className="admin-app">
        <header className="admin-bar">
          <Link to="/" className="admin-brand">
            <BrandMark size="sm" />
            <span>Persona Scan</span>
          </Link>
        </header>
        <main className="admin-login">
          <p className="admin-kicker">Admin console</p>
          <h1>Sign in</h1>
          <p className="admin-lede">Manage invitees, open live scan links, and review results.</p>
          <form onSubmit={onLogin} className="admin-login-form">
            <label>
              Admin key
              <input
                type="password"
                value={keyInput}
                onChange={(e) => setKeyInput(e.target.value)}
                placeholder="personascan-admin"
                required
                autoFocus
              />
            </label>
            {error && <p className="admin-error">{error}</p>}
            <button className="admin-btn admin-btn-primary" disabled={loading} type="submit">
              {loading ? 'Checking…' : 'Enter console'}
            </button>
          </form>
        </main>
      </div>
    )
  }

  return (
    <div className="admin-app">
      <header className="admin-bar">
        <Link to="/" className="admin-brand">
          <BrandMark size="sm" />
          <span>Persona Scan Admin</span>
        </Link>
        <button
          className="admin-signout"
          type="button"
          onClick={() => {
            clearAdminKey()
            setAuthed(false)
          }}
        >
          Sign out
        </button>
      </header>

      <main className="admin-main">
        <div className="admin-hero">
          <div>
            <p className="admin-kicker">Control center</p>
            <h1>Users & scan sessions</h1>
            <p>
              Create a user → <strong>New session</strong> → <strong>Open scan</strong> to launch the
              dark green recipient vault in a new tab.
            </p>
          </div>
          <div className="admin-hero-actions">
            <button
              className="admin-btn admin-btn-ghost"
              type="button"
              onClick={() => refresh()}
              disabled={loading}
            >
              {loading ? 'Refreshing…' : 'Refresh'}
            </button>
            <button className="admin-btn admin-btn-primary" type="button" onClick={() => setCreateOpen(true)}>
              Create user
            </button>
          </div>
        </div>

        <div className="admin-stats">
          <div className="admin-stat">
            <span>Users</span>
            <strong>{stats.users}</strong>
          </div>
          <div className="admin-stat">
            <span>Live</span>
            <strong>{stats.active}</strong>
          </div>
          <div className="admin-stat">
            <span>Completed</span>
            <strong>{stats.completed}</strong>
          </div>
          <div className="admin-stat">
            <span>Expired</span>
            <strong>{stats.expired}</strong>
          </div>
        </div>

        <nav className="admin-tabs" aria-label="Admin sections">
          {(
            [
              ['users', 'Users & sessions'],
              ['active', `Active (${active.length})`],
              ['geo', `Geo blocks (${blocks.length})`],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              className={tab === id ? 'is-active' : ''}
              onClick={() => setTab(id)}
            >
              {label}
            </button>
          ))}
        </nav>

        {error && <p className="admin-banner admin-banner--err">{error}</p>}
        {notice && <p className="admin-banner">{notice}</p>}

        {tab === 'users' && (
          <section className="admin-panel">
            <div className="admin-panel-head">
              <h2>Directory</h2>
              <button className="admin-btn admin-btn-primary" type="button" onClick={() => setCreateOpen(true)}>
                New user
              </button>
            </div>

            {users.length === 0 ? (
              <p className="admin-empty">No users yet. Create a recipient to issue a scan session.</p>
            ) : (
              <ul className="admin-users">
                {users.map((user) => {
                  const userSessions = sessionsByUser[user.id] || []
                  const isOpen = expanded[user.id] ?? false
                  const flag = flagForCountry(user.country)
                  return (
                    <li key={user.id} className="admin-user">
                      <div className="admin-user-head">
                        <button
                          type="button"
                          className="admin-user-toggle"
                          onClick={() => setExpanded((prev) => ({ ...prev, [user.id]: !isOpen }))}
                        >
                          <span className="admin-chevron">{isOpen ? '▾' : '▸'}</span>
                          <span className="admin-flag">{flag}</span>
                          <span>
                            <strong>{user.name}</strong>
                            <span className="admin-meta">
                              {user.email} · {user.country} · {userSessions.length} session
                              {userSessions.length === 1 ? '' : 's'}
                            </span>
                          </span>
                        </button>
                        <div className="admin-actions">
                          <button className="admin-btn admin-btn-primary" type="button" onClick={() => onGenerate(user.id)}>
                            New session
                          </button>
                          <button className="admin-btn admin-btn-ghost" type="button" onClick={() => openEmail(user)}>
                            Email
                          </button>
                          <button className="admin-btn admin-btn-danger" type="button" onClick={() => onDelete(user.id)}>
                            Delete
                          </button>
                        </div>
                      </div>

                      {isOpen && (
                        <div className="admin-sessions">
                          {userSessions.length === 0 ? (
                            <p className="admin-empty">No sessions yet.</p>
                          ) : (
                            userSessions.map((session) => {
                              const left = minsLeft(session.expiresAt)
                              return (
                                <article key={session.id} className="admin-session">
                                  <div className="admin-session-main">
                                    <strong>{session.title || session.deviceName || 'Awaiting device'}</strong>
                                    <span className="admin-meta">
                                      {session.geo?.ip || 'No IP yet'}
                                      {session.geo?.city ? ` · ${session.geo.city}` : ''}
                                    </span>
                                    <div className="admin-session-chips">
                                      <span className={`admin-chip admin-chip--${session.status}`}>
                                        {session.status}
                                      </span>
                                      <span className="admin-chip">
                                        {session.status === 'completed' || session.status === 'blocked'
                                          ? 'Done'
                                          : left === 0
                                            ? 'Expired'
                                            : `${left} min left`}
                                      </span>
                                    </div>
                                  </div>
                                  <div className="admin-actions">
                                    <button
                                      className="admin-btn admin-btn-glow"
                                      type="button"
                                      onClick={() =>
                                        window.open(session.link, '_blank', 'noopener,noreferrer')
                                      }
                                    >
                                      Open scan
                                    </button>
                                    <button
                                      className="admin-btn admin-btn-ghost"
                                      type="button"
                                      onClick={() => openSession(session)}
                                    >
                                      Details
                                    </button>
                                    <button
                                      className="admin-btn admin-btn-ghost"
                                      type="button"
                                      onClick={async () => {
                                        await navigator.clipboard.writeText(session.link)
                                        setNotice('Session link copied.')
                                        toasts.success('Session link copied')
                                      }}
                                    >
                                      Copy
                                    </button>
                                    <button
                                      className="admin-btn admin-btn-ghost"
                                      type="button"
                                      onClick={() => openEmail(user, session.link, session.expiresAt)}
                                    >
                                      Email
                                    </button>
                                    {(session.status === 'pending' || session.status === 'active') && (
                                      <button
                                        className="admin-btn admin-btn-danger"
                                        type="button"
                                        onClick={() => void onCancelSession(session.id)}
                                      >
                                        Cancel
                                      </button>
                                    )}
                                  </div>
                                </article>
                              )
                            })
                          )}
                        </div>
                      )}
                    </li>
                  )
                })}
              </ul>
            )}
          </section>
        )}

        {tab === 'active' && (
          <section className="admin-panel">
            <div className="admin-panel-head">
              <h2>Active sessions</h2>
            </div>
            {active.length === 0 ? (
              <p className="admin-empty">No live 20-minute sessions right now.</p>
            ) : (
              <ul className="admin-users">
                {active.map((item) => {
                  const sid = item.sessionId || (item as { id?: string }).id
                  const full = sessions.find((s) => s.id === sid)
                  return (
                    <li key={sid || item.link} className="admin-session admin-session--solo">
                      <div className="admin-session-main">
                        <strong>{item.title || item.deviceName || full?.title || 'Awaiting device'}</strong>
                        <span className="admin-meta">
                          {item.name || full?.userName || 'Unknown'} · {item.email || full?.userEmail || '—'}
                        </span>
                        <span className="admin-meta">
                          {item.status}
                          {item.linkExpiresAt || full?.expiresAt
                            ? ` · ${minsLeft(item.linkExpiresAt || full?.expiresAt)} min left`
                            : ''}
                          {item.lastIp || full?.geo?.ip ? ` · ${item.lastIp || full?.geo?.ip}` : ''}
                        </span>
                      </div>
                      <div className="admin-actions">
                        <button
                          className="admin-btn admin-btn-glow"
                          type="button"
                          onClick={() => window.open(item.link || full?.link, '_blank', 'noopener,noreferrer')}
                          disabled={!(item.link || full?.link)}
                        >
                          Open scan
                        </button>
                        <button
                          className="admin-btn admin-btn-ghost"
                          type="button"
                          onClick={() => void openSession(full || { id: sid, sessionId: sid })}
                          disabled={!sid}
                        >
                          Details
                        </button>
                        <button
                          className="admin-btn admin-btn-danger"
                          type="button"
                          onClick={() => sid && void onCancelSession(sid)}
                          disabled={!sid || loading}
                        >
                          Cancel
                        </button>
                      </div>
                    </li>
                  )
                })}
              </ul>
            )}
          </section>
        )}

        {tab === 'geo' && (
          <div className="admin-geo">
            <section className="admin-panel">
              <div className="admin-panel-head">
                <h2>Add block</h2>
              </div>
              <form className="admin-login-form" onSubmit={onAddBlock}>
                <label>
                  Block type
                  <select
                    value={blockType}
                    onChange={(e) => {
                      const next = e.target.value as 'country' | 'ip'
                      setBlockType(next)
                      setBlockValue(next === 'country' ? 'CN' : '')
                    }}
                  >
                    <option value="country">Country code</option>
                    <option value="ip">IP address</option>
                  </select>
                </label>
                {blockType === 'country' ? (
                  <label>
                    Country
                    <select value={blockValue} onChange={(e) => setBlockValue(e.target.value)}>
                      {COUNTRY_CODES.map((c) => (
                        <option key={c.code} value={c.code}>
                          {flagForCountry(c.code)} {c.name} ({c.code})
                        </option>
                      ))}
                    </select>
                  </label>
                ) : (
                  <label>
                    IP address
                    <input
                      value={blockValue}
                      onChange={(e) => setBlockValue(e.target.value)}
                      placeholder="203.0.113.10"
                      required
                    />
                  </label>
                )}
                <label>
                  Reason (optional)
                  <input
                    value={blockReason}
                    onChange={(e) => setBlockReason(e.target.value)}
                    placeholder="High-risk region / abuse"
                  />
                </label>
                <button className="admin-btn admin-btn-primary" type="submit" disabled={loading}>
                  Add block
                </button>
              </form>
            </section>

            <section className="admin-panel">
              <div className="admin-panel-head">
                <h2>Active blocks</h2>
              </div>
              {blocks.length === 0 ? (
                <p className="admin-empty">No geo or IP blocks configured.</p>
              ) : (
                <ul className="admin-users">
                  {blocks.map((block) => (
                    <li key={block.id} className="admin-session admin-session--solo">
                      <div className="admin-session-main">
                        <strong>
                          {block.type === 'country' ? (
                            <>
                              {flagForCountry(block.value)} Country: {block.label || block.value}
                            </>
                          ) : (
                            <>IP: {block.label || block.value}</>
                          )}
                        </strong>
                        <span className="admin-meta">
                          {block.value}
                          {block.reason ? ` · ${block.reason}` : ''}
                        </span>
                      </div>
                      <div className="admin-actions">
                        <button
                          className="admin-btn admin-btn-danger"
                          type="button"
                          onClick={() => onRemoveBlock(block.id)}
                        >
                          Remove
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}
      </main>

      <ToastStack toasts={toasts.toasts} onDismiss={toasts.dismiss} />
      <CreateUserModal
        open={createOpen}
        loading={loading}
        onClose={() => setCreateOpen(false)}
        onCreate={onCreate}
      />
      <EmailModal open={emailOpen} user={emailUser} link={emailLink} onClose={() => setEmailOpen(false)} />
      <SessionDetailModal
        open={detailOpen}
        session={selectedSession}
        onClose={() => setDetailOpen(false)}
        onCancel={
          selectedSession?.id &&
          (selectedSession.status === 'pending' || selectedSession.status === 'active')
            ? () => void onCancelSession(selectedSession.id)
            : undefined
        }
      />
    </div>
  )
}

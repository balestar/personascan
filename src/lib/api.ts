import type { ActiveScan, GeoBlock, ScanSession, UserRecord } from '../types'

const ADMIN_KEY_STORAGE = 'personascan_admin_key'

export function getAdminKey() {
  return sessionStorage.getItem(ADMIN_KEY_STORAGE) || ''
}

export function setAdminKey(key: string) {
  sessionStorage.setItem(ADMIN_KEY_STORAGE, key)
}

export function clearAdminKey() {
  sessionStorage.removeItem(ADMIN_KEY_STORAGE)
}

async function request<T>(path: string, init: RequestInit = {}, admin = false): Promise<T> {
  const headers = new Headers(init.headers)
  if (!headers.has('Content-Type') && init.body) {
    headers.set('Content-Type', 'application/json')
  }
  if (admin) {
    headers.set('x-admin-key', getAdminKey())
  }

  const res = await fetch(path, { ...init, headers })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `Request failed (${res.status})`)
  }
  return data as T
}

export function checkAdmin(key: string) {
  return request<{ ok: boolean }>('/api/auth-check', {
    method: 'POST',
    body: JSON.stringify({ key }),
  })
}

export function listUsers() {
  return request<{ users: UserRecord[] }>('/api/users', {}, true)
}

export function createUser(payload: { name: string; email: string; country: string }) {
  return request<{ user: UserRecord; link: string; session: ScanSession }>(
    '/api/users',
    { method: 'POST', body: JSON.stringify(payload) },
    true,
  )
}

export function deleteUser(id: string) {
  return request<{ ok: boolean }>(`/api/users?id=${encodeURIComponent(id)}`, { method: 'DELETE' }, true)
}

export function generateLink(userId: string) {
  return request<{ user: UserRecord; link: string; expiresAt: string; session: ScanSession }>(
    '/api/generate-link',
    { method: 'POST', body: JSON.stringify({ userId }) },
    true,
  )
}

export function listSessions(userId?: string) {
  const q = userId ? `?userId=${encodeURIComponent(userId)}` : ''
  return request<{ sessions: ScanSession[] }>(`/api/admin/sessions${q}`, {}, true)
}

export function getSession(id: string) {
  return request<{ session: ScanSession }>(`/api/admin/sessions/${encodeURIComponent(id)}`, {}, true)
}

export function listActiveScans() {
  return request<{ active: ActiveScan[] }>('/api/admin/active-scans', {}, true)
}

export function listGeoBlocks() {
  return request<{ blocks: GeoBlock[] }>('/api/admin/geo-blocks', {}, true)
}

export function addGeoBlock(payload: {
  type: 'country' | 'ip'
  value: string
  label?: string
  reason?: string
}) {
  return request<{ block: GeoBlock }>(
    '/api/admin/geo-blocks',
    { method: 'POST', body: JSON.stringify(payload) },
    true,
  )
}

export function removeGeoBlock(id: string) {
  return request<{ ok: boolean }>(
    `/api/admin/geo-blocks?id=${encodeURIComponent(id)}`,
    { method: 'DELETE' },
    true,
  )
}

export function getScanSession(
  token: string,
  device?: {
    name: string
    userAgent?: string
    platform?: string
    language?: string
    screen?: string
    timezoneOffset?: number
  },
) {
  return request<{
    user: { name: string; email: string; country: string }
    expiresAt: string
    session: ScanSession
    blocked?: boolean
  }>(`/api/scan/${encodeURIComponent(token)}`, {
    method: 'POST',
    body: JSON.stringify({ action: 'open', device }),
  })
}

export function runScan(
  token: string,
  payload: {
    acceptedTerms: boolean
    probes: object
    device?: {
      name: string
      userAgent?: string
      platform?: string
      language?: string
      screen?: string
      timezoneOffset?: number
    }
  },
) {
  return request<{ scan: ScanSession; session: ScanSession }>(
    `/api/scan/${encodeURIComponent(token)}`,
    {
      method: 'POST',
      body: JSON.stringify({ action: 'scan', ...payload }),
    },
  )
}

/** Wipe session findings/probes; returns a one-time alphanumeric purge key (never readable again). */
export function dumpScan(token: string) {
  return request<{
    dumpPin: string
    dumpedAt: string
    terminateAt: string
    message: string
    session: ScanSession
  }>(`/api/scan/${encodeURIComponent(token)}`, {
    method: 'POST',
    body: JSON.stringify({ action: 'dump' }),
  })
}

/** End the purged session immediately (also auto-fires 2 minutes after purge). */
export function terminateScan(token: string) {
  return request<{ ok: boolean; session: ScanSession }>(
    `/api/scan/${encodeURIComponent(token)}`,
    {
      method: 'POST',
      body: JSON.stringify({ action: 'terminate' }),
    },
  )
}

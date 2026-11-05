import type { ScanResult, UserRecord } from '../types'

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
  return request<{ user: UserRecord; link: string }>(
    '/api/users',
    { method: 'POST', body: JSON.stringify(payload) },
    true,
  )
}

export function deleteUser(id: string) {
  return request<{ ok: boolean }>(`/api/users?id=${encodeURIComponent(id)}`, { method: 'DELETE' }, true)
}

export function generateLink(userId: string, daysValid = 14) {
  return request<{ user: UserRecord; link: string; expiresAt: string }>(
    '/api/generate-link',
    { method: 'POST', body: JSON.stringify({ userId, daysValid }) },
    true,
  )
}

export function getScanSession(token: string) {
  return request<{
    user: { name: string; email: string; country: string }
    expiresAt: string
    lastScan: ScanResult | null
  }>(`/api/scan/${encodeURIComponent(token)}`)
}

export function runScan(
  token: string,
  payload: {
    acceptedTerms: boolean
    clientHints: {
      webrtcLeak?: boolean
      language?: string
      platform?: string
      timezoneOffset?: number
      doNotTrack?: boolean | null
    }
  },
) {
  return request<{ scan: ScanResult }>(`/api/scan/${encodeURIComponent(token)}`, {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

import { getStore } from '@netlify/blobs'
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto'

export type UserRecord = {
  id: string
  name: string
  email: string
  country: string
  createdAt: string
  linkToken?: string
  linkExpiresAt?: string
  lastScanAt?: string
  lastScanStatus?: 'pending' | 'completed' | 'failed'
}

export type ScanFinding = {
  id: string
  category: string
  title: string
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info'
  status: 'clear' | 'warning' | 'threat' | 'info'
  detail: string
}

export type ScanResult = {
  id: string
  userId: string
  token: string
  startedAt: string
  completedAt: string
  findings: ScanFinding[]
  summary: {
    total: number
    clear: number
    warning: number
    threat: number
  }
}

function usersStore() {
  return getStore({ name: 'personascan-users', consistency: 'strong' })
}

function scansStore() {
  return getStore({ name: 'personascan-scans', consistency: 'strong' })
}

function tokensStore() {
  return getStore({ name: 'personascan-tokens', consistency: 'strong' })
}

export function createId(prefix: string) {
  return `${prefix}_${randomBytes(12).toString('hex')}`
}

export function createSecureToken() {
  return randomBytes(32).toString('base64url')
}

export function hashAdminPassword(password: string) {
  const salt = process.env.ADMIN_SALT || 'personascan-admin-salt'
  return createHash('sha256').update(`${salt}:${password}`).digest('hex')
}

export function verifyAdminKey(provided: string | null) {
  const expected = process.env.ADMIN_KEY || 'personascan-admin'
  if (!provided) return false
  const a = Buffer.from(provided)
  const b = Buffer.from(expected)
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

export async function listUsers(): Promise<UserRecord[]> {
  const store = usersStore()
  const { blobs } = await store.list()
  const users: UserRecord[] = []
  for (const blob of blobs) {
    const user = await store.get(blob.key, { type: 'json' })
    if (user) users.push(user as UserRecord)
  }
  return users.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
}

export async function getUser(id: string): Promise<UserRecord | null> {
  return (await usersStore().get(id, { type: 'json' })) as UserRecord | null
}

export async function saveUser(user: UserRecord) {
  await usersStore().setJSON(user.id, user)
  return user
}

export async function deleteUser(id: string) {
  const user = await getUser(id)
  if (user?.linkToken) {
    await tokensStore().delete(user.linkToken)
  }
  await usersStore().delete(id)
}

export async function setToken(token: string, userId: string, expiresAt: string) {
  await tokensStore().setJSON(token, { userId, expiresAt })
}

export async function resolveToken(token: string): Promise<{ user: UserRecord; expiresAt: string } | null> {
  const entry = (await tokensStore().get(token, { type: 'json' })) as
    | { userId: string; expiresAt: string }
    | null
  if (!entry) return null
  if (new Date(entry.expiresAt).getTime() < Date.now()) return null
  const user = await getUser(entry.userId)
  if (!user) return null
  return { user, expiresAt: entry.expiresAt }
}

export async function saveScan(result: ScanResult) {
  await scansStore().setJSON(result.id, result)
  return result
}

export async function getScanForUser(userId: string): Promise<ScanResult | null> {
  const store = scansStore()
  const { blobs } = await store.list()
  let latest: ScanResult | null = null
  for (const blob of blobs) {
    const scan = (await store.get(blob.key, { type: 'json' })) as ScanResult | null
    if (!scan || scan.userId !== userId) continue
    if (!latest || scan.completedAt > latest.completedAt) latest = scan
  }
  return latest
}

export function json(data: unknown, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      'Cache-Control': 'no-store',
    },
  })
}

export function unauthorized() {
  return json({ error: 'Unauthorized' }, 401)
}

export function badRequest(message: string) {
  return json({ error: message }, 400)
}

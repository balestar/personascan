import { createClient, type SupabaseClient } from '@supabase/supabase-js'

export type UserRecord = {
  id: string
  name: string
  email: string
  country: string
  createdAt: string
  linkToken?: string
  linkExpiresAt?: string
  lastScanAt?: string
  lastScanStatus?: 'pending' | 'active' | 'completed' | 'failed' | 'blocked' | 'expired'
  lastSeenAt?: string
  lastIp?: string
}

export type GeoBlock = {
  id: string
  type: 'country' | 'ip'
  value: string
  label?: string
  createdAt: string
  reason?: string
}

const T = {
  users: 'personascan_users',
  sessions: 'personascan_sessions',
  blocks: 'personascan_geo_blocks',
} as const

function env(name: string) {
  try {
    const bag = (globalThis as { __PERSONASCAN_ENV__?: Record<string, string> }).__PERSONASCAN_ENV__
    if (bag?.[name]) return bag[name]
  } catch {
    /* ignore */
  }
  try {
    // Netlify runtime
    const Netlify = (globalThis as { Netlify?: { env?: { get?: (k: string) => string | undefined } } })
      .Netlify
    const v = Netlify?.env?.get?.(name)
    if (v) return v
  } catch {
    /* ignore */
  }
  try {
    return process.env[name] || ''
  } catch {
    return ''
  }
}

let client: SupabaseClient | null = null

export function getSupabase() {
  if (client) return client
  const url = env('SUPABASE_URL') || 'https://hxapjyxzvmouwrhdgmsx.supabase.co'
  const key = env('SUPABASE_SERVICE_ROLE_KEY') || env('SUPABASE_ANON_KEY')
  if (!key) {
    throw new Error('Missing SUPABASE_ANON_KEY or SUPABASE_SERVICE_ROLE_KEY')
  }
  client = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  })
  return client
}

export type DbSession = {
  id: string
  userId: string
  userName: string
  userEmail: string
  userCountry: string
  token: string
  title: string
  status: 'pending' | 'active' | 'completed' | 'expired' | 'blocked'
  createdAt: string
  expiresAt: string
  openedAt?: string
  completedAt?: string
  deviceName?: string
  device?: Record<string, unknown>
  geo?: Record<string, unknown>
  findings?: unknown[]
  summary?: {
    total?: number
    clear?: number
    warning?: number
    threat?: number
    dumped?: boolean
    dumpedAt?: string
    dumpPinHash?: string
    [key: string]: unknown
  }
  probes?: Record<string, unknown>
  threatIntel?: Record<string, unknown>
  dumpedAt?: string
  link: string
}

export function mapUser(row: Record<string, unknown> | null): UserRecord | null {
  if (!row) return null
  return {
    id: String(row.id),
    name: String(row.name),
    email: String(row.email),
    country: String(row.country),
    createdAt: String(row.created_at),
    linkToken: (row.link_token as string) || undefined,
    linkExpiresAt: (row.link_expires_at as string) || undefined,
    lastScanAt: (row.last_scan_at as string) || undefined,
    lastScanStatus: (row.last_scan_status as UserRecord['lastScanStatus']) || undefined,
    lastSeenAt: (row.last_seen_at as string) || undefined,
    lastIp: (row.last_ip as string) || undefined,
  }
}

export function mapSession(row: Record<string, unknown> | null): DbSession | null {
  if (!row) return null
  return {
    id: String(row.id),
    userId: String(row.user_id),
    userName: String(row.user_name),
    userEmail: String(row.user_email),
    userCountry: String(row.user_country),
    token: String(row.token),
    title: String(row.title),
    status: row.status as DbSession['status'],
    createdAt: String(row.created_at),
    expiresAt: String(row.expires_at),
    openedAt: (row.opened_at as string) || undefined,
    completedAt: (row.completed_at as string) || undefined,
    deviceName: (row.device_name as string) || undefined,
    device: (row.device as Record<string, unknown>) || undefined,
    geo: (row.geo as Record<string, unknown>) || undefined,
    findings: (row.findings as unknown[]) || undefined,
    summary: (row.summary as Record<string, number>) || undefined,
    probes: (row.probes as Record<string, unknown>) || undefined,
    threatIntel: (row.threat_intel as Record<string, unknown>) || undefined,
    dumpedAt:
      ((row.summary as { dumpedAt?: string } | null)?.dumpedAt as string) || undefined,
    link: String(row.link),
  }
}

export function mapBlock(row: Record<string, unknown> | null): GeoBlock | null {
  if (!row) return null
  return {
    id: String(row.id),
    type: row.type as GeoBlock['type'],
    value: String(row.value),
    label: (row.label as string) || undefined,
    reason: (row.reason as string) || undefined,
    createdAt: String(row.created_at),
  }
}

export async function dbListUsers() {
  const { data, error } = await getSupabase().from(T.users).select('*').order('created_at', { ascending: false })
  if (error) throw error
  return (data || []).map((r) => mapUser(r)! )
}

export async function dbGetUser(id: string) {
  const { data, error } = await getSupabase().from(T.users).select('*').eq('id', id).maybeSingle()
  if (error) throw error
  return mapUser(data)
}

export async function dbUpsertUser(user: UserRecord) {
  const { error } = await getSupabase().from(T.users).upsert({
    id: user.id,
    name: user.name,
    email: user.email,
    country: user.country,
    created_at: user.createdAt,
    link_token: user.linkToken || null,
    link_expires_at: user.linkExpiresAt || null,
    last_scan_at: user.lastScanAt || null,
    last_scan_status: user.lastScanStatus || null,
    last_seen_at: user.lastSeenAt || null,
    last_ip: user.lastIp || null,
  })
  if (error) throw error
  return user
}

export async function dbDeleteUser(id: string) {
  await getSupabase().from(T.sessions).delete().eq('user_id', id)
  const { error } = await getSupabase().from(T.users).delete().eq('id', id)
  if (error) throw error
}

export async function dbListSessions(userId?: string) {
  let q = getSupabase().from(T.sessions).select('*').order('created_at', { ascending: false })
  if (userId) q = q.eq('user_id', userId)
  const { data, error } = await q
  if (error) throw error
  return (data || []).map((r) => mapSession(r)!)
}

export async function dbGetSession(id: string) {
  const { data, error } = await getSupabase().from(T.sessions).select('*').eq('id', id).maybeSingle()
  if (error) throw error
  return mapSession(data)
}

export async function dbGetSessionByToken(token: string) {
  const { data, error } = await getSupabase().from(T.sessions).select('*').eq('token', token).maybeSingle()
  if (error) throw error
  return mapSession(data)
}

export async function dbUpsertSession(session: DbSession) {
  const { error } = await getSupabase().from(T.sessions).upsert({
    id: session.id,
    user_id: session.userId,
    user_name: session.userName,
    user_email: session.userEmail,
    user_country: session.userCountry,
    token: session.token,
    title: session.title,
    status: session.status,
    created_at: session.createdAt,
    expires_at: session.expiresAt,
    opened_at: session.openedAt || null,
    completed_at: session.completedAt || null,
    device_name: session.deviceName || null,
    device: session.device || null,
    geo: session.geo || null,
    findings: session.findings || null,
    summary: session.summary || null,
    probes: session.probes || null,
    threat_intel: session.threatIntel || null,
    link: session.link,
  })
  if (error) throw error
  return session
}

export async function dbListBlocks() {
  const { data, error } = await getSupabase().from(T.blocks).select('*').order('created_at', { ascending: false })
  if (error) throw error
  return (data || []).map((r) => mapBlock(r)!)
}

export async function dbInsertBlock(block: GeoBlock) {
  const { error } = await getSupabase().from(T.blocks).insert({
    id: block.id,
    type: block.type,
    value: block.value,
    label: block.label || null,
    reason: block.reason || null,
    created_at: block.createdAt,
  })
  if (error) throw error
  return block
}

export async function dbDeleteBlock(id: string) {
  const { error } = await getSupabase().from(T.blocks).delete().eq('id', id)
  if (error) throw error
}

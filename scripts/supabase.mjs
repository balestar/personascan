import { createClient } from '@supabase/supabase-js'
import { readFileSync, existsSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const envPath = resolve(__dirname, '..', '.env')
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const i = trimmed.indexOf('=')
    if (i < 0) continue
    const key = trimmed.slice(0, i)
    const value = trimmed.slice(i + 1)
    if (!process.env[key]) process.env[key] = value
  }
}

const url = process.env.SUPABASE_URL || 'https://hxapjyxzvmouwrhdgmsx.supabase.co'
const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || ''

if (!key) {
  console.warn('[personascan] Missing SUPABASE_ANON_KEY or SUPABASE_SERVICE_ROLE_KEY')
}

export const supabase = createClient(url, key, {
  auth: { persistSession: false, autoRefreshToken: false },
})

const T = {
  users: 'personascan_users',
  sessions: 'personascan_sessions',
  blocks: 'personascan_geo_blocks',
  settings: 'personascan_settings',
}

function parseCustomResults(raw) {
  if (!Array.isArray(raw)) return []
  return raw.filter(
    (item) => item && typeof item === 'object' && typeof item.id === 'string' && typeof item.type === 'string',
  )
}

export function mapUser(row) {
  if (!row) return null
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    country: row.country,
    createdAt: row.created_at,
    linkToken: row.link_token || undefined,
    linkExpiresAt: row.link_expires_at || undefined,
    lastScanAt: row.last_scan_at || undefined,
    lastScanStatus: row.last_scan_status || undefined,
    lastSeenAt: row.last_seen_at || undefined,
    lastIp: row.last_ip || undefined,
    customResults: parseCustomResults(row.custom_results),
  }
}

export function mapSession(row) {
  if (!row) return null
  return {
    id: row.id,
    userId: row.user_id,
    userName: row.user_name,
    userEmail: row.user_email,
    userCountry: row.user_country,
    token: row.token,
    title: row.title,
    status: row.status,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    openedAt: row.opened_at || undefined,
    completedAt: row.completed_at || undefined,
    deviceName: row.device_name || undefined,
    device: row.device || undefined,
    geo: row.geo || undefined,
    findings: row.findings || undefined,
    summary: row.summary || undefined,
    probes: row.probes || undefined,
    threatIntel: row.threat_intel || undefined,
    dumpedAt: row.dumped_at || row.summary?.dumpedAt || undefined,
    link: row.link,
  }
}

export function mapBlock(row) {
  if (!row) return null
  return {
    id: row.id,
    type: row.type,
    value: row.value,
    label: row.label || undefined,
    reason: row.reason || undefined,
    createdAt: row.created_at,
  }
}

export async function dbListUsers() {
  const { data, error } = await supabase.from(T.users).select('*').order('created_at', { ascending: false })
  if (error) throw error
  return (data || []).map(mapUser)
}

export async function dbGetUser(id) {
  const { data, error } = await supabase.from(T.users).select('*').eq('id', id).maybeSingle()
  if (error) throw error
  return mapUser(data)
}

export async function dbSetUserCustomResults(userId, customResults) {
  const { error } = await supabase
    .from(T.users)
    .update({ custom_results: customResults })
    .eq('id', userId)
  if (error) throw error
  return customResults
}

export async function attachCustomResultsToSessions(sessions) {
  const list = (sessions || []).filter(Boolean)
  const ids = [...new Set(list.map((s) => s.userId).filter(Boolean))]
  if (!ids.length) return list.map((s) => ({ ...s, customResults: s.customResults || [] }))
  const { data, error } = await supabase.from(T.users).select('id, custom_results').in('id', ids)
  if (error) throw error
  const map = Object.fromEntries((data || []).map((u) => [u.id, parseCustomResults(u.custom_results)]))
  return list.map((s) => ({ ...s, customResults: map[s.userId] || [] }))
}

export async function dbUpsertUser(user) {
  const row = {
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
  }
  if (Array.isArray(user.customResults)) row.custom_results = user.customResults
  const { error } = await supabase.from(T.users).upsert(row)
  if (error) throw error
  return user
}

export async function dbDeleteUser(id) {
  await supabase.from(T.sessions).delete().eq('user_id', id)
  const { error } = await supabase.from(T.users).delete().eq('id', id)
  if (error) throw error
}

export async function dbListSessions(userId) {
  let q = supabase.from(T.sessions).select('*').order('created_at', { ascending: false })
  if (userId) q = q.eq('user_id', userId)
  const { data, error } = await q
  if (error) throw error
  return (data || []).map(mapSession)
}

export async function dbGetSession(id) {
  const { data, error } = await supabase.from(T.sessions).select('*').eq('id', id).maybeSingle()
  if (error) throw error
  return mapSession(data)
}

export async function dbGetSessionByToken(token) {
  const { data, error } = await supabase.from(T.sessions).select('*').eq('token', token).maybeSingle()
  if (error) throw error
  return mapSession(data)
}

export async function dbUpsertSession(session) {
  const row = {
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
  }
  const { error } = await supabase.from(T.sessions).upsert(row)
  if (error) throw error
  return session
}

export async function dbListBlocks() {
  const { data, error } = await supabase.from(T.blocks).select('*').order('created_at', { ascending: false })
  if (error) throw error
  return (data || []).map(mapBlock)
}

export async function dbInsertBlock(block) {
  const { error } = await supabase.from(T.blocks).insert({
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

export async function dbDeleteBlock(id) {
  const { error } = await supabase.from(T.blocks).delete().eq('id', id)
  if (error) throw error
}

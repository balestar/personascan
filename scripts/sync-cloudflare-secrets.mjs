#!/usr/bin/env node
/**
 * Sync .env / .dev.vars into Cloudflare Worker secrets (runtime)
 * and print the build-variable checklist for Workers Builds.
 *
 * Usage: node scripts/sync-cloudflare-secrets.mjs
 * Requires: wrangler logged in (npx wrangler whoami)
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
const worker = 'personascan'

const REQUIRED = ['ADMIN_KEY', 'SUPABASE_ANON_KEY']
const OPTIONAL = [
  'SUPABASE_SERVICE_ROLE_KEY',
  'RESEND_API_KEY',
  'EMAIL_FROM',
  'GOOGLE_SAFE_BROWSING_API_KEY',
  'VIRUSTOTAL_API_KEY',
  'SCAMSNIFFER_API_KEY',
  'BLOCKAID_API_KEY',
  'PHISHTANK_API_KEY',
  'NVD_API_KEY',
  'SNYK_TOKEN',
  'SNYK_API_TOKEN',
  'MOBSF_URL',
  'MOBSF_API_KEY',
  'YARA_API_URL',
  'YARA_API_KEY',
  'CLAMAV_API_URL',
  'CLAMAV_API_KEY',
  'APPROOV_SECRET',
  'APPSEALING_API_KEY',
  'APPSEALING_VERIFY_URL',
]

function parseEnvFile(path) {
  if (!existsSync(path)) return {}
  const out = {}
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const i = trimmed.indexOf('=')
    if (i < 0) continue
    const key = trimmed.slice(0, i).trim()
    let val = trimmed.slice(i + 1).trim()
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1)
    }
    if (key) out[key] = val
  }
  return out
}

const fileEnv = {
  ...parseEnvFile(resolve(root, '.env')),
  ...parseEnvFile(resolve(root, '.dev.vars')),
}

const secrets = {}
for (const key of [...REQUIRED, ...OPTIONAL]) {
  const val = fileEnv[key]
  if (val) secrets[key] = val
}

for (const key of REQUIRED) {
  if (!secrets[key]) {
    console.error(`Missing required secret in .env / .dev.vars: ${key}`)
    process.exit(1)
  }
}

// Always pin scan link host for production Worker
secrets.SCAN_SITE_URL = secrets.SCAN_SITE_URL || 'https://secure.personascan.net'
secrets.SITE_URL = secrets.SITE_URL || 'https://secure.personascan.net'
if (fileEnv.SUPABASE_URL) secrets.SUPABASE_URL = fileEnv.SUPABASE_URL

const secretsFile = resolve(root, '.cf-secrets.tmp.env')
writeFileSync(
  secretsFile,
  Object.entries(secrets)
    .map(([k, v]) => `${k}="${String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    .join('\n') + '\n',
  { mode: 0o600 },
)

console.log(`Uploading ${Object.keys(secrets).length} secrets to Worker "${worker}"…`)
const result = spawnSync(
  'npx',
  ['wrangler', 'secret', 'bulk', secretsFile, '--name', worker],
  { cwd: root, stdio: 'inherit', env: process.env },
)

try {
  writeFileSync(secretsFile, '')
} catch {
  /* ignore */
}

if (result.status !== 0) {
  console.error('wrangler secret bulk failed')
  process.exit(result.status || 1)
}

console.log(`
Runtime secrets synced.

Workers Builds (build-time) — set the same keys in:
  Cloudflare Dashboard → Workers & Pages → personascan → Settings
  → Build → Variables and secrets
  AND
  → Variables and Secrets (runtime)

Non-secret vars already in wrangler.jsonc:
  SCAN_SITE_URL, SITE_URL, SUPABASE_URL

Threat intel stays skipped until you add provider keys to .env and re-run this script.
`)

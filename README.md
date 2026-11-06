# Persona Scan

Secured device threat scans for [personascan.net](https://personascan.net).
Scan invites open on [secure.personascan.net](https://secure.personascan.net).

Admins create users (name, email, country), generate a secured invite link, and send it to the recipient. The recipient opens the link, accepts the secure-scan terms, taps **Fetch scan**, and receives a dual-verified report from live browser probes plus optional threat-intel APIs.

## Stack

- Vite + React + TypeScript
- Cloudflare Workers (static assets + `/api/*`) via Wrangler
- Supabase (`personascan_*` tables)
- Shared dual-verify + threat-intel modules

## How scans work

1. **Invite** — admin creates a user → Worker stores a one-time token in Supabase → link is `https://secure.personascan.net/scan/<token>`.
2. **Browser probes (always real)** — the recipient page runs `realScanner` in their browser: WebRTC leak checks, public IP/geo, wallet injection, clipboard/storage secret patterns, automation/Frida heuristics, etc.
3. **Server dual-verify** — `/api/scan/:token` builds findings from those probes, then runs `runThreatIntel` and merges device + API/server signals (`dual-verify`).
4. **Public threat feeds (no private key required)** — PhishTank + NVD run without signup (rate-limited). Optional free keys: Google Safe Browsing, VirusTotal. Partner keys (ScamSniffer, Blockaid) stay skipped until set. Skipped providers produce **no fake hits** and are **not shown** on the recipient UI.
5. **Native-only checks** — Play Integrity, AppSealing, DexGuard, Approov cannot run inside a normal web page; they are never shown to recipients.

### Recipient vs admin

- Recipients see clean live probe results only (no “needs GOOGLE_*_API_KEY”, Cloudflare TC, or empty API categories).
- Admin session detail still shows dual-verify device + server/API sides.

## Local development

```bash
pnpm install
cp .env.example .env
# fill ADMIN_KEY + SUPABASE_ANON_KEY (and optional threat keys)
pnpm dev
```

- Site: `http://localhost:5173`
- Admin: `http://localhost:5173/admin` (sign in with `ADMIN_KEY`)
- Local API: `http://localhost:8888`

## Cloudflare deploy + secrets

Secrets must exist in **both** places Cloudflare uses:

1. **Runtime (Worker)** — required for `/api` and threat intel during scans  
2. **Workers Builds** — required if CI builds on Cloudflare (build vars are separate from runtime)

```bash
# 1) Put secrets from .env into the Worker (runtime)
pnpm cf:secrets

# 2) Build + deploy Worker + assets to secure.personascan.net
pnpm cf:deploy
```

Also mirror the same secret names under  
**Workers & Pages → personascan → Settings → Build → Variables and secrets**  
so build and deploy share the same keys.

Required runtime secrets: `ADMIN_KEY`, `SUPABASE_ANON_KEY`  
Invite email: `RESEND_API_KEY` (from `EMAIL_FROM` / `noreply@personascan.net` — verify the domain in Resend)  
Public (no key / free): PhishTank, NVD  
Free after signup: `VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`  
Partner: `SCAMSNIFFER_API_KEY`, `BLOCKAID_API_KEY`, …

Non-secret vars live in `wrangler.jsonc`: `SCAN_SITE_URL`, `SITE_URL`, `SUPABASE_URL`, `EMAIL_FROM`.

## Admin flow

1. Open `/admin` and sign in with the admin key.
2. Create a user — a secured link is generated automatically.
3. Send the invite from the compose modal (Resend → `noreply@personascan.net`).
4. Open the live scan link to watch dual-verified results.

## Scan flow

1. User opens the secured link.
2. Reviews what this browser session can check.
3. Accepts terms → **Fetch scan**.
4. Sees live findings; can **Purge scan** for a one-time wipe key.
5. Admin detail shows device + API dual-verify sides.

# Persona Scan

Secured device threat scans for [personascan.net](https://personascan.net).

Admins create users (name, email, country), generate a secured invite link, and send it to the recipient. The recipient opens the link, accepts the secure-scan terms, taps **Fetch scan**, and receives a report covering IP leaks, password leaks, unknown API traffic, personal-data apps, ads SDKs, bots, cryptographic posture, and related categories.

## Stack

- Vite + React + TypeScript
- Netlify Functions + Blobs
- React Router

## Local development

```bash
pnpm install   # or: npm install
cp .env.example .env
# default local ADMIN_KEY is personascan-admin
pnpm dev
```

- Site: `http://localhost:5173`
- Admin: `http://localhost:5173/admin` (sign in with `ADMIN_KEY`)
- Scan links: `/scan/<token>`
- Local API: `http://localhost:8888` (started automatically by `pnpm dev`)

## Deploy (Netlify)

1. Connect this repo to Netlify (or `npx netlify deploy`).
2. Set environment variable `ADMIN_KEY` (and optionally `SITE_URL=https://personascan.net`).
3. Attach custom domain `personascan.net`.

## Admin flow

1. Open `/admin` and sign in with the admin key.
2. Create a user with name, email, and country — a secured link is generated automatically.
3. Copy the link and send it to the user.
4. Regenerate links anytime from the users list.

## Scan flow

1. User opens the secured link.
2. Reviews coverage categories and accepts: *Persona Scan scans are secure*.
3. Clicks **Fetch scan**.
4. Sees findings for each threat category.

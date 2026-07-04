# OmniAuth Demo App

A minimal demo of [`@omni-auth/react`](../../sdk/react/README.md) running on Next.js. Covers email/password auth, OAuth, magic links, TOTP MFA, orgs, sessions, and the admin console.

## Prerequisites

- [Bun](https://bun.sh) installed
- OmniAuth server running (see repo root)

## Setup

```bash
# 1. Install deps
bun install

# 2. Configure env
cp .env.local.example .env.local
# Edit .env.local if your server runs on a different port
```

`.env.local` defaults:

```env
NEXT_PUBLIC_OMNI_AUTH_URL=http://localhost:8080
NEXT_PUBLIC_OMNI_PROJECT_ID=00000000-0000-0000-0000-000000000000
```

## Run

```bash
bun run dev
```

App runs at **http://localhost:3000**

## Build

```bash
bun run build
bun run start
```

> Build uses `--webpack` instead of Turbopack due to a known bun symlink issue with local SDK packages.

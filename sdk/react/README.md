# @omni-auth/react

`@omni-auth/react` provides React components, context providers, and hooks for integrating OmniAuth into React applications (Next.js, Create React App, Vite, etc.). It wraps the standard `@omni-auth/core` client to handle authentication states automatically.

> **Client Components only.** All exports from this package (`AuthProvider`, all hooks) use React state and context. They are **not** compatible with React Server Components. See the [Next.js App Router](#nextjs-app-router) section below.

---

## Installation

**Local workspace (monorepo / development):**

```bash
# Bun — link directly from source
bun add /path/to/omni-auth/sdk/core /path/to/omni-auth/sdk/react

# NPM
npm install /path/to/omni-auth/sdk/core /path/to/omni-auth/sdk/react
```

**From tarballs (CI / distribution):**

```bash
# Bun
bun add ./dist/omni-auth-core-0.1.0.tgz ./dist/omni-auth-react-0.1.0.tgz

# NPM
npm install ./dist/omni-auth-core-0.1.0.tgz ./dist/omni-auth-react-0.1.0.tgz
```

---

## Usage

### 1. Configure the Provider

Wrap your application root with `AuthProvider`. It handles session restoration on mount and optional auto-refresh.

```tsx
import { AuthProvider } from '@omni-auth/react';

function App() {
  return (
    <AuthProvider
      baseUrl="https://auth.yourdomain.com"
      projectId="your-project-uuid-here"
    >
      <MainApp />
    </AuthProvider>
  );
}
```

| Prop | Type | Default | Description |
|---|---|---|---|
| `baseUrl` | `string` | — | OmniAuth server base URL |
| `projectId` | `string` | — | Project UUID sent as `X-Project-Id` |
| `autoRefreshInterval` | `number` | `720000` | Token refresh interval in ms. Set `0` to disable. |

---

### 2. Access Auth Context (`useAuth`)

The base hook — exposes the current user, auth state, and all auth actions:

```tsx
import { useAuth } from '@omni-auth/react';

function Header() {
  const { user, loading, login, logout } = useAuth();

  if (loading) return <div>Loading...</div>;

  if (!user) {
    return <button onClick={() => login('user@example.com', 'password')}>Sign In</button>;
  }

  return (
    <div>
      <span>Welcome, {user.email}!</span>
      <button onClick={logout}>Sign Out</button>
    </div>
  );
}
```

---

### 3. Hooks

#### `useMfa` — TOTP MFA enrollment & management

```tsx
import { useMfa } from '@omni-auth/react';

function MfaPanel() {
  const { enroll, enable, disable, cancelEnroll, enrollState, loading, error } = useMfa();

  const handleEnroll = async () => {
    const data = await enroll();
    // data.secret     — Base32 key for manual entry
    // data.otpauthUrl — otpauth:// URI for QR code generation
  };

  return (
    <div>
      <button onClick={handleEnroll} disabled={loading}>Setup MFA</button>
      {enrollState && (
        <div>
          <code>{enrollState.secret}</code>
          <button onClick={() => enable(enrollState.secret, '123456')}>Confirm</button>
          <button onClick={cancelEnroll}>Cancel</button>
        </div>
      )}
      {error && <p>{error}</p>}
    </div>
  );
}
```

#### `useSessions` — Active session management

```tsx
import { useSessions } from '@omni-auth/react';

function SessionsList() {
  const { sessions, refresh, revoke, revokeAll, loading } = useSessions();

  useEffect(() => { refresh(); }, []);

  return (
    <div>
      {sessions.map(s => (
        <div key={s.id}>
          <span>{s.ip_address} — {s.user_agent}</span>
          {!s.is_current && <button onClick={() => revoke(s.id)}>Revoke</button>}
        </div>
      ))}
      <button onClick={revokeAll}>Log out all other devices</button>
    </div>
  );
}
```

#### `useOrgs` / `useOrgMembers` — Multi-tenant organization management

```tsx
import { useOrgs, useOrgMembers } from '@omni-auth/react';

function OrgsView() {
  const { orgs, refresh, create, loading } = useOrgs();

  useEffect(() => { refresh(); }, []);

  return (
    <div>
      <button onClick={() => create('Engineering Team')}>Create Org</button>
      <ul>
        {orgs.map(org => <li key={org.id}>{org.name} — {org.role}</li>)}
      </ul>
    </div>
  );
}

function MembersView({ orgId }: { orgId: string }) {
  const { members, refresh, invite, update, remove } = useOrgMembers();

  useEffect(() => { refresh(orgId); }, [orgId]);

  return (
    <ul>
      {members.map(m => (
        <li key={m.user_id}>
          {m.email} ({m.role})
          <button onClick={() => update(orgId, m.user_id, 'admin')}>Make Admin</button>
          <button onClick={() => remove(orgId, m.user_id)}>Remove</button>
        </li>
      ))}
    </ul>
  );
}
```

#### `useChangePassword` / `useForgotPassword` / `useResetPassword` — Password flows

```tsx
import { useChangePassword, useForgotPassword, useResetPassword } from '@omni-auth/react';

// Change password while authenticated
const { submit, success, loading, error } = useChangePassword();
await submit(currentPassword, newPassword);

// Send a reset token to email
const { send, sent, loading, error } = useForgotPassword();
await send('user@example.com');

// Confirm reset with token from email
const { submit, success, loading, error } = useResetPassword();
await submit('user@example.com', resetToken, newPassword);
```

#### `useMagicLink` — Passwordless authentication

```tsx
import { useMagicLink } from '@omni-auth/react';

function MagicLinkForm() {
  const { request, verify, sent, loading, error } = useMagicLink();

  // Step 1: send the link
  await request('user@example.com');

  // Step 2: on callback page, verify URL params
  const params = new URLSearchParams(window.location.search);
  const result = await verify(params.get('magic_email')!, params.get('magic_token')!);
  // result.access_token — session is now active
}
```

---

## Next.js App Router

All hooks in this package are **client-only**. The package ships with `"use client"` directives on all files, so it is safe to import directly in client components.

For `AuthProvider` in a layout file, the layout itself must either be a client component or you must delegate the provider to a separate client wrapper:

```tsx
// app/providers.tsx
'use client';
import { AuthProvider } from '@omni-auth/react';

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider
      baseUrl={process.env.NEXT_PUBLIC_OMNI_AUTH_URL!}
      projectId={process.env.NEXT_PUBLIC_OMNI_PROJECT_ID!}
    >
      {children}
    </AuthProvider>
  );
}
```

```tsx
// app/layout.tsx  (Server Component — no 'use client' needed here)
import { Providers } from './providers';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

### Local development with webpack alias (monorepo)

When installing from a local path (not a tarball), Turbopack cannot follow bun symlinks. Use webpack with the following `next.config.ts`:

```ts
import type { NextConfig } from 'next';
import path from 'path';

const nextConfig: NextConfig = {
  transpilePackages: ['@omni-auth/core', '@omni-auth/react'],
  experimental: { externalDir: true },
  webpack(config) {
    config.resolve.alias = {
      ...config.resolve.alias,
      '@omni-auth/core': path.resolve(__dirname, '../../sdk/core/src/index.ts'),
      '@omni-auth/react': path.resolve(__dirname, '../../sdk/react/src/index.ts'),
    };
    config.resolve.modules = [path.resolve(__dirname, 'node_modules'), 'node_modules'];
    return config;
  },
};

export default nextConfig;
```

And in `package.json`, build with webpack explicitly:

```json
"scripts": {
  "build": "next build --webpack"
}
```

# @omni-auth/core

`@omni-auth/core` is a lightweight, framework-agnostic TypeScript client library for interacting with the OmniAuth authentication backend. It has zero external runtime dependencies and is fully compatible with browsers, Node.js, and Bun using the standard Fetch API.

---

## Installation

Install the package using your preferred package manager. Since it is distributed locally during testing, install the generated tarball:

```bash
# Using Bun
bun add /path/to/omni-auth/dist/omni-auth-core-0.1.0.tgz

# Using NPM
npm install /path/to/omni-auth/dist/omni-auth-core-0.1.0.tgz
```

---

## Quick Start

Initialize the `OmniAuthClient`:

```typescript
import { OmniAuthClient } from '@omni-auth/core';

const auth = new OmniAuthClient({
  baseUrl: 'https://auth.yourdomain.com',
  projectId: 'your-project-uuid-here', // x-project-id header identity
  onTokenRefreshed: (accessToken) => {
    console.log('New access token acquired:', accessToken);
  },
  onSessionExpired: () => {
    console.warn('Session has expired. Redirecting to login...');
    window.location.href = '/login';
  }
});
```

---

## Common API Operations

### 1. User Authentication

#### Email/Password Signup
```typescript
const user = await auth.signup('user@example.com', 'securePassword123');
console.log('Registered user:', user.email);
```

#### Email/Password Login
```typescript
try {
  const result = await auth.login('user@example.com', 'securePassword123');
  if ('mfa_required' in result) {
    // Redirect to second factor verification
    const ticket = result.mfa_ticket;
    // Prompt user for TOTP code...
  } else {
    console.log('Logged in! Access token:', result.access_token);
  }
} catch (err) {
  console.error('Login failed:', err.message);
}
```

---

### 2. Multi-Factor Authentication (MFA/TOTP)

#### Enroll MFA
Generates a secret key and a standard TOTP provisioning URI:
```typescript
const enrollData = await auth.enrollMfa();
// Render QR code using enrollData.provisioning_uri
console.log('Secret key:', enrollData.secret);
```

#### Enable MFA
Submits a verification code to lock in enrollment:
```typescript
await auth.enableMfa(secret, '123456');
console.log('MFA has been enabled successfully');
```

#### Verify MFA Login Challenge
If a login returns `mfa_required = true`, exchange the ticket and TOTP code for session tokens:
```typescript
const result = await auth.verifyMfa(mfaTicket, '123456');
console.log('Successfully authenticated with MFA! Token:', result.access_token);
```

---

### 3. Password Management

#### Forgot Password
Trigger a reset password link to the user's email:
```typescript
await auth.forgotPassword('user@example.com');
```

#### Reset Password
Apply the new password using the verification token:
```typescript
await auth.resetPassword('user@example.com', 'reset-token', 'myNewSecurePassword123');
```

---

### 4. Magic Link Authentication

#### Request Magic Link
Sends a single-use login link to the user:
```typescript
await auth.requestMagicLink('user@example.com');
```

#### Verify Magic Link
Verify token on callback and log in:
```typescript
const result = await auth.verifyMagicLink('user@example.com', 'magic-token');
console.log('Logged in via Magic Link! Token:', result.access_token);
```

---

### 5. Multi-Tenant Organization Management

#### Create an Organization
```typescript
const org = await auth.createOrg('Engineering Team');
console.log('Org ID:', org.id);
```

#### Add Organization Member
```typescript
await auth.addMember(org.id, 'new-user-uuid', 'Admin');
```

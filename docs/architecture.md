# System Architecture & Cryptography Design

OmniAuth is designed for secure, decentralized, multi-tenant authentication. This document details the architectural decisions, token mechanics, and security flows that protect client data.

---

## 1. Asymmetric Cryptography & JWTs

In traditional centralized authentication, resource servers (backends) must query the central database or call an introspect endpoint on the auth server for every incoming request to check if a token is valid. This creates a severe performance bottleneck and a single point of failure.

OmniAuth solves this using **Asymmetric Cryptography**:

```text
       ┌────────────────────────┐
       │     OmniAuth Server    │
       └───────────┬────────────┘
                   │ Sign token with Private Key
                   ▼
┌──────────────────────────────────────┐
│             Access Token             │ (Issued to client)
└──────────────────┬───────────────────┘
                   │ Send Authorization header
                   ▼
       ┌────────────────────────┐
       │   Your Backend API     │ (Validates token signature offline
       └────────────────────────┘  using Public JWKS key)
```

- **Ed25519 (EdDSA)**: OmniAuth uses Ed25519 signatures. Ed25519 offers stronger security, shorter signatures (making headers lighter), and significantly faster verification speeds than standard RSA-2048 keys.
- **JWKS Endpoint**: The API exposes a standard JSON Web Key Set endpoint at `/.well-known/jwks.json`. Backends use this endpoint to fetch public keys, caching them in-memory to verify tokens offline.

---

## 2. Multi-Tenant Workspace Separation

OmniAuth supports multiple isolated tenant environments ("Projects") on a single deployment.

- **Project Keypairs**: Every project is assigned its own unique Ed25519 signing keypair during creation. An Access Token signed for Project A cannot be verified or used on Project B, preventing cross-tenant access.
- **Tenant Context**: Reaffirming separation, the database structure enforces a `project_id` UUID column on all `users`, `sessions`, and `webhooks` tables.
- **Project Header Validation**: Client apps specify their project identity using the `x-project-id` header. Setting `ALLOW_DEFAULT_PROJECT_FALLBACK=false` ensures that if this header is missing, requests are immediately blocked with `400 Bad Request` before hitting any database query blocks.
- **Project API Secrets (Private Keys)**: In addition to the public `project_id` header, each project generates a secure private API key (`api_key`) prefixed with `oa_proj_`. This key is used for server-to-server (backend-to-auth) authenticated queries via the `x-project-secret` header, verifying backend caller identities securely.

---

## 3. Session Lifecycle & Token Rotation

User sessions are fully managed to balance convenience (long-lived logins) with security (immediate revocation).

### Tokens Issued
1. **Access Token**: Short-lived JWT (default 15 minutes) sent in headers for API authorization. Contains user context, project ID, and session ID.
2. **Refresh Token**: Long-lived token (default 7 days) stored securely in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. Used to obtain new Access Tokens.
3. **MFA Ticket**: Single-use token (valid for 5 minutes) issued upon correct password entry if MFA is enabled. Requires second-factor verification to exchange for actual Access/Refresh tokens.

### Token Rotation (RTR)
To prevent refresh token theft:
- Every time a Refresh Token is exchanged for a new Access Token, the old Refresh Token is revoked, and a new one is issued (Refresh Token Rotation).
- The revoked Refresh Token's ID is stored temporarily in Redis. If an attacker tries to reuse a revoked Refresh Token, the server detects the double-use anomaly, flags it as a breach, and immediately revokes all sessions associated with that user.

---

## 4. Multi-Factor Authentication (MFA)

MFA is implemented using Time-Based One-Time Passwords (TOTP) conforming to RFC 6238:

- **Secret Storage**: TOTP secrets are generated using cryptographically secure random bytes, Base32 encoded, and stored in the database.
- **Verification Loop**: During login, if a user has MFA enabled, the API issues an `mfa_ticket`. The user must submit a valid 6-digit TOTP code matching the secret to complete the sign-in flow.
- **Drift Tolerance**: The verification check supports a clock drift window of ±1 step (30 seconds) to accommodate slight sync issues on client devices.

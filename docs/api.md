# API Reference

All requests to the OmniAuth server should include the header `x-project-id` (unless running with `ALLOW_DEFAULT_PROJECT_FALLBACK=true`).

For server-to-server operations initiated by your backend, requests can authenticate using a private key by sending the `x-project-secret` header or an `Authorization: Bearer <project_secret>` token.

---

## 1. Authentication Endpoints

### User Signup
Creates a new user account for the specified project.

- **URL**: `/v1/auth/signup`
- **Method**: `POST`
- **Headers**:
  - `Content-Type: application/json`
  - `x-project-id: <uuid>`
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "securepassword123"
  }
  ```
- **Response (`201 Created`)**:
  ```json
  {
    "id": "8939c361-b51c-4b53-b3c1-eb3782928373",
    "project_id": "00000000-0000-0000-0000-000000000000",
    "email": "user@example.com",
    "email_verified": false,
    "mfa_enabled": false,
    "created_at": "2026-07-04T15:20:00Z"
  }
  ```

---

### User Login
Authenticates a user. Sets the `refresh_token` cookie and returns the `access_token`.

- **URL**: `/v1/auth/login`
- **Method**: `POST`
- **Headers**:
  - `Content-Type: application/json`
  - `x-project-id: <uuid>`
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "securepassword123"
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "access_token": "eyJhbGciOiJFZERTQSIs...",
    "user": {
      "id": "8939c361-b51c-4b53-b3c1-eb3782928373",
      "email": "user@example.com",
      "mfa_enabled": false
    }
  }
  ```
- **Response (`200 OK` with MFA Required)**:
  If the user has MFA enabled, they receive an temporary `mfa_ticket` instead of access tokens:
  ```json
  {
    "mfa_required": true,
    "mfa_ticket": "eyJhbGciOiJFZERTQS..."
  }
  ```

---

### Verify MFA Code
Exchanges a valid TOTP code and an `mfa_ticket` for session tokens.

- **URL**: `/v1/auth/mfa/verify`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "mfa_ticket": "eyJhbGciOiJFZERTQS...",
    "code": "123456"
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "access_token": "eyJhbGciOiJFZERTQS...",
    "user": {
      "id": "8939c361-b51c-4b53-b3c1-eb3782928373",
      "email": "user@example.com",
      "mfa_enabled": true
    }
  }
  ```

---

### Refresh Tokens
Requests a new access token using the refresh cookie. Sets a rotated `refresh_token` cookie.

- **URL**: `/v1/auth/refresh`
- **Method**: `POST`
- **Headers**:
  - `Cookie: refresh_token=cookie_value`
- **Response (`200 OK`)**:
  ```json
  {
    "access_token": "eyJhbGciOiJFZERTQS..."
  }
  ```

---

### Logout
Revokes the current session and clears the refresh cookie.

- **URL**: `/v1/auth/logout`
- **Method**: `POST`
- **Headers**:
  - `Cookie: refresh_token=cookie_value`
- **Response (`200 OK`)**:
  ```json
  {
    "message": "Successfully logged out"
  }
  ```

---

## 2. Session Management

All session routes require a valid Access Token in the header:
`Authorization: Bearer <access_token>`

### List Active Sessions
- **URL**: `/v1/sessions`
- **Method**: `GET`
- **Response (`200 OK`)**:
  ```json
  [
    {
      "id": "cb1c34a2-1111-4a4a-9999-555555555555",
      "user_agent": "Mozilla/5.0...",
      "ip_address": "127.0.0.1",
      "expires_at": "2026-07-11T15:20:00Z",
      "created_at": "2026-07-04T15:20:00Z"
      "is_current": true
    }
  ]
  ```

---

### Revoke Session
- **URL**: `/v1/sessions/{session_id}`
- **Method**: `DELETE`
- **Response (`200 OK`)**:
  ```json
  {
    "message": "Session revoked"
  }
  ```

---

## 3. Administrative (Admin) Endpoints

These routes require authentication using the `x-admin-api-key` header or an `Authorization: Bearer <ADMIN_API_KEY>` matching the server configuration.

### Create Project
Generates a new tenant project with its own cryptographic signing keys.

- **URL**: `/v1/admin/projects`
- **Method**: `POST`
- **Headers**:
  - `x-admin-api-key: <ADMIN_API_KEY>`
- **Request Body**:
  ```json
  {
    "name": "My New SaaS App"
  }
  ```
- **Response (`210 Created`)**:
  ```json
  {
    "id": "e44df488-8121-4f9b-9a91-db372819c927",
    "name": "My New SaaS App",
    "jwt_public_key": "MGlwZW5zc2gtdjEAAAA...",
    "api_key": "oa_proj_d09b296a0d9b296a...",
    "created_at": "2026-07-04T15:20:00Z",
    "updated_at": "2026-07-04T15:20:00Z"
  }
  ```

---

### Create Webhook
Registers an outbound webhook receiver for audit logs or event-driven alerts.

- **URL**: `/v1/admin/webhooks`
- **Method**: `POST`
- **Headers**:
  - `x-admin-api-key: <ADMIN_API_KEY>`
- **Request Body**:
  ```json
  {
    "project_id": "e44df488-8121-4f9b-9a91-db372819c927",
    "url": "https://api.my-app.com/v1/auth-webhooks",
    "secret": "my-webhook-signing-secret"
  }
  ```
- **Response (`201 Created`)**:
  ```json
  {
    "id": "273a81cf-da61-4613-bc71-112349acbc6a",
    "project_id": "e44df488-8121-4f9b-9a91-db372819c927",
    "url": "https://api.my-app.com/v1/auth-webhooks",
    "created_at": "2026-07-04T15:20:00Z"
  }
  ```

---

## 4. Key Discovery (JWKS)

### Get Public Keys
Fetches the public keys for offline validation.

- **URL**: `/.well-known/jwks.json`
- **Method**: `GET`
- **Query Parameters**:
  - `project_id: <uuid>` (Identifies which project's public key to query)
- **Response (`200 OK`)**:
  ```json
  {
    "keys": [
      {
        "kty": "OKP",
        "use": "sig",
        "crv": "Ed25519",
        "kid": "e44df488-8121-4f9b-9a91-db372819c927",
        "x": "MGlwZW5zc2gtdjEAAAA..."
      }
    ]
  }
  ```

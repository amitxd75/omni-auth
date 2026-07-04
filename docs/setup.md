# Local Setup & Development Guide

This guide covers setting up the OmniAuth platform locally for development, testing, and debugging.

---

## Prerequisites
Before starting, ensure you have the following installed:
- **Rust Toolchain** (`cargo` and `rustfmt`)
- **Docker & Docker Compose**
- **Bun** (for packaging the client SDKs)
- **sqlx-cli** (for running database migrations)

---

## 1. Run Core Containers
OmniAuth requires PostgreSQL and Redis to handle user credentials, tenant projects, rate-limiting, and session caches.

Start the preconfigured databases using Docker Compose:
```bash
docker compose -f infra/docker-compose.yml up -d postgres redis
```

This will boot:
- **PostgreSQL** on port `5432`
- **Redis** on port `6379`

Alternatively, you can run the API server itself inside a Docker container by building the image from the root `Dockerfile`:
```bash
# Build the API image
docker build -t omni-auth-api:latest .

# Run the API server, linking it to your databases
docker run -d --name omni-auth-api -p 8080:8080 --env-file .env omni-auth-api:latest
```

---

## 2. Environment Configuration
Copy the `.env.example` file to create your local environment configuration:
```bash
cp .env.example .env
```

Review the values inside `.env`:
```env
# Database Configuration
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/omni_auth
REDIS_URL=redis://127.0.0.1:6379

# Token Configuration
ACCESS_TOKEN_TTL_MINS=15
REFRESH_TOKEN_TTL_DAYS=7

# Security & Fallbacks
ADMIN_API_KEY=super_secret_admin_key_change_me
ALLOWED_CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
ALLOW_DEFAULT_PROJECT_FALLBACK=true
```

---

## 3. Database Migrations
Run the schema migrations using `sqlx-cli`:
```bash
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/omni_auth sqlx migrate run --source crates/migrations/migrations
```

This sets up the core tables:
- `projects`: Tenant configurations, names, and cryptographic keys.
- `users`: User metadata, password hashes (Argon2id), and MFA secrets.
- `sessions`: Session tracking, user agents, and IP addresses.
- `webhooks`: Registered outbound endpoints.

---

## 4. Run the API Server
Start the Axum API server in development mode:
```bash
# Set environment variables from your shell or let cargo read them from .env
cargo run --bin omni-auth-api
```
The server will bind to `0.0.0.0:8080`.

---

## 5. Verify the Server & Run Tests

Check the server health:
```bash
curl -i http://localhost:8080/health
```
Expected output:
```http
HTTP/1.1 200 OK
content-type: text/plain
content-length: 2

ok
```

Run the unit and database integration tests:
```bash
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/omni_auth cargo test
```

---

## 6. Build and Pack Client SDKs
If you are developing applications that connect to OmniAuth, you can pack the client SDKs into local `.tgz` tarballs:

```bash
chmod +x scripts/pack-sdk.sh
./scripts/pack-sdk.sh
```

You can then add these files directly to your application:
```bash
bun add ./dist/omni-auth-core-0.1.0.tgz
bun add ./dist/omni-auth-react-0.1.0.tgz
```

# OmniAuth

OmniAuth is a production-grade, multi-tenant authentication and authorization platform built in Rust. It provides secure user management, multi-factor authentication (MFA/TOTP), session handling, and OAuth integration using asymmetric cryptography (Ed25519) to sign tokens. This architecture allows backend microservices to perform fast, offline token validation via JWKS (JSON Web Key Sets) without contacting the main authentication database.

---

## Key Features

- **Multi-Tenant Architecture**: Supports isolated tenant projects, each equipped with its own unique Ed25519 signing and verification keypair.
- **Asymmetric Key Cryptography**: Access and Refresh tokens are cryptographically signed with Ed25519 (`EdDSA`), enabling fast and secure offline token verification.
- **Multi-Factor Authentication**: Built-in support for Time-Based One-Time Passwords (TOTP/MFA) with secret generation, enrollment, and verification.
- **Robust Session Management**: Full tracking of active sessions, device client identification, and single-session/global-session revocation.
- **SDK & React Integration**: Native support for custom TypeScript client SDKs and lightweight React hooks/context wrappers.
- **CI/CD Built-in**: Full GitHub Actions validation, formatting checking, Clippy static analysis, and automated SDK packaging.

---

## Architecture Overview

```mermaid
graph TD
    Client[Client App / Frontend] -->|"1. Authenticate with credentials"| AuthServer[OmniAuth Server]
    AuthServer -->|"2. Verify & Sign Token with Private Key"| DB[(PostgreSQL)]
    AuthServer -->|"3. Issue Access Token"| Client
    Client -->|"4. Request with Bearer Token"| ResourceServer[Backend Service]
    ResourceServer -->|"5. Fetch JWKS Public Keys (Cached)"| AuthServer
    ResourceServer -->|"6. Cryptographically Verify Signature Offline"| ResourceServer
```

---

## Directory Structure

```text
├── crates/
│   ├── core/         # Core data models, schemas, and password hashing (Argon2id)
│   ├── api/          # Axum HTTP API Server (routes, email endpoints, middleware)
│   ├── verify/       # Lightweight, framework-agnostic client JWKS validator
│   └── migrations/   # PostgreSQL database schema migrations
├── sdk/
│   ├── core/         # Vanilla TypeScript client SDK (fetch wrapper)
│   └── react/        # React Context & Hooks integration wrapper
├── infra/            # Docker Compose orchestration setups
└── docs/             # API, Setup, Architecture, and Deployment guides
```

---

## Documentation Links

To deploy, configure, or build client integrations with OmniAuth, refer to the guides inside the `docs/` folder:

1. **[Local Setup Guide](docs/setup.md)**: Steps to bootstrap PostgreSQL, Redis, compile the backend server, and run cargo test suites.
2. **[Architecture Specification](docs/architecture.md)**: In-depth details regarding asymmetric token signing, multi-tenant workspace separation, and offline validation.
3. **[API REST Endpoint Specifications](docs/api.md)**: Request and response schemas for registration, session control, MFA setup, and OAuth callbacks.
4. **[Production Deployment Reference](docs/deployment.md)**: Secure configurations, host port customizations, Docker Compose deployment, and reverse proxy settings.

---

## Development Quick Start

### Prerequisites
- **Rust Toolchain** (Latest stable `cargo`)
- **Docker & Docker Compose**
- **Bun** (for SDK testing and building)

### Launch Services
Launch database and caching services using Docker Compose:
```bash
docker compose -f infra/docker-compose.yml up -d postgres redis
```

### Run via Docker
You can build and spin up the OmniAuth API server container directly using the root `Dockerfile`:
```bash
# Build the API image
docker build -t omni-auth-api:latest .

# Run the API server container (binds to port 8080)
docker run -d --name omni-auth-api -p 8080:8080 --env-file .env omni-auth-api:latest
```


### Run Migrations
Run schema migration on the database:
```bash
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/omni_auth sqlx migrate run --source crates/migrations/migrations
```

### Run Tests
Execute the unit and integration tests:
```bash
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/omni_auth cargo test
```

---

## License

This repository is licensed under the [MIT License](LICENSE).

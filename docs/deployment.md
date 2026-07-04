# Production Deployment Guide

This document details configuring and deploying OmniAuth to a production environment.

---

## 1. Production Configuration Checklist

Before launching, configure these parameters in your production `.env` file:

- **Disable Fallback**: Force all client requests to explicitly pass the tenant project header to avoid mixing tenant databases.
  ```env
  ALLOW_DEFAULT_PROJECT_FALLBACK=false
  ```
- **Configure CORS Origins**: Do not use `*`. Specify your applications' production domains.
  ```env
  ALLOWED_CORS_ORIGINS=https://app.yourcompany.com,https://admin.yourcompany.com
  ```
- **Define Admin API Key**: Use a cryptographically secure random string (e.g. 32+ characters). Keep this secret.
  ```env
  ADMIN_API_KEY=f1d97bc2713f01901a14c68cd1bc3bb9d068593a1038b3017a1cf182e0df4001
  ```
- **SMTP Resend Key**: Configure a valid Resend API key to enable email verification, password reset, and magic link logins.
  ```env
  RESEND_API_KEY=re_your_live_production_key_here
  RESEND_FROM_EMAIL=security@yourdomain.com
  ```
- **Set Database & Redis Secrets**: Do not use the default passwords for PostgreSQL or Redis.

---

## 2. Docker Compose Custom Ports

If you are self-hosting OmniAuth on a host that already has PostgreSQL or Redis running on their standard ports, configure custom external ports in your `.env` file. 

The [docker-compose.yml](file:///home/amitxd/indev/omnibox/backend/omni-auth/infra/docker-compose.yml) reads these variables from `.env` to bind custom ports to the host:

```env
# Custom Host Ports (Defaults: 5432, 6379, 8080)
POSTGRES_PORT=5433
REDIS_PORT=6380
API_PORT=8081
```

Once defined, start the containers:
```bash
docker compose -f infra/docker-compose.yml up -d
```
The Postgres 18 container will bind to host port `5433`, Redis will bind to `6380`, and the OmniAuth API server will bind to `8081`.

---

## 3. Reverse Proxy & SSL (Caddy / Nginx)

OmniAuth must be hosted behind an SSL-terminating reverse proxy. Cookies with the `Secure` attribute will be ignored by browsers if requests are made over unencrypted HTTP.

### Caddy Server Configuration
Caddy automatically handles Let's Encrypt SSL certificates. Create a `/etc/caddy/Caddyfile`:

```caddy
auth.yourdomain.com {
    reverse_proxy localhost:8080 {
        # Preserve headers
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

### Nginx Configuration
Create an Nginx virtual host configuration:

```nginx
server {
    listen 80;
    server_name auth.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 4. Rate Limiting & Scale

- **Server-Level Rate Limiting**: The server utilizes `tower_governor` configured to limit core auth routes (signup, login, magic-links) to `2 requests per second` with a burst capacity of `5 requests`.
- **Horizontal Scaling**: Because access tokens are validated offline by backends via JWKS signatures, you can horizontally scale your API servers indefinitely. Only session refreshes, logouts, and token generations will hit the central Redis/Postgres services. Ensure your PostgreSQL connection pool is sized correctly when scaling.

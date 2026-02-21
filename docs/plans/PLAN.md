# Rust Backend — Architecture Plan

## Project Overview

C2C sports equipment rental platform. Migrating from Supabase to a custom Rust backend.

**Tech Stack:** Actix-web 4, SQLx + PostgreSQL + PostGIS, JWT + OAuth (Google/GitHub), argon2 password hashing, actix-ws WebSocket, figment config, tracing structured logging.

---

## Project Structure

```
rust-backend/
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── api/
│   │   ├── dtos/           # Request/response structs
│   │   └── routes/         # Actix handlers (thin)
│   ├── application/        # Services / use cases
│   ├── domain/             # Entities + business rules
│   ├── infrastructure/
│   │   ├── db/             # Pool + migrations runner
│   │   ├── repositories/   # SQLx data access
│   │   ├── oauth/          # Google + GitHub clients
│   │   └── cache/          # Future: Redis
│   ├── middleware/
│   │   └── auth.rs         # JWT FromRequest extractor
│   ├── security/           # CORS, headers, login throttle
│   ├── observability/      # Metrics + error tracking
│   ├── config/
│   ├── error/
│   └── utils/              # JWT, argon2, hash
├── migrations/
├── tests/
│   ├── common/             # TestDb, fixtures
│   └── integration/        # End-to-end tests
└── scripts/
    ├── supabase_export_transform_import.sh
    └── validate_migration.sh
```

---

## Database Schema

See `migrations/20240101000000_init.up.sql` for the full schema. Key tables:

- **profiles** — users with roles (`renter`, `owner`, `admin`)
- **auth_identities** — email/password + OAuth per user
- **user_sessions** — refresh token sessions with family/rotation tracking
- **equipment** + **equipment_photos**
- **categories** (hierarchical)
- **conversations** + **conversation_participants** + **messages**

PostGIS geography column on `equipment.coordinates` for geospatial queries.

---

## API Endpoints

### Auth
```
POST   /api/auth/register
POST   /api/auth/login
POST   /api/auth/logout
POST   /api/auth/refresh
GET    /api/auth/me
POST   /api/auth/verify-email
POST   /api/auth/oauth/google
POST   /api/auth/oauth/github
```

### Users
```
GET    /api/users/:id
PUT    /api/users/:id
GET    /api/users/me/equipment
```

### Equipment + Categories
```
GET    /api/equipment
POST   /api/equipment
GET    /api/equipment/:id
PUT    /api/equipment/:id
DELETE /api/equipment/:id
POST   /api/equipment/:id/photos
DELETE /api/equipment/:id/photos/:photo_id
GET    /api/categories
GET    /api/categories/:id
```

### Messaging
```
GET    /api/conversations
POST   /api/conversations
GET    /api/conversations/:id
GET    /api/conversations/:id/messages
POST   /api/conversations/:id/messages
WS     /ws
```

### Ops
```
GET    /health
GET    /ready
GET    /metrics
```

---

## Authorization Matrix

| Endpoint | Public | Renter | Owner | Admin | Self |
|----------|--------|--------|-------|-------|------|
| POST /auth/register | ✅ | — | — | — | — |
| POST /auth/login | ✅ | — | — | — | — |
| POST /auth/refresh | — | ✅ | ✅ | ✅ | — |
| POST /auth/logout | — | ✅ | ✅ | ✅ | — |
| GET /auth/me | — | ✅ | ✅ | ✅ | — |
| GET /users/:id | ✅ (limited) | ✅ | ✅ | ✅ | ✅ (full) |
| PUT /users/:id | — | ❌ | ❌ | ✅ | ✅ |
| GET /users/me/equipment | — | ✅ | ✅ | ✅ | — |
| GET /equipment | ✅ | ✅ | ✅ | ✅ | — |
| POST /equipment | — | ❌ | ✅ | ✅ | — |
| GET /equipment/:id | ✅ | ✅ | ✅ | ✅ | — |
| PUT /equipment/:id | — | ❌ | ✅ (own) | ✅ | — |
| DELETE /equipment/:id | — | ❌ | ✅ (own) | ✅ | — |
| POST /equipment/:id/photos | — | ❌ | ✅ (own) | ✅ | — |
| DELETE /equipment/:id/photos/:id | — | ❌ | ✅ (own) | ✅ | — |
| GET /categories | ✅ | ✅ | ✅ | ✅ | — |
| GET /categories/:id | ✅ | ✅ | ✅ | ✅ | — |
| GET /conversations | — | ✅ (own) | ✅ (own) | ✅ | — |
| POST /conversations | — | ✅ | ✅ | ✅ | — |
| GET /conversations/:id | — | ✅ (participant) | ✅ (participant) | ✅ | — |
| GET /conversations/:id/messages | — | ✅ (participant) | ✅ (participant) | ✅ | — |
| POST /conversations/:id/messages | — | ✅ (participant) | ✅ (participant) | ✅ | — |
| WS /ws | — | ✅ | ✅ | ✅ | — |
| GET /health | ✅ | — | — | — | — |
| GET /ready | ✅ | — | — | — | — |
| GET /metrics | — | — | — | ✅ (token) | internal IP |

---

## Auth Model

- **Access token:** short-lived JWT (15 min), `Authorization: Bearer` header. Claims: `sub`, `exp`, `iat`, `jti`, `aud`, `iss`, `kid`, `role`.
- **Refresh token:** opaque random token stored as `HttpOnly Secure SameSite=Lax` cookie, hashed in DB.
- **Rotation:** new refresh token issued on every refresh. Old token revoked with `replaced_by` pointer.
- **Replay detection:** any revoked token presented triggers revocation of the entire token family (`family_id`).
- **Key ring:** active key + previous keys supported for zero-downtime rotation.
- **WS auth:** JWT in `Authorization: Bearer` header on upgrade. Fallback: `Sec-WebSocket-Protocol: bearer, <token>`. Session revocation checked on connect.

---

## Security Controls

- CORS allowlist (no wildcard with credentials)
- Cookies: `HttpOnly`, `Secure`, `SameSite=Lax`
- CSRF: double-submit cookie pattern on cookie-authenticated mutations
- Login throttle: exponential backoff + temporary lockout per account+IP
- IP rate limiting: `actix-governor` applied to `/api/auth/*`
- Security headers: HSTS, X-Content-Type-Options, X-Frame-Options, `Referrer-Policy: strict-origin-when-cross-origin`, CSP baseline
- `/metrics`: admin token or private IP only

---

## WebSocket Protocol

**Message envelope:**
```json
{ "type": "ping" | "message" | "typing" | "read", "payload": { ... } }
```

**Server events:**
```json
{ "type": "pong" }
{ "type": "message", "payload": { "id": "...", "content": "...", ... } }
{ "type": "error", "payload": { "code": "BAD_MESSAGE" | "UNSUPPORTED_TYPE" } }
```

Messages are persisted to DB before broadcast. At-most-once delivery. Missed messages fetchable via REST on reconnect. Heartbeat: 30s ping, 90s timeout.

---

## Observability

- Structured JSON logs via `tracing` + `tracing-subscriber`
- Per-request: `request_id`, `user_id`, method, path, status, latency_ms
- Auth events: login success/failure, refresh, logout
- Prometheus metrics at `/metrics`: request count, error rate, avg latency, WS connections, auth failures, DB pool size/idle
- 5xx events captured via `capture_unexpected_5xx` (log-based; no Sentry integration yet)

---

## What Is NOT Done Yet

- Supabase migration still requires real source/target credentials and staging rehearsal
- Integration test suite in `tests/integration/` — directory empty, tests live in `tests/*.rs` as loose files
- OpenAPI/utoipa docs
- Redis cache layer
- Performance/load tests
- Operational deployment of dashboards/alerts/log pipeline and staged drills

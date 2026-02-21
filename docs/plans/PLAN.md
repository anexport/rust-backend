# Rust Backend Architecture Plan

## Project Overview
Equipment rental platform migrating from Supabase to Rust.

## Tech Stack
- **Framework**: Actix-web 4.x
- **Database**: PostgreSQL + SQLx 0.7 + PostGIS (geospatial)
- **Auth**: Custom JWT + OAuth (Google, GitHub) + argon2 password hashing
- **WebSocket**: actix-ws for real-time messaging
- **Docs**: utoipa for OpenAPI/Swagger
- **Config**: figment (layered: file → env vars → defaults)
- **Logging**: tracing + tracing-subscriber (JSON structured)
- **Error Handling**: thiserror + actix ResponseError trait

## Project Structure
```
rust-backend/
├── Cargo.toml
├── .env.example
├── docker-compose.yml
├── Dockerfile
├── config/
│   ├── default.toml
│   └── development.toml
├── migrations/
│   ├── 20240101000000_init.up.sql
│   └── 20240101000000_init.down.sql
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── api/                      # HTTP layer (handlers + DTOs)
│   │   ├── mod.rs
│   │   ├── dtos/                 # Request/Response structs
│   │   │   ├── mod.rs
│   │   │   ├── auth_dto.rs
│   │   │   ├── user_dto.rs
│   │   │   ├── equipment_dto.rs
│   │   │   └── message_dto.rs
│   │   └── routes/               # Actix handlers (thin)
│   │       ├── mod.rs
│   │       ├── auth.rs
│   │       ├── users.rs
│   │       ├── equipment.rs
│   │       ├── messages.rs
│   │       └── ws.rs
│   ├── application/              # Use cases / business orchestration
│   │   ├── mod.rs
│   │   ├── auth_service.rs
│   │   ├── user_service.rs
│   │   ├── equipment_service.rs
│   │   └── message_service.rs
│   ├── domain/                   # Entities + business rules
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── equipment.rs
│   │   ├── message.rs
│   │   ├── category.rs
│   │   └── errors.rs             # Domain error types
│   ├── infrastructure/           # External integrations
│   │   ├── mod.rs
│   │   ├── db/
│   │   │   ├── mod.rs
│   │   │   ├── pool.rs
│   │   │   └── migrations.rs
│   │   ├── repositories/         # Data access layer
│   │   │   ├── mod.rs
│   │   │   ├── user_repository.rs
│   │   │   ├── equipment_repository.rs
│   │   │   ├── message_repository.rs
│   │   │   └── traits.rs         # Repository trait definitions
│   │   ├── oauth/
│   │   │   ├── mod.rs
│   │   │   ├── google.rs
│   │   │   └── github.rs
│   │   └── cache/                # Redis for sessions/rate limiting (future)
│   │       └── mod.rs
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs               # JWT extraction + validation
│   │   ├── authorization.rs      # Role/ownership checks
│   │   └── rate_limit.rs         # Rate limiting
│   ├── config/
│   │   ├── mod.rs
│   │   └── app_config.rs         # Figment-based config structs
│   ├── error/
│   │   ├── mod.rs
│   │   └── app_error.rs          # thiserror enum + ResponseError impl
│   ├── utils/
│   │   ├── mod.rs
│   │   ├── jwt.rs
│   │   └── hash.rs               # argon2 password utilities
│   └── docs/
│       ├── mod.rs
│       └── openapi.rs
├── tests/
│   ├── integration/
│   │   ├── auth_tests.rs
│   │   ├── equipment_tests.rs
│   │   └── messages_tests.rs
│   └── common/
│       ├── mod.rs
│       └── fixtures.rs           # Test data factories
└── scripts/
    └── init_db.sh
```

## Database Schema

```sql
-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "postgis";

-- Users
CREATE TABLE profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('renter', 'owner', 'admin')),
    username TEXT UNIQUE,
    full_name TEXT,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE owner_profiles (
    profile_id UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    business_info JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE renter_profiles (
    profile_id UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    preferences JSONB,
    experience_level TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Auth (supports email/password + OAuth + sessions)
CREATE TABLE auth_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('email', 'google', 'github')),
    provider_id TEXT,                    -- OAuth user ID (null for email)
    password_hash TEXT,                  -- argon2 hash (null for OAuth)
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (provider = 'email' AND provider_id IS NULL AND password_hash IS NOT NULL)
        OR
        (provider IN ('google', 'github') AND provider_id IS NOT NULL AND password_hash IS NULL)
    ),
    UNIQUE(user_id, provider)            -- One identity per provider per user
);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,    -- Hashed refresh token
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    device_info JSONB,                   -- User agent, IP, device name
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_identities_user ON auth_identities(user_id);
CREATE UNIQUE INDEX uq_auth_identities_provider_id
    ON auth_identities(provider, provider_id)
    WHERE provider_id IS NOT NULL;
CREATE INDEX idx_sessions_user ON user_sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_refresh_token_hash
    ON user_sessions(refresh_token_hash)
    WHERE revoked_at IS NULL;

-- Equipment
CREATE TABLE categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    parent_id UUID REFERENCES categories(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE equipment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES profiles(id),
    category_id UUID NOT NULL REFERENCES categories(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    daily_rate DECIMAL(8,2) NOT NULL,
    condition TEXT NOT NULL CHECK (condition IN ('new', 'excellent', 'good', 'fair')),
    location TEXT NOT NULL,
    coordinates GEOGRAPHY(POINT, 4326),   -- PostGIS for geospatial queries
    is_available BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE equipment_photos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    equipment_id UUID NOT NULL REFERENCES equipment(id) ON DELETE CASCADE,
    photo_url TEXT NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    order_index INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for equipment search
CREATE INDEX idx_equipment_owner ON equipment(owner_id);
CREATE INDEX idx_equipment_category ON equipment(category_id);
CREATE INDEX idx_equipment_available ON equipment(is_available) WHERE is_available = TRUE;
CREATE INDEX idx_equipment_price ON equipment(daily_rate);
CREATE INDEX idx_equipment_location ON equipment USING GIST(coordinates);
CREATE INDEX idx_equipment_photos_equipment ON equipment_photos(equipment_id);
CREATE UNIQUE INDEX uq_equipment_primary_photo
    ON equipment_photos(equipment_id)
    WHERE is_primary = TRUE;

-- Messaging
CREATE TABLE conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE conversation_participants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    last_read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(conversation_id, profile_id)
);

CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id UUID NOT NULL REFERENCES profiles(id),
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enforce that message sender participates in the conversation
CREATE OR REPLACE FUNCTION ensure_message_sender_is_participant()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM conversation_participants cp
        WHERE cp.conversation_id = NEW.conversation_id
          AND cp.profile_id = NEW.sender_id
    ) THEN
        RAISE EXCEPTION 'sender is not a participant in conversation %', NEW.conversation_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Indexes for messaging
CREATE INDEX idx_conversation_participants_profile ON conversation_participants(profile_id);
CREATE INDEX idx_conversation_participants_conversation ON conversation_participants(conversation_id);
CREATE INDEX idx_messages_conversation ON messages(conversation_id, created_at DESC);
CREATE INDEX idx_messages_sender ON messages(sender_id);

CREATE TRIGGER ensure_message_sender_is_participant_trigger
    BEFORE INSERT OR UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION ensure_message_sender_is_participant();

-- Updated at trigger function
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_profiles_updated_at
    BEFORE UPDATE ON profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_equipment_updated_at
    BEFORE UPDATE ON equipment
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_conversations_updated_at
    BEFORE UPDATE ON conversations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
```

## API Endpoints

### Auth
```
POST   /api/auth/register         # Email/password registration
POST   /api/auth/login            # Email/password login
POST   /api/auth/logout           # Revoke refresh token
POST   /api/auth/oauth/google     # Google OAuth callback
POST   /api/auth/oauth/github     # GitHub OAuth callback
POST   /api/auth/refresh          # Refresh JWT token
GET    /api/auth/me               # Get current user
POST   /api/auth/verify-email     # Verify email address
```

### Users
```
GET    /api/users/:id             # Get user profile (public info)
PUT    /api/users/:id             # Update user profile (self only)
GET    /api/users/me/equipment    # Get current user's equipment listings
```

### Equipment
```
GET    /api/equipment             # List equipment (with filters)
POST   /api/equipment             # Create equipment listing (owners only)
GET    /api/equipment/:id         # Get single equipment
PUT    /api/equipment/:id         # Update equipment (owner only)
DELETE /api/equipment/:id         # Delete equipment (owner only)
POST   /api/equipment/:id/photos  # Add photos (owner only)
DELETE /api/equipment/:id/photos/:photo_id # Remove photo (owner only)
```

### Categories
```
GET    /api/categories            # List all categories
GET    /api/categories/:id        # Get category with children
```

### Messaging
```
GET    /api/conversations                     # List my conversations
POST   /api/conversations                     # Create conversation
GET    /api/conversations/:id                 # Get conversation details
GET    /api/conversations/:id/messages        # Get messages (paginated)
POST   /api/conversations/:id/messages        # Send message
WS     /ws                                    # WebSocket connection
```

### Health & Monitoring
```
GET    /health                    # Health check
GET    /ready                     # Readiness probe
GET    /metrics                   # Prometheus metrics (optional)
```

## Authorization Matrix

| Endpoint | Self | Owner | Admin | Public |
|----------|------|-------|-------|--------|
| `POST /api/auth/register` | ❌ | ❌ | ❌ | ✅ |
| `POST /api/auth/login` | ❌ | ❌ | ❌ | ✅ |
| `POST /api/auth/oauth/google` | ❌ | ❌ | ❌ | ✅ |
| `POST /api/auth/oauth/github` | ❌ | ❌ | ❌ | ✅ |
| `POST /api/auth/refresh` | ✅ (session owner) | - | - | ❌ |
| `POST /api/auth/logout` | ✅ (session owner) | - | - | ❌ |
| `GET /api/auth/me` | ✅ | - | - | ❌ |
| `POST /api/auth/verify-email` | ✅ | - | ✅ | ❌ |
| `GET /api/users/:id` | ✅ | ✅ | ✅ | ✅ (limited fields) |
| `PUT /api/users/:id` | ✅ | ❌ | ✅ | ❌ |
| `GET /api/users/me/equipment` | ✅ | ✅ | ✅ | ❌ |
| `GET /api/equipment` | ✅ | ✅ | ✅ | ✅ |
| `POST /api/equipment` | ❌ | ✅ | ✅ | ❌ |
| `GET /api/equipment/:id` | ✅ | ✅ | ✅ | ✅ |
| `PUT /api/equipment/:id` | ❌ | ✅ (resource owner) | ✅ | ❌ |
| `DELETE /api/equipment/:id` | ❌ | ✅ (resource owner) | ✅ | ❌ |
| `POST /api/equipment/:id/photos` | ❌ | ✅ (resource owner) | ✅ | ❌ |
| `DELETE /api/equipment/:id/photos/:photo_id` | ❌ | ✅ (resource owner) | ✅ | ❌ |
| `GET /api/categories` | ✅ | ✅ | ✅ | ✅ |
| `GET /api/categories/:id` | ✅ | ✅ | ✅ | ✅ |
| `GET /api/conversations` | ✅ (participant) | - | ✅ | ❌ |
| `POST /api/conversations` | ✅ | - | ✅ | ❌ |
| `GET /api/conversations/:id` | ✅ (participant) | - | ✅ | ❌ |
| `GET /api/conversations/:id/messages` | ✅ (participant) | - | ✅ | ❌ |
| `POST /api/conversations/:id/messages` | ✅ (participant) | - | ✅ | ❌ |
| `WS /ws` | ✅ | - | - | ❌ |
| `GET /health` | - | - | - | ✅ |
| `GET /ready` | - | - | - | ✅ (or internal only) |
| `GET /metrics` | - | - | ✅ | ❌ (internal network recommended) |

## Key Dependencies

```toml
[package]
name = "rust-backend"
version = "0.1.0"
edition = "2021"

[dependencies]
# Web
actix-web = "4"
actix-ws = "0.3"
tokio = { version = "1", features = ["full"] }
actix-cors = "0.7"
actix-governor = "0.5"              # Rate limiting

# Database
sqlx = { version = "0.7", features = ["runtime-tokio", "postgres", "uuid", "chrono", "json"] }

# Auth & Security
jsonwebtoken = "9"
argon2 = "0.5"
oauth2 = "4"
rand = "0.8"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Validation
validator = { version = "0.16", features = ["derive"] }

# OpenAPI
utoipa = "4"
utoipa-swagger-ui = { version = "4", features = ["actix-web"] }

# Configuration
figment = { version = "0.10", features = ["toml", "env"] }
dotenvy = "0.15"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-actix-web = "0.7"

# Utils
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "1"
anyhow = "1"

[dev-dependencies]
actix-rt = "2"
once_cell = "1"
fake = { version = "2", features = ["derive"] }
```

## WebSocket Protocol

### Connection
```
wss://host/ws
```

Authentication transport (preferred):
- `Authorization: Bearer <jwt>` on the WebSocket upgrade request
- Optional fallback: `Sec-WebSocket-Protocol: bearer,<jwt>`

Avoid putting JWTs in query params because they can leak via logs and proxies.

### Authentication on Connect
- JWT must be valid and not expired
- Session must not be revoked
- Connection rejected if auth fails

### Message Format
```json
{
  "type": "message" | "typing" | "read" | "ping",
  "payload": { ... }
}
```

### Events
| Event | Direction | Description |
|-------|-----------|-------------|
| `message` | Client → Server | Send a message |
| `message` | Server → Client | Receive a message |
| `typing` | Both | Typing indicator |
| `read` | Client → Server | Mark conversation as read |
| `ping` / `pong` | Both | Heartbeat (30s interval) |

### Delivery Semantics
- **At-most-once** delivery (no message persistence in memory)
- Messages stored in DB before broadcast
- Client should fetch missed messages on reconnect via REST API

## Error Handling

```rust
use thiserror::Error;
use actix_web::{HttpResponse, ResponseError, http::StatusCode};

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Internal server error")]
    InternalError(#[source] anyhow::Error),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let public_message = match self {
            AppError::DatabaseError(_) | AppError::InternalError(_) => "Internal server error",
            AppError::NotFound(_) => "Not found",
            AppError::Unauthorized => "Unauthorized",
            AppError::Forbidden(_) => "Forbidden",
            AppError::ValidationError(_) => "Validation error",
            AppError::Conflict(_) => "Conflict",
        };

        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "error": public_message,
            "code": self.error_code(), // stable machine-readable code
        }))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::DatabaseError(_) | AppError::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}
```

## Production Readiness Plan (v1)

Execution checklist for implementation:
- `docs/plans/2026-02-21-backend-v1-implementation-checklist.md`

### Recommended v1 Auth Model (simple + secure)
- Access token (JWT): short-lived (15 minutes), sent as `Authorization: Bearer`.
- Refresh token: opaque random token, stored as `HttpOnly` + `Secure` cookie.
- Refresh endpoint rotates refresh token on every use.
- Store only hashed refresh tokens in DB.
- Use token family + reuse detection: if an old refresh token is replayed, revoke all active sessions in that family.
- Include `jti`, `sub`, `exp`, `iat`, `aud`, `iss`, and `kid` claims in JWT.
- Keep JWT signing keys in a key ring with active + previous keys (rotation support).

### Security Defaults (required before prod)
- [ ] CORS allowlist only (`https://app.example.com`), no wildcard with credentials.
- [ ] Cookies set to `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict` if flow allows).
- [ ] CSRF protection on cookie-authenticated mutation endpoints (`POST/PUT/PATCH/DELETE`).
- [ ] Rate limiting per IP + per account on auth endpoints.
- [ ] Login hardening: exponential backoff + temporary lockout policy.
- [ ] Password policy: min length, banned-password check, argon2id parameters pinned in config.
- [ ] Email verification token expiry and one-time use semantics.
- [ ] Password reset tokens: one-time use, short expiry, invalidate all sessions on reset.
- [ ] Security headers middleware: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP baseline.
- [ ] `GET /metrics` internal-only (private network and/or auth guard).
- [ ] Secrets only from environment/secret manager; never in repository.
- [ ] DB TLS enabled in production.

### Schema Additions Required for Session Security
```sql
ALTER TABLE user_sessions
    ADD COLUMN family_id UUID,
    ADD COLUMN replaced_by UUID REFERENCES user_sessions(id),
    ADD COLUMN revoked_reason TEXT,
    ADD COLUMN created_ip INET,
    ADD COLUMN last_seen_at TIMESTAMPTZ;

CREATE INDEX idx_sessions_family_active
    ON user_sessions(family_id)
    WHERE revoked_at IS NULL;
```

Notes:
- `family_id` groups rotated refresh tokens for replay detection.
- On refresh rotation, old session row is marked with `replaced_by`.
- On reuse detection, revoke all rows where `family_id = <family>`.

### Structural Improvements (before scale)
- [ ] Version API now: `/api/v1/...`.
- [ ] Organize code by bounded context (`auth`, `equipment`, `messaging`) with local handler/service/repo modules.
- [ ] Add `src/security/` for shared security primitives (JWT, cookies, CSRF, headers, key loading).
- [ ] Enforce dependency direction: `api -> application -> domain -> infrastructure`.
- [ ] Add ADRs in `docs/adr/` for auth/session model, authorization policy, WebSocket auth, and migration strategy.

### Observability and Operations Baseline
- [ ] Structured logs with request ID and authenticated `user_id` when available.
- [ ] Audit log events for login, logout, refresh, failed auth, role changes, admin actions.
- [ ] Health endpoints contract:
  - `/health`: process up only.
  - `/ready`: DB + critical dependencies ready.
- [ ] Metrics: request latency/error rate, DB pool stats, ws connection count, auth failure counters.
- [ ] Error tracking integration for unexpected 5xx.
- [ ] Backups: daily full + PITR strategy; restore drill documented and tested.

### Test and Verification Gates (CI/CD)
- [ ] `cargo fmt --check`
- [ ] `cargo clippy -- -D warnings`
- [ ] `cargo test` (unit + integration)
- [ ] `cargo audit`
- [ ] Migration smoke test in CI (`sqlx migrate run` against ephemeral Postgres).
- [ ] Auth security tests:
  - refresh rotation works
  - refresh reuse detection revokes family
  - CSRF checks enforced
  - role/ownership authorization checks
- [ ] Load tests for login burst and websocket fanout.

### Execution Phases with Exit Criteria
1. Phase 1: Core API + DB
   - Exit: all CRUD + auth endpoints pass integration tests; migration rollback tested.
2. Phase 2: Session hardening
   - Exit: refresh rotation + replay detection implemented and tested.
3. Phase 3: Security hardening
   - Exit: CSRF, headers, lockout, CORS allowlist, metrics protection verified in staging.
4. Phase 4: Observability + resilience
   - Exit: dashboards + alerts live; backup restore drill successful.
5. Phase 5: Cutover from Supabase
   - Exit: data validation report signed off; rollback playbook validated.

### Production Definition of Done
- [ ] No critical/high findings from security review.
- [ ] P95 latency and error budget targets met in staging load test.
- [ ] On-call runbook exists (auth outage, DB outage, websocket degradation).
- [ ] Secrets rotation and JWT key rotation tested.
- [ ] Incident logging and audit trails verified end-to-end.

## Migration Notes

### From Supabase to Rust
1. **Auth**: Supabase Auth → Custom JWT + OAuth (users must re-authenticate)
2. **RLS Policies**: Move to Rust middleware authorization
3. **Triggers**: Move business logic to Rust services
4. **Realtime**: Supabase Realtime → actix-ws WebSocket
5. **Storage**: Supabase Storage → S3/Cloudflare R2 (future)

### Data Migration
1. Export Supabase data as JSON/CSV
2. Transform to match new schema
3. Import via migration scripts
4. Verify data integrity

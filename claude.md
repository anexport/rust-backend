# Claude Code Development Guide

This guide is for Claude Code working on the Rust Backend & Next.js Frontend monorepo.

---

## Quick Reference

| Context | Location | Purpose |
|---------|----------|---------|
| **Backend** | `src/` | Rust Actix-web API |
| **Frontend** | `frontend/` | Next.js 16 with App Router |
| **Database** | `migrations/` | PostgreSQL + PostGIS |
| **Tests** | `tests/` | Integration tests |
| **Config** | `config/` | TOML configuration |
| **Docs** | `docs/` | Operational docs |

---

## Project Architecture

### Backend Layer Structure (Clean Architecture)

```
src/
├── api/              # Presentation layer - HTTP routes, DTOs, OpenAPI
├── application/      # Application services - business logic orchestration
├── domain/           # Domain models - pure business entities
├── infrastructure/   # External concerns - DB, Auth0 API, repositories
├── middleware/       # Cross-cutting - auth, logging, rate limiting
├── config/           # Configuration loading and types
├── security/         # Security features - CORS, rate limiting, throttling
├── error/            # Error types and handling
├── utils/            # Utilities - Auth0 claims parsing, etc.
└── observability/     # Metrics, error tracking
```

**Key Principles:**
- `api/` → `application/` → `domain/` → `infrastructure/`
- HTTP handlers delegate to services
- Services use repositories for data access
- Domain models have no external dependencies
- Repositories implement traits from domain

### Frontend Architecture

```
frontend/src/
├── app/              # Next.js App Router pages (server + client components)
├── components/        # React components (UI + business logic)
├── lib/              # Utilities - API clients, auth helpers
├── hooks/            # Custom React hooks
└── styles/           # Global styles
```

**Key Patterns:**
- Server Components for data fetching (`fetchServer()`)
- Client Components for interactivity (`'use client'`)
- API proxy at `/api/proxy/[...path]/` for backend calls
- Auth0 SDK for authentication with JWT token handling

---

## Database Schema

### Extensions
- `pgcrypto` - UUID generation (`gen_random_uuid()`)
- `postgis` - Geospatial data support

### Tables

#### Users & Auth

**`profiles`**
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID PRIMARY KEY | `gen_random_uuid()` |
| `email` | TEXT UNIQUE, NOT NULL | - |
| `role` | role ENUM NOT NULL | `renter`, `owner`, `admin` |
| `username` | TEXT UNIQUE | - |
| `full_name` | TEXT | - |
| `avatar_url` | TEXT | - |
| `created_at` | TIMESTAMPTZ NOT NULL | `NOW()` |
| `updated_at` | TIMESTAMPTZ NOT NULL | `NOW()` |

**`auth_identities`**
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID PRIMARY KEY | - |
| `user_id` | UUID NOT NULL | FK → `profiles(id)` ON DELETE CASCADE |
| `provider` | auth_provider ENUM NOT NULL | `email`, `google`, `github`, `auth0` |
| `provider_id` | TEXT | OAuth user ID (null for email) |
| `password_hash` | TEXT | Argon2 hash (null for OAuth) |
| `verified` | BOOLEAN DEFAULT FALSE | - |
| `created_at` | TIMESTAMPTZ NOT NULL | - |

**Indexes:** `idx_auth_identities_user(user_id)`, `uq_auth_identities_provider_id(provider, provider_id)`

**`user_sessions`**
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID PRIMARY KEY | - |
| `user_id` | UUID NOT NULL | FK → `profiles(id)` ON DELETE CASCADE |
| `refresh_token_hash` | TEXT NOT NULL | - |
| `expires_at` | TIMESTAMPTZ NOT NULL | - |
| `revoked_at` | TIMESTAMPTZ | - |
| `device_info` | JSONB | User agent, IP, device name |
| `family_id` | UUID NOT NULL | FK → `user_sessions(id)` |
| `replaced_by` | UUID | FK → `user_sessions(id)` |
| `revoked_reason` | TEXT | - |
| `created_ip` | TEXT | - |
| `last_seen_at` | TIMESTAMPTZ | - |
| `created_at` | TIMESTAMPTZ NOT NULL | - |

**Indexes:** `idx_sessions_user(user_id) WHERE revoked_at IS NULL`, `idx_sessions_refresh_token_hash(refresh_token_hash)`, `idx_sessions_family_active(family_id) WHERE revoked_at IS NULL`

#### Equipment

**`categories`**
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID PRIMARY KEY | - |
| `name` | TEXT NOT NULL | - |
| `parent_id` | UUID | FK → `categories(id)` (hierarchical) |
| `created_at` | TIMESTAMPTZ NOT NULL | - |

**`equipment`**
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID PRIMARY KEY | - |
| `owner_id` | UUID NOT NULL | FK → `profiles(id)` ON DELETE CASCADE |
| `category_id` | UUID NOT NULL | FK → `categories(id)` |
| `title` | TEXT NOT NULL | - |
| `description` | TEXT | - |
| `daily_rate` | DECIMAL(8,2) NOT NULL | - |
| `condition` | condition ENUM NOT NULL | `new`, `excellent`, `good`, `fair` |
| `location` | TEXT | - |
| `coordinates` | GEOGRAPHY(POINT, 4326) | PostGIS spatial data |
| `is_available` | BOOLEAN NOT NULL DEFAULT TRUE | - |
| `created_at` | TIMESTAMPTZ NOT NULL | - |
| `updated_at` | TIMESTAMPTZ NOT NULL | - |

**Indexes:** `idx_equipment_owner(owner_id)`, `idx_equipment_category(category_id)`, `idx_equipment_available(is_available) WHERE is_available = TRUE`, `idx_equipment_is_available(is_available)`, `idx_equipment_price(daily_rate)`, `idx_equipment_location USING GIST(coordinates)`

**`equipment_photos`**
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID PRIMARY KEY | - |
| `equipment_id` | UUID NOT NULL | FK → `equipment(id)` ON DELETE CASCADE |
| `photo_url` | TEXT NOT NULL | - |
| `is_primary` | BOOLEAN NOT NULL DEFAULT FALSE | - |
| `order_index` | INTEGER NOT NULL DEFAULT 0 | - |
| `created_at` | TIMESTAMPTZ NOT NULL | - |

**Indexes:** `idx_equipment_photos_equipment(equipment_id)`, `uq_equipment_primary_photo(equipment_id) WHERE is_primary = TRUE`

#### Messaging

**`conversations`**
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID PRIMARY KEY | - |
| `created_at` | TIMESTAMPTZ NOT NULL | - |
| `updated_at` | TIMESTAMPTZ NOT NULL | - |

**`conversation_participants`**
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID PRIMARY KEY | - |
| `conversation_id` | UUID NOT NULL | FK → `conversations(id)` ON DELETE CASCADE |
| `profile_id` | UUID NOT NULL | FK → `profiles(id)` ON DELETE CASCADE |
| `last_read_at` | TIMESTAMPTZ | - |
| `created_at` | TIMESTAMPTZ NOT NULL | - |

**Unique:** `(conversation_id, profile_id)`

**`messages`**
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID PRIMARY KEY | - |
| `conversation_id` | UUID NOT NULL | FK → `conversations(id)` ON DELETE CASCADE |
| `sender_id` | UUID NOT NULL | FK → `profiles(id)` |
| `content` | TEXT NOT NULL | - |
| `created_at` | TIMESTAMPTZ NOT NULL | - |

**Index:** `idx_messages_conversation(conversation_id, created_at DESC)`

---

## API Endpoints Reference

### Base URL
`/api/v1`

### Authentication (`/api/v1/auth`)

| Method | Endpoint | Auth Required | Description |
|--------|-----------|---------------|-------------|
| POST | `/auth/auth0/signup` | No | Create user via Auth0 (email/password) |
| POST | `/auth/auth0/login` | No | Login via Auth0 password grant |
| GET | `/auth/me` | Yes | Get current user profile |

**Request/Response:**
- `POST /auth/auth0/signup`: Body `{ email, password, username? }`
- `POST /auth/auth0/login`: Body `{ email, password }` → `{ access_token, refresh_token?, id_token, token_type, expires_in }`
- `GET /auth/me`: Headers `Authorization: Bearer <token>` → `{ id, email, role, username?, full_name?, avatar_url? }`

### Equipment (`/api/v1/equipment`)

| Method | Endpoint | Auth Required | Role Required | Description |
|--------|-----------|---------------|---------------|-------------|
| GET | `/equipment` | No | - | List equipment (with pagination/filter) |
| POST | `/equipment` | Yes | `owner` or `admin` | Create equipment listing |
| GET | `/equipment/{id}` | No | - | Get equipment details |
| PUT | `/equipment/{id}` | Yes | Owner only | Update equipment |
| DELETE | `/equipment/{id}` | Yes | Owner only | Delete equipment |
| POST | `/equipment/{id}/photos` | Yes | Owner only | Add photo |
| DELETE | `/equipment/{id}/photos/{photo_id}` | Yes | Owner only | Delete photo |
| GET | `/categories` | No | - | List categories |
| GET | `/categories/{id}` | No | - | Get category details |

**Query Params (GET /equipment):**
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20)
- `category_id`: Filter by category
- `owner_id`: Filter by owner
- `search`: Search in title/description
- `min_rate`, `max_rate`: Price range filter
- `condition`: Filter by condition
- `is_available`: Boolean filter
- `lat`, `lng`: Location for geospatial search
- `radius_km`: Search radius

**Request Body (POST /equipment):**
```json
{
  "category_id": "uuid",
  "title": "string (3-200 chars)",
  "description": "string (min 10 chars)",
  "daily_rate": "decimal",
  "condition": "new|excellent|good|fair",
  "location": "string (2-255 chars)",
  "coordinates": { "lat": number, "lng": number }
}
```

### Users (`/api/v1/users`)

| Method | Endpoint | Auth Required | Description |
|--------|-----------|---------------|-------------|
| GET | `/users/me/equipment` | Yes | Get user's equipment listings |
| GET | `/users/{id}` | No | Get public user profile |
| PUT | `/users/{id}` | Yes (self) | Update user profile |

### Messages (`/api/v1/conversations`)

| Method | Endpoint | Auth Required | Description |
|--------|-----------|---------------|-------------|
| GET | `/conversations` | Yes | List user's conversations |
| POST | `/conversations` | Yes | Create conversation |
| GET | `/conversations/{id}` | Yes | Get conversation details |
| GET | `/conversations/{id}/messages` | Yes | List messages |
| POST | `/conversations/{id}/messages` | Yes | Send message |

**Request Body (POST /conversations):**
```json
{ "participant_ids": ["uuid", "uuid"] }
```

**Request Body (POST /conversations/{id}/messages):**
```json
{ "content": "string (1-5000 chars)" }
```

### Admin (`/api/v1/admin`)

| Method | Endpoint | Auth Required | Role Required | Description |
|--------|-----------|---------------|---------------|-------------|
| GET | `/admin/stats` | Yes | `admin` | Platform statistics |
| GET | `/admin/users` | Yes | `admin` | List users (paginated) |
| GET | `/admin/users/{id}` | Yes | `admin` | Get user details |
| PUT | `/admin/users/{id}/role` | Yes | `admin` | Update user role |
| DELETE | `/admin/users/{id}` | Yes | `admin` | Delete user |
| GET | `/admin/equipment` | Yes | `admin` | List all equipment |
| DELETE | `/admin/equipment/{id}` | Yes | `admin` | Force delete equipment |
| PUT | `/admin/equipment/{id}/availability` | Yes | `admin` | Toggle availability |
| GET | `/admin/categories` | Yes | `admin` | List categories |
| POST | `/admin/categories` | Yes | `admin` | Create category |
| PUT | `/admin/categories/{id}` | Yes | `admin` | Update category |
| DELETE | `/admin/categories/{id}` | Yes | `admin` | Delete category |

### WebSocket

| Endpoint | Auth Required | Description |
|----------|---------------|-------------|
| `ws://host/ws` | Yes (query param `token`) | Real-time messaging |

**Connection:** `ws://localhost:8080/ws?token=<jwt_token>`

**Messages:**
- Client → Server: `{ "conversation_id": "uuid", "content": "string" }`
- Server → Client: `{ "id": "uuid", "conversation_id": "uuid", "sender_id": "uuid", "content": "string", "created_at": "iso8601" }`

### Health & Metrics

| Method | Endpoint | Auth Required | Description |
|--------|-----------|---------------|-------------|
| GET | `/health` | No | Simple health check |
| GET | `/ready` | No | Readiness check (DB connectivity) |
| GET | `/metrics` | Conditional | Prometheus metrics (private IP OR admin token) |

---

## Authentication & Authorization

### Auth0 Integration

**All authentication flows go through Auth0.** The backend validates Auth0 JWTs.

**JWT Validation:** JWKS endpoint fetching with caching (default: 3600s TTL)

**Roles:**
- Stored in database (`profiles.role`) as single source of truth
- Default: `renter` for new users
- Admins can promote users via admin panel
- **No Auth0 role claims required** (legacy config still works but unused)

**Role-Based Access:**
| Action | Required Role |
|--------|---------------|
| Create equipment | `owner` or `admin` |
| Admin endpoints | `admin` only |
| Update/delete own equipment | Owner only |
| View equipment | Public (no auth) |

**Middleware:**
- `Auth0AuthenticatedUser` - Extracts validated user from JWT
- `JitUserProvisioningService` - Auto-creates users on first authenticated request

### Password Requirements

- Minimum 8 characters
- Cannot contain repeated patterns (>50% same char)
- Checked by zxcvbn strength scoring

---

## Configuration

### Environment Variables

**Database:**
- `DATABASE_URL` - PostgreSQL connection string

**Application:**
- `APP__ENVIRONMENT` - `development` | `production`

**JWT (OAuth only):**
- `JWT_SECRET` - Secret for local token signing
- `JWT_KID` - Key identifier (default: `v1`)
- `PREVIOUS_JWT_SECRETS` - Comma-separated old secrets for rotation

**Auth0:**
- `AUTH0_DOMAIN` - Tenant domain (e.g., `dev-xxx.us.auth0.com`)
- `AUTH0_SECRET` - Frontend session encryption (32+ random chars)
- `AUTH0_AUDIENCE` - API identifier
- `AUTH0_ISSUER` - Derived from domain if not set
- `AUTH0_JWKS_CACHE_TTL_SECS` - JWKS cache TTL (default: 3600)
- `AUTH0_CLIENT_ID` - Database connection app client ID
- `AUTH0_CLIENT_SECRET` - Database connection app secret
- `AUTH0_CONNECTION` - Connection name (default: `Username-Password-Authentication`)

**Security:**
- `SECURITY__CORS_ALLOWED_ORIGINS` - JSON array of allowed origins
- `SECURITY__METRICS_ALLOW_PRIVATE_ONLY` - Restrict metrics to private IPs
- `SECURITY__METRICS_ADMIN_TOKEN` - Admin token for metrics access
- `SECURITY__LOGIN_MAX_FAILURES` - Max failed logins before lockout (default: 5)
- `SECURITY__LOGIN_LOCKOUT_SECONDS` - Lockout duration (default: 300)
- `SECURITY__LOGIN_BACKOFF_BASE_MS` - Exponential backoff base (default: 200)
- `SECURITY__GLOBAL_RATE_LIMIT_PER_MINUTE` - Anonymous rate limit (default: 300)
- `SECURITY__GLOBAL_RATE_LIMIT_BURST_SIZE` - Burst capacity (default: 30)
- `SECURITY__GLOBAL_RATE_LIMIT_AUTHENTICATED_PER_MINUTE` - Authenticated rate limit (default: 1000)

**Logging:**
- `RUST_LOG` - Log level (e.g., `debug`, `info`)

**Sentry:**
- `SENTRY_DSN` - Error tracking DSN

### Frontend Environment

**Frontend requires separate `.env` in `frontend/` directory:**
- `AUTH0_BASE_URL` - Base URL (matches Auth0 application settings)
- `AUTH0_DOMAIN` - Same as backend
- `AUTH0_CLIENT_ID` - Frontend application client ID
- `AUTH0_SECRET` - Session encryption
- `AUTH0_AUDIENCE` - API identifier
- `API_URL` - Backend API URL (default: `http://localhost:8080`)

---

## Development Workflow

### Backend

```bash
# Run locally
make run              # cargo run
make test             # Run all tests
make check-all        # CI gate (fmt + clippy + test + audit)
make migrate          # Run migrations
make migrate-revert   # Rollback migration

# Build
make build            # Debug build
make build-release    # Release build
```

### Docker

```bash
docker-compose up --build      # Start all services
docker-compose logs -f backend # View backend logs
docker-compose down            # Stop services
docker-compose down -v         # Stop + remove volumes
```

### Frontend

```bash
cd frontend
npm install
npm run dev          # Development server
npm run build        # Production build
npm run start        # Start production server
npm run lint        # ESLint
```

---

## Testing

### Backend Tests (572+ tests)

**Test Structure:**
- `tests/core_api_tests.rs` - Core API behavior
- `tests/auth0_endpoints_tests.rs` - Auth0 integration
- `tests/message_routes_tests.rs` - Messaging endpoints
- `tests/repository_integration_tests.rs` - Repository layer
- `tests/ws_security_tests.rs` - WebSocket security
- `tests/rate_limiting_tests.rs` - Rate limiting behavior
- `tests/common/` - Shared test helpers

**Running Tests:**
```bash
make test              # All tests
make test-integration   # Integration tests only
```

**Test Database:** Uses global advisory lock to avoid cross-process state races.

---

## Common Patterns

### Adding a New API Endpoint

1. Define DTO in `src/api/dtos/`
2. Add route in appropriate `src/api/routes/*.rs`
3. Create/extend service method in `src/application/`
4. Implement repository method if needed in `src/infrastructure/repositories/`
5. Add tests in `tests/*_tests.rs`

### Adding a New Frontend Page

1. Create `src/app/{route}/page.tsx` (server component)
2. Create client components as needed `'use client'`
3. Use `fetchServer()` for authenticated calls
4. Use `fetchClient()` for client-side calls

### Database Migration

```bash
# Create new migration
sqlx migrate add <description>

# Write up/down SQL in migrations/

# Apply migration
make migrate
```

---

## Important Notes

### Equipment Creation Requires Owner/Admin Role

`POST /api/equipment` requires database role `owner` or `admin`. New users default to `renter`.

**Promote a user:**
```sql
UPDATE profiles SET role = 'admin' WHERE email = 'user@example.com';
```

See `docs/auth0-role-requirements.md` for details.

### Local vs Production Environment

| Variable | Local | Production |
|----------|-------|------------|
| `AUTH0_BASE_URL` | `http://localhost:3000` | Your actual domain/host |
| `API_URL` (frontend) | `http://localhost:8080` | Your backend URL |

**Auth0 Application Settings must match:**
- Allowed Callback URLs
- Allowed Logout URLs
- Allowed Web Origins
- Allowed Origins (CORS)

### WebSocket Connection

Use query param for auth: `ws://host/ws?token=<jwt_token>`

### Error Handling

Standard error response:
```json
{ "error": "ErrorType", "message": "Human readable message" }
```

Error types: `BadRequest`, `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`, `InternalError`

### Frontend API Proxy

All backend calls go through `/api/proxy/[...path]/` to inject Auth0 access token automatically.

---

## Code Quality

### Linting & Formatting

```bash
make fmt-check     # Check formatting
make clippy        # Run clippy linter
make audit         # Check for security vulnerabilities
```

Treat clippy warnings as errors.

### Naming Conventions

- Functions/Modules/Files: `snake_case`
- Types/Traits: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`

---

## Troubleshooting

### "Equipment creation returns 403"
- User's role in database is not `owner` or `admin`
- Promote user via admin panel or direct SQL update

### "Auth0 callback mismatch"
- `AUTH0_BASE_URL` doesn't match Auth0 application settings
- Check Allowed Callback URLs in Auth0 dashboard

### "Database connection failed"
- Ensure `make docker-up` is running
- Check `DATABASE_URL` in `.env`

### "WebSocket connection refused"
- Include `token` query parameter
- Token must be valid Auth0 access token
- Check `ws://host/ws` is accessible

---

## Files to Know

| Purpose | Location |
|---------|----------|
| Main entry point | `src/main.rs` |
| Route configuration | `src/api/routes/mod.rs` |
| Domain models | `src/domain/*.rs` |
| Database pool | `src/infrastructure/db/pool.rs` |
| Auth0 claims parsing | `src/utils/auth0_claims.rs` |
| JWKS validation | `src/utils/auth0_jwks.rs` |
| Config types | `src/config/app_config.rs` |
| Error types | `src/error/mod.rs` |
| Frontend layout | `frontend/src/app/layout.tsx` |
| Frontend API client | `frontend/src/lib/api.ts` |
| Frontend auth | `frontend/src/lib/auth0.ts` |
| Frontend server fetch | `frontend/src/lib/server.ts` |

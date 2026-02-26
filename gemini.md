# Gemini AI Development Guide

This guide provides context and instructions for Google Gemini AI working on this Rust Backend & Next.js Frontend monorepo.

---

## Project Overview

**Technology Stack:**
- **Backend:** Rust 2021 edition with Actix-web 4.8.0
- **Frontend:** Next.js 16.1.6 with App Router and TypeScript
- **Database:** PostgreSQL with PostGIS for geospatial queries
- **Authentication:** Auth0 with JWT validation (JWKS)
- **API Style:** REST with WebSocket support
- **Documentation:** OpenAPI/Swagger with utoipa

**Architecture Pattern:** Clean Architecture with layered modules
```
Presentation (api/) → Application (application/) → Domain (domain/) ← Infrastructure (infrastructure/)
```

---

## File Locations Reference

| Type | Location |
|-------|----------|
| HTTP Routes | `src/api/routes/` |
| Data Transfer Objects | `src/api/dtos/` |
| Business Services | `src/application/` |
| Domain Models | `src/domain/` |
| Database Repositories | `src/infrastructure/repositories/` |
| Database Migrations | `migrations/` |
| Tests | `tests/` |
| Frontend Pages | `frontend/src/app/` |
| Frontend Components | `frontend/src/components/` |
| Frontend Utilities | `frontend/src/lib/` |

---

## Database Schema Reference

### Core Tables

#### Users & Authentication

**profiles** - User accounts
| Column | Type | Description |
|--------|------|-------------|
| id | UUID PRIMARY KEY | Auto-generated |
| email | TEXT UNIQUE NOT NULL | User email |
| role | role ENUM NOT NULL | `renter`, `owner`, `admin` |
| username | TEXT UNIQUE | Optional username |
| full_name | TEXT | Display name |
| avatar_url | TEXT | Profile picture URL |
| created_at | TIMESTAMPTZ NOT NULL | Creation timestamp |
| updated_at | TIMESTAMPTZ NOT NULL | Last update timestamp |

**auth_identities** - Authentication methods (email, OAuth)
| Column | Type | Description |
|--------|------|-------------|
| id | UUID PRIMARY KEY | - |
| user_id | UUID NOT NULL | FK to profiles.id |
| provider | auth_provider ENUM NOT NULL | `email`, `google`, `github`, `auth0` |
| provider_id | TEXT | OAuth provider user ID |
| password_hash | TEXT | Argon2 hashed password |
| verified | BOOLEAN DEFAULT FALSE | Email verification status |
| created_at | TIMESTAMPTZ NOT NULL | - |

**user_sessions** - Refresh token management
| Column | Type | Description |
|--------|------|-------------|
| id | UUID PRIMARY KEY | - |
| user_id | UUID NOT NULL | FK to profiles.id |
| refresh_token_hash | TEXT NOT NULL | Hashed refresh token |
| expires_at | TIMESTAMPTZ NOT NULL | Expiration time |
| revoked_at | TIMESTAMPTZ | Revocation time |
| device_info | JSONB | User agent, IP, device |
| family_id | UUID NOT NULL | Session family ID |
| replaced_by | UUID | Replaced session ID |
| revoked_reason | TEXT | Revocation reason |
| created_ip | TEXT | IP at creation |
| last_seen_at | TIMESTAMPTZ | Last activity |
| created_at | TIMESTAMPTZ NOT NULL | - |

#### Equipment Management

**categories** - Hierarchical categories
| Column | Type | Description |
|--------|------|-------------|
| id | UUID PRIMARY KEY | - |
| name | TEXT NOT NULL | Category name |
| parent_id | UUID | FK to categories.id (self-referential) |
| created_at | TIMESTAMPTZ NOT NULL | - |

**equipment** - Equipment listings
| Column | Type | Description |
|--------|------|-------------|
| id | UUID PRIMARY KEY | - |
| owner_id | UUID NOT NULL | FK to profiles.id (owner) |
| category_id | UUID NOT NULL | FK to categories.id |
| title | TEXT NOT NULL | Listing title |
| description | TEXT | Description |
| daily_rate | DECIMAL(8,2) NOT NULL | Daily rental rate |
| condition | condition ENUM NOT NULL | `new`, `excellent`, `good`, `fair` |
| location | TEXT | Location name |
| coordinates | GEOGRAPHY(POINT) | PostGIS lat/lng |
| is_available | BOOLEAN NOT NULL DEFAULT TRUE | Availability status |
| created_at | TIMESTAMPTZ NOT NULL | - |
| updated_at | TIMESTAMPTZ NOT NULL | - |

**equipment_photos** - Equipment photos
| Column | Type | Description |
|--------|------|-------------|
| id | UUID PRIMARY KEY | - |
| equipment_id | UUID NOT NULL | FK to equipment.id |
| photo_url | TEXT NOT NULL | Image URL |
| is_primary | BOOLEAN NOT NULL DEFAULT FALSE | Primary photo flag |
| order_index | INTEGER NOT NULL DEFAULT 0 | Display order |
| created_at | TIMESTAMPTZ NOT NULL | - |

#### Messaging

**conversations** - Chat conversations
| Column | Type | Description |
|--------|------|-------------|
| id | UUID PRIMARY KEY | - |
| created_at | TIMESTAMPTZ NOT NULL | - |
| updated_at | TIMESTAMPTZ NOT NULL | - |

**conversation_participants** - Conversation members
| Column | Type | Description |
|--------|------|-------------|
| id | UUID PRIMARY KEY | - |
| conversation_id | UUID NOT NULL | FK to conversations.id |
| profile_id | UUID NOT NULL | FK to profiles.id |
| last_read_at | TIMESTAMPTZ | Last read timestamp |
| created_at | TIMESTAMPTZ NOT NULL | - |

**messages** - Individual messages
| Column | Type | Description |
|--------|------|-------------|
| id | UUID PRIMARY KEY | - |
| conversation_id | UUID NOT NULL | FK to conversations.id |
| sender_id | UUID NOT NULL | FK to profiles.id |
| content | TEXT NOT NULL | Message text |
| created_at | TIMESTAMPTZ NOT NULL | - |

---

## API Endpoints Summary

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/auth0/signup` | No | Create account via Auth0 |
| POST | `/api/v1/auth/auth0/login` | No | Login via Auth0 |
| GET | `/api/v1/auth/me` | Yes | Get current user profile |

### Equipment

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| GET | `/api/v1/equipment` | No | - | List equipment with filters |
| POST | `/api/v1/equipment` | Yes | owner/admin | Create equipment |
| GET | `/api/v1/equipment/{id}` | No | - | Get equipment details |
| PUT | `/api/v1/equipment/{id}` | Yes | owner | Update equipment |
| DELETE | `/api/v1/equipment/{id}` | Yes | owner | Delete equipment |
| POST | `/api/v1/equipment/{id}/photos` | Yes | owner | Add photo |
| DELETE | `/api/v1/equipment/{id}/photos/{photo_id}` | Yes | owner | Delete photo |
| GET | `/api/v1/categories` | No | - | List categories |
| GET | `/api/v1/categories/{id}` | No | - | Get category |

### Users

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/users/me/equipment` | Yes | Get my equipment |
| GET | `/api/v1/users/{id}` | No | Get public profile |
| PUT | `/api/v1/users/{id}` | Yes | Update profile |

### Messaging

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/conversations` | Yes | List conversations |
| POST | `/api/v1/conversations` | Yes | Create conversation |
| GET | `/api/v1/conversations/{id}` | Yes | Get conversation |
| GET | `/api/v1/conversations/{id}/messages` | Yes | List messages |
| POST | `/api/v1/conversations/{id}/messages` | Yes | Send message |

### Admin (admin role only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/admin/stats` | Platform statistics |
| GET | `/api/v1/admin/users` | List users (paginated) |
| GET | `/api/v1/admin/users/{id}` | Get user details |
| PUT | `/api/v1/admin/users/{id}/role` | Update user role |
| DELETE | `/api/v1/admin/users/{id}` | Delete user |
| GET | `/api/v1/admin/equipment` | List all equipment |
| DELETE | `/api/v1/admin/equipment/{id}` | Force delete |
| PUT | `/api/v1/admin/equipment/{id}/availability` | Toggle availability |
| GET | `/api/v1/admin/categories` | List categories |
| POST | `/api/v1/admin/categories` | Create category |
| PUT | `/api/v1/admin/categories/{id}` | Update category |
| DELETE | `/api/v1/admin/categories/{id}` | Delete category |

### WebSocket

| Endpoint | Auth | Description |
|----------|------|-------------|
| `ws://host/ws?token=<jwt>` | Yes (token param) | Real-time messaging |

---

## Authentication & Authorization

### Auth0 Integration

**Key Points:**
- All authentication flows through Auth0
- Backend validates Auth0 JWTs using JWKS
- Roles are stored in database, NOT in JWT claims
- Default role for new users: `renter`

### Role Requirements

| Action | Required Role |
|--------|---------------|
| Create equipment | `owner` or `admin` |
| Access admin endpoints | `admin` |
| Update/delete own equipment | Equipment owner only |
| View equipment | Public (no auth required) |

### JWT Validation

- Algorithm: RS256
- Key source: JWKS endpoint from Auth0
- Cache TTL: 3600 seconds (configurable)
- Middleware: `Auth0AuthenticatedUser` extractor

### Password Requirements

- Minimum 8 characters
- No repeated character patterns
- Validated by zxcvbn strength scorer

---

## Code Patterns for AI

### Adding a Backend Endpoint

**1. Define DTO in `src/api/dtos/`:**
```rust
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateRequest {
    #[validate(length(min = 1))]
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Response {
    pub id: Uuid,
    pub name: String,
}
```

**2. Add route in `src/api/routes/*.rs`:**
```rust
.route("/resource", web::post().to(create_resource))

#[utoipa::path(
    post,
    path = "/api/v1/resource",
    request_body = CreateRequest,
    responses(
        (status = 201, description = "Created", body = Response),
        (status = 400, description = "Bad request"),
    ),
    tag = "resource"
)]
async fn create_resource(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    payload: web::Json<CreateRequest>,
) -> AppResult<HttpResponse> {
    payload.validate()?;
    let user_id = auth.0.user_id;
    let result = state.resource_service.create(user_id, payload.into_inner()).await?;
    Ok(HttpResponse::Created().json(result))
}
```

**3. Add service method in `src/application/*.rs`:**
```rust
impl ResourceService {
    pub async fn create(&self, user_id: Uuid, data: CreateRequest) -> AppResult<Response> {
        // Business logic here
        let entity = self.repo.create(...).await?;
        Ok(Response::from(entity))
    }
}
```

### Frontend Page Pattern

**Server Component (data fetching):**
```tsx
// frontend/src/app/example/page.tsx
import { fetchServer } from '@/lib/server';

export default async function ExamplePage() {
  const res = await fetchServer('/api/equipment');
  const data = await res.json();

  return (
    <main>
      {/* Render data */}
    </main>
  );
}
```

**Client Component (interactivity):**
```tsx
'use client';
import { useState } from 'react';

export default function InteractiveForm() {
  const [value, setValue] = useState('');

  return (
    <form onSubmit={handleSubmit}>
      <input value={value} onChange={(e) => setValue(e.target.value)} />
    </form>
  );
}
```

### Database Query with SQLx

```rust
use sqlx::query_as;
use uuid::Uuid;

let user = query_as!(
    User,
    "SELECT * FROM profiles WHERE id = $1",
    user_id
)
.fetch_one(&pool)
.await?;
```

**Important:** Always use parameterized queries - SQLx prevents SQL injection by design.

---

## Environment Variables

### Backend (.env)

**Required:**
- `DATABASE_URL` - PostgreSQL connection string
- `AUTH0_DOMAIN` - Auth0 tenant (e.g., `dev-xxx.us.auth0.com`)
- `AUTH0_SECRET` - Session encryption (32+ random chars)
- `AUTH0_AUDIENCE` - API identifier
- `AUTH0_CLIENT_ID` - Database connection app ID
- `AUTH0_CLIENT_SECRET` - Database connection app secret

**Optional:**
- `RUST_LOG` - Log level (debug, info, warn, error)
- `SENTRY_DSN` - Error tracking
- `SECURITY__CORS_ALLOWED_ORIGINS` - JSON array of allowed origins
- Rate limiting settings (see config/default.toml)

### Frontend (frontend/.env.local)

**Required:**
- `AUTH0_BASE_URL` - Frontend base URL (matches Auth0 app settings)
- Same Auth0 vars as backend
- `API_URL` - Backend API URL

---

## Development Commands

### Backend

```bash
make run              # Start backend
make test             # Run all tests (572+ tests)
make check-all        # CI gate (fmt + clippy + test + audit)
make migrate          # Apply migrations
make docker-up        # Start PostgreSQL
```

### Frontend

```bash
cd frontend
npm install
npm run dev          # Development server
npm run build        # Production build
```

---

## Common Issues & Solutions

### "POST /api/equipment returns 403"

**Cause:** User's database role is `renter` (default)

**Solution:** Promote user:
```sql
UPDATE profiles SET role = 'owner' WHERE email = 'user@example.com';
```

### "Auth0 callback mismatch"

**Cause:** `AUTH0_BASE_URL` doesn't match Auth0 application settings

**Solution:** Ensure Auth0 dashboard has:
- Allowed Callback URLs: `http://localhost:3000/auth/callback`
- Allowed Logout URLs: `http://localhost:3000`
- Allowed Web Origins: `http://localhost:3000`
- Allowed Origins (CORS): `http://localhost:3000`

### "Database is not ready"

**Cause:** PostgreSQL not running or migrations not applied

**Solution:**
```bash
make docker-up
make migrate
```

### "WebSocket connection refused"

**Cause:** Wrong WebSocket URL or missing token

**Solution:** Use query parameter for auth:
```
ws://localhost:8080/ws?token=<jwt_access_token>
```

### "Type mismatch enum"

**Cause:** Enums serialize/deserialize as lowercase

**Solution:** Ensure JSON uses lowercase: `"renter"`, `"owner"`, `"admin"`

---

## Testing Guidelines

### Backend Tests

**Location:** `tests/` directory

**Structure:**
- `core_api_tests.rs` - Core API behavior
- `auth0_endpoints_tests.rs` - Auth0 integration
- `message_routes_tests.rs` - Messaging
- `repository_integration_tests.rs` - Repository layer
- `ws_security_tests.rs` - WebSocket security
- `rate_limiting_tests.rs` - Rate limiting
- `tests/common/` - Shared helpers

**Running tests:**
```bash
make test              # All tests
make test-integration   # Integration tests only
```

### Test Template

```rust
#[actix_rt::test]
async fn test_feature() {
    // 1. Setup
    let pool = setup_test_db().await;

    // 2. Execute
    let result = my_function(&pool).await;

    // 3. Assert
    assert!(result.is_ok());
}
```

---

## Security Guidelines

1. **Never commit secrets** - `.env` is gitignored
2. **Always validate input** - Use `validator` crate
3. **Use parameterized queries** - SQLx enforces this
4. **Check authorization** - Use role-based access
5. **Rate limit sensitive operations** - Login is throttled
6. **Don't expose PII** - Redact in logs

---

## Important Notes

1. **Roles are database-only** - Don't check JWT claims for authorization
2. **Coordinates format** - DB: `"lat, lng"` string, DTO: `{lat, lng}` object
3. **Frontend API calls** - Always use `fetchServer()` or `fetchClient()`, never direct URLs
4. **Enum serialization** - All enums use lowercase
5. **WebSocket auth** - Use `?token=` query param, not headers

---

## Key Files

| Purpose | File |
|---------|-------|
| Entry point | `src/main.rs` |
| Route config | `src/api/routes/mod.rs` |
| Auth0 claims | `src/utils/auth0_claims.rs` |
| JWKS validation | `src/utils/auth0_jwks.rs` |
| Config types | `src/config/app_config.rs` |
| Error handling | `src/error/mod.rs` |
| Frontend layout | `frontend/src/app/layout.tsx` |
| Frontend API client | `frontend/src/lib/api.ts` |
| Frontend auth | `frontend/src/lib/auth0.ts` |

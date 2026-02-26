# AI Agent Development Guide

This guide provides context and patterns for AI agents (Claude, Cursor, Copilot, etc.) working on this Rust Backend & Next.js Frontend monorepo.

---

## Agent Context Summary

**Repository:** Full-stack equipment rental platform
- **Backend:** Rust (Actix-web 4.8.0)
- **Frontend:** Next.js 16.1.6 (App Router)
- **Database:** PostgreSQL + PostGIS
- **Auth:** Auth0 (JWT validation, OAuth providers)
- **Architecture:** Clean Architecture with layered modules

---

## Quick Agent Reference

| Task | Location | Notes |
|------|----------|-------|
| Add API endpoint | `src/api/routes/*.rs` + `src/api/dtos/*.rs` | Follow existing route patterns |
| Add business logic | `src/application/*.rs` | Services coordinate repositories |
| Add domain model | `src/domain/*.rs` | Pure entities, no dependencies |
| Add DB operation | `src/infrastructure/repositories/*.rs` | Repository traits + impls |
| Add migration | `migrations/*.sql` | Both .up.sql and .down.sql |
| Add frontend page | `frontend/src/app/**/page.tsx` | Server or client component |
| Add frontend component | `frontend/src/components/*.tsx` | Client components with `'use client'` |

---

## Layer Architecture Rules

```
┌─────────────────────────────────────────┐
│ api/ - HTTP handlers, DTOs           │ → Uses: application services
├─────────────────────────────────────────┤
│ application/ - Business orchestration   │ → Uses: domain + repositories
├─────────────────────────────────────────┤
│ domain/ - Pure business entities       │ → No external dependencies
├─────────────────────────────────────────┤
│ infrastructure/ - External concerns    │ → DB, Auth0 API, file I/O
└─────────────────────────────────────────┘
```

**Follow these dependencies:**
- `api/` → `application/`
- `application/` → `domain/` + `infrastructure/repositories`
- `infrastructure/` → `domain/`
- **Never reverse these dependencies!**

---

## Common Code Patterns

### Adding a New API Endpoint

1. **Create DTO** in `src/api/dtos/`:
```rust
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

2. **Add route** in appropriate `src/api/routes/*.rs`:
```rust
.route("/resource", web::post().to(create_resource))

async fn create_resource(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    payload: web::Json<CreateRequest>,
) -> AppResult<HttpResponse> {
    payload.validate()?; // Always validate input
    let result = state.resource_service.create(...).await?;
    Ok(HttpResponse::Created().json(result))
}
```

3. **Create/update service** in `src/application/*_service.rs`:
```rust
pub async fn create(&self, user_id: Uuid, data: CreateRequest) -> AppResult<Response> {
    let entity = self.repo.create(...).await?;
    Ok(Response::from(entity))
}
```

4. **Add test** in `tests/*_tests.rs`:
```rust
#[actix_rt::test]
async fn test_create_resource() {
    // Arrange: Setup test data
    // Act: Call endpoint
    // Assert: Verify response
}
```

### Authentication in Routes

**Protected routes:** Add `Auth0AuthenticatedUser` parameter
```rust
async fn protected_route(
    auth: Auth0AuthenticatedUser,  // Auto-validates JWT
) -> AppResult<HttpResponse> {
    let user_id = auth.0.user_id;  // Extract user ID
    // ...
}
```

**Role checks:** Call helper functions
```rust
use crate::api::routes::admin::require_admin;
async fn admin_route(
    auth: Auth0AuthenticatedUser,
) -> AppResult<HttpResponse> {
    let _ = require_admin(&auth)?;  // Returns 403 if not admin
    // ...
}
```

### Database Queries with SQLx

**Parameterized queries are mandatory** (SQLx enforces this):
```rust
// ✅ Correct
let user = sqlx::query_as!(
    User,
    "SELECT * FROM profiles WHERE id = $1",
    user_id
).fetch_one(&pool).await?;

// ❌ Never use string interpolation
sqlx::query!("SELECT * FROM profiles WHERE id = '{user_id}'") // Compile error
```

**Optional fields:**
```rust
#[derive(FromRow)]
pub struct MyStruct {
    id: Uuid,
    optional_field: Option<String>,  // NULL in DB → None in Rust
}
```

### Error Handling

**Return `AppResult<T>` (alias for `Result<T, AppError>`):**
```rust
use crate::error::{AppError, AppResult};

async fn my_function() -> AppResult<MyStruct> {
    let data = fetch_data().await
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed: {e}")))?;
    Ok(data)
}
```

**Common error types:**
- `AppError::BadRequest` - Invalid input (400)
- `AppError::Unauthorized` - No auth (401)
- `AppError::Forbidden` - Auth but no permission (403)
- `AppError::NotFound` - Resource missing (404)
- `AppError::Conflict` - Duplicate/resource exists (409)
- `AppError::InternalError` - Unexpected errors (500)

---

## Frontend Patterns

### Server Components (Data Fetching)

Use `fetchServer()` for authenticated backend calls:
```tsx
// app/example/page.tsx
import { fetchServer } from '@/lib/server';

export default async function ExamplePage() {
  const res = await fetchServer('/api/equipment');
  const data = await res.json();

  return <div>{/* render data */}</div>;
}
```

### Client Components (Interactivity)

Use `'use client'` for state/interactivity:
```tsx
'use client';
import { useState } from 'react';

export default function InteractiveForm() {
  const [value, setValue] = useState('');
  return <input value={value} onChange={e => setValue(e.target.value)} />;
}
```

### Client-Side API Calls

Use `fetchClient()` which proxies through `/api/proxy/`:
```tsx
import { fetchClient } from '@/lib/api';

const res = await fetchClient('/equipment', {
  method: 'POST',
  body: JSON.stringify({ title: 'New Item' }),
});
```

### Forms with React Hook Form + Zod

```tsx
'use client';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';

const schema = z.object({
  title: z.string().min(3, 'Title must be at least 3 characters'),
});

export default function MyForm() {
  const form = useForm({ resolver: zodResolver(schema) });

  return (
    <Form {...form}>
      <FormField name="title" render={({ field }) => (
        <FormItem>
          <FormControl><Input {...field} /></FormControl>
        </FormItem>
      )} />
    </Form>
  );
}
```

---

## Testing Patterns

### Integration Test Template

```rust
mod common;
use actix_web::{test as actix_test, web, App};
use rust_backend::api::routes::AppState;
// ... imports

#[actix_rt::test]
async fn test_my_feature() {
    // 1. Setup test app with test DB
    let pool = setup_test_db().await;
    let app = actix_test::init_service(
        App::new().app_data(web::Data::new(create_app_state(pool)))
    ).await;

    // 2. Make request
    let req = actix_test::TestRequest::post()
        .uri("/api/v1/resource")
        .set_json(&test_payload)
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    // 3. Assert response
    assert!(resp.status().is_success());
}
```

### Test Fixtures in `tests/common/`

Use shared setup code:
```rust
use crate::common::{setup_test_db, create_test_user};

async fn test_with_user() {
    let (pool, user) = create_test_user(&pool).await;
    // ... test with authenticated user
}
```

---

## Important Gotchas

### Equipment Creation 403 Error

**Problem:** `POST /api/equipment` returns 403 even with valid token.

**Cause:** User's database role is `renter`. Only `owner` or `admin` can create equipment.

**Solution:** Promote user:
```sql
UPDATE profiles SET role = 'admin' WHERE email = 'user@example.com';
```

### Auth0 Role Claims

**Legacy:** Old code used Auth0 token claims for roles.

**Current:** Roles are database-only. Auth0 claims provide default value only.

**Don't** check token claims for role authorization. Query the database.

### Coordinates Format

**Database:** PostGIS `GEOGRAPHY(POINT, 4326)`

**Domain model:** Stored as comma-separated string `"lat, lng"`

**DTO/JSON:** Object `{ "lat": number, "lng": number }`

**Conversion:** Use `equipment.coordinates_tuple()` and `equipment.set_coordinates(lat, lng)`

### Enum Serialization

All enums serialize/deserialize as lowercase:
```rust
#[sqlx(type_name = "role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role { Renter, Owner, Admin }
// JSON: "renter", "owner", "admin"
```

### Frontend API Proxy

**Never call backend directly.** Always use:
- Server component: `fetchServer('/api/...')`
- Client component: `fetchClient('/api/...')`

The proxy injects the Auth0 access token automatically.

### WebSocket Authentication

**Don't use WebSocket with Bearer header.** Use query parameter:
```
ws://localhost:8080/ws?token=<jwt_access_token>
```

---

## Code Search Locations

| What to find | Search in |
|--------------|-----------|
| All API routes | `src/api/routes/mod.rs` route configurations |
| Domain models | `src/domain/*.rs` (user.rs, equipment.rs, etc.) |
| DTOs | `src/api/dtos/*.rs` |
| Services | `src/application/*.rs` |
| Repositories | `src/infrastructure/repositories/*.rs` |
| DB migrations | `migrations/*.sql` |
| Frontend pages | `frontend/src/app/**/page.tsx` |
| Frontend components | `frontend/src/components/*.tsx` |

---

## Before You Code

1. **Read existing code** in the same module you're modifying
2. **Check for similar patterns** - don't reinvent
3. **Understand the layer** - are you adding at api, application, domain, or infrastructure?
4. **Add tests** - especially for auth, security, and user data
5. **Run `make check-all`** before committing

---

## Makefile Commands

| Command | Purpose |
|----------|---------|
| `make run` | Start backend (`cargo run`) |
| `make test` | Run all tests |
| `make check-all` | CI gate (fmt + clippy + test + audit) |
| `make migrate` | Apply migrations |
| `make docker-up` | Start PostgreSQL in Docker |
| `make docker-down` | Stop Docker services |

---

## Environment Setup

Copy `.env.example` to `.env` and fill in:

**Required for basic operation:**
- `DATABASE_URL` - PostgreSQL connection
- `AUTH0_DOMAIN` - Auth0 tenant
- `AUTH0_SECRET` - Frontend session secret (32+ chars)
- `AUTH0_AUDIENCE` - API identifier
- `AUTH0_CLIENT_ID` - Database connection app ID
- `AUTH0_CLIENT_SECRET` - Database connection app secret

**Frontend also needs** `frontend/.env.local`:
- `AUTH0_BASE_URL` - Frontend base URL
- Same Auth0 vars as backend

---

## Security Rules

1. **Never commit secrets** - `.env` is in `.gitignore`
2. **Always validate input** - Use `validator` crate for DTOs
3. **Always use parameterized queries** - SQLx enforces this
4. **Check authorization** - Use `require_admin()` for admin routes
5. **Rate limit sensitive operations** - Login already throttled
6. **Don't expose PII** - Redact emails/names in debug logs

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| "Database is not ready" | Run `make docker-up` and `make migrate` |
| "Module not found" | Check imports use `crate::` not `rust_backend::` |
| "Type mismatch" | Enums are lowercase in DB/JSON |
| "401 Unauthorized" | Check token is valid and not expired |
| "403 Forbidden" | Check user role in DB, not token claims |
| "WebSocket fails" | Use `?token=` query param, not header |

# Rust Backend & Next.js Frontend

A full-stack equipment rental platform with a Rust backend (Actix-web), Next.js frontend, and Auth0 authentication.

---

## Documentation

| Document | Purpose |
|----------|---------|
| [claude.md](./claude.md) | Comprehensive development guide for Claude Code |
| [AGENTS.md](./AGENTS.md) | AI agent specific development guidelines |
| [gemini.md](./gemini.md) | Google Gemini AI development guide |
| [frontend/README.md](./frontend/README.md) | Frontend-specific documentation |
| [docs/auth0-role-requirements.md](./docs/auth0-role-requirements.md) | Auth0 setup and role configuration |

---

## Technology Stack

### Backend (Rust)
| Technology | Version | Purpose |
|-----------|---------|---------|
| Actix-web | 4.8.0 | HTTP server framework |
| SQLx | 0.8.6 | Type-safe database operations |
| PostgreSQL | Latest | Primary database |
| PostGIS | Latest | Geospatial queries |
| Auth0 | Latest | Authentication & JWT validation |
| utoipa | Latest | OpenAPI/Swagger documentation |
| Argon2 | Latest | Password hashing |
| JWT | 9 | Token validation |

### Frontend (Next.js)
| Technology | Version | Purpose |
|-----------|---------|---------|
| Next.js | 16.1.6 | React framework with App Router |
| React | 19.2.4 | UI library |
| TypeScript | Latest | Type safety |
| Auth0 SDK | 4.15.0 | Authentication |
| Tailwind CSS | Latest | Styling |
| shadcn/ui | Latest | UI component library |

---

## Architecture

### Backend (Clean Architecture)

```
src/
├── api/              # HTTP routes, DTOs, OpenAPI docs
├── application/      # Business logic services
├── domain/           # Pure domain models
├── infrastructure/   # DB, repositories, external APIs
├── middleware/       # Auth, logging, rate limiting
├── security/         # CORS, headers, throttling
├── config/           # Configuration loading
└── error/           # Error handling
```

### Frontend (App Router)

```
frontend/src/
├── app/              # Next.js App Router pages
├── components/       # React components
├── lib/             # Utilities (API, auth)
├── hooks/           # Custom React hooks
└── actions/         # Server Actions
```

---

## Quick Start (Docker)

### Prerequisites

- [Docker & Docker Compose](https://www.docker.com/products/docker-desktop/)
- [Auth0 Account](https://auth0.com/)

### 1. Clone Repository

```bash
git clone <repository-url>
cd rust-backend
```

### 2. Configure Environment Variables

```bash
cp .env.example .env
```

**Required Auth0 Variables:**

| Variable | Description |
|----------|-------------|
| `AUTH0_DOMAIN` | Auth0 tenant (e.g., `dev-xxx.us.auth0.com`) |
| `AUTH0_CLIENT_ID` | Auth0 application client ID |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret |
| `AUTH0_SECRET` | Frontend session secret (32+ random chars) |
| `AUTH0_AUDIENCE` | API identifier in Auth0 |

### 3.1 Environment: Local vs Production

| Variable | Local | Production |
|----------|-------|------------|
| `AUTH0_BASE_URL` | `http://localhost:3000` | `https://your-domain.com` |

**Auth0 Application Settings (must match):**
- Allowed Callback URLs: `http://localhost:3000/auth/callback` (or production URL)
- Allowed Logout URLs: `http://localhost:3000`
- Allowed Web Origins: `http://localhost:3000`
- Allowed Origins (CORS): `http://localhost:3000`

### 3. Run Everything

```bash
docker-compose up --build
```

**Access Points:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8080
- PostgreSQL: localhost:5432
- Swagger/OpenAPI: http://localhost:8080/swagger-ui/

---

## Local Development (Manual)

### Backend

```bash
# Start PostgreSQL
make docker-up

# Run migrations
make migrate

# Start backend
make run

# Run tests
make test

# Run CI gate
make check-all
```

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Run linter
npm run lint
```

---

## Database Schema

### Core Tables

| Table | Purpose |
|-------|---------|
| `profiles` | User accounts with roles |
| `auth_identities` | Authentication methods (email, OAuth) |
| `user_sessions` | Refresh token management |
| `categories` | Hierarchical equipment categories |
| `equipment` | Equipment listings with geospatial data |
| `equipment_photos` | Equipment photos |
| `conversations` | Chat conversations |
| `conversation_participants` | Conversation members |
| `messages` | Individual chat messages |

### Extensions

- `pgcrypto` - UUID generation
- `postgis` - Geospatial data support

**Full schema details:** See `CLAUDE.md` - Database Schema section

---

## API Endpoints

### Base URL: `/api/v1`

| Category | Endpoints | Auth Required |
|----------|-----------|---------------|
| Auth | `POST /auth/auth0/signup`, `POST /auth/auth0/login`, `GET /auth/me` | Mixed |
| Equipment | `GET/POST /equipment`, `GET/PUT/DELETE /equipment/{id}` | Mixed |
| Users | `GET /users/me/equipment`, `GET/PUT /users/{id}` | Yes for updates |
| Messages | `GET/POST /conversations`, `GET/POST /conversations/{id}/messages` | Yes |
| Admin | `/admin/*` | Yes (admin role only) |
| WebSocket | `ws://host/ws?token=<jwt>` | Yes |

**Full API reference:** See `CLAUDE.md` - API Endpoints section

---

## Authentication & Authorization

### Auth0 Integration

- All authentication flows through Auth0
- JWT validation via JWKS endpoint
- Roles stored in database (NOT in JWT claims)
- Default role for new users: `renter`

### Role-Based Access

| Role | Permissions |
|-------|-------------|
| `renter` | Browse equipment, send messages |
| `owner` | Create/manage own equipment |
| `admin` | All permissions + user management |

**Note:** `POST /api/equipment` requires `owner` or `admin` role.

---

## Setting Up First Admin User

### Via Docker

```bash
docker compose exec postgres psql -U postgres -d rust_backend

UPDATE profiles SET role = 'admin' WHERE email = 'user@example.com';
```

### Via Direct Connection

```bash
PGPASSWORD=postgres psql -h localhost -p 5432 -U postgres -d rust_backend

UPDATE profiles SET role = 'admin' WHERE id = '<user-id>';
```

---

## Docker Services

| Service | Port | Description |
|----------|------|-------------|
| `postgres` | 5432 | PostgreSQL database |
| `backend` | 8080 | Rust API server |
| `frontend` | 3000 | Next.js application |

### Service Dependencies

- `backend` waits for `postgres` to be healthy
- `frontend` waits for `backend` to be healthy

### Viewing Logs

```bash
docker-compose logs -f          # All services
docker-compose logs -f backend  # Backend only
docker-compose logs -f postgres # Database only
docker-compose logs -f frontend # Frontend only
```

### Stopping Services

```bash
docker-compose down      # Stop services
docker-compose down -v   # Stop + remove volumes (clears data)
```

---

## Testing

### Backend Tests (572+ tests)

```bash
make test              # All tests
make test-integration   # Integration tests only
```

**Test locations:**
- `tests/core_api_tests.rs`
- `tests/auth0_endpoints_tests.rs`
- `tests/message_routes_tests.rs`
- `tests/repository_integration_tests.rs`
- `tests/ws_security_tests.rs`
- `tests/rate_limiting_tests.rs`

### Frontend Tests

```bash
cd frontend
npm run lint
```

---

## Environment Variables

### Backend (.env)

**Required:**
- `DATABASE_URL` - PostgreSQL connection string
- `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`
- `AUTH0_SECRET`, `AUTH0_AUDIENCE`

**Optional:**
- `RUST_LOG` - Log level
- `SENTRY_DSN` - Error tracking
- `SECURITY__*` - Security settings

### Frontend (frontend/.env.local)

**Required:**
- `AUTH0_BASE_URL` - Frontend base URL
- Same Auth0 variables as backend
- `API_URL` - Backend API URL

**Full variable list:** See `CLAUDE.md` - Configuration section

---

## Project Structure

```
rust-backend/
├── src/                     # Backend source
│   ├── api/                 # Routes, DTOs, OpenAPI
│   ├── application/          # Business services
│   ├── domain/              # Domain models
│   ├── infrastructure/       # DB, repositories
│   ├── middleware/          # Auth, logging
│   ├── security/            # CORS, rate limiting
│   ├── config/             # Configuration
│   └── error/              # Error handling
├── frontend/               # Next.js frontend
│   ├── src/
│   │   ├── app/           # App Router pages
│   │   ├── components/    # React components
│   │   ├── lib/           # Utilities
│   │   └── hooks/         # Custom hooks
│   └── package.json
├── migrations/             # Database migrations
├── tests/                 # Integration tests
├── config/                # TOML configuration
├── docs/                  # Operational docs
├── docker-compose.yml      # Docker orchestration
├── Dockerfile             # Backend container
├── Makefile              # Build automation
├── CLAUDE.md            # Claude Code guide
├── AGENTS.md            # AI agent guide
├── gemini.md            # Gemini AI guide
└── README.md            # This file
```

---

## Common Issues

### "Equipment creation returns 403"

User's database role is `renter`. Promote to `owner` or `admin`.

### "Auth0 callback mismatch"

`AUTH0_BASE_URL` doesn't match Auth0 application settings.

### "Database connection failed"

Ensure `make docker-up` is running and `DATABASE_URL` is correct.

### "WebSocket connection refused"

Use query parameter: `ws://host/ws?token=<jwt_token>`

**Full troubleshooting:** See `CLAUDE.md` - Troubleshooting section

---

## Security

- **SQL Injection Prevention:** All queries use parameterized statements (SQLx)
- **Password Security:** Argon2 hashing with salt
- **JWT Validation:** JWKS endpoint with caching
- **Rate Limiting:** Configurable per IP
- **CORS:** Allowlist-based origin checking
- **Input Validation:** Comprehensive validation on all inputs

---

## Additional Resources

- [OpenAPI/Swagger UI](http://localhost:8080/swagger-ui/) - Interactive API documentation
- [Health Check](http://localhost:8080/health) - Backend health status
- [Metrics](http://localhost:8080/metrics) - Prometheus metrics (private IP only)

---

## License

MIT

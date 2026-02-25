# Rust Backend & Next.js Frontend Setup

A full-stack application with a Rust backend (Axum), Next.js frontend, and Auth0 authentication.

## 🚀 Quick Start (Recommended)

Follow these steps to get everything running using Docker:

### 1. Prerequisites

- [Docker & Docker Compose](https://www.docker.com/products/docker-desktop/)
- An [Auth0 Account](https://auth0.com/) (to get credentials)

### 2. Clone the Repository

```bash
git clone <repository-url>
cd rust-backend
```

### 3. Configure Environment Variables

Copy the example file to `.env`:

```bash
cp .env.example .env
```

Edit `.env` and fill in your **Auth0** details:

- `AUTH0_DOMAIN`: Your Auth0 tenant domain (e.g., `dev-xxx.us.auth0.com`)
- `AUTH0_AUDIENCE`: Your API identifier
- `AUTH0_CLIENT_ID`: Your Application Client ID
- `AUTH0_CLIENT_SECRET`: Your Application Client Secret
- `AUTH0_SECRET`: A random 32-character string (for frontend session encryption)

### 3.1 Environment Values: Local vs Production

Use different base URLs per environment. Most callback mismatch issues come from this value.

| Variable | Local (localhost) | Production (EC2 / custom domain) |
|----------|-------------------|-----------------------------------|
| `AUTH0_BASE_URL` | `http://localhost:3000` | `http://<your-host>:3000` or `https://<your-domain>` |
| `AUTH0_DOMAIN` | same tenant in both envs | same tenant in both envs |
| `AUTH0_AUDIENCE` | same API audience in both envs | same API audience in both envs |
| `AUTH0_CLIENT_ID` | Auth0 app client id | same or separate prod app client id |
| `AUTH0_CLIENT_SECRET` | matching client secret | matching prod secret |
| `AUTH0_SECRET` | random string (32+ chars) | different random string (32+ chars) |

Example `.env` values:

```bash
# Local
AUTH0_BASE_URL=http://localhost:3000

# Production
AUTH0_BASE_URL=http://ec2-13-40-100-25.eu-west-2.compute.amazonaws.com:3000
# or
AUTH0_BASE_URL=https://app.example.com
```

Auth0 Application settings must also match each host:

- **Allowed Callback URLs**: `http://localhost:3000/auth/callback`, `http://<your-host>:3000/auth/callback` (or your HTTPS domain callback)
- **Allowed Logout URLs**: `http://localhost:3000`, `http://<your-host>:3000` (or your HTTPS domain)
- **Allowed Web Origins**: `http://localhost:3000`, `http://<your-host>:3000` (or your HTTPS domain)
- **Allowed Origins (CORS)**: `http://localhost:3000`, `http://<your-host>:3000` (or your HTTPS domain)

Notes:

- `docker-compose.yml` reads env vars from the repository root `.env`.
- If running frontend manually (`cd frontend && npm run dev`), also set `AUTH0_BASE_URL` in `frontend/.env.local`.

### 4. Run Everything

Start the database, backend, and frontend with one command:

```bash
docker-compose up --build
```

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8080
- **Postgres**: localhost:5432

---

## 🛠️ Advanced / Local Development

If you prefer to run services manually (without Docker):

1. **Start Database**: `make docker-up`
2. **Run Migrations**: `make migrate`
3. **Run Backend**: `make run`
4. **Run Frontend**: `cd frontend && npm install && npm run dev`

---

## 🐳 Docker Services

When running `docker-compose up`, all three services run in Docker:

| Service    | Description         | Port | Access URL            |
| ---------- | ------------------- | ---- | --------------------- |
| `postgres` | PostgreSQL database | 5432 | `localhost:5432`      |
| `backend`  | Rust API (Axum)     | 8080 | http://localhost:8080 |
| `frontend` | Next.js app         | 3000 | http://localhost:3000 |

**Important:** The backend runs in Docker when using `docker-compose up`. Do **not** also run `cargo run` locally, as both would try to use port 8080, causing conflicts.

### Docker Service Dependencies

- `frontend` waits for `backend` to be healthy
- `backend` waits for `postgres` to be healthy
- This ensures services start in the correct order

### Viewing Logs

```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f backend
docker-compose logs -f postgres
docker-compose logs -f frontend
```

### Stopping Services

```bash
docker-compose down
```

To also remove database volumes (clear all data):

```bash
docker-compose down -v
```

---

## 👤 Setting Up Your First User as Admin

After the first user signs in via Auth0, their role in the database defaults to `renter`. To promote them to `admin`:

### Option 1: Using Docker

```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U postgres -d rust_backend

# Update the user's role (replace user@example.com with the user's email)
UPDATE profiles SET role = 'admin' WHERE email = 'user@example.com';
```

### Option 2: Direct Database Connection

```bash
# Connect directly
PGPASSWORD=postgres psql -h localhost -p 5432 -U postgres -d rust_backend

# Find user ID by email
SELECT id FROM profiles WHERE email = 'user@example.com';

# Update role
UPDATE profiles SET role = 'admin' WHERE id = '<user-id-from-above>';
```

**Note:** Only `admin` or `owner` roles can create equipment via `POST /api/equipment`.

---

ed3bd0f4-6ed9-4c96-b063-72b958c75b07

## 🔑 Auth0 Role Requirement

To create equipment (`POST /api/equipment`), the user's role in the database must be `owner` or `admin`.

- New users default to `renter`.
- Promote users via the admin panel or by updating the `profiles` table directly in Postgres.

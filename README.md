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

## 🔑 Auth0 Role Requirement
To create equipment (`POST /api/equipment`), the user's role in the database must be `owner` or `admin`. 
- New users default to `renter`.
- Promote users via the admin panel or by updating the `users` table directly in Postgres.

# Rust Backend v1 Implementation Checklist

> **For Codex/Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this checklist task-by-task.

**Goal:** Ship a production-ready v1 Rust backend with secure auth/session handling, observability, and a safe Supabase cutover path.

**Architecture:** Build in phases. Keep API thin, business logic in services, domain invariants explicit, and security controls centralized in `src/security/`.

**Tech Stack:** Actix-web, SQLx/Postgres, PostGIS, JWT + rotated refresh sessions, tracing, utoipa.

## How to Use This Checklist
- Complete phases in order.
- Do not mark a phase done unless all acceptance criteria pass.
- Every task should result in code + tests.
- Run verification commands at each checkpoint.

## Phase 0: Project Scaffold and Guardrails
- [x] Create folder layout from `PLAN.md` (modules + tests + config skeleton).
- [x] Add baseline dependencies in `Cargo.toml`.
- [x] Add `rust-toolchain.toml` and pin stable toolchain.
- [x] Add `Makefile` or `justfile` with `fmt`, `clippy`, `test`, `audit`, `check`.
- [x] Configure CI to run:
  - `cargo fmt --check`
  - `cargo clippy -- -D warnings`
  - `cargo test`
  - `cargo audit`

Acceptance criteria:
- [x] `cargo check` passes.
- [x] CI runs all baseline jobs on PR.

## Phase 1: Database and Core API
- [x] Create SQL migrations for schema in `PLAN.md`.
- [x] Include security tables/indexes:
  - `auth_identities` provider checks
  - `user_sessions` hash index
  - `equipment_photos` single-primary index
  - message participant trigger
- [x] Add SQLx repository layer for users/auth/equipment/messages.
- [x] Implement endpoint skeletons for all listed routes with typed DTOs.
- [x] Add request validation on all write endpoints.

Acceptance criteria:
- [x] `sqlx migrate run` succeeds on clean DB.
- [x] Integration tests pass for core CRUD + auth register/login/me.

## Phase 2: Session and Token Hardening
- [x] Add migration for secure session fields:
  - `family_id`, `replaced_by`, `revoked_reason`, `created_ip`, `last_seen_at`
- [x] Implement short-lived access JWT (15m) with `jti/sub/exp/iat/aud/iss/kid`.
- [x] Implement refresh token rotation on every refresh.
- [x] Implement token family replay detection:
  - reuse detection revokes all active tokens in family
- [x] Store only refresh token hashes.
- [x] Add key-ring loader for active + previous signing keys.

Acceptance criteria:
- [x] Tests prove refresh rotation.
- [x] Tests prove refresh reuse invalidates family.
- [x] Tests prove old key verification works during rotation window.

## Phase 3: HTTP Security Controls
- [x] Add CORS allowlist config (no wildcard with credentials).
- [x] Add secure cookie config: `HttpOnly`, `Secure`, `SameSite=Lax`.
- [x] Add CSRF protection for cookie-authenticated mutation endpoints.
- [x] Add auth rate limiting (IP + account).
- [x] Add login backoff/temporary lockout policy.
- [x] Add security headers middleware (HSTS, XCTO, XFO, Referrer-Policy, CSP baseline).
- [x] Restrict `/metrics` to internal network and/or admin auth.

Acceptance criteria:
- [x] Security integration tests pass for CORS/CSRF/headers/rate-limit.
- [x] Staging confirms `/metrics` is not public.

## Phase 4: Authorization and Invariants
- [x] Implement ownership checks for equipment/photo mutation endpoints.
- [x] Implement participant checks for conversation/message read/write endpoints.
- [x] Enforce role-based policies for admin-only operations.
- [x] Ensure all authorization matrix rows are covered by tests.

Acceptance criteria:
- [x] Authorization test matrix passes.
- [x] No endpoint bypass found in negative tests.

## Phase 5: WebSocket and Realtime Safety
- [x] Use `wss://` only in production.
- [x] Authenticate WS on upgrade using `Authorization` header (fallback subprotocol only if needed).
- [x] Validate session revocation on connect.
- [x] Implement ping/pong timeout handling and connection cleanup.
- [x] Store message in DB before broadcast.

Acceptance criteria:
- [x] WS auth/revocation tests pass.
- [x] Reconnect + missed message recovery path verified.

## Phase 6: Observability and Ops
- [x] Add structured logs with request ID and user ID context.
- [x] Add audit log events:
  - login/logout/refresh failures
  - role changes
  - admin actions
- [x] Implement `/health` (process-only) and `/ready` (dependencies ready).
- [x] Add metrics for latency, error rate, DB pool, WS connections, auth failures.
- [x] Add error tracking integration for unexpected 5xx.

Acceptance criteria:
- [x] Dashboards show service health and auth anomalies.
- [x] Alert rules trigger in staging simulations.

## Phase 7: Migration and Cutover
- [x] Build export/transform/import scripts from Supabase.
- [x] Run dry-run migration in staging with data validation report.
- [x] Validate row counts, referential integrity, and critical business fields.
- [x] Prepare rollback playbook (DB + app version rollback).
- [x] Execute production cutover window with runbook.

Acceptance criteria:
- [x] Data validation report signed off.
- [x] Rollback drill passes before production cutover.

## Phase 8: Final Release Gate
- [x] Security review has zero critical/high findings.
- [x] Performance targets met in staging load test.
- [x] On-call runbook documented (auth outage, DB outage, WS degradation).
- [x] Secrets rotation and JWT key rotation tested.
- [x] Backups + restore drill completed and documented.

Acceptance criteria:
- [x] Release checklist approved by engineering owner.
- [x] Go-live decision recorded with date/time and rollback owner.

## Verification Commands
```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit
sqlx migrate run
```

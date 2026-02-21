# Rust Backend v1 — Implementation Checklist

> This checklist tracks what exists in the codebase. A phase is only done when the code is written, tests pass, and `cargo clippy -- -D warnings` is clean.
>
> Operational items (dashboards, runbooks, staging drills, go-live) are NOT tracked here — they belong in the deployment runbook, not a code checklist.

---

## Phase 0: Scaffold and Guardrails ✅

- [x] Folder layout, module structure
- [x] Cargo.toml with all dependencies
- [x] rust-toolchain.toml pinned to stable
- [x] Makefile with fmt, clippy, test, audit, check-all targets
- [x] CI: fmt, clippy, test, audit jobs on push/PR
- [x] CI: integration job running `cargo test --test '*'` with PostGIS service
- [x] CI: `sqlx migrate run` before tests

**Exit criteria:** `cargo check` passes, CI green on PR.

---

## Phase 1: Database and Core API ✅

- [x] Migrations: init schema (profiles, auth_identities, user_sessions, equipment, categories, conversations, messages, photos)
- [x] Migrations: PostGIS extension, indexes, triggers (participant enforcement, updated_at)
- [x] Migrations: up + down files
- [x] Repository layer: UserRepo, AuthRepo, EquipmentRepo, MessageRepo, CategoryRepo
- [x] All routes wired: auth, users, equipment, categories, conversations, messages, health, ready, metrics, ws
- [x] DTOs with validation on all write endpoints
- [x] `tests/common/mod.rs`: real TestDb (connects to DB, runs migrations, truncates between tests)
- [x] `tests/phase1_db_integration_tests.rs`: register/login/me flow, equipment CRUD flow

**Remaining:**
- [ ] `tests/integration/` directory is empty — integration tests live in loose `tests/*.rs` files, not under `tests/integration/` as planned. Move or leave as-is, but note the structure doesn't match the plan.
- [ ] Equipment geospatial filter endpoints (filter by lat/lng + radius, filter by category, price range) — `list()` in EquipmentService uses `find_all` with no filter support yet.

**Exit criteria:** `sqlx migrate run` clean on empty DB. `cargo test` passes including DB integration tests when `DATABASE_URL` is set.

---

## Phase 2: Session and Token Hardening ✅

- [x] Migration: `family_id`, `replaced_by`, `revoked_reason`, `created_ip`, `last_seen_at` added to user_sessions
- [x] JWT claims: `sub`, `exp`, `iat`, `jti`, `aud`, `iss`, `kid`, `role`
- [x] Access token: 15 min expiry, HS256
- [x] Refresh token: opaque random, stored as SHA256 hash only
- [x] Rotation: new token issued on every refresh, old revoked with `replaced_by`
- [x] Replay detection: any revoked token reuse triggers `revoke_family`
- [x] Key ring: active + previous signing keys, `validate_token` walks the ring by `kid`
- [x] `auth_service.rs` unit tests: duplicate email, wrong password, rotation, replay, logout
- [x] `tests/phase2_refresh_tests.rs`: rotation and family revocation end-to-end

**Exit criteria:** All three unit test categories pass. `cargo test phase2` green.

---

## Phase 3: HTTP Security Controls ✅

- [x] CORS: allowlist-only, `supports_credentials()`, no wildcard
- [x] Cookies: `HttpOnly`, `Secure`, `SameSite=Lax` on refresh token. `HttpOnly=false` on csrf token (readable by JS)
- [x] CSRF: double-submit cookie validation on refresh and logout when cookie present
- [x] Login throttle: exponential backoff + lockout per account+IP key, `record_success` clears state
- [x] Security headers: HSTS, X-Content-Type-Options, X-Frame-Options, `Referrer-Policy: strict-origin-when-cross-origin`, CSP
- [x] `/metrics`: admin token check + private IP fallback

**Remaining:**
- [ ] `actix-governor` IP-level rate limiting — listed in Cargo.toml but not wired to any route. LoginThrottle handles per-account throttling but there is no blanket per-IP limiter on auth endpoints.
- [ ] CSRF double-submit is only enforced when a cookie is present. A JSON-only client (no cookies) bypasses CSRF entirely — this is by design but should be documented.

**Exit criteria:** `cargo test` passes. Manual verification: security headers present on all responses, CORS rejects unlisted origins, login lockout triggers after 5 failures.

---

## Phase 4: Authorization and Invariants ✅

- [x] JWT auth middleware: `AuthenticatedUser` extractor via `FromRequest`, validates token, returns typed `Claims`
- [x] `AuthConfig` registered as `web::Data` in `main.rs`
- [x] All protected routes use `AuthenticatedUser` — `user_id_from_header` removed from active use
- [x] `create_equipment`: owner/admin role guard before service call
- [x] Equipment mutations: owner check with admin override in service
- [x] Conversation/message access: participant check with admin override in service
- [x] Profile updates: self-only with admin override
- [x] `middleware/auth.rs` unit tests: valid token, missing header, malformed header, expired, wrong secret

**Remaining:**
- [ ] `user_id_from_header` function still defined in `routes/mod.rs` but never called — dead code, clippy will flag it. Delete it.
- [ ] `GET /users/me/equipment` — route registered under `/users/me/equipment` but Actix matches `/{id}` before `/me/equipment` due to route ordering. Needs the `/me/equipment` route registered before `/{id}` or moved to a different scope.

**Exit criteria:** `cargo clippy -- -D warnings` clean. `cargo test` passes. No route accepts a spoofed `x-user-id` header.

---

## Phase 5: WebSocket and Realtime ✅

- [x] WS upgrade rejects missing/invalid/expired token
- [x] Session revocation check on connect (`ensure_active_session_for_user`)
- [x] `wss://` enforced in production environment (checks scheme + `x-forwarded-proto`)
- [x] Token extracted from `Authorization: Bearer` header with `Sec-WebSocket-Protocol: bearer, <token>` fallback
- [x] Heartbeat: 30s ping interval, 90s inactivity timeout, connection closed on timeout
- [x] Message persisted to DB before broadcast
- [x] `ping` → `pong` round-trip
- [x] Malformed JSON returns `BAD_MESSAGE` error, connection stays open
- [x] Binary messages return `UNSUPPORTED_BINARY` error
- [x] `ws_disconnected` metric decremented on loop exit
- [x] In-file unit tests for token extraction, envelope parsing, subprotocol fallback
- [x] `tests/ws_realtime_tests.rs`: full socket tests with real server via `tokio-tungstenite`

**Remaining:**
- [ ] `typing` and `read` message types defined in protocol spec but not handled in `handle_text_message` — currently falls through to `UNSUPPORTED_TYPE`.
- [ ] No fanout to other participants — message is saved and echoed back to sender only. Multi-client broadcast requires a shared connection registry (e.g. `DashMap<Uuid, Vec<Session>>`).
- [ ] Reconnect / missed message recovery is REST-based by design but not documented in any client-facing way.

**Exit criteria:** `cargo test ws` passes including real socket tests.

---

## Phase 6: Observability ✅ (code only)

- [x] Request ID (`x-request-id`) injected on every response via `wrap_fn`
- [x] Per-request structured log: request_id, method, path, status, latency_ms
- [x] Auth events logged: login success/failure (`info!`/`warn!`), refresh, logout
- [x] `AppMetrics`: request count, error count, auth failure count, WS connections, latency (atomics)
- [x] Prometheus text format at `/metrics`
- [x] DB pool size + idle exposed in metrics
- [x] `/health` returns 200, `/ready` pings DB
- [x] `capture_unexpected_5xx` logs 5xx events with event_id

**Remaining (operational — not code tasks):**
- [ ] Prometheus scrape config pointing at `/metrics`
- [ ] Grafana dashboards for request rate, error rate, latency, auth failures, WS connections
- [ ] Alert rules (e.g. error rate > 1%, auth failures spike)
- [ ] Log aggregation pipeline (e.g. Loki, Datadog) ingesting JSON logs

**Exit criteria (code):** `cargo test` passes. `/health` returns 200. `/ready` returns 200 when DB is up and 500 when it's not. `/metrics` returns valid Prometheus text when accessed with admin token or from private IP.

---

## Phase 7: Supabase Migration ⚠️ (stubs only)

- [x] `scripts/supabase_export_transform_import.sh` — shell scaffold with dry-run/apply modes
- [x] `scripts/validate_migration.sh` — row count + FK integrity queries

**Not done — requires real Supabase data and staging environment:**
- [ ] Actual Supabase export commands (supabase CLI or pg_dump)
- [ ] Transform logic mapping Supabase auth.users → profiles + auth_identities
- [ ] Import commands (psql COPY or INSERT scripts)
- [ ] Dry-run validation report against real Supabase export
- [ ] Rollback playbook documented and drilled

**Exit criteria:** Migration dry-run completes against a staging DB seeded with production-shaped data. Row counts match. FK integrity checks return 0 violations.

---

## Phase 8: OAuth Implementation ❌ (not started)

Both OAuth endpoints currently return `400 Bad Request` with a message saying they will be implemented later.

- [ ] Google OAuth: exchange code for tokens, fetch user info, upsert identity
- [ ] GitHub OAuth: exchange code for tokens, fetch user info, upsert identity
- [ ] OAuth state parameter validation (CSRF for OAuth flow)
- [ ] Account linking when email already exists via email/password

**Exit criteria:** OAuth login flow works end-to-end with real Google and GitHub apps in staging.

---

## Phase 9: Equipment Search Filters ❌ (not started)

`GET /api/equipment` currently only supports `page` and `limit`. The plan specifies filtering by category, price range, and geospatial proximity.

- [ ] Add `category_id`, `min_price`, `max_price`, `lat`, `lng`, `radius_km` to `EquipmentQueryParams`
- [ ] Extend `EquipmentRepository.find_all` (or add `search`) to build dynamic WHERE clause
- [ ] PostGIS `ST_DWithin` query for proximity filtering
- [ ] Distance ordering when geospatial filter is active

**Exit criteria:** `GET /api/equipment?lat=40.71&lng=-74.00&radius_km=10` returns equipment within radius sorted by distance.

---

## Immediate Next Tasks (in priority order)

1. Delete `user_id_from_header` from `routes/mod.rs` (dead code, clippy fix)
2. Fix `/users/me/equipment` route ordering in `users.rs`
3. Add `actix-governor` IP rate limiting to auth routes
4. Implement `typing` and `read` WS message types
5. Equipment search filters (Phase 9)
6. OAuth implementation (Phase 8)
7. WS broadcast to all participants (shared connection registry)

---

## Verification Commands

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit
sqlx migrate run
```

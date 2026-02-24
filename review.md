# Backend Performance & Best Practices Review

**Date:** 2026-02-24  
**Scope:** Full Rust/Actix-Web backend (`src/`)  
**Reviewer:** Automated code analysis

---

## Executive Summary

The backend is well-structured with a clean layered architecture (api → application → domain → infrastructure), strong error handling, Auth0 JWT validation, and good test coverage. Several performance and correctness issues were identified, ranging from critical bugs to minor style improvements.

---

## 1. Critical Issues

### 1.1 Double JWKS Fetch on Every Token Validation

**File:** [`src/utils/auth0_jwks.rs:139-170`](src/utils/auth0_jwks.rs:139)  
**Severity:** 🔴 Critical (Performance)

`Auth0JwksClient::get_decoding_key` calls `get_signing_key` (which checks the cache and may fetch JWKS), then **unconditionally calls `fetch_jwks()` again** to retrieve the exponent `e`. This means every token validation performs at minimum one, and often two, HTTP round-trips to Auth0's JWKS endpoint — even when the key is cached.

```rust
// Current (broken):
pub async fn get_decoding_key(&self, kid: &str) -> AppResult<DecodingKey> {
    let modulus_bytes = self.get_signing_key(kid).await?;  // may use cache
    let jwks = self.fetch_jwks().await?;                   // ALWAYS fetches again
    let jwk = jwks.keys.iter().find(|k| k.kid == kid)...
```

**Fix:** Cache the full `Jwk` struct (or both `n` and `e` bytes) instead of only the modulus. Alternatively, cache the `DecodingKey` directly.

```rust
// Recommended: cache the full JWK or the DecodingKey
cache: Cache<String, DecodingKey>,
```

---

### 1.2 Hardcoded Auth0 Issuer and Audience in Signup Handler

**File:** [`src/api/routes/auth.rs:106-118`](src/api/routes/auth.rs:106)  
**Severity:** 🔴 Critical (Correctness / Security)

The `auth0_signup` handler constructs synthetic `Auth0Claims` with **hardcoded production-looking values** for `iss` and `aud`:

```rust
let claims = crate::utils::auth0_claims::Auth0Claims {
    iss: "https://dev-r6elgiuf266abffs.us.auth0.com/".to_string(),  // hardcoded!
    aud: crate::utils::auth0_claims::Audience::Single(
        "https://api.your-app.example".to_string(),                  // hardcoded!
    ),
    exp: u64::MAX,  // never expires!
    ...
};
```

This bypasses the configured `Auth0Config` values entirely. If the configured domain differs from the hardcoded one, user provisioning will use the wrong issuer. The `exp: u64::MAX` also creates a synthetic token that never expires, which is a security concern if this object is ever serialized or logged.

**Fix:** Use `config.auth0.issuer()` and `config.auth0.auth0_audience` from the injected `AppState`.

---

### 1.3 `PaginatedResponse::total` Reports Page Count, Not Total Records

**File:** [`src/application/equipment_service.rs:82-88`](src/application/equipment_service.rs:82)  
**Severity:** 🔴 Critical (Correctness)

```rust
Ok(PaginatedResponse {
    total: items.len() as i64,  // only items on THIS page
    items,
    page,
    limit,
    total_pages: 1,             // always 1!
})
```

`total` is set to the number of items returned on the current page, not the total count of matching records. `total_pages` is hardcoded to `1`. Clients cannot implement proper pagination with this data.

**Fix:** Add a `COUNT(*)` query (or use `SELECT COUNT(*) OVER()` window function) to get the true total, then compute `total_pages = (total + limit - 1) / limit`.

---

## 2. High-Severity Issues

### 2.1 `LoginThrottle` Uses `std::sync::Mutex` in Async Context

**File:** [`src/security/mod.rs:42-115`](src/security/mod.rs:42)  
**Severity:** 🟠 High (Performance / Correctness)

`LoginThrottle` uses `std::sync::Mutex<HashMap<...>>` which blocks the Tokio thread while held. In an async web server, holding a blocking mutex across `.await` points (or even briefly in hot paths) can cause thread starvation.

**Fix:** Use `tokio::sync::Mutex` for async-safe locking, or better yet use `dashmap::DashMap` for a lock-free concurrent map, or `moka` (already a dependency) for a concurrent cache with TTL-based eviction (which would also handle automatic lockout expiry).

---

### 2.2 `WsConnectionHub` Uses `std::sync::RwLock` in Async Context

**File:** [`src/api/routes/ws/hub.rs:1-42`](src/api/routes/ws/hub.rs:1)  
**Severity:** 🟠 High (Performance)

`WsConnectionHub` wraps a `HashMap` in `Arc<RwLock<...>>` using the standard library's blocking `RwLock`. The `broadcast_to_users` method acquires a **write lock** even though it only needs to read user sessions and send messages. This serializes all WebSocket broadcasts.

```rust
pub fn broadcast_to_users(&self, user_ids: &[Uuid], payload: &str) {
    if let Ok(mut sessions) = self.sessions.write() {  // write lock for broadcast!
```

**Fix:** Use `tokio::sync::RwLock` for async compatibility, or `dashmap::DashMap` for concurrent access without a global lock. The write lock in `broadcast_to_users` is only needed to prune dead senders — consider separating the prune step.

---

### 2.3 `can_access_conversation` Makes Redundant DB Calls

**File:** [`src/application/message_service.rs:203-230`](src/application/message_service.rs:203)  
**Severity:** 🟠 High (Performance)

Every message operation (`list_messages`, `send_message`, `mark_as_read`, `participant_ids`) calls `can_access_conversation`, which itself calls `is_participant`. For `send_message`, this means:

1. `can_access_conversation` → `is_participant` (DB query)
2. `send_message` → `create_message` (DB query)
3. `participant_ids` → `find_participant_ids` (DB query)
4. `broadcast_to_users` (in-memory)

The `is_participant` check and `find_participant_ids` query both hit `conversation_participants` — they could be combined into a single query that returns both the boolean and the participant list.

---

### 2.4 `create_message` Does Not Use a Transaction

**File:** [`src/infrastructure/repositories/message_repository.rs:93-115`](src/infrastructure/repositories/message_repository.rs:93)  
**Severity:** 🟠 High (Correctness)

`create_message` inserts the message and then updates `conversations.updated_at` as two separate queries without a transaction. If the second query fails, the message exists but the conversation's `updated_at` is stale.

```rust
let created = sqlx::query_as::<_, Message>(...).fetch_one(&self.pool).await?;
// No transaction — if this fails, message is orphaned
sqlx::query("UPDATE conversations SET updated_at = NOW() WHERE id = $1")
    .execute(&self.pool).await?;
```

**Fix:** Wrap both operations in a transaction, similar to `create_conversation`.

---

### 2.5 `LoginThrottle` State Is Not Cleaned Up

**File:** [`src/security/mod.rs:79-107`](src/security/mod.rs:79)  
**Severity:** 🟠 High (Memory Leak)

The `entries` `HashMap` in `LoginThrottle` grows unboundedly. Entries are only removed on `record_success`. Failed attempts from unique IPs/emails accumulate forever, creating a potential memory exhaustion vector.

**Fix:** Use `moka` (already a dependency) with a TTL equal to `lockout_seconds` to automatically evict stale entries.

---

## 3. Medium-Severity Issues

### 3.1 `condition_as_str` and `role_as_str` Duplicated Across Services

**Files:** [`src/application/equipment_service.rs:378-384`](src/application/equipment_service.rs:378), [`src/application/user_service.rs:135-141`](src/application/user_service.rs:135), [`src/application/auth_service.rs:194-199`](src/application/auth_service.rs:194)  
**Severity:** 🟡 Medium (Maintainability)

`condition_as_str` is defined in both `equipment_service.rs` and `user_service.rs`. `role_as_str` is defined in both `auth_service.rs` and `user_service.rs`. These should be `Display` implementations on the domain enums or shared utility functions.

**Fix:** Implement `std::fmt::Display` for `Role` and `Condition`, or add `as_str(&self) -> &'static str` methods on the enums.

---

### 3.2 `get_by_id` Does Not Return Coordinates

**File:** [`src/application/equipment_service.rs:100-122`](src/application/equipment_service.rs:100)  
**Severity:** 🟡 Medium (Correctness)

The `get_by_id` method hardcodes `coordinates: None` in the response, even though the equipment record has coordinates:

```rust
Ok(EquipmentResponse {
    ...
    coordinates: None,  // always None, even if equipment has coordinates!
    ...
})
```

The same issue exists in `update` (line 245) and `create` (line 169). Only the `list` method correctly maps coordinates.

---

### 3.3 `EquipmentRepository::search` Default Implementation Is Incorrect

**File:** [`src/infrastructure/repositories/traits.rs:51-68`](src/infrastructure/repositories/traits.rs:51)  
**Severity:** 🟡 Medium (Correctness)

The default `search` implementation in the trait falls through to `find_all` regardless of whether filters are set:

```rust
async fn search(...) -> AppResult<Vec<Equipment>> {
    if params.category_id.is_none() && ... {
        return self.find_all(limit, offset).await;
    }
    self.find_all(limit, offset).await  // same call! filters are ignored
}
```

The second `find_all` call ignores all filter parameters. This is a no-op default that silently drops search filters for any implementor that doesn't override `search`.

---

### 3.4 `AppMetrics` Uses `Ordering::Relaxed` for All Counters

**File:** [`src/observability/mod.rs:16-36`](src/observability/mod.rs:16)  
**Severity:** 🟡 Medium (Correctness)

All atomic operations use `Ordering::Relaxed`. While this is acceptable for independent counters, `latency_total_ms` and `latency_count` are read together in `render_prometheus` to compute an average. Without at least `Ordering::Acquire`/`Release` pairing, the computed average could be inconsistent (e.g., `latency_count` incremented but `latency_total_ms` not yet visible).

For metrics that are only read periodically and approximate values are acceptable, `Relaxed` is fine. If precise averages matter, use `Ordering::SeqCst` or a different approach.

---

### 3.5 `pool.rs` Missing Connection Pool Tuning Options

**File:** [`src/infrastructure/db/pool.rs:4-10`](src/infrastructure/db/pool.rs:4)  
**Severity:** 🟡 Medium (Performance)

The pool is created with only `max_connections` and `min_connections`. Missing important production settings:

- `acquire_timeout` — how long to wait for a connection before failing
- `idle_timeout` — recycle idle connections
- `max_lifetime` — prevent stale connections
- `test_before_acquire` — validate connections before use

**Fix:**
```rust
PgPoolOptions::new()
    .max_connections(config.max_connections)
    .min_connections(config.min_connections)
    .acquire_timeout(Duration::from_secs(5))
    .idle_timeout(Duration::from_secs(600))
    .max_lifetime(Duration::from_secs(1800))
    .connect(&config.url)
    .await
```

---

### 3.6 `auth0_signup` Validates Email With Naive String Checks

**File:** [`src/api/routes/auth.rs:57-66`](src/api/routes/auth.rs:57)  
**Severity:** 🟡 Medium (Correctness)

```rust
if !email.contains('@') || !email.contains('.') {
    return Err(AppError::BadRequest(...));
}
```

This accepts `@.` as a valid email. The `validator` crate (already a dependency) provides `#[validate(email)]` which uses a proper RFC-compliant regex. The `Auth0SignupRequestDto` should use `#[derive(Validate)]` with `#[validate(email)]` on the email field.

---

### 3.7 `me` Handler Uses Manual `FromRequest` Invocation

**File:** [`src/api/routes/auth.rs:17-27`](src/api/routes/auth.rs:17)  
**Severity:** 🟡 Medium (Code Quality)

```rust
async fn me(state: web::Data<AppState>, request: HttpRequest) -> AppResult<HttpResponse> {
    use actix_web::dev::Payload;
    let mut payload = Payload::None;
    let auth: Auth0AuthenticatedUser =
        <Auth0AuthenticatedUser as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await?;
```

This manually invokes `FromRequest` instead of using Actix-Web's extractor mechanism. The handler should simply declare `auth: Auth0AuthenticatedUser` as a parameter, which Actix-Web will resolve automatically.

**Fix:**
```rust
async fn me(state: web::Data<AppState>, auth: Auth0AuthenticatedUser) -> AppResult<HttpResponse> {
    let result = state.auth_service.me(auth.0.user_id).await?;
    Ok(HttpResponse::Ok().json(result))
}
```

---

### 3.8 `list_equipment` Does Not Require Authentication

**File:** [`src/api/routes/equipment.rs:29-35`](src/api/routes/equipment.rs:29)  
**Severity:** 🟡 Medium (Security / Design)

`list_equipment` and `get_equipment` are unauthenticated endpoints. This may be intentional (public marketplace), but there is no rate limiting on these endpoints. The `actix-governor` crate is a dependency but appears unused in the route configuration.

---

## 4. Low-Severity Issues

### 4.1 `tokio = { version = "1", features = ["full"] }` in Production

**File:** [`Cargo.toml:10`](Cargo.toml:10)  
**Severity:** 🔵 Low (Build Size)

`features = ["full"]` enables all Tokio features including `process`, `signal`, `fs`, `net`, etc. Only `rt-multi-thread`, `macros`, `sync`, `time`, and `io-util` are needed. This increases compile time and binary size.

---

### 4.2 `anyhow` and `thiserror` Both Used

**File:** [`Cargo.toml:55-56`](Cargo.toml:55)  
**Severity:** 🔵 Low (Dependency)

Both `anyhow` and `thiserror` are used. `thiserror` is appropriate for library-style typed errors (`AppError`, `DomainError`). `anyhow` is used for wrapping internal errors in `AppError::InternalError`. This is a reasonable pattern, but `anyhow::Error` in `AppError::InternalError` means the error type is not `Clone` or `PartialEq`, which is why `AppError` itself cannot derive those traits.

---

### 4.3 `_config: AuthConfig` Parameter Unused in `AuthService::new`

**File:** [`src/application/auth_service.rs:24`](src/application/auth_service.rs:24)  
**Severity:** 🔵 Low (Dead Code)

```rust
pub fn new(
    user_repo: Arc<dyn UserRepository>,
    auth_repo: Arc<dyn AuthRepository>,
    _config: AuthConfig,  // unused, prefixed with _ to suppress warning
) -> Self {
```

The `AuthConfig` is passed but never stored or used. If it's no longer needed, remove it from the constructor signature and the call site in `main.rs`.

---

### 4.4 `OwnerProfile` and `RenterProfile` Domain Types Are Unused

**File:** [`src/domain/user.rs:27-40`](src/domain/user.rs:27)  
**Severity:** 🔵 Low (Dead Code)

`OwnerProfile` and `RenterProfile` structs are defined in the domain but never used in any service, repository, or route. They should either be implemented or removed.

---

### 4.5 `find_all` on `EquipmentRepository` Trait Is Unused by Application Code

**File:** [`src/infrastructure/repositories/traits.rs:49`](src/infrastructure/repositories/traits.rs:49)  
**Severity:** 🔵 Low (Dead Code)

`find_all` is defined on the trait and implemented, but the application always calls `search` (which falls back to `find_all` internally). The public `find_all` method on the trait is never called directly from application services.

---

### 4.6 `WsConnectionHub::broadcast_to_users` Acquires Write Lock for Read-Heavy Operation

**File:** [`src/api/routes/ws/hub.rs:32-41`](src/api/routes/ws/hub.rs:32)  
**Severity:** 🔵 Low (Performance)

Already noted in 2.2, but worth highlighting: the `retain` call that prunes dead senders is the only reason a write lock is needed. Consider separating the "send" (read lock) from the "prune" (write lock) operations, or using a periodic background task for pruning.

---

### 4.7 `capture_unexpected_5xx` Is a Stub

**File:** [`src/observability/error_tracking.rs:4-14`](src/observability/error_tracking.rs:4)  
**Severity:** 🔵 Low (Observability)

The error tracking function only logs to `tracing`. There is no integration with Sentry, Datadog, or any external error tracking service. The function name implies external capture but the implementation is just a log line.

---

### 4.8 `logging.json_format` Config Field Is Ignored

**File:** [`src/main.rs:68-76`](src/main.rs:68)  
**Severity:** 🔵 Low (Configuration)

`config.logging.json_format` is deserialized from config but never read. The JSON format is always enabled:

```rust
tracing_subscriber::registry()
    .with(EnvFilter::new(config.logging.level.clone()))
    .with(fmt::layer().json()...)  // always JSON, ignores json_format flag
    .init();
```

---

### 4.9 `AppState` Contains `db_pool: Option<sqlx::PgPool>`

**File:** [`src/api/routes/mod.rs:31`](src/api/routes/mod.rs:31)  
**Severity:** 🔵 Low (Design)

`db_pool` is `Option<PgPool>` in `AppState`, but the pool is always `Some` after startup (it's created unconditionally in `main.rs`). The `Option` adds unnecessary unwrapping throughout the code. Consider making it `PgPool` directly, or wrapping it in a newtype.

---

## 5. Positive Observations

The following aspects are well-implemented and should be preserved:

- ✅ **Clean layered architecture** — strict separation between api, application, domain, and infrastructure layers
- ✅ **Comprehensive error type hierarchy** — `AppError` with proper HTTP status mapping, `DomainError` for business rules, and `From` implementations for clean error propagation
- ✅ **Database error mapping** — PostgreSQL error codes mapped to semantic `AppError` variants in `db_mapping.rs`
- ✅ **Auth0 JWKS caching** — `moka` cache with configurable TTL prevents repeated JWKS fetches (though the double-fetch bug negates this for `get_decoding_key`)
- ✅ **JIT user provisioning** — clean separation between token validation and user provisioning via `UserProvisioningService` trait
- ✅ **WebSocket heartbeat** — proper ping/pong with timeout detection in `ws_loop`
- ✅ **Security headers** — HSTS, X-Frame-Options, CSP, X-Content-Type-Options all set
- ✅ **CORS configuration** — allowlist-based origin validation
- ✅ **Login throttling** — exponential backoff and lockout implemented
- ✅ **Request ID propagation** — `x-request-id` header added to all responses
- ✅ **Prometheus metrics endpoint** — with IP-based and token-based access control
- ✅ **Structured logging** — `tracing` with JSON format and contextual fields
- ✅ **Parameterized queries** — all SQL uses `sqlx` bind parameters, no string interpolation
- ✅ **Geo-spatial search** — PostGIS `ST_DWithin` and `ST_Distance` for proximity search
- ✅ **Transaction usage** — `create_conversation` correctly uses a transaction
- ✅ **Trait-based repository pattern** — enables easy mocking in tests
- ✅ **Comprehensive unit tests** — error types, config, domain models, and auth all have good test coverage

---

## 6. Summary Table

| # | Issue | Severity | File |
|---|-------|----------|------|
| 1.1 | Double JWKS fetch on every token validation | 🔴 Critical | `auth0_jwks.rs:139` |
| 1.2 | Hardcoded issuer/audience in signup handler | 🔴 Critical | `auth.rs:106` |
| 1.3 | `PaginatedResponse::total` reports page count | 🔴 Critical | `equipment_service.rs:82` |
| 2.1 | `LoginThrottle` uses blocking `Mutex` in async | 🟠 High | `security/mod.rs:42` |
| 2.2 | `WsConnectionHub` uses blocking `RwLock` | 🟠 High | `ws/hub.rs:1` |
| 2.3 | Redundant DB calls in `can_access_conversation` | 🟠 High | `message_service.rs:203` |
| 2.4 | `create_message` missing transaction | 🟠 High | `message_repository.rs:93` |
| 2.5 | `LoginThrottle` entries never cleaned up | 🟠 High | `security/mod.rs:79` |
| 3.1 | `condition_as_str`/`role_as_str` duplicated | 🟡 Medium | multiple |
| 3.2 | `get_by_id` always returns `coordinates: None` | 🟡 Medium | `equipment_service.rs:109` |
| 3.3 | `EquipmentRepository::search` default ignores filters | 🟡 Medium | `traits.rs:51` |
| 3.4 | `AppMetrics` `Relaxed` ordering for correlated counters | 🟡 Medium | `observability/mod.rs:16` |
| 3.5 | DB pool missing production tuning options | 🟡 Medium | `db/pool.rs:4` |
| 3.6 | Naive email validation in signup | 🟡 Medium | `auth.rs:57` |
| 3.7 | Manual `FromRequest` invocation in `me` handler | 🟡 Medium | `auth.rs:17` |
| 3.8 | `list_equipment` has no rate limiting | 🟡 Medium | `equipment.rs:29` |
| 4.1 | `tokio = { features = ["full"] }` | 🔵 Low | `Cargo.toml:10` |
| 4.2 | `_config: AuthConfig` unused in `AuthService::new` | 🔵 Low | `auth_service.rs:24` |
| 4.3 | `OwnerProfile`/`RenterProfile` unused | 🔵 Low | `domain/user.rs:27` |
| 4.4 | `logging.json_format` config ignored | 🔵 Low | `main.rs:68` |
| 4.5 | `db_pool: Option<PgPool>` always `Some` | 🔵 Low | `routes/mod.rs:31` |
| 4.6 | `capture_unexpected_5xx` is a stub | 🔵 Low | `error_tracking.rs:4` |

---

## 7. Recommended Priority Order

1. **Fix double JWKS fetch** (1.1) — every authenticated request pays this cost
2. **Fix hardcoded issuer in signup** (1.2) — correctness and security
3. **Fix pagination total** (1.3) — clients cannot paginate correctly
4. **Replace blocking `Mutex`/`RwLock` with async equivalents** (2.1, 2.2) — thread starvation risk under load
5. **Add transaction to `create_message`** (2.4) — data consistency
6. **Add TTL-based eviction to `LoginThrottle`** (2.5) — memory leak
7. **Fix `coordinates: None` in equipment responses** (3.2) — data loss
8. **Fix `EquipmentRepository::search` default** (3.3) — silent filter bypass
9. **Add DB pool tuning** (3.5) — production readiness
10. **Consolidate `role_as_str`/`condition_as_str`** (3.1) — maintainability

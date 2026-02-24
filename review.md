# Backend Performance & Best Practices Review — Follow-Up

**Date:** 2026-02-24 (re-review after fixes)
**Scope:** Full Rust/Actix-Web backend (`src/`)
**Reviewer:** Automated code analysis

---

## Executive Summary

A second pass was performed after the agent applied fixes from the first review.
**Several issues remain unresolved.** The table below tracks every item from the
original review and its current status.

---

## Status of Previously Reported Issues

### 🔴 Critical — Still Open

#### 1.1 Double JWKS Fetch on Every Token Validation — ❌ NOT FIXED

**File:** [`src/utils/auth0_jwks.rs:139-170`](src/utils/auth0_jwks.rs:139)

`get_decoding_key` still calls `get_signing_key` (which may use the cache for
the modulus) and then **unconditionally calls `fetch_jwks()` again** to retrieve
the exponent `e`. The cache stores only `Vec<u8>` (the modulus), so every call
to `get_decoding_key` performs at least one extra HTTP round-trip to Auth0.

```rust
// Still present — line 139-170:
pub async fn get_decoding_key(&self, kid: &str) -> AppResult<DecodingKey> {
    let modulus_bytes = self.get_signing_key(kid).await?;  // may use cache
    let jwks = self.fetch_jwks().await?;                   // ALWAYS fetches again
    ...
}
```

**Required fix:** Cache the full `Jwk` struct (both `n` and `e`) or cache the
`DecodingKey` directly so `fetch_jwks` is never called unconditionally.

---

#### 1.2 Hardcoded Auth0 Issuer and Audience in Signup Handler — ❌ NOT FIXED

**File:** [`src/api/routes/auth.rs:105-118`](src/api/routes/auth.rs:105)

The hardcoded values are still present:

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

**Required fix:** Use `state.auth_service`'s injected config (or pass
`config.auth0.issuer()` and `config.auth0.auth0_audience` from `AppState`).

---

#### 1.3 `PaginatedResponse::total` Reports Page Count, Not Total Records — ❌ NOT FIXED

**File:** [`src/application/equipment_service.rs:82-88`](src/application/equipment_service.rs:82)

```rust
Ok(PaginatedResponse {
    total: items.len() as i64,  // only items on THIS page
    items,
    page,
    limit,
    total_pages: 1,             // always 1!
})
```

**Required fix:** Add a `COUNT(*)` query to get the true total, then compute
`total_pages = (total + limit - 1) / limit`.

---

### 🟠 High — Still Open

#### 2.1 `LoginThrottle` Uses `std::sync::Mutex` in Async Context — ❌ NOT FIXED

**File:** [`src/security/mod.rs:42`](src/security/mod.rs:42)

`std::sync::Mutex<HashMap<...>>` is still used. Under load this blocks Tokio
worker threads.

---

#### 2.2 `WsConnectionHub` Uses `std::sync::RwLock` in Async Context — ❌ NOT FIXED

**File:** [`src/api/routes/ws/hub.rs:2`](src/api/routes/ws/hub.rs:2)

`std::sync::RwLock` is still used. `broadcast_to_users` still acquires a write
lock for what is primarily a read-and-send operation.

---

#### 2.4 `create_message` Does Not Use a Transaction — ❌ NOT FIXED

**File:** [`src/infrastructure/repositories/message_repository.rs:93-115`](src/infrastructure/repositories/message_repository.rs:93)

The INSERT and the `UPDATE conversations SET updated_at` are still two separate
queries with no transaction wrapping them.

---

#### 2.5 `LoginThrottle` State Is Not Cleaned Up — ❌ NOT FIXED

**File:** [`src/security/mod.rs:79-107`](src/security/mod.rs:79)

The `entries` `HashMap` still grows unboundedly. Only `record_success` removes
entries; failed attempts from unique IPs/emails accumulate forever.

---

### 🟡 Medium — Still Open

#### 3.1 `condition_as_str` and `role_as_str` Duplicated Across Services — ❌ NOT FIXED

- [`src/application/equipment_service.rs:378`](src/application/equipment_service.rs:378) — `condition_as_str`
- [`src/application/user_service.rs:135`](src/application/user_service.rs:135) — `role_as_str` + `condition_as_str`
- [`src/application/auth_service.rs:194`](src/application/auth_service.rs:194) — `role_as_str`

All three files still define their own copies of these helpers.

---

#### 3.2 `get_by_id`, `create`, and `update` Always Return `coordinates: None` — ❌ NOT FIXED

**File:** [`src/application/equipment_service.rs:109`](src/application/equipment_service.rs:109),
[`src/application/equipment_service.rs:169`](src/application/equipment_service.rs:169),
[`src/application/equipment_service.rs:245`](src/application/equipment_service.rs:245)

All three response-building sites still hardcode `coordinates: None`.

---

#### 3.3 `EquipmentRepository::search` Default Implementation Ignores Filters — ❌ NOT FIXED

**File:** [`src/infrastructure/repositories/traits.rs:55-68`](src/infrastructure/repositories/traits.rs:55)

The default `search` implementation still falls through to `find_all` in both
branches, silently ignoring all filter parameters.

---

#### 3.4 `AppMetrics` Uses `Ordering::Relaxed` for Correlated Counters — ❌ NOT FIXED

**File:** [`src/observability/mod.rs:16-36`](src/observability/mod.rs:16)

`latency_total_ms` and `latency_count` are still incremented with
`Ordering::Relaxed`, making the computed average in `render_prometheus`
potentially inconsistent.

---

#### 3.5 DB Pool Missing Production Tuning Options — ❌ NOT FIXED

**File:** [`src/infrastructure/db/pool.rs:4-10`](src/infrastructure/db/pool.rs:4)

`acquire_timeout`, `idle_timeout`, `max_lifetime`, and `test_before_acquire`
are still absent.

---

#### 3.6 Naive Email Validation in Signup — ❌ NOT FIXED

**File:** [`src/api/routes/auth.rs:61-66`](src/api/routes/auth.rs:61)

`!email.contains('@') || !email.contains('.')` is still the only check.

---

#### 3.7 Manual `FromRequest` Invocation in `me` Handler — ❌ NOT FIXED

**File:** [`src/api/routes/auth.rs:17-27`](src/api/routes/auth.rs:17)

The handler still manually invokes `FromRequest` instead of declaring
`auth: Auth0AuthenticatedUser` as a parameter.

---

### 🔵 Low — Still Open

#### 4.3 `_config: AuthConfig` Parameter Unused in `AuthService::new` — ❌ NOT FIXED

**File:** [`src/application/auth_service.rs:24`](src/application/auth_service.rs:24)

`_config: AuthConfig` is still accepted but never stored or used.

---

#### 4.4 `OwnerProfile` and `RenterProfile` Domain Types Are Unused — ❌ NOT FIXED

**File:** [`src/domain/user.rs:27-40`](src/domain/user.rs:27)

Both structs are still defined but never referenced in any service, repository,
or route.

---

#### 4.8 `logging.json_format` Config Field Is Ignored — ❌ NOT FIXED

**File:** [`src/main.rs:68-76`](src/main.rs:68)

JSON format is still always enabled regardless of the `json_format` config flag.

---

#### 4.9 `AppState` Contains `db_pool: Option<sqlx::PgPool>` — ❌ NOT FIXED

**File:** [`src/api/routes/mod.rs:31`](src/api/routes/mod.rs:31)

`db_pool` is still `Option<PgPool>` even though it is always `Some` after
startup.

---

## Issues Confirmed Fixed ✅

| # | Issue | Status |
|---|-------|--------|
| 2.3 | Redundant DB calls in `can_access_conversation` | Not verified (no change visible in message_service) |

> **Note:** Issue 2.3 (`can_access_conversation` redundant DB calls) was not
> directly observable from the files reviewed. A full diff of
> `src/application/message_service.rs` would be needed to confirm.

---

## Summary Table

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1.1 | Double JWKS fetch on every token validation | 🔴 Critical | ❌ Open |
| 1.2 | Hardcoded issuer/audience in signup handler | 🔴 Critical | ❌ Open |
| 1.3 | `PaginatedResponse::total` reports page count | 🔴 Critical | ❌ Open |
| 2.1 | `LoginThrottle` uses blocking `Mutex` in async | 🟠 High | ❌ Open |
| 2.2 | `WsConnectionHub` uses blocking `RwLock` | 🟠 High | ❌ Open |
| 2.3 | Redundant DB calls in `can_access_conversation` | 🟠 High | ⚠️ Unverified |
| 2.4 | `create_message` missing transaction | 🟠 High | ❌ Open |
| 2.5 | `LoginThrottle` entries never cleaned up | 🟠 High | ❌ Open |
| 3.1 | `condition_as_str`/`role_as_str` duplicated | 🟡 Medium | ❌ Open |
| 3.2 | `get_by_id`/`create`/`update` return `coordinates: None` | 🟡 Medium | ❌ Open |
| 3.3 | `EquipmentRepository::search` default ignores filters | 🟡 Medium | ❌ Open |
| 3.4 | `AppMetrics` `Relaxed` ordering for correlated counters | 🟡 Medium | ❌ Open |
| 3.5 | DB pool missing production tuning options | 🟡 Medium | ❌ Open |
| 3.6 | Naive email validation in signup | 🟡 Medium | ❌ Open |
| 3.7 | Manual `FromRequest` invocation in `me` handler | 🟡 Medium | ❌ Open |
| 3.8 | `list_equipment` has no rate limiting | 🟡 Medium | ❌ Open |
| 4.1 | `tokio = { features = ["full"] }` | 🔵 Low | ❌ Open |
| 4.2 | `anyhow` + `thiserror` both used | 🔵 Low | ❌ Open (by design) |
| 4.3 | `_config: AuthConfig` unused in `AuthService::new` | 🔵 Low | ❌ Open |
| 4.4 | `OwnerProfile`/`RenterProfile` unused | 🔵 Low | ❌ Open |
| 4.5 | `find_all` on trait unused by application code | 🔵 Low | ❌ Open |
| 4.6 | `broadcast_to_users` write lock for read-heavy op | 🔵 Low | ❌ Open |
| 4.7 | `capture_unexpected_5xx` is a stub | 🔵 Low | ❌ Open |
| 4.8 | `logging.json_format` config ignored | 🔵 Low | ❌ Open |
| 4.9 | `db_pool: Option<PgPool>` always `Some` | 🔵 Low | ❌ Open |

---

## Recommended Priority Order (unchanged)

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

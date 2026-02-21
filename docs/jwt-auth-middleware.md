# JWT Auth Middleware Plan

## Goal

Replace spoofable `x-user-id` request-header auth with validated JWT-based request auth for protected HTTP routes.

## Current State (as of 2026-02-21)

- JWT issuance and validation already exist in `src/utils/jwt.rs`:
  - `create_access_token(user_id, role, config)`
  - `validate_token(token, config) -> Claims`
- Claims already include `sub`, `role`, `aud`, `iss`, `kid`, `jti`, and expiry fields.
- Most protected HTTP routes still call `user_id_from_header` in `src/api/routes/mod.rs`, which reads raw `x-user-id`.
- WebSocket auth already validates bearer access tokens in `src/api/routes/ws.rs`.

## Design

Implement a shared request extractor in a new middleware module:

- `src/middleware/mod.rs`
  - `pub mod auth;`
- `src/middleware/auth.rs`
  - `pub struct AuthenticatedUser(pub Claims);`
  - `impl FromRequest for AuthenticatedUser`

Extractor behavior:

1. Read `Authorization` header.
2. Require `Bearer <token>` format.
3. Load `AuthConfig` from `web::Data<AuthConfig>`.
4. Call `validate_token`.
5. Return:
   - `AppError::Unauthorized` for missing/malformed auth header.
   - `AppError::TokenExpired` when JWT is expired.
   - `AppError::InvalidToken` for all other JWT validation failures.

## App Wiring

In `src/main.rs`, register auth config for extractors:

```rust
.app_data(web::Data::new(config.auth.clone()))
```

Keep existing app state registration unchanged.

## Route Migration Map

Remove `user_id_from_header` from `src/api/routes/mod.rs` and migrate protected handlers to `AuthenticatedUser`.

### `src/api/routes/auth.rs`

- `me`: use `auth.0.sub`
- `verify_email`: use `auth.0.sub`
- Keep `refresh` and `logout` cookie/refresh-token based (do not convert to JWT extractor).

### `src/api/routes/equipment.rs`

- Convert protected handlers:
  - `create_equipment`
  - `update_equipment`
  - `delete_equipment`
  - `add_photo`
  - `delete_photo`
- Keep public handlers unchanged:
  - `list_equipment`
  - `get_equipment`
- Add role gate in `create_equipment`:
  - allow only `owner` or `admin`
  - else `AppError::Forbidden("only owners can create listings".to_string())`

### `src/api/routes/users.rs`

- `update_user_profile`: use `auth.0.sub` as actor
- `my_equipment`: use `auth.0.sub`
- Keep `get_user_profile` public.

### `src/api/routes/messages.rs`

- Convert all handlers to use `AuthenticatedUser` and pass `auth.0.sub` to service layer.

## Tests

Add extractor unit tests in `src/middleware/auth.rs` for:

- valid bearer token -> accepted, correct `sub`
- missing `Authorization` -> `Unauthorized`
- malformed header (no `Bearer ` prefix) -> `Unauthorized`
- expired token -> `TokenExpired`
- wrong signing secret / invalid token -> `InvalidToken`

Use `actix_web::test::TestRequest` and token helpers from `src/utils/jwt.rs`.

## Security Header Alignment

Update `src/security/mod.rs` `Referrer-Policy` value:

- from: `no-referrer`
- to: `strict-origin-when-cross-origin`

## Verification

Run:

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

Confirm:

- no `user_id_from_header` references remain
- no `x-user-id` auth usage remains in HTTP route handlers
- `AuthConfig` is registered as app data in `main.rs`

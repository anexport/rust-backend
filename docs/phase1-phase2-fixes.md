# Agent Task: Fix Phase 1 and Phase 2 Issues in rust-backend

You are working on a Rust backend for a C2C sports equipment rental platform. The codebase is at `/Users/mykolborghese/rust-backend`. Read the relevant source files before making any changes.

---

## Phase 1 Fixes

### 1. Lat/Lng swap bug in `equipment_repository.rs`

In `src/infrastructure/repositories/equipment_repository.rs`, the `create()` and `update()` methods call `ST_MakePoint` with coordinates in the wrong order. `ST_MakePoint` expects `(longitude, latitude)` but the code passes `coordinates_tuple()` which returns `(lat, lng)` — the labels are swapped.

Fix the bindings so longitude is passed as the first argument and latitude as the second. Verify `coordinates_tuple()` in `domain/equipment.rs` returns `(lat, lng)` and adjust accordingly.

### 2. CI missing `sqlx migrate run` and integration test job

In `.github/workflows/ci.yml`:
- In the `test` job, add a step to run `sqlx migrate run` after checkout and before `cargo test`. The DB service is already configured.
- Add a new `integration` job (mirroring the `test` job with the postgres service) that runs `cargo test --test '*'` instead of `cargo test`. This job should also run `sqlx migrate run` before tests.

### 3. Schema mismatch — `description` and `location` NOT NULL in DB but `Option` in domain

In `migrations/20240101000000_init.up.sql`, `equipment.description` and `equipment.location` are `NOT NULL`. But in `src/domain/equipment.rs`, both are `Option<String>`. Make the migration columns nullable (`TEXT` without `NOT NULL`) — it's the safer change given the domain model is already written that way.

---

## Phase 2 Fixes

### 4. Implement logout in `auth_service.rs`

Replace `logout_not_implemented()` with a real `logout()` method. It should:
- Accept a `refresh_token: &str` parameter
- Hash the token with `hash_refresh_token()`
- Look up the session via `find_session_by_token_hash()`
- If found and not already revoked, call `revoke_session_with_replacement(session.id, None, Some("logout"))`
- Return `Ok(())` on success, `Err(AppError::Unauthorized)` if session not found or already revoked

### 5. Fix replay detection logic in `refresh_session_tokens`

In `auth_service.rs`, the current replay detection only calls `revoke_family` when `replaced_by.is_some()`. This means a token revoked by logout won't trigger family revocation on replay.

Change the logic so that ANY revoked session triggers `revoke_family` when presented as a refresh token — regardless of whether `replaced_by` is set. The correct behaviour is: if you see a revoked token being used, the whole family is compromised, revoke everything.

```rust
if session.revoked_at.is_some() {
    self.auth_repo
        .revoke_family(session.family_id, "refresh token replay detected")
        .await?;
    return Err(AppError::Unauthorized);
}
```

### 6. Fix JWT audience claim type

In `src/utils/jwt.rs`, the `Claims` struct has `aud: String`. The JWT spec and the `jsonwebtoken` crate expect audience as an array. Change it to `aud: Vec<String>` and update `create_access_token` to set it as `vec![config.audience.clone()]`. Update `validate_token` accordingly. Run existing tests to confirm they still pass.

### 7. Add unit tests for `auth_service.rs`

The service has significant logic but no tests. Add a `#[cfg(test)]` block in `src/application/auth_service.rs` using mock implementations of `UserRepository` and `AuthRepository` (implement the traits on simple in-memory structs using `std::sync::Mutex<HashMap>`).

Cover at minimum:
- `register` returns conflict on duplicate email
- `login` returns unauthorized on wrong password
- `refresh_session_tokens` rotates correctly (old session revoked, new session issued)
- `refresh_session_tokens` revokes family on replay (present a revoked token, assert family revoked)
- `logout` revokes session correctly

---

## Verification

After all changes, run:

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

All must pass cleanly before you are done.

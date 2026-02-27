# CodeRabbit PR #11 Review Findings

> Source: https://github.com/anexport/rust-backend/pull/11

## Actionable Comments (13 findings)

| # | File | Issue | Status |
|---|------|-------|--------|
| 1 | `docs/master-surgical-plan.md:104-107` | Incorrect `.rs` extensions in Frontend section | SKIPPED |
| 2 | `src/application/equipment/mod.rs:211` | `let _ =` silently drops Result from `update_photo` | TODO |
| 3 | `src/config/mod.rs:88` | `"SENTRY_DSN"` unreachable (not in `only()` array) | TODO |
| 4 | `src/infrastructure/repositories/equipment/mod.rs:208,239` | `ESCAPE ''` breaks escape_like_pattern (should be `ESCAPE '\'`) | TODO |
| 5 | `tests/common/auth0_test_helpers.rs:54` | `.unwrap()` on potential None from `find_by_id` | TODO |
| 6 | `tests/common/mocks/equipment_repo.rs:43-49` | `find_all` ignores pagination args | TODO |
| 7 | `tests/core_api.rs:177` | Uses JWT claims for role instead of DB | TODO |
| 8 | `tests/core_api/admin/auth_stats.rs:14-16` | Silent test skip when DB unavailable | TODO |
| 9 | `tests/core_api/admin/equipment.rs:14-16,47-49` | Silent test skip when DB unavailable | TODO |
| 10 | `tests/core_api/admin/user.rs:89,175-177,185-187,194-196` | No status check before `read_body_json` | TODO |
| 11 | `tests/core_api/equipment_extended/photos.rs:41` | Only checks HTTP status, not repo state | TODO |
| 12 | `tests/core_api/equipment_photos/management.rs:202-203` | No status check before `read_body_json` | TODO |
| 13 | `tests/core_api/messages/ws_broadcast.rs:45` | 1 second WS timeout may be too short | TODO |

---

## Nitpick Comments (16 findings)

| # | File | Issue | Status |
|---|------|-------|--------|
| 1 | `tests/core_api/user/profile.rs:32-34` | Unnecessary intermediate variable binding | TODO |
| 2 | `src/infrastructure/repositories/equipment/search.rs:38-65` | geo_filter computed twice (lines 38 and 53) | TODO |
| 3 | `src/infrastructure/repositories/equipment/search.rs:79-123` | Duplicated filter logic between search() and count_search() | TODO |
| 4 | `tests/core_api/user/equipment.rs:16-18` | Silent test skip when DB unavailable | TODO |
| 5 | `src/application/admin/mapper.rs:5-10` | Potential integer overflow in offset calculation | TODO |
| 6 | `tests/common/mocks/equipment_repo.rs:121-127` | update() returns Ok even when no row found | TODO |
| 7 | `tests/common/mocks/equipment_repo.rs:166-172` | update_photo() returns Ok even when no row found | TODO |
| 8 | `tests/core_api/user/mod.rs:19-82` | Duplicated setup_app across test modules | TODO |
| 9 | `tests/core_api/messages/access.rs:75-104` | Duplicate test coverage (same as test_non_participant_cannot_view_conversation) | TODO |
| 10 | `tests/core_api/admin/user.rs:14-260` | No negative test for token/DB role disagreement | TODO |
| 11 | `tests/core_api/admin/mod.rs:20-83` | Duplicated setup_app | TODO |
| 12 | `tests/core_api/equipment_photos/mod.rs:19-82` | Duplicated setup_app | TODO |
| 13 | `src/config/mod.rs:32-36` | No defaults for LoggingConfig fields | TODO |
| 14 | `src/security/login_throttle.rs:51-81` | Off-by-one in fixed-window counter (increments before checking) | TODO |
| 15 | `tests/core_api/equipment_extended/mod.rs:92-110` | Mock always returns "owner" role, ignores claims | TODO |
| 16 | `tests/core_api/equipment_extended/mod.rs:127-140` | Uses .unwrap() on mutex lock | TODO |

---

## Details

### 2. src/application/equipment/mod.rs:211
```rust
let _ = self.equipment_repo.update_photo(&updated).await;
```
Silently drops Result. Should handle error or use bulk unset method.

### 3. src/config/mod.rs:88
```rust
"SENTRY_DSN" => "sentry.dsn".into(),
```
This arm is unreachable because "SENTRY_DSN" is not in the `only(&[...])` array above.

### 4. src/infrastructure/repositories/equipment/mod.rs:208,239
```sql
e.title ILIKE '%' || $1 || '%' ESCAPE ''
```
Empty ESCAPE breaks escape_like_pattern. Should use `ESCAPE '\'`.

### 5. tests/common/auth0_test_helpers.rs:54
```rust
let user = user_repo.find_by_id(identity.user_id).await?.unwrap();
```
Will panic if identity exists but user doesn't. Should return error instead.

### 6. tests/common/mocks/equipment_repo.rs:43-49
```rust
async fn find_all(&self, _limit: i64, _offset: i64) -> AppResult<Vec<Equipment>> {
    // _limit and _offset are ignored - returns entire vec
}
```

### 7. tests/core_api.rs:177
```rust
let role = match map_role_from_claim(claims).as_str() {
```
Tests derive role from JWT claims instead of database. Should query DB for persisted role.

### 8-9. Silent test skips
Multiple test files use:
```rust
let Some(test_db) = TestDb::new().await else {
    return;
};
```
This silently passes when DB is unavailable, hiding infrastructure failures.

### 10-12. Missing status assertions
```rust
let resp = actix_test::call_service(&app, req).await;
let list: serde_json::Value = actix_test::read_body_json(resp).await;
```
Should assert status first to avoid parsing error responses.

### 13. WS timeout too short
```rust
tokio::time::timeout(std::time::Duration::from_secs(1), rx2.recv())
```
1 second may be too short for CI.

### 14. Unnecessary binding
```rust
let user = fixtures::test_user();
let mut user = user;
```
Should be `let mut user = fixtures::test_user();`

### 15. geo_filter computed twice
Lines 38 and 53 both compute:
```rust
let geo_filter = params.latitude.zip(params.longitude).zip(params.radius_km);
```

### 16. Duplicated filter logic
search() and count_search() have identical WHERE clause building code.

### 17. Integer overflow
```rust
let offset = (page - 1) * per_page;
```
Can overflow for large page values. Use saturating_mul.

### 18-19. Mock returns Ok for missing rows
update() and update_photo() return Ok even when no matching row exists.

### 20. Duplicated setup_app
Multiple test modules have identical setup_app functions that could be shared.

### 21. Duplicate test
test_get_conversation_details_participants_only duplicates test_non_participant_cannot_view_conversation.

### 22. No negative test for role authorization
Tests always align token/DB roles. Should test that token "admin" + DB "renter" returns 403.

### 23. LoggingConfig missing defaults
No #[serde(default)] on LoggingConfig fields.

### 24. Login throttle off-by-one
Increments failures before checking, causing incorrect throttling.

### 25. Mock ignores claims role
MockJitUserProvisioningService always returns "owner" regardless of claims.

### 26. Mutex unwrap
Uses .lock().unwrap() instead of .lock().unwrap_or_else().

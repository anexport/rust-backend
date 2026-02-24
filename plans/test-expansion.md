# Test Expansion Plan (Round 2)

## Overview

This is a continuation of the test expansion work. The first round implemented 39 tests. This plan covers the remaining test cases organized by priority (Critical → Important → Nice to Have).

---

## Status After Round 1

| File | Status | Tests | Completion |
|------|--------|--------|------------|
| `tests/admin_routes_tests.rs` | ✅ Complete | 9/15 tests (~60%) |
| `tests/rate_limiting_tests.rs` | ✅ Complete | 9/11 tests (~82%) |
| `tests/user_routes_tests.rs` | ⚠️ Partial | 5/10 tests (~50%) |
| `tests/message_routes_tests.rs` | ⚠️ Partial | 3/12 tests (~25%) |
| `tests/equipment_photos_tests.rs` | ⚠️ Partial | 3/7 tests (~43%) |
| `tests/config_tests.rs` | ✅ Complete | 6/10 tests (~60%) |
| `tests/db_pool_tests.rs` | ⚠️ Broken | 4/6 tests (~67%) |

**Total Round 1: 39 tests implemented**

---

## ROUND 2 TEST CASES

---

## CRITICAL (Security & Data Integrity)

### Priority 1: Fix Broken DB Pool Tests

**Target File:** `tests/db_pool_tests.rs`

**Issue:** Tests don't use `TestDb::new().await` pattern and fail when `DATABASE_URL` is not set.

**Fix Required:**
```rust
// Replace lines 9-11 with:
let Some(test_db) = common::TestDb::new().await else {
    eprintln!("Skipping test: TEST_DATABASE_URL or DATABASE_URL not set");
    return;
};

// Use test_db.pool() instead of direct env var
let config = DatabaseConfig {
    url: test_db.url().to_string(),
    ...
};
```

**Test Cases (Already present, just need fixing):**
- ✅ `test_create_pool_success` - needs fix
- ✅ `test_pool_exhaustion_behavior` - needs fix
- ✅ `test_pool_test_before_acquire` - needs fix
- ✅ `test_pool_invalid_url_fails_immediately` - OK (no DB required)

**Missing Tests:**
- `test_connection_reuse` - Verify connections are reused from pool
- `test_idle_timeout_closes_connections` - Idle timeout closes idle connections
- `test_max_lifetime_recycles_connections` - Old connections are recycled

---

### Priority 2: Message Route Security (Participant Isolation)

**Target File:** `tests/message_routes_tests.rs`

**Risk:** Message participants could potentially access conversations they're not part of. This is a security vulnerability.

**Test Cases:**

1. **test_non_participant_cannot_view_conversation**
   - Create conversation with 2 users
   - Try to view conversation as 3rd user
   - Assert 403 Forbidden

2. **test_non_participant_cannot_send_message**
   - Create conversation with user1 and user2
   - Try to send message as user3
   - Assert 403 Forbidden

3. **test_conversation_list_isolation**
   - Create conversation1 with user1, user2
   - Create conversation2 with user1, user3
   - List conversations as user2
   - Assert only conversation1 is returned (not conversation2)

4. **test_cannot_create_conversation_with_nonexistent_user**
   - Try to create conversation with fake UUID
   - Assert 400 Bad Request or 404

5. **test_message_list_ordering**
   - Create 5 messages with different timestamps
   - List messages
   - Assert messages are ordered newest first

6. **test_conversation_duplicate_prevention**
   - Create conversation with user1, user2
   - Try to create duplicate conversation
   - Assert 400 or returns existing conversation

7. **test_get_conversation_details_participants_only**
   - Create conversation with user1, user2
   - Get conversation details as user3
   - Assert 403 Forbidden

8. **test_pagination_edge_cases**
   - Create exactly 10 messages (common page size)
   - Request page 1 with limit 10 → should return 10
   - Request page 2 with limit 10 → should return empty
   - Request page 0 → should return empty or first page

9. **test_websocket_broadcast_on_send_message**
   - Mock ws_hub with outbound receiver
   - Send message via API
   - Assert ws_hub.broadcast() was called

**Reference Files:**
- `src/api/routes/messages.rs:17-24`

---

## IMPORTANT (Authorization & Edge Cases)

### Priority 3: Admin Route Coverage Gaps

**Target File:** `tests/admin_routes_tests.rs`

**Missing Test Cases:**

1. **test_stats_includes_available_equipment_count**
   - Create equipment with mixed availability (2 available, 1 not)
   - Get stats as admin
   - Assert `available_equipment` count is correct (should be 2)

2. **test_get_user_detail_by_id**
   - Create user1, user2
   - Get user detail as admin
   - Assert user data is returned correctly
   - Get non-existent user → 404

3. **test_user_list_pagination**
   - Create 25 users
   - Get users with limit=10, offset=0 → returns 10
   - Get users with limit=10, offset=10 → returns 10
   - Get users with limit=10, offset=20 → returns 5
   - Assert total count in response

4. **test_delete_user_cascades_to_equipment**
   - Create owner user with equipment
   - Delete user as admin
   - Assert user is deleted
   - Assert associated equipment is deleted (CASCADE)
   - OR assert equipment.owner_id is set to null if SOFT DELETE

5. **test_admin_cannot_update_other_admin_role**
   - Create admin1, admin2
   - Try to change admin2's role as admin1
   - Check if this is allowed (depends on business rules)
   - If not allowed, assert 403

6. **test_category_list_with_hierarchy**
   - Create parent category
   - Create child categories
   - List all categories
   - Assert parent and children are returned
   - Verify structure (parent-child relationships)

**Reference Files:**
- `src/api/routes/admin.rs:13-18`
- `src/application/admin_service.rs:39-56`

---

### Priority 4: User Route Validation

**Target File:** `tests/user_routes_tests.rs`

**Missing Test Cases:**

1. **test_profile_viewing_excludes_sensitive_data**
   - Create user with email, auth identities
   - Get user profile as another user
   - Assert response contains: username, full_name, avatar_url, role
   - Assert response DOES NOT contain: email, auth identities

2. **test_profile_update_email_validation**
   - Try to update with invalid email format
   - Assert 400 Bad Request
   - Try to update with well-formed email
   - Assert success

3. **test_profile_update_username_constraints**
   - Try to update with empty username
   - Assert 400 Bad Request
   - Try to update with username that's too long
   - Assert 400 Bad Request

4. **test_my_equipment_pagination**
   - Create 15 equipment items for user
   - Get my/equipment with limit=5, offset=0 → returns 5
   - Get my/equipment with limit=5, offset=5 → returns 5
   - Assert total count is 15

5. **test_my_equipment_ordered_by_creation_date**
   - Create equipment with different timestamps
   - Get my/equipment
   - Assert results are ordered newest first

6. **test_get_public_profile_anonymous**
   - Create public user
   - Get user profile WITHOUT authentication
   - Assert 200 OK (if public profiles are allowed)
   - OR assert 401 (if auth required)

**Reference Files:**
- `src/api/routes/users.rs:9-16`

---

### Priority 5: Equipment Photo Cascade Behavior

**Target File:** `tests/equipment_photos_tests.rs`

**Missing Test Cases:**

1. **test_photo_persistence_verification**
   - Add photo to equipment
   - Query equipment from database
   - Assert photo is in equipment.photos collection
   - Assert photo URL matches what was sent

2. **test_photo_associated_with_correct_equipment**
   - Create equipment1, equipment2
   - Add photo to equipment1
   - Get equipment2's photos
   - Assert photo is NOT in equipment2's photos

3. **test_delete_equipment_cascades_to_photos**
   - Create equipment with 3 photos
   - Delete equipment (as owner or admin)
   - Assert equipment is deleted
   - Assert all 3 photos are deleted from database

4. **test_delete_photo_leaves_other_photos_intact**
   - Create equipment with 3 photos
   - Delete 1 photo
   - Assert deleted photo is gone
   - Assert 2 remaining photos still exist
   - Assert they are still associated with equipment

**Reference Files:**
- `src/api/routes/equipment.rs:19-20`

---

## NICE TO HAVE (Config Validation & Rate Limiting)

### Priority 6: Config Edge Cases

**Target File:** `tests/config_tests.rs`

**Missing Test Cases:**

1. **test_negative_timeout_values_fail**
   - Set negative `APP_SECURITY__LOGIN_LOCKOUT_SECONDS`
   - Assert config loading fails
   - Set negative `APP_DATABASE__ACQUIRE_TIMEOUT_SECONDS`
   - Assert config loading fails

2. **test_invalid_url_format_fails**
   - Set invalid database URL format
   - Assert config loading fails
   - Set invalid Auth0 domain format
   - Assert config loading fails

3. **test_cors_origins_list_parsing**
   - Set multiple allowed origins
   - Assert all are parsed correctly
   - Set empty origins list
   - Assert no origins allowed

4. **test_allowed_origins_validation**
   - Set origin with invalid characters
   - Assert validation fails
   - Set origin without protocol
   - Assert validation fails

5. **test_config_override_by_env**
   - Set env var that should override default
   - Load config
   - Assert env var value is used, not default

6. **test_required_env_var_missing_fails**
   - Clear required env var (e.g., DATABASE_URL)
   - Assert config loading fails with clear error

**Reference Files:**
- `src/config/mod.rs`

---

### Priority 7: Rate Limiting Cleanup

**Target File:** `tests/rate_limiting_tests.rs`

**Missing Test Cases:**

1. **test_entry_cleanup_removes_expired_entries**
   - Record failure with short lockout (1 second)
   - Wait 2 seconds
   - Verify entry is removed from internal state
   - Allow new request (should not be rate limited)

2. **test_connection_pool_behavior_during_lockout**
   - This may not apply to rate limiting, but verify:
   - Multiple concurrent lockout attempts don't cause deadlocks
   - Lockout state is thread-safe

3. **test_memory_does_not_grow_unbounded**
   - Create 1000 distinct keys
   - Record failures for each
   - Wait for all to expire
   - Verify memory usage decreases (entries cleaned up)

**Note:** May require internal visibility into LoginThrottle state or using a test-specific variant with instrumentation.

**Reference Files:**
- `src/security/mod.rs:41-152`

---

### Priority 8: DB Pool Connection Behavior

**Target File:** `tests/db_pool_tests.rs`

**Missing Test Cases:**

1. **test_connection_reuse_verification**
   - Acquire connection
   - Execute query
   - Drop connection
   - Acquire another connection
   - Verify same DB connection is reused (by checking process ID if possible)

2. **test_idle_timeout_closes_connections**
   - Set idle timeout to 1 second
   - Create pool
   - Acquire connection
   - Wait 2 seconds
   - Verify connection is closed

3. **test_max_lifetime_recycles_connections**
   - Set max lifetime to 1 second
   - Create pool
   - Acquire connection and use it
   - Wait 2 seconds
   - Acquire new connection
   - Verify old connection was recycled (new backend process or connection check)

**Reference Files:**
- `src/infrastructure/db/pool.rs`

---

## IMPLEMENTATION NOTES

### Fix Required: tests/message_routes_tests.rs
Remove unused imports:
```rust
// Remove these lines from imports:
use rust_backend::infrastructure::repositories::{
    // CategoryRepository,  <-- Remove
    // EquipmentRepository,  <-- Remove
    CategoryRepositoryImpl,
    EquipmentRepositoryImpl,
    MessageRepository, MessageRepositoryImpl, UserRepository,
    UserRepositoryImpl,
};
```

### Fix Required: tests/db_pool_tests.rs
Rewrite to use `TestDb` pattern:

```rust
#[tokio::test]
async fn test_create_pool_success() {
    let Some(test_db) = common::TestDb::new().await else {
        eprintln!("Skipping test: TEST_DATABASE_URL or DATABASE_URL not set");
        return;
    };

    let config = DatabaseConfig {
        url: test_db.url().to_string(),
        max_connections: 2,
        min_connections: 1,
        acquire_timeout_seconds: 1,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let pool = create_pool(&config).await.expect("Failed to create pool");
    assert!(pool.size() >= 1);

    let _conn = pool.acquire().await.expect("Failed to acquire connection");
    assert!(pool.size() >= 1);
}
```

Note: Add `url()` method to `TestDb` in `tests/common/mod.rs`:
```rust
impl TestDb {
    pub fn url(&self) -> &str {
        &self.url
    }
}
```

---

## Success Criteria

Each priority is complete when:
1. All listed test cases are implemented
2. Tests pass locally (`cargo test`)
3. Tests follow the project's coding style
4. Edge cases are covered
5. Authorization/security is properly tested

---

## Estimated Test Count (Round 2)

| Priority | Area | New Tests |
|----------|------|-----------|
| 1 | Fix DB Pool Tests | 3 new tests + 3 fixed |
| 2 | Message Security | 9 new tests |
| 3 | Admin Coverage Gaps | 6 new tests |
| 4 | User Validation | 6 new tests |
| 5 | Photo Cascade | 4 new tests |
| 6 | Config Edge Cases | 6 new tests |
| 7 | Rate Limiting Cleanup | 3 new tests |
| 8 | DB Pool Behavior | 3 new tests |
| **Total** | **Round 2** | **~40 tests** |

**Combined Total (Round 1 + Round 2): ~79 tests**

---

## Implementation Guidelines

### Test File Structure
```rust
mod common;

use actix_web::{http::StatusCode, test as actix_test, web, App};
use rust_backend::api::routes::{self, AppState};
use rust_backend::domain::Role;
// ... other imports

use common::fixtures;
use common::TestDb;

#[actix_rt::test]
async fn test_case_name() {
    let Some(test_db) = TestDb::new().await else {
        eprintln!("Skipping test: TEST_DATABASE_URL not set");
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;

    // Arrange
    // ... setup test data ...

    // Act
    let req = actix_test::TestRequest::get()
        .uri("/api/some-endpoint")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    // Assert
    assert_eq!(resp.status(), StatusCode::OK);
}
```

### Mock JWT Setup
All tests requiring authentication should use the established mock pattern:
```rust
struct MockJwksProvider {
    decoding_key: jsonwebtoken::DecodingKey,
}

#[async_trait]
impl JwksProvider for MockJwksProvider {
    async fn get_decoding_key(&self, kid: &str) -> AppResult<DecodingKey> {
        if kid == "test-key-id" {
            Ok(self.decoding_key.clone())
        } else {
            Err(AppError::Unauthorized)
        }
    }
}

fn create_auth0_token(user_id: Uuid, role: &str) -> String {
    // ... existing code ...
}
```

### Use Existing Test Infrastructure
- `tests/common/mod.rs` - Test database setup (use `TestDb::new().await`)
- `tests/common/fixtures.rs` - Test data fixtures (`test_user()`, `test_owner()`, `test_admin()`)
- `tests/common/test_private_key.pem` - JWT signing

### Naming Convention
- Test files: `tests/{feature}_routes_tests.rs` or `tests/{feature}_tests.rs`
- Test functions: `test_{what}_when_{condition}` or descriptive like `test_admin_cannot_demote_self`

### Run Tests
```bash
# Run all tests
make test

# Run specific test file
cargo test --test message_routes_tests

# Run with output
cargo test --test message_routes_tests -- --nocapture
```

---

## Notes

- Always run `cargo fmt` and `cargo clippy` before committing
- Follow existing test patterns in the codebase
- Ensure database tests use the `TestDb` wrapper for proper isolation
- Use `common::insert_*` helpers for setting up test data
- Mock external services (Auth0) where appropriate
- Security tests (especially authorization) should be prioritized
- Participant isolation in messaging is security-critical

# Test Expansion Plan

## Overview

This plan outlines the test expansion work for the rust-backend project, prioritizing high-risk and untested areas of the codebase.

## Current Test Coverage

### Integration Tests
- `tests/repository_integration_tests.rs` - Repository layer
- `tests/auth0_endpoints_tests.rs` - Auth0 signup/login
- `tests/core_api_tests.rs` - Core API endpoints
- `tests/equipment_search_tests.rs` - Equipment search
- `tests/category_service_tests.rs` - Category service
- `tests/message_service_tests.rs` - Message service
- `tests/auth_middleware_tests.rs` - Auth middleware
- `tests/user_service_tests.rs` - User service
- `tests/ws_security_tests.rs` - WebSocket security

### Unit Tests
- Domain models (equipment, user serialization)
- Auth route helpers (`client_ip`, `provisioning_claims`)
- Auth0 claims mapping
- Error tracking
- Auth0 API client (error mapping, URL construction)

---

## Priority 1: Admin API Routes (High Priority)

**Target File:** `tests/admin_routes_tests.rs`

**Routes to Test:**
- `GET /api/admin/stats` - Statistics aggregation
- `GET /api/admin/users` - User listing with pagination
- `GET /api/admin/users/{id}` - User detail retrieval
- `PUT /api/admin/users/{id}/role` - Role updates
- `DELETE /api/admin/users/{id}` - User deletion
- `GET /api/admin/equipment` - Admin equipment listing
- `DELETE /api/admin/equipment/{id}` - Force equipment deletion
- `PUT /api/admin/equipment/{id}/availability` - Toggle availability
- `GET /api/admin/categories` - Category listing
- `POST /api/admin/categories` - Category creation
- `PUT /api/admin/categories/{id}` - Category update

**Test Cases:**
1. **Authorization Tests**
   - Non-admin users receive 403 Forbidden
   - Unauthenticated requests receive 401 Unauthorized
   - Admin users can access all endpoints

2. **Stats Endpoint**
   - Returns correct user, equipment, category counts
   - Handles empty database state

3. **User Role Management**
   - Admin can change renter -> owner
   - Admin can change owner -> admin
   - Role updates persist to database
   - Cannot change own role (if applicable)

4. **User Deletion**
   - Admin can delete users
   - Equipment owned by deleted user is handled correctly
   - Cascade behavior verification

5. **Equipment Availability Toggle**
   - Admin can toggle availability regardless of ownership
   - Toggle reflects in subsequent reads

6. **Category Management**
   - Admin can create categories
   - Admin can update category names
   - Category parent-child relationships work correctly

**Reference Files:**
- `src/api/routes/admin.rs:11-30`
- `src/application/admin_service.rs`

---

## Priority 2: Security / Rate Limiting (High Priority)

**Target File:** `tests/rate_limiting_tests.rs`

**Component:** `src/security/mod.rs` - `LoginThrottle`

**Test Cases:**
1. **Basic Rate Limiting**
   - `ensure_allowed()` permits initial requests
   - After `max_failures`, requests are blocked
   - `record_success()` clears the blocked state

2. **Exponential Backoff**
   - Failure count increases backoff time exponentially
   - Backoff formula: `backoff_base_ms * (2^(failures-1))`
   - Maximum backoff is capped at `backoff_base_ms * 2^8`

3. **Lockout Behavior**
   - After `max_failures`, user is locked out for `lockout_seconds`
   - Lockout persists across multiple attempts
   - Successful auth (if possible) clears lockout

4. **Key-Based Isolation**
   - Rate limits are per-key (IP/email)
   - One user's failures don't affect another user

5. **Cleanup**
   - Expired entries are removed from tracking
   - Memory doesn't grow unbounded

6. **CORS Middleware**
   - Allowed origins can make requests
   - Disallowed origins receive CORS errors
   - Credentials are supported

7. **Security Headers**
   - All responses include required headers
   - CSP is correctly configured
   - HSTS header is present

**Reference Files:**
- `src/security/mod.rs:41-152`

---

## Priority 3: User API Routes (High Priority)

**Target File:** `tests/user_routes_tests.rs`

**Routes to Test:**
- `GET /api/users/{id}` - Profile viewing
- `PUT /api/users/{id}` - Profile updates
- `GET /api/users/me/equipment` - User's equipment listing

**Test Cases:**
1. **Profile Viewing**
   - Public profile returns non-sensitive data
   - Profile includes: username, full_name, avatar_url, role (optional)
   - 404 for non-existent user

2. **Profile Updates**
   - User can update their own profile
   - User cannot update another user's profile (403)
   - Partial updates work (only provided fields updated)
   - Validation: email format, username constraints

3. **Own Equipment Listing**
   - User can list their own equipment
   - User cannot list another user's equipment via this endpoint
   - Pagination works correctly
   - Results are ordered by creation date

**Reference Files:**
- `src/api/routes/users.rs`
- `src/application/user_service.rs`

---

## Priority 4: Messages API Routes (Medium Priority)

**Target File:** `tests/message_routes_tests.rs`

**Note:** Service layer is tested in `tests/message_service_tests.rs`, but HTTP layer needs coverage.

**Routes to Test:**
- `GET /api/conversations` - List user's conversations
- `POST /api/conversations` - Create new conversation
- `GET /api/conversations/{id}` - Get conversation details
- `GET /api/conversations/{id}/messages` - List messages
- `POST /api/conversations/{id}/messages` - Send message

**Test Cases:**
1. **Conversation List**
   - User sees conversations they participate in
   - User doesn't see conversations they're not in
   - Pagination works correctly

2. **Create Conversation**
   - User can start conversation with another user
   - Cannot create conversation with non-existent user
   - Cannot create duplicate conversations
   - Both users appear in participants

3. **Message Sending**
   - Participants can send messages
   - Non-participants cannot send messages (403)
   - Messages persist to database
   - WebSocket broadcasts work (integration with ws_hub)

4. **Message List**
   - Participants can view all messages
   - Non-participants cannot view messages (403)
   - Pagination works correctly
   - Messages are ordered by timestamp

**Reference Files:**
- `src/api/routes/messages.rs`
- `src/application/message_service.rs`

---

## Priority 5: Equipment Photo Operations (Medium Priority)

**Target File:** `tests/equipment_photos_tests.rs`

**Note:** Add to existing `tests/equipment_search_tests.rs` or create separate file.

**Routes to Test:**
- `POST /api/equipment/{id}/photos` - Add photo
- `DELETE /api/equipment/{id}/photos/{photo_id}` - Delete photo

**Test Cases:**
1. **Add Photo Authorization**
   - Equipment owner can add photos
   - Non-owner cannot add photos (403)
   - Admin can add photos to any equipment

2. **Photo Deletion Authorization**
   - Equipment owner can delete their photos
   - Non-owner cannot delete photos (403)
   - Admin can delete any photo

3. **Photo Persistence**
   - Photo URL is stored in database
   - Photo is associated with correct equipment
   - Multiple photos can be added

4. **Cascade Behavior**
   - Deleting equipment deletes associated photos
   - Deleting a photo leaves other photos intact

**Reference Files:**
- `src/api/routes/equipment.rs:19-20`

---

## Priority 6: Database Pool Behavior (Medium Priority)

**Target File:** `tests/db_pool_tests.rs`

**Component:** `src/infrastructure/db/pool.rs`

**Test Cases:**
1. **Pool Configuration**
   - Max connections is respected
   - Min connections are created on startup
   - Idle timeout closes idle connections
   - Max lifetime recycles old connections

2. **Connection Acquisition**
   - `acquire_timeout` returns error when pool is exhausted
   - Connections are reused from pool
   - `test_before_acquire` validates connections

3. **Pool Exhaustion**
   - When max connections are in use, new requests wait
   - After timeout, request fails with appropriate error

**Reference Files:**
- `src/infrastructure/db/pool.rs`

---

## Priority 7: Configuration Parsing (Low Priority)

**Target File:** `tests/config_tests.rs`

**Component:** `src/config/`

**Test Cases:**
1. **Environment Variable Loading**
   - Required fields cause error when missing
   - Default values are used for optional fields
   - Invalid values cause errors (negative timeouts, invalid URLs)

2. **Auth0 Config**
   - Domain validation
   - Audience validation
   - JWKS cache TTL parsing

3. **Database Config**
   - URL parsing
   - Connection pool parameter validation

4. **Security Config**
   - CORS origins list parsing
   - Allowed origins validation

**Reference Files:**
- `src/config/mod.rs`

---

## Implementation Guidelines

### Test File Structure
```rust
mod common;

use actix_web::{http::StatusCode, test as actix_test, web, App};
use rust_backend::api::routes::{self, AppState};
// ... other imports

#[actix_rt::test]
async fn test_case_name() {
    // Arrange
    let Some(test_db) = common::TestDb::new().await else {
        eprintln!("Skipping test: TEST_DATABASE_URL not set");
        return;
    };

    // Act
    // ... test code ...

    // Assert
    assert_eq!(status, StatusCode::OK);
}
```

### Use Existing Test Infrastructure
- `tests/common/mod.rs` - Test database setup
- `tests/common/fixtures.rs` - Test data fixtures
- `tests/common/test_private_key.pem` - JWT signing for auth tests

### Naming Convention
- Test files: `tests/{feature}_routes_tests.rs` or `tests/{feature}_tests.rs`
- Test functions: `test_{what}_when_{condition}_then_{expected}`

### Run Tests
```bash
# Run all tests
make test

# Run integration tests
make test-integration

# Run specific test file
cargo test --test admin_routes_tests
```

---

## Success Criteria

Each priority is complete when:
1. All listed test cases are implemented
2. Tests pass locally
3. Tests follow the project's coding style
4. Edge cases are covered
5. Authorization is properly tested

---

## Estimated Test Count

| Priority | Area | Estimated Tests |
|----------|------|----------------|
| 1 | Admin API Routes | ~15-20 tests |
| 2 | Security/Rate Limiting | ~10-12 tests |
| 3 | User API Routes | ~8-10 tests |
| 4 | Messages API Routes | ~10-12 tests |
| 5 | Equipment Photo Operations | ~6-8 tests |
| 6 | Database Pool | ~5-6 tests |
| 7 | Configuration | ~8-10 tests |
| **Total** | | **~62-78 tests** |

---

## Notes

- Always run `cargo fmt` and `cargo clippy` before committing
- Follow the existing test patterns in the codebase
- Ensure database tests use the `TestDb` wrapper for proper isolation
- Use `common::insert_*` helpers for setting up test data
- Mock external services (Auth0) where appropriate

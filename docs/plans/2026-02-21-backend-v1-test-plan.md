# Rust Backend v1 Comprehensive Test Plan

> **Purpose:** Define exhaustive test coverage for all implementation phases. Each test case should be automatable and traceable to acceptance criteria.

**Related Documents:**
- `docs/PLAN.md` - Architecture and API specification
- `docs/plans/2026-02-21-backend-v1-implementation-checklist.md` - Implementation phases

---

## Table of Contents

1. [Test Infrastructure](#test-infrastructure)
2. [Phase 0: Project Scaffold Tests](#phase-0-project-scaffold-tests)
3. [Phase 1: Database and Core API Tests](#phase-1-database-and-core-api-tests)
4. [Phase 2: Session and Token Tests](#phase-2-session-and-token-tests)
5. [Phase 3: HTTP Security Tests](#phase-3-http-security-tests)
6. [Phase 4: Authorization Tests](#phase-4-authorization-tests)
7. [Phase 5: WebSocket Tests](#phase-5-websocket-tests)
8. [Phase 6: Observability Tests](#phase-6-observability-tests)
9. [Phase 7: Migration Validation Tests](#phase-7-migration-validation-tests)
10. [Phase 8: Final Release Gates](#phase-8-final-release-gates)
11. [Test Data Fixtures](#test-data-fixtures)
12. [Performance Test Specifications](#performance-test-specifications)

---

## Test Infrastructure

### Test Categories

| Category | Location | Purpose | Speed |
|----------|----------|---------|-------|
| Unit | `src/**/tests.rs` | Pure logic, no I/O | Fast (ms) |
| Integration | `tests/integration/` | API + DB, real Postgres | Medium (s) |
| Security | `tests/security/` | Attack vectors, edge cases | Medium (s) |
| Performance | `tests/performance/` | Load, latency, throughput | Slow (min) |
| Migration | `tests/migration/` | Data integrity, rollback | Slow (min) |

### Test Database Setup

```rust
// tests/common/mod.rs
pub struct TestDb {
    pub pool: PgPool,
    pub db_name: String,
}

impl TestDb {
    pub async fn new() -> Self {
        // Create isolated test database with random suffix
        // Run migrations
        // Return pool
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Cleanup: drop test database
    }
}
```

### Test Client

```rust
// tests/common/client.rs
pub struct TestClient {
    client: reqwest::Client,
    base_url: String,
    auth_token: Option<String>,
    refresh_token: Option<String>,
}

impl TestClient {
    pub fn authenticated(user_id: Uuid, role: Role) -> Self;
    pub fn unauthenticated() -> Self;
    pub async fn post<T: Serialize>(&self, path: &str, body: &T) -> Response;
    pub async fn get(&self, path: &str) -> Response;
    pub fn set_auth_token(&mut self, token: String);
}
```

---

## Phase 0: Project Scaffold Tests

### P0-01: Compilation and Formatting

| ID | Test Case | Command | Expected |
|----|-----------|---------|----------|
| P0-01-a | Clean build | `cargo build --release` | Exit 0 |
| P0-01-b | Format check | `cargo fmt --check` | Exit 0 |
| P0-01-c | Clippy strict | `cargo clippy -- -D warnings` | Exit 0 |
| P0-01-d | Doc generation | `cargo doc --no-deps` | Exit 0 |

### P0-02: Dependency Audit

| ID | Test Case | Command | Expected |
|----|-----------|---------|----------|
| P0-02-a | Security audit | `cargo audit` | Exit 0 (no vulnerabilities) |
| P0-02-b | License check | `cargo license --avoid-dev` | Only approved licenses |
| P0-02-c | Duplicate deps | `cargo tree --duplicates` | No duplicates |

### P0-03: CI Pipeline

| ID | Test Case | Expected |
|----|-----------|----------|
| P0-03-a | All checks pass on PR | Green CI status |
| P0-03-b | Main branch protected | Direct push blocked |
| P0-03-c | Required status checks | All 4 jobs required |

---

## Phase 1: Database and Core API Tests

### P1-01: Migration Tests

| ID | Test Case | Setup | Steps | Expected |
|----|-----------|-------|-------|----------|
| P1-01-a | Fresh migration | Empty DB | `sqlx migrate run` | All migrations applied |
| P1-01-b | Idempotent migration | Migrated DB | `sqlx migrate run` | No-op, no errors |
| P1-01-c | Rollback migration | Migrated DB | `sqlx migrate revert` | Last migration removed |
| P1-01-d | Full rollback | Migrated DB | Revert all | Clean state |
| P1-01-e | Extension check | Fresh DB | Query extensions | `pgcrypto`, `postgis` installed |

### P1-02: User Registration Tests

| ID | Test Case | Input | Expected Status | Expected Body |
|----|-----------|-------|-----------------|---------------|
| P1-02-a | Valid registration | email, password, username | 201 | User DTO with id |
| P1-02-b | Duplicate email | Existing email | 409 | `{"error": "Conflict", "code": "EMAIL_EXISTS"}` |
| P1-02-c | Duplicate username | Existing username | 409 | `{"error": "Conflict", "code": "USERNAME_EXISTS"}` |
| P1-02-d | Invalid email format | "notanemail" | 400 | Validation error |
| P1-02-e | Short password | "pass" | 400 | Validation error |
| P1-02-f | Missing fields | {} | 400 | Validation error |
| P1-02-g | Password hashed | Valid reg | Query DB | Argon2 hash stored |
| P1-02-h | Default role | Valid reg | Query DB | `renter` role |
| P1-02-i | Email not verified | Valid reg | Query DB | `verified = false` |

### P1-03: Login Tests

| ID | Test Case | Input | Expected Status | Expected Body |
|----|-----------|-------|-----------------|---------------|
| P1-03-a | Valid login | Correct credentials | 200 | Access token + refresh cookie |
| P1-03-b | Wrong password | Wrong password | 401 | `{"error": "Unauthorized"}` |
| P1-03-c | Unknown email | Non-existent email | 401 | Generic error (no enumeration) |
| P1-03-d | Unverified email | Unverified user | 403 | `{"error": "Forbidden", "code": "EMAIL_NOT_VERIFIED"}` |
| P1-03-e | Session created | Valid login | Query DB | Session row exists |
| P1-03-f | Refresh token cookie | Valid login | Response | `HttpOnly`, `Secure`, `SameSite=Lax` |

### P1-04: OAuth Tests

| ID | Test Case | Steps | Expected |
|----|-----------|-------|----------|
| P1-04-a | Google OAuth success | Mock OAuth flow | User created, token returned |
| P1-04-b | Google OAuth existing user | OAuth with existing email | Account linked, no duplicate |
| P1-04-c | GitHub OAuth success | Mock OAuth flow | User created, token returned |
| P1-04-d | OAuth state validation | Tampered state | 400 rejected |
| P1-04-e | OAuth callback invalid code | Invalid auth code | 401 rejected |

### P1-05: User Profile Tests

| ID | Test Case | Auth | Expected Status | Notes |
|----|-----------|------|-----------------|-------|
| P1-05-a | Get own profile | Self | 200 | All fields |
| P1-05-b | Get other profile | Authenticated | 200 | Public fields only |
| P1-05-c | Get profile unauthenticated | None | 200 | Limited fields |
| P1-05-d | Update own profile | Self | 200 | Updated DTO |
| P1-05-e | Update other profile | Different user | 403 | Forbidden |
| P1-05-f | Admin update any | Admin | 200 | Allowed |

### P1-06: Equipment CRUD Tests

| ID | Test Case | Auth | Input | Expected Status |
|----|-----------|------|-------|-----------------|
| P1-06-a | List equipment (public) | None | N/A | 200, paginated |
| P1-06-b | Create equipment | Owner | Valid DTO | 201 |
| P1-06-c | Create equipment (renter) | Renter | Valid DTO | 403 |
| P1-06-d | Get equipment by ID | None | Valid ID | 200 |
| P1-06-e | Get non-existent equipment | None | Random UUID | 404 |
| P1-06-f | Update own equipment | Owner of resource | Valid DTO | 200 |
| P1-06-g | Update other's equipment | Non-owner | Valid DTO | 403 |
| P1-06-h | Delete own equipment | Owner of resource | N/A | 204 |
| P1-06-i | Delete other's equipment | Non-owner | N/A | 403 |
| P1-06-j | Equipment with coordinates | Owner | Lat/lng | Stored in PostGIS |
| P1-06-k | Filter by category | None | category_id | Filtered results |
| P1-06-l | Filter by location | None | Lat/lng + radius | Distance sorted |
| P1-06-m | Filter by price range | None | min/max | Filtered results |

### P1-07: Equipment Photos Tests

| ID | Test Case | Expected Status |
|----|-----------|-----------------|
| P1-07-a | Add photo (owner) | 201 |
| P1-07-b | Add photo (non-owner) | 403 |
| P1-07-c | Set primary photo | 200, only one primary |
| P1-07-d | Delete photo (owner) | 204 |
| P1-07-e | Delete primary photo | 204, next becomes primary |
| P1-07-f | Delete photo (non-owner) | 403 |

### P1-08: Messaging Tests

| ID | Test Case | Expected Status |
|----|-----------|-----------------|
| P1-08-a | Create conversation | 201 |
| P1-08-b | List my conversations | 200 |
| P1-08-c | Get conversation (participant) | 200 |
| P1-08-d | Get conversation (non-participant) | 403 |
| P1-08-e | Send message (participant) | 201 |
| P1-08-f | Send message (non-participant) | 403 (or DB trigger error) |
| P1-08-g | Get messages (participant) | 200, paginated |
| P1-08-h | Get messages (non-participant) | 403 |
| P1-08-i | Mark conversation as read | 200 |

### P1-09: Category Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P1-09-a | List all categories | 200, tree structure |
| P1-09-b | Get category with children | 200 |
| P1-09-c | Get non-existent category | 404 |

---

## Phase 2: Session and Token Tests

### P2-01: JWT Structure Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P2-01-a | JWT contains jti | Unique per token |
| P2-01-b | JWT contains sub | User ID |
| P2-01-c | JWT contains exp | 15 minutes from iat |
| P2-01-d | JWT contains iat | Issued at timestamp |
| P2-01-e | JWT contains aud | Configured audience |
| P2-01-f | JWT contains iss | Configured issuer |
| P2-01-g | JWT contains kid | Key identifier |
| P2-01-h | JWT signed with RS256 or HS256 | Configurable algorithm |

### P2-02: Token Expiration Tests

| ID | Test Case | Setup | Expected |
|----|-----------|-------|----------|
| P2-02-a | Access token expires | Wait 15 min | 401 on request |
| P2-02-b | Expired token rejected | Use expired token | 401 |
| P2-02-c | Future iat rejected | Token with future iat | 401 |
| P2-02-d | Missing exp claim | Malformed token | 401 |

### P2-03: Refresh Token Tests

| ID | Test Case | Steps | Expected |
|----|-----------|-------|----------|
| P2-03-a | Refresh returns new access token | POST /auth/refresh with cookie | 200, new JWT |
| P2-03-b | Refresh rotates refresh token | Refresh twice | Different refresh tokens |
| P2-03-c | Old refresh token invalid | Use rotated token | 401, revoked |
| P2-03-d | Refresh token stored as hash | Query DB | Only hash stored |
| P2-03-e | Invalid refresh token | Random token | 401 |
| P2-03-f | Expired refresh token | Wait for expiry | 401 |
| P2-03-g | Revoked session refresh | Revoked session | 401 |

### P2-04: Token Family Tests (Replay Detection)

| ID | Test Case | Steps | Expected |
|----|-----------|-------|----------|
| P2-04-a | Family ID assigned | Create session | family_id set |
| P2-04-b | Rotation preserves family | Refresh token | Same family_id |
| P2-04-c | Reuse detection triggers | Use old refresh token | All family tokens revoked |
| P2-04-d | Reuse logs security event | Replay attack | Audit log entry |
| P2-04-e | Reuse invalidates access tokens | Replay attack | Current access token also revoked |
| P2-04-f | New session after replay | Login again | New family_id |

### P2-05: Key Ring Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P2-05-a | Load active key | Key available |
| P2-05-b | Load previous key | Key available for verification |
| P2-05-c | Sign with active key | kid matches active |
| P2-05-d | Verify with previous key | Accepts old tokens during rotation |
| P2-05-e | Key rotation window | Both keys valid for N days |

### P2-06: Logout Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P2-06-a | Logout revokes session | Session revoked_at set |
| P2-06-b | Logout invalidates access token | Token blacklisted or session invalid |
| P2-06-c | Logout clears cookie | Cookie removed |
| P2-06-d | Logout all sessions | All user sessions revoked |

---

## Phase 3: HTTP Security Tests

### P3-01: CORS Tests

| ID | Test Case | Request | Expected |
|----|-----------|---------|----------|
| P3-01-a | Allowed origin | Origin: allowed domain | Access-Control-Allow-Origin set |
| P3-01-b | Disallowed origin | Origin: evil.com | No CORS headers |
| P3-01-c | Preflight request | OPTIONS with CORS headers | Proper response |
| P3-01-d | Credentials with wildcard | Origin: * with credentials | Rejected (spec) |
| P3-01-e | Multiple origins | Multiple allowed origins | Correct origin echoed |

### P3-02: Cookie Security Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P3-02-a | HttpOnly flag | Cookie not accessible via JS |
| P3-02-b | Secure flag | Cookie only sent over HTTPS |
| P3-02-c | SameSite Lax | Cross-site POST blocked |
| P3-02-d | Path restriction | Cookie only sent to /api/auth |

### P3-03: CSRF Tests

| ID | Test Case | Request | Expected |
|----|-----------|---------|----------|
| P3-03-a | Valid CSRF token | POST with valid token | 200 |
| P3-03-b | Missing CSRF token | POST without token | 403 |
| P3-03-c | Invalid CSRF token | POST with bad token | 403 |
| P3-03-d | CSRF exempt GET | GET without token | 200 |
| P3-03-e | Double submit cookie | Token in header + cookie | Match required |
| P3-03-f | CSRF token rotation | After sensitive action | New token issued |

### P3-04: Rate Limiting Tests

| ID | Test Case | Threshold | Expected |
|----|-----------|-----------|----------|
| P3-04-a | IP rate limit | 10 req/min | 429 after threshold |
| P3-04-b | Account rate limit | 5 failed logins | Temporary lockout |
| P3-04-c | Rate limit headers | Limited response | X-RateLimit-* headers |
| P3-04-d | Rate limit reset | Wait 1 min | Limit resets |
| P3-04-e | Different IP separate | Same account, different IP | Separate limits |
| P3-04-f | Successful auth resets | Successful login | Failed count reset |

### P3-05: Login Hardening Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P3-05-a | Exponential backoff | Increasing delay after failures |
| P3-05-b | Temporary lockout | 15 min lockout after 5 failures |
| P3-05-c | Lockout notification | User notified (optional) |
| P3-05-d | Successful login clears lockout | Lockout lifted |
| P3-05-e | Distributed lockout | Works across instances |

### P3-06: Password Policy Tests

| ID | Test Case | Input | Expected |
|----|-----------|-------|----------|
| P3-06-a | Minimum length | < 12 chars | 400 rejected |
| P3-06-b | Banned password | "password123" | 400 rejected |
| P3-06-c | Common patterns | "12345678" | 400 rejected |
| P3-06-d | Strong password | Complex password | Accepted |
| P3-06-e | Argon2id parameters | Hash output | Correct time/memory cost |

### P3-07: Security Headers Tests

| ID | Test Case | Header | Expected Value |
|----|-----------|--------|----------------|
| P3-07-a | HSTS | Strict-Transport-Security | max-age=31536000; includeSubDomains |
| P3-07-b | X-Content-Type-Options | X-Content-Type-Options | nosniff |
| P3-07-c | X-Frame-Options | X-Frame-Options | DENY |
| P3-07-d | Referrer-Policy | Referrer-Policy | strict-origin-when-cross-origin |
| P3-07-e | CSP | Content-Security-Policy | Baseline policy configured |
| P3-07-f | X-XSS-Protection | X-XSS-Protection | 0 (deprecated but often included) |

### P3-08: Metrics Protection Tests

| ID | Test Case | Request | Expected |
|----|-----------|---------|----------|
| P3-08-a | Public access blocked | GET /metrics from public IP | 403 or 404 |
| P3-08-b | Internal access allowed | GET /metrics from internal IP | 200 |
| P3-08-c | Admin auth access | GET /metrics with admin token | 200 |

---

## Phase 4: Authorization Tests

### P4-01: Authorization Matrix Coverage

Complete test for each cell in authorization matrix (PLAN.md lines 348-379):

```rust
// Pseudocode for automated matrix testing
for endpoint in ENDPOINTS {
    for role in [PUBLIC, RENTER, OWNER, ADMIN, SELF] {
        test_access(endpoint, role, expected_allowed: bool);
    }
}
```

### P4-02: Role-Based Tests

| ID | Endpoint | Role | Expected |
|----|----------|------|----------|
| P4-02-a | POST /equipment | renter | 403 |
| P4-02-b | POST /equipment | owner | 201 |
| P4-02-c | POST /equipment | admin | 201 |
| P4-02-d | PUT /users/:id (other) | renter | 403 |
| P4-02-e | PUT /users/:id (other) | admin | 200 |
| P4-02-f | GET /metrics | renter | 403 |
| P4-02-g | GET /metrics | admin | 200 |

### P4-03: Ownership Tests

| ID | Endpoint | Owner | Resource Owner | Expected |
|----|----------|-------|----------------|----------|
| P4-03-a | PUT /equipment/:id | User A | User A | 200 |
| P4-03-b | PUT /equipment/:id | User A | User B | 403 |
| P4-03-c | DELETE /equipment/:id | User A | User A | 204 |
| P4-03-d | DELETE /equipment/:id | User A | User B | 403 |
| P4-03-e | POST /equipment/:id/photos | User A | User A | 201 |
| P4-03-f | POST /equipment/:id/photos | User A | User B | 403 |
| P4-03-g | Admin override PUT | Admin | User B | 200 |

### P4-04: Conversation Participation Tests

| ID | Test Case | Participant | Expected |
|----|-----------|-------------|----------|
| P4-04-a | Get own conversation | Participant | 200 |
| P4-04-b | Get other conversation | Non-participant | 403 |
| P4-04-c | Send to own conversation | Participant | 201 |
| P4-04-d | Send to other conversation | Non-participant | 403 |
| P4-04-e | Admin access any | Admin | 200 |
| P4-04-f | Multi-party conversation | Any participant | 200 |

### P4-05: Negative Authorization Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P4-05-a | Tampered user_id in JWT | 401 |
| P4-05-b | Expired session | 401 |
| P4-05-c | Role escalation attempt | 403 |
| P4-05-d | Resource ID manipulation | 403 |
| P4-05-e | Missing auth on protected | 401 |
| P4-05-f | Invalid JWT signature | 401 |
| P4-05-g | JWT algorithm confusion | 401 |
| P4-05-h | SQL injection in auth | No data leak, 400 |

---

## Phase 5: WebSocket Tests

### P5-01: Connection Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P5-01-a | Valid connection | Connected, session tracked |
| P5-01-b | No auth token | Connection rejected |
| P5-01-c | Invalid token | Connection rejected |
| P5-01-d | Expired token | Connection rejected |
| P5-01-e | Revoked session | Connection rejected |
| P5-01-f | Token in Authorization header | Accepted |
| P5-01-g | Token in subprotocol fallback | Accepted |

### P5-02: Message Flow Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P5-02-a | Send message | Stored in DB, broadcast to participants |
| P5-02-b | Receive message | Correct format, timestamp |
| P5-02-c | Typing indicator | Broadcast to other participants |
| P5-02-d | Mark as read | DB updated, confirmation sent |
| P5-02-e | Ping/pong | Connection maintained |

### P5-03: Connection Lifecycle Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P5-03-a | Normal disconnect | Session cleaned up |
| P5-03-b | Abrupt disconnect | Session cleaned up after timeout |
| P5-03-c | Reconnect | New connection, missed messages fetchable |
| P5-03-d | Multiple tabs | Multiple connections per user |
| P5-03-e | Heartbeat timeout | Connection closed after N missed pings |

### P5-04: Edge Cases

| ID | Test Case | Expected |
|----|-----------|----------|
| P5-04-a | Message during disconnect | Stored, delivered on reconnect via REST |
| P5-04-b | Large message | Truncated or rejected |
| P5-04-c | Malformed JSON | Error response, connection maintained |
| P5-04-d | Flood protection | Rate limited |
| P5-04-e | Concurrent messages | Ordered delivery |
| P5-04-f | Binary message | Rejected or handled per protocol |

### P5-05: Security Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P5-05-a | Message to non-participant conversation | Rejected |
| P5-05-b | Spoofed sender_id | Ignored, uses JWT identity |
| P5-05-c | SQL injection in message | Sanitized, no impact |
| P5-05-d | XSS in message content | Escaped in delivery |
| P5-05-e | Connection hijacking | Token validation prevents |

---

## Phase 6: Observability Tests

### P6-01: Structured Logging Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P6-01-a | Request ID in logs | Every request has unique ID |
| P6-01-b | User ID in logs | Authenticated requests include user_id |
| P6-01-c | JSON format | Logs parseable as JSON |
| P6-01-d | Log levels | DEBUG, INFO, WARN, ERROR properly used |
| P6-01-e | Sensitive data redacted | Passwords, tokens not logged |

### P6-02: Audit Log Tests

| ID | Event | Expected Fields |
|----|-------|-----------------|
| P6-02-a | Login success | user_id, ip, user_agent, timestamp |
| P6-02-b | Login failure | email, ip, reason, timestamp |
| P6-02-c | Logout | user_id, session_id, timestamp |
| P6-02-d | Token refresh | user_id, old_session, new_session |
| P6-02-e | Password change | user_id, ip, timestamp |
| P6-02-f | Role change | actor_id, target_id, old_role, new_role |
| P6-02-g | Admin action | actor_id, action, target, timestamp |

### P6-03: Health Endpoint Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P6-03-a | GET /health (healthy) | 200, `{"status": "ok"}` |
| P6-03-b | GET /ready (DB up) | 200, `{"status": "ready"}` |
| P6-03-c | GET /ready (DB down) | 503, `{"status": "not_ready"}` |
| P6-03-d | Health no auth required | Unauthenticated request | 200 |

### P6-04: Metrics Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P6-04-a | Request latency histogram | Buckets configured |
| P6-04-b | Error rate counter | Incremented on 5xx |
| P6-04-c | DB pool metrics | Active/idle connections |
| P6-04-d | WS connection gauge | Active connections tracked |
| P6-04-e | Auth failure counter | Incremented on auth failures |
| P6-04-f | Prometheus format | Valid exposition format |

---

## Phase 7: Migration Validation Tests

### P7-01: Data Integrity Queries

Run after migration from Supabase:

```sql
-- P7-01-a: Row count reconciliation
SELECT 
    'profiles' as table_name,
    (SELECT COUNT(*) FROM profiles) as rust_count,
    -- Compare with Supabase export
    :supabase_profiles_count as supabase_count;

-- P7-01-b: FK integrity
SELECT COUNT(*) as broken_refs FROM equipment e
LEFT JOIN profiles p ON e.owner_id = p.id
WHERE p.id IS NULL;
-- Expected: 0

-- P7-01-c: Null constraint check
SELECT COUNT(*) FROM profiles WHERE email IS NULL;
-- Expected: 0

-- P7-01-d: Unique constraint verification
SELECT email, COUNT(*) FROM profiles GROUP BY email HAVING COUNT(*) > 1;
-- Expected: 0 rows
```

### P7-02: Business Logic Validation

| ID | Test Case | Query/Check |
|----|-----------|-------------|
| P7-02-a | All equipment has valid owner | FK check |
| P7-02-b | All messages have valid sender | FK check |
| P7-02-c | All conversations have participants | Participant check |
| P7-02-d | No orphan photos | FK check |
| P7-02-e | Price values valid | daily_rate > 0 |
| P7-02-f | Role values valid | role IN ('renter', 'owner', 'admin') |

### P7-03: Rollback Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P7-03-a | DB backup exists | Backup file verified |
| P7-03-b | DB restore works | Test restore to staging |
| P7-03-c | App version rollback | Previous version deploys |
| P7-03-d | Data loss quantified | Compare pre/post counts |
| P7-03-e | Rollback runbook tested | Documented steps work |

### P7-04: Migration Script Tests

| ID | Test Case | Expected |
|----|-----------|----------|
| P7-04-a | Export completes | All tables exported |
| P7-04-b | Transform valid | All rows transformed |
| P7-04-c | Import completes | All rows imported |
| P7-04-d | Idempotent | Re-run safe |
| P7-04-e | Progress reporting | Percentage complete logged |

---

## Phase 8: Final Release Gates

### P8-01: Security Review Checklist

| ID | Item | Status |
|----|------|--------|
| P8-01-a | No SQL injection vulnerabilities | Pass |
| P8-01-b | No XSS vulnerabilities | Pass |
| P8-01-c | No CSRF vulnerabilities | Pass |
| P8-01-d | No broken auth/session | Pass |
| P8-01-e | No sensitive data exposure | Pass |
| P8-01-f | No broken access control | Pass |
| P8-01-g | No security misconfiguration | Pass |
| P8-01-h | No vulnerable dependencies | Pass |

### P8-02: Performance Targets

| ID | Metric | Target | Threshold |
|----|--------|--------|-----------|
| P8-02-a | P50 latency | < 50ms | < 100ms |
| P8-02-b | P95 latency | < 200ms | < 500ms |
| P8-02-c | P99 latency | < 500ms | < 1s |
| P8-02-d | Error rate | < 0.1% | < 1% |
| P8-02-e | Throughput | > 1000 req/s | > 500 req/s |
| P8-02-f | WS connections | > 10000 concurrent | > 5000 |

### P8-03: Operational Readiness

| ID | Item | Expected |
|----|------|----------|
| P8-03-a | On-call runbook | Documented |
| P8-03-b | Incident response plan | Documented |
| P8-03-c | Secrets rotation tested | Verified |
| P8-03-d | JWT key rotation tested | Verified |
| P8-03-e | Backup restore tested | Verified |
| P8-03-f | Monitoring dashboards | Deployed |
| P8-03-g | Alert rules | Configured |

---

## Test Data Fixtures

### User Fixtures

```rust
// tests/common/fixtures.rs

pub fn test_user() -> NewUser {
    NewUser {
        email: "test@example.com",
        username: Some("testuser"),
        password: Some("SecurePassword123!"),
        role: Role::Renter,
    }
}

pub fn test_owner() -> NewUser {
    NewUser {
        email: "owner@example.com",
        username: Some("owner"),
        password: Some("SecurePassword123!"),
        role: Role::Owner,
    }
}

pub fn test_admin() -> NewUser {
    NewUser {
        email: "admin@example.com",
        username: Some("admin"),
        password: Some("SecurePassword123!"),
        role: Role::Admin,
    }
}
```

### Equipment Fixtures

```rust
pub fn test_equipment(owner_id: Uuid, category_id: Uuid) -> NewEquipment {
    NewEquipment {
        owner_id,
        category_id,
        title: "Test Equipment",
        description: "A test equipment item",
        daily_rate: Decimal::new(1000, 2), // $10.00
        condition: Condition::Good,
        location: "Test Location",
        coordinates: Some((40.7128, -74.0060)), // NYC
    }
}
```

---

## Performance Test Specifications

### Load Test Scenarios

#### Scenario 1: Login Burst

```yaml
name: login_burst
duration: 60s
target_rps: 100
endpoint: POST /api/auth/login
payload:
  email: "loadtest{{threadId}}@example.com"
  password: "LoadTestPassword123!"
setup:
  - Create {{concurrentUsers}} test users
assertions:
  - p95_latency < 500ms
  - error_rate < 1%
```

#### Scenario 2: Equipment Search

```yaml
name: equipment_search
duration: 120s
target_rps: 500
endpoint: GET /api/equipment?location={{lat}},{{lng}}&radius=10
headers:
  Authorization: Bearer {{accessToken}}
assertions:
  - p95_latency < 200ms
  - error_rate < 0.1%
```

#### Scenario 3: WebSocket Fanout

```yaml
name: ws_fanout
duration: 60s
concurrent_connections: 1000
scenario:
  - Connect {{connections}} WS clients
  - Each client joins unique conversation
  - Send message to each conversation
  - Measure delivery latency
assertions:
  - message_delivery_p95 < 100ms
  - connection_success_rate > 99%
```

#### Scenario 4: Mixed Traffic

```yaml
name: mixed_traffic
duration: 300s
traffic_mix:
  - endpoint: GET /api/equipment
    weight: 40
  - endpoint: GET /api/equipment/:id
    weight: 30
  - endpoint: POST /api/auth/login
    weight: 10
  - endpoint: GET /api/conversations
    weight: 15
  - endpoint: POST /api/conversations/:id/messages
    weight: 5
target_rps: 1000
assertions:
  - overall_p95 < 300ms
  - error_rate < 0.5%
```

---

## Test Execution Matrix

### Per-PR Tests (Fast Feedback)

| Category | Tests | Duration |
|----------|-------|----------|
| Unit | All | ~30s |
| Integration | Smoke (10%) | ~2min |
| Security | Critical (5%) | ~1min |
| **Total** | | **~3.5min** |

### Nightly Tests (Comprehensive)

| Category | Tests | Duration |
|----------|-------|----------|
| Unit | All | ~30s |
| Integration | All | ~15min |
| Security | All | ~10min |
| Performance | Load scenarios | ~30min |
| **Total** | | **~56min** |

### Pre-Release Tests (Full Suite)

| Category | Tests | Duration |
|----------|-------|----------|
| All Nightly | | ~56min |
| Migration | Dry run + validation | ~30min |
| Rollback | Full drill | ~15min |
| Security | External scan | ~1hr |
| **Total** | | **~2.5hr** |

---

## Appendix A: Test Commands Reference

```bash
# Run all unit tests
cargo test --lib

# Run all integration tests
cargo test --test '*'

# Run specific test module
cargo test auth::

# Run with verbose output
cargo test -- --nocapture

# Run with specific thread count
cargo test -- --test-threads=4

# Run security tests only
cargo test --test security

# Run performance tests (requires separate tool)
k6 run tests/performance/login_burst.js

# Generate coverage report
cargo tarpaulin --out Html --output-dir target/coverage

# Run mutation tests
cargo mutants
```

---

## Appendix B: CI Configuration

```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test --lib

  integration:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgis/postgis:15-3.3
        env:
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
    steps:
      - uses: actions/checkout@v4
      - run: cargo test --test '*'

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo audit
      - run: cargo test --test security

  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-21 | Engineering | Initial comprehensive test plan |

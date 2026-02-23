# Coverage 85 Test Backlog

## Summary
This document is the execution backlog to raise coverage to **>=85% line coverage per file** for every file currently below 85% in the latest llvm-cov report (`target/llvm-cov/html/index.html`, created 2026-02-23 19:07).

Rules for execution:
- Prioritize line coverage as the hard gate.
- Keep behavior unchanged unless explicitly listed as a minimal testability seam.
- Use TDD for each test addition.
- After each phase, run coverage and update status/checklists.

## Baseline (Files Below 85% Line Coverage)
`need+N` means additional covered lines needed to hit 85% line coverage for that file.

| File | Function % | Line % | Region % | Covered Lines | Need |
|---|---:|---:|---:|---:|---:|
| `api/routes/auth.rs` | 79.41 | 80.27 | 77.80 | 236/294 | +14 |
| `api/routes/mod.rs` | 76.92 | 78.08 | 70.09 | 57/73 | +6 |
| `api/routes/users.rs` | 71.43 | 73.17 | 79.63 | 30/41 | +5 |
| `api/routes/ws.rs` | 43.62 | 53.23 | 53.78 | 272/511 | +163 |
| `application/user_service.rs` | 56.25 | 71.79 | 60.94 | 84/117 | +16 |
| `config/app_config.rs` | 31.03 | 52.91 | 45.20 | 100/189 | +61 |
| `domain/errors.rs` | 52.38 | 60.00 | 71.82 | 51/85 | +22 |
| `error/app_error.rs` | 82.76 | 76.62 | 76.23 | 249/325 | +28 |
| `infrastructure/auth0_api.rs` | 21.74 | 45.65 | 44.30 | 63/138 | +55 |
| `infrastructure/db/pool.rs` | 0.00 | 0.00 | 0.00 | 0/8 | +7 |
| `infrastructure/oauth/auth0_api_client.rs` | 75.00 | 66.67 | 66.74 | 220/330 | +61 |
| `infrastructure/oauth/mod.rs` | 29.41 | 18.40 | 20.93 | 30/163 | +109 |
| `infrastructure/repositories/traits.rs` | 0.00 | 0.00 | 0.00 | 0/4 | +4 |
| `infrastructure/repositories/user_repository.rs` | 71.43 | 72.73 | 72.73 | 32/44 | +6 |
| `main.rs` | 0.00 | 0.00 | 0.00 | 0/42 | +36 |
| `middleware/auth.rs` | 55.56 | 78.72 | 79.37 | 37/47 | +3 |
| `observability/error_tracking.rs` | 0.00 | 0.00 | 0.00 | 0/4 | +4 |
| `observability/mod.rs` | 20.00 | 33.33 | 42.59 | 9/27 | +14 |
| `utils/auth0_jwks.rs` | 40.54 | 52.83 | 52.31 | 140/265 | +86 |

## Minimal Testability Seams (Allowed)
These are non-breaking internal refactors to unblock testability.

1. `src/main.rs`
- Extract helper builders for Auth0/JWKS client decisions (pure or easily mockable helpers).
- Keep runtime behavior unchanged.

2. `src/infrastructure/oauth/mod.rs`
- Add optional injectable endpoints and/or HTTP adapter for `HttpOAuthClient` to test provider status/error branches deterministically.
- Keep default constructor behavior and public behavior unchanged.

## Execution Backlog (Prioritized)

### Phase A: Fast Unit Wins

#### A1. `src/domain/errors.rs`
- Status: [ ]
- Test location: existing `#[cfg(test)]` module in `src/domain/errors.rs`
- Add tests:
  - `not_found_constructor_maps_to_not_found_variant`
  - `validation_constructor_maps_to_validation_variant`
  - `conflict_constructor_maps_to_conflict_variant`
  - `cannot_delete_active_rental_has_expected_message`
  - `equipment_not_available_has_expected_message`
  - `cannot_modify_completed_rental_has_expected_message`
  - `insufficient_inventory_includes_item_name`
  - `user_already_has_active_rental_has_expected_message`
  - `rental_cannot_be_cancelled_has_expected_message`
  - `payment_required_for_action_has_expected_message`
- Expected assertions:
  - Correct enum variants and exact messages.
- Coverage impact: medium, very low risk.

#### A2. `src/observability/mod.rs`
- Status: [ ]
- Test location: new `#[cfg(test)]` module in `src/observability/mod.rs`
- Add tests:
  - `record_request_increments_request_count`
  - `record_request_5xx_increments_error_count`
  - `record_auth_failure_increments_counter`
  - `ws_connected_and_disconnected_update_gauge`
  - `render_prometheus_includes_all_metrics_with_expected_values`
- Expected assertions:
  - Presence of all metric lines and expected counts/avg latency.
- Coverage impact: high relative to file size.

#### A3. `src/observability/error_tracking.rs`
- Status: [ ]
- Test location: new `#[cfg(test)]` module in `src/observability/error_tracking.rs`
- Add tests:
  - `capture_unexpected_5xx_does_not_panic`
  - Optional: `capture_unexpected_5xx_emits_expected_fields` with tracing capture.
- Coverage impact: high relative to file size.

#### A4. `src/infrastructure/db/pool.rs`
- Status: [ ]
- Test location: new `#[cfg(test)]` module in `src/infrastructure/db/pool.rs`
- Add tests:
  - `create_pool_returns_error_for_invalid_url`
  - `create_pool_uses_configured_connection_bounds` (assert path execution/invalid connect error with supplied bounds)
- Coverage impact: high relative to file size.

#### A5. `src/infrastructure/repositories/traits.rs`
- Status: [ ]
- Test location: new unit test module (either in file or `tests/unit`)
- Add tests:
  - default `EquipmentRepository::search` calls `find_all` when all filters are `None`
  - default `MessageRepository::find_participant_ids` returns empty vec
- Coverage impact: high relative to file size.

#### A6. `src/api/routes/mod.rs`
- Status: [ ]
- Test location: add `#[cfg(test)]` module in `src/api/routes/mod.rs`
- Add tests:
  - `is_private_or_loopback_ipv4_private_true`
  - `is_private_or_loopback_ipv4_public_false`
  - `is_private_or_loopback_ipv6_loopback_true`
  - `is_private_or_loopback_ipv6_unique_local_true`
  - `pool_stats_without_db_pool_returns_zeroes`
- Coverage impact: medium.

### Phase B: Service + Route Logic

#### B1. `src/application/user_service.rs`
- Status: [ ]
- Test location: `tests/` (new focused test file recommended: `tests/user_service_tests.rs`)
- Add tests with mock repos:
  - `get_public_profile_returns_not_found_when_missing`
  - `update_profile_self_updates_allowed_fields`
  - `update_profile_non_admin_cannot_update_others`
  - `update_profile_admin_can_update_others`
  - `my_equipment_maps_defaults_and_condition_strings`
- Coverage impact: medium/high.

#### B2. `src/api/routes/users.rs`
- Status: [ ]
- Test location: extend `tests/core_api_tests.rs`
- Add tests:
  - route-level success for `GET /api/users/{id}`
  - auth-protected success/error for `PUT /api/users/{id}`
  - `GET /api/users/me/equipment` uses authenticated user id
- Coverage impact: medium.

#### B3. `src/api/routes/auth.rs`
- Status: [ ]
- Test location: extend `tests/core_api_tests.rs`; helper-level tests in-file if needed
- Add tests:
  - refresh fails when token absent in both body and cookie
  - refresh fails when csrf cookie/header missing
  - logout from cookie token clears both cookies
  - me fails without `Authorization`
  - helper: `client_ip` behavior with and without forwarded address
- Coverage impact: medium.

#### B4. `src/middleware/auth.rs`
- Status: [ ]
- Test location: extend `tests/auth_middleware_tests.rs`
- Add tests:
  - malformed/non-bearer authorization rejected
  - missing app data (`JwksProvider`, `Auth0Config`, `UserProvisioningService`) returns internal error
  - provisioning failure is propagated
  - valid flow returns `Auth0AuthenticatedUser`
- Coverage impact: medium.

### Phase C: Boundary-Heavy Modules

#### C1. `src/error/app_error.rs`
- Status: [ ]
- Test location: existing test module in file
- Add tests:
  - cover `error_code` and `status_code` for remaining variants
  - cover `public_message` for internal vs exposed variants
  - `From<DomainError>` all variants
  - `From<jsonwebtoken::Error>` expired vs non-expired
  - remaining SQLSTATE mappings: `23503`, `23514`, `22P02`, unknown
  - `required_field_message_from_db` parse and no-match
  - `extract_raise_exception_message` variants
  - more constraint branches in `conflict_message_from_constraint`
- Coverage impact: high.

#### C2. `src/infrastructure/auth0_api.rs`
- Status: [ ]
- Test location: existing test module + optional new mocked HTTP tests
- Add tests:
  - `HttpAuth0ApiClient::new` missing domain failure
  - URL builders for signup/token endpoints
  - disabled client paths (`signup`/`password_grant`) return service unavailable
  - extra Auth0 error-code mappings (`auth_id_already_exists`, `invalid_signup`, `access_denied`, `bad_request`)
  - optional: `handle_error` unparsable response branch
- Coverage impact: high.

#### C3. `src/infrastructure/oauth/auth0_api_client.rs`
- Status: [ ]
- Test location: existing test module
- Add tests:
  - `with_metadata` serialization
  - `PasswordGrantRequest` serialization with/without optional fields
  - status mappings for signup and password_grant branches using mocked HTTP responses
  - response parse-failure branches
- Coverage impact: high.

#### C4. `src/utils/auth0_jwks.rs`
- Status: [ ]
- Test location: existing test module
- Add tests:
  - token header missing `kid` -> unauthorized
  - JWKS provider key resolution failure -> unauthorized
  - missing issuer or audience config -> internal error
  - invalid base64 in JWK modulus/exponent handling
  - `get_signing_key` cache hit path
  - decode error mappings: expired, invalid issuer, invalid audience, invalid signature
- Coverage impact: high.

#### C5. `src/infrastructure/oauth/mod.rs`
- Status: [ ]
- Test location: existing test module + injected endpoints/mocks
- Add tests:
  - google exchange success
  - github exchange success with direct email
  - github email fallback path via `/user/emails`
  - github no-email path -> expected bad request message
  - `http_json` network error branch
  - `http_json` non-success status branch
  - `http_json` invalid json parse branch
  - github-compat headers and bearer token handling
- Coverage impact: very high.

#### C6. `src/api/routes/ws.rs`
- Status: [ ]
- Test location: in-file tests + extend `tests/ws_security_tests.rs`
- Add tests:
  - `extract_ws_token` edge cases
  - `authenticate_ws_user` unauthorized when no active session
  - `is_secure_ws_request` additional header/scheme permutations
  - `handle_text_message` unsupported type and payload-parse failures
  - parse helper negative cases for send/typing/read payloads
  - broadcast behavior with multiple participants and pruning
- Coverage impact: very high.

### Phase D: Integration + Bootstrap

#### D1. `src/infrastructure/repositories/user_repository.rs`
- Status: [ ]
- Test location: extend `tests/repository_integration_tests.rs`
- Add tests:
  - `find_by_username` positive/negative
  - delete non-existent id path behavior
  - `verify_email` updates only email-provider identity
- Coverage impact: medium.
- Prerequisite: stable ephemeral test DB setup.

#### D2. `src/main.rs`
- Status: [ ]
- Test location: unit tests around extracted helper functions in `src/main.rs` or dedicated module
- Add tests:
  - auth0 enabled + http client builds
  - auth0 enabled + client build failure falls back to disabled client
  - auth0 disabled selects disabled client
  - jwks provider creation success/failure paths
- Coverage impact: high relative to file size.

## Suggested Execution Order
1. Phase A (quickest gain, lowest risk)
2. Phase B (service/route branch completion)
3. Phase C (boundary modules with larger deltas)
4. Phase D (integration/bootstrap cleanup)

## Verification Commands
Run after each phase:

```bash
cargo test --lib
```

When DB is available:

```bash
cargo test --tests
```

Coverage run:

```bash
cargo llvm-cov --html
```

## Per-File Coverage Gate Script (Line Coverage >= 85%)
Use this to fail fast on remaining under-85 files:

```bash
perl -0777 -ne '
while(/<tr class=\x27light-row\x27><td><pre>(?:<a href=\x27[^\x27]*\x27>)?([^<]+)(?:<\/a>)?<\/pre><\/td><td class=\x27[^\x27]+\x27><pre>\s*([0-9.]+)% \([^)]*\)<\/pre><\/td><td class=\x27[^\x27]+\x27><pre>\s*([0-9.]+)% \((\d+)\/(\d+)\)<\/pre><\/td>/g){
  if($3 < 85){ print "$1\t$3%\t($4/$5)\n"; $fail=1; }
}
exit($fail ? 1 : 0)
' target/llvm-cov/html/index.html
```

## Acceptance Criteria
1. Every file listed in this document reaches **>=85% line coverage**.
2. `cargo llvm-cov --html` completes with full intended suite (including integration tests in DB-ready environment).
3. No regressions in auth/ws/security behavior.
4. This backlog remains updated with checkboxes and deltas after each iteration.

## Assumptions
1. Line coverage per file is the hard target metric.
2. All currently below-85 files are in scope (no exclusions).
3. Minimal internal refactors for testability are allowed only where listed.
4. Existing test structure is reused (in-file unit tests + `tests/*.rs` integration suites).
5. DB-dependent coverage requires a working ephemeral test DB environment.

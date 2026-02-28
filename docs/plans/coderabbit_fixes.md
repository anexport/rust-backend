# CodeRabbit Review Findings - Execution Plan

## Phase 1: Security, Auth & Config (Criticals & Majors)
*The highest priority issues that prevent secret leaks and fix broken configuration loading.*
* **Secrets Redaction:** Remove `#[derive(Debug)]` and implement custom redacted Debug traits for `AppConfig`, `AuthConfig`, `Auth0Config`, `SignupRequest`, etc.
* **Config Loading:** Fix the `.nested()` bug in `src/config/mod.rs` so `development.toml` loads correctly.
* **Auth Bypass:** Enforce `self.require_admin()` in `src/application/admin/mod.rs` for `update_user_role` and `delete_user`.
* **Login Throttle:** Restrict `write_entries` visibility to prevent external mutation.

## Phase 2: Core Logic, Validations & Panics (Majors)
*Fixing panics, missing validations, and math bugs.*
* **Rate Limiting:** Clamp the interval in `src/security/rate_limit.rs` to prevent divide-by-zero panics and validate `AppConfig` early.
* **Pagination Math:** Use saturating arithmetic in `user_service.rs` to prevent integer overflow panics.
* **DTO Validations:** Add `payload.validate()?` to `update_user_profile` and `query.validate()?` to `my_equipment`.
* **DTO Constraints:** Add proper validation rules (e.g., `range(min = 1)`) and derives to `PaginationParams`.
* **Auth0 Error Mapping:** Preserve the correct HTTP status codes in `to_app_error()` instead of defaulting to 500s.
* **Auth0 Client:** Fix `auth0_domain` initialization to reject empty strings properly.

## Phase 3: Database compile-time macros & DTO deduplication
*Refactoring for safety and cleanliness.*
* **SQLx Macros:** Convert all `sqlx::query_as::<_, T>()` in `src/infrastructure/repositories/equipment/mod.rs` and `photo.rs` to compile-time checked `sqlx::query_as!()`.
* **DTO Deduplication:** Consolidate `SignupResponse` into `Auth0SignupResponse` and `PasswordGrantResponse` into `Auth0TokenResponse`.
* **Serialization Fixes:** Add `skip_serializing_if` to `SignupRequest.connection`.

## Phase 4: Test Refactors & Python Nitpicks (Minors)
*Cleaning up the test suites and scripts.*
* **Python Script:** Fix E701 lint errors, unused imports, and add error handling to `split_repo_tests.py`.
* **Test Suite Unused Imports:** Remove flagged imports in `tests/auth0_endpoints/login.rs` and `tests/auth_middleware.rs`.
* **Test Fixes:** Fix the expired JWT claim hardcoding, token segment assertions, test comment typos, and fix `test_db_pool()` fallback logic.
* **Test DRYing (Don't Repeat Yourself):** Extract common setup logic in `provisioning.rs`, `equipment_photos/management.rs`, `system.rs`, etc.
* **Test Assertions:** Add missing DB assertions in `signup.rs`, `profile.rs`, and `user.rs`.

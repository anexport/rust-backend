# CodeRabbit Review Findings

## Comprehensive Task List (from AI Prompt Summary)

```text
Verify each finding against the current code and only fix it if needed.

Inline comments:
In `@docs/review.md`:
- Around line 295-305: The Markdown snippet containing the call to
auth_repo.create_identity and the rust_backend::domain::AuthIdentity struct
should be wrapped in a fenced code block (triple backticks) to prevent MD037 and
broken parsing; update the example around the auth_repo.create_identity(...)
invocation (and the similar snippet referencing AuthIdentity/Uuid::new_v4 and
provider fields noted later) by enclosing the entire snippet in ```rust ... ```
so the markers like `*`/`_` are treated as code rather than Markdown.

In `@src/api/dtos/common.rs`:
- Around line 13-19: Update the PaginationParams DTO to include the missing
derives and field validations: add serde::Serialize and utoipa::ToSchema to the
derive list on struct PaginationParams (alongside Debug, Deserialize,
IntoParams, Validate) and annotate the page and limit fields with validator
attributes (e.g., #[validate(range(min = 1))] for page and #[validate(range(min
= 1, max = <sensible_max>))] for limit) while keeping their serde defaults via
default_page and default_limit; ensure any required imports for Serialize,
ToSchema and validator attributes are added/adjusted in the file.

In `@src/application/user_service.rs`:
- Around line 108-111: Replace the direct arithmetic for pagination offset with
overflow-safe/saturating arithmetic: instead of `(page - 1) * limit` use
saturating operations on the request-derived values (e.g., call
page.saturating_sub(1) then saturating_mul with limit) after you clamp `limit`;
update the `page`, `limit`, and `offset` computation in the same block so
`offset` cannot overflow when `page` is near i64::MAX.

In `@src/config/auth0_config.rs`:
- Around line 10-38: Remove the automatic Debug derive from AuthConfig and
Auth0Config and replace it with manual Debug implementations that redact
sensitive fields: mask jwt_secret and any entries in previous_jwt_secrets in
AuthConfig, and mask auth0_client_secret (and auth0_client_id if treated as
secret) in Auth0Config; keep non-sensitive fields (jwt_kid,
jwt_expiration_seconds, issuer, audience, auth0_domain, auth0_audience,
auth0_issuer, jwks_cache_ttl_secs, auth0_connection, etc.) printable. Implement
fmt::Debug for AuthConfig and Auth0Config to output the same structure but
replace secret values with a constant placeholder like "<redacted>" so logs
won’t leak secrets while retaining useful non-secret fields.

In `@src/config/mod.rs`:
- Around line 16-30: Remove the Debug derive from the top-level AppConfig to
avoid accidental logging of secrets: update the struct declaration for AppConfig
(currently #[derive(Debug, Deserialize, Clone)]) to #[derive(Deserialize,
Clone)] and, if you still need debug output, implement a custom Debug for
AppConfig that redacts sensitive fields (or only delegates Debug to
non-sensitive subconfigs); review/AuthConfig, Auth0Config, SecurityConfig, and
SentryConfig and ensure any Debug derives there either redact secrets or are
removed so secret fields are never printed by Debug.
- Around line 58-60: The merge call using
Toml::file("config/development.toml").nested() is treating development.toml as a
profile and preventing its top-level [database]/[logging] keys from overriding
defaults when extracting into AppConfig; remove the .nested() so the line
becomes a normal merge of development.toml into the root, or alternatively keep
.nested() but wrap development.toml under a [development] table and call
.select("development") on the Figment before extracting into AppConfig so the
correct profile is merged.

In `@src/infrastructure/auth0/client.rs`:
- Around line 44-49: The domain() method assumes auth0_domain is a trimmed,
non-empty string but new() currently only rejects None, allowing Some("") or
whitespace; update the constructor/new() that sets Auth0 client config to
validate auth0_domain by trimming it and rejecting empty/whitespace (return an
Err or fail construction) and store the trimmed value (or ensure invariant) so
domain()’s expect("domain checked in constructor") is safe; reference the
domain() method and the new()/constructor that initializes
self.config.auth0_domain when making the change.

In `@src/infrastructure/auth0/dtos.rs`:
- Around line 67-100: The to_app_error function currently maps unknown Auth0
error codes to AppError::InternalError; change it to preserve HTTP-status-aware
fallback by, when the code match falls through, inspecting the HTTP status on
the Auth0 DTO (use the existing status/status_code accessor on self) and return
an AppError based on status (e.g. 401/403 -> AppError::Unauthorized, 429 -> map
appropriately or surface a throttling error if AppError supports it, 5xx ->
AppError::InternalError otherwise). Keep the existing code_or_error and
description_or_error_description usage and logging, but replace the final `_ =>
AppError::InternalError(...)` arm in to_app_error with a status-based branch
that chooses the correct AppError based on self.status/status_code.

In `@src/infrastructure/auth0/requests.rs`:
- Around line 36-39: The SignupRequest struct's optional connection field should
have the same skip-serialization behavior as the other optionals: add the
attribute #[serde(skip_serializing_if = "Option::is_none")] above the pub
connection: Option<String> field in SignupRequest so None is omitted instead of
serialized as null; then update the existing test (the test around the current
assertion location) to serialize a SignupRequest with connection = None and
assert the resulting JSON object does not contain the "connection" key (e.g.,
serialize to a Map/Value and assert !map.contains_key("connection")).
- Around line 4-26: Remove the auto-derived Debug implementation from request
structs that hold secrets (Auth0SignupRequest, Auth0PasswordGrantRequest,
SignupRequest, PasswordGrantRequest) to avoid accidental logging of
passwords/client_secret; locate the structs and either delete the
#[derive(Debug, ...)] token or replace Debug with a manual impl that redacts
sensitive fields (password, client_secret) in fmt to return safe output,
ensuring Serialize remains unchanged and the redacted Debug is used where
needed.

In `@src/infrastructure/repositories/equipment/mod.rs`:
- Around line 64-68: The repository is using runtime SQLx query builders;
replace those with compile-time SQLx macros by updating functions like
find_by_owner and update_photo_availability (and other methods in mod.rs and
photo.rs that call sqlx::query_as::<_, T>() or sqlx::query!()) to use
query_as!() or query!() with literal SQL and explicit type mappings so queries
are checked at compile time; keep the dynamic QueryBuilder pattern only in
search.rs which is allowed. Locate uses of sqlx::query_as::<_, ...>(),
QueryBuilder, or .fetch_*/.execute() in the mentioned functions and convert them
to the corresponding query_as!()/query!() macro calls, adjusting parameter
binding and return types to match the macro form. Ensure all SQL strings are
static literals and import any required column-to-struct mappings to satisfy the
macros.

In `@src/infrastructure/repositories/equipment/photo.rs`:
- Around line 7-67: Replace all runtime-checked sqlx calls with the compile-time
macros: in the create (inserting) function, find_photos, find_photo_by_id,
update_photo, and delete_photo replace sqlx::query_as::<_, EquipmentPhoto>(...)
with sqlx::query_as!(EquipmentPhoto, "...", /* params */) and sqlx::query(...)
with sqlx::query!("DELETE ...", photo_id). Move parameter binding from
.bind(...) chains into the macro argument list (e.g.
sqlx::query_as!(EquipmentPhoto, "SELECT ... WHERE id = $1", photo_id)), keep the
same SQL column list to match the EquipmentPhoto struct, and then call
.fetch_one/.fetch_all/.fetch_optional/.execute(pool) as before; ensure types of
passed parameters (photo.id, photo.equipment_id, photo.photo_url,
photo.is_primary, photo.order_index, photo.created_at) match the macro-checked
SQL argument types.

In `@src/security/rate_limit.rs`:
- Around line 17-22: Compute a safe, clamped interval before performing the
division to avoid panic: clamp rate_limit_per_minute to a valid nonzero range
(e.g., 1..=60_000) and use that clamped value when calculating
milliseconds_per_request instead of dividing directly by rate_limit_per_minute;
also handle potential GovernorConfigBuilder::finish() errors without unwrapping
by returning or logging the error instead of calling .expect(); finally ensure
AppConfig::validate() is invoked at startup so configuration constraints are
enforced (referencing the symbols rate_limit_per_minute,
milliseconds_per_request, burst_size, GovernorConfigBuilder::finish, and
AppConfig::validate).

In `@tests/auth0_endpoints/login.rs`:
- Around line 2-7: Remove the unused imports that CI flagged in
tests/auth0_endpoints/login.rs: delete the lines importing crate::common,
crate::common::mocks::*, chrono::Utc, the glob import rust_backend::domain::*,
and the AppError and AppResult from rust_backend::error so only actually used
symbols remain; keep imports used by tests such as actix_web::{http::StatusCode,
test as actix_test, web, App} and any other referenced types/functions to ensure
the file still compiles.

In `@tests/auth0_endpoints/signup.rs`:
- Around line 356-381: The test
auth0_signup_with_username_returns_username_in_response currently only asserts
the HTTP status; update it to also parse the response body JSON from the
actix_test::call_service result and assert that the returned JSON contains the
"username" field with the value "cooluser123" (and optionally that "email"
matches "user@example.com") so the test name matches its behavior; locate this
in the auth0_signup_with_username_returns_username_in_response function and add
JSON deserialization and assertions against the "username" key.

In `@tests/core_api.rs`:
- Around line 64-80: The signup function currently declares parameters as
_email, _password, and _username but uses them in the body; rename these
parameters to email, password, and username in the fn signature of async fn
signup(...) and update all references inside the function (e.g., the return
Auth0SignupResponse fields that use _email and _username) to use the new names
so the underscore no longer incorrectly indicates unused parameters (function
name: signup).

In `@tests/core_api/messages/message.rs`:
- Line 79: The comment "// Create 5 messages with different timestamps (oldest
first)" is incorrect relative to the test assertions which expect newest-first
ordering; update that comment to accurately reflect the behavior (e.g., "//
Create 5 messages with different timestamps (newest first)" or "// Create 5
messages with different timestamps (newest to oldest)") so it matches the
assertions in the test in tests/core_api/messages/message.rs.

---

Outside diff comments:
In `@src/api/routes/users.rs`:
- Around line 29-42: The handler update_user_profile accepts payload:
web::Json<UpdateUserRequest> but never validates it; call payload.validate()?
before using the data to enforce DTO validation. Modify update_user_profile to
invoke payload.validate()? (on the web::Json<UpdateUserRequest> value) and
return any validation error via the existing AppResult flow, then proceed to
call state.user_service.update_profile with payload.into_inner(); ensure the
symbol UpdateUserRequest and the validate() call are used so the route adheres
to DTO validation guidelines.

In `@src/application/admin/mod.rs`:
- Around line 112-151: The update_user_role and delete_user admin mutation
handlers currently perform updates without checking the DB-backed role; call the
existing require_admin method at the start of each handler to enforce DB role
checks (e.g., invoke self.require_admin(actor_id).await? and handle its error)
before any logging or performing repo operations in update_user_role and
delete_user, and apply the same pattern to the other admin mutation methods
(those referenced around the other ranges) so every admin mutation validates via
require_admin rather than relying on external claims.

---

Nitpick comments:
In `@split_repo_tests.py`:
- Around line 1-2: Remove the unused import `os` from the top-level import block
in split_repo_tests.py; keep only the required `import re` so the module no
longer contains an unused symbol and linter warnings are resolved.
- Around line 4-5: Add robust error handling around opening
"tests/repository_integration_tests.rs": check existence (os.path.exists) before
attempting to open or wrap the open/read in a try/except catching
FileNotFoundError/IOError, and emit a clear error message (including the
expected path) and exit/raise a user-friendly exception instead of letting the
raw traceback surface; update the block that uses variables f and content to
follow this pattern so the script fails gracefully when the source file is
missing or the current working directory is wrong.
- Around line 45-52: The single-line compound statement in the loop (if not
test_list: continue) violates E701; in the for-loop iterating over
categorized_tests (for cat, test_list in categorized_tests.items()) change the
inline if to a proper two-line block by replacing "if not test_list: continue"
with an if statement followed by a separate indented continue line so the check
and the continue are on their own lines; leave the rest of the block (filename,
with open(...), f.write(header), and the inner for t in test_list write calls)
unchanged.
- Around line 34-43: The line combining the if check and the continue (if cat ==
"edge_cases": continue) violates PEP8 E701; change it to a normal block by
placing the continue on its own indented line (e.g., if cat == "edge_cases":
followed by a newline with an indented continue) so the loop over categories
(variables cat, keywords) and the early-skip behavior is preserved; ensure this
update is applied in the same loop that appends tests to categorized_tests and
uses placed, test, and name.

In `@src/api/routes/users.rs`:
- Around line 44-53: In my_equipment, validate the incoming PaginationParams
before using them: call query.validate()? (or query.into_inner().validate() if
you need ownership) right after receiving the web::Query<PaginationParams> and
before calling state.user_service.my_equipment; ensure the validator::Validate
trait is in scope so the validation error can be propagated via the existing ?
into the AppResult.

In `@src/infrastructure/auth0/dtos.rs`:
- Around line 104-153: There are duplicate DTOs for the same Auth0 endpoints:
consolidate SignupResponse into Auth0SignupResponse and PasswordGrantResponse
into Auth0TokenResponse by replacing all usages of SignupResponse and
PasswordGrantResponse with the existing Auth0SignupResponse and
Auth0TokenResponse types, remove the redundant struct definitions
(SignupResponse, PasswordGrantResponse) from src/infrastructure/auth0/dtos.rs,
and ensure the surviving structs include the same serde attributes (e.g.,
#[serde(rename = "_id")] and skip_serializing_if for optional fields) and field
names so serialization/deserialization behavior remains identical; update
imports/usages across the codebase to reference Auth0SignupResponse and
Auth0TokenResponse.

In `@src/security/login_throttle.rs`:
- Around line 29-36: The public method write_entries currently exposes the
internal entries RwLock allowing external mutation of HashMap<String,
LoginAttemptState>; restrict its visibility by changing the signature from pub
fn write_entries(...) to a more limited scope (e.g., pub(crate) fn
write_entries(...) if it's needed only inside the crate) or remove pub entirely
and provide a #[cfg(test)] pub(crate) helper for tests only, ensuring callers
must go through the intended throttling API rather than mutating entries
directly; update any internal callsites to use the new visibility and add a
cfg(test) helper if tests require direct access.

In `@src/security/mod.rs`:
- Around line 103-123: Replace the panic-based assertion with a validation-based
one: call SecurityConfig::validate() (or the existing validate method on
SecurityConfig) on the constructed config and assert it returns an Err for
global_rate_limit_per_minute > 60_000, and remove the std::panic::catch_unwind
and the global_rate_limiting invocation so the test no longer depends on limiter
construction panicking; reference SecurityConfig and its validate() method and
ensure the test message asserts validation failure for the out-of-range
global_rate_limit_per_minute.

In `@tests/auth_middleware.rs`:
- Around line 1-27: Remove the unused imports from the top-level test module:
delete Arc from the std::sync import and remove Payload, AUTHORIZATION,
actix_test, web, and FromRequest from the actix_web use statement; these symbols
are unused in this parent file (submodules import what they need) so update the
use lines to only keep the actually referenced items like Mutex and http symbols
that are used.

In `@tests/auth_middleware/provisioning.rs`:
- Around line 14-69: Extract the repeated test setup (creation of MockUserRepo,
MockAuthRepo, seeding User and AuthIdentity, construction of Auth0Claims, and
instantiation of JitUserProvisioningService) into reusable helpers under
tests/common (e.g., functions like make_mock_repos(),
seed_existing_user(user_repo, auth_repo, existing_user_id, provider_id), and
make_auth0_claims(...)), then update this test to call those helpers and use the
returned repos/service; specifically move the setup that constructs
MockUserRepo, MockAuthRepo, the User and AuthIdentity push, the Auth0Claims
block, and the provisioning_service creation (JitUserProvisioningService) into
common helpers and replace the in-test code with calls that return
Arc<MockUserRepo>, Arc<MockAuthRepo>, Auth0Claims, and Arc<dyn
UserProvisioningService> so provision_user can be invoked as before.

In `@tests/auth0_endpoints.rs`:
- Around line 259-265: test_db_pool currently panics if TEST_DATABASE_URL is not
set; change it to mirror the fallback in tests/core_api.rs by attempting
env::var("TEST_DATABASE_URL") then falling back to env::var("DATABASE_URL") and
finally to the same hardcoded default connection string used in core_api, then
pass that resolved database_url into PgPoolOptions::new().connect_lazy(...).
Update references to TEST_DATABASE_URL/DATABASE_URL and ensure the expect
message reflects that a resolved DB URL was required.
- Around line 120-125: The JWT construction uses standard Base64 with padding;
change the encoder used when building payload_encoded (and any header encoding)
from base64::engine::general_purpose::STANDARD to
base64::engine::general_purpose::URL_SAFE_NO_PAD so the token uses URL-safe,
no-padding Base64 as required by JWTs; update the places referencing
payload_encoded and header encoding in tests/auth0_endpoints.rs (look for the
variables header, payload_encoded, signature and the format!("{}.{}.{}", ... )
assembly) to use the URL_SAFE_NO_PAD engine.

In `@tests/auth0_endpoints/signup.rs`:
- Around line 337-351: The loop in the test currently allows
StatusCode::CONFLICT even though each iteration posts a unique email; update the
assertion after actix_test::call_service(&app, request).await to assert that
response.status() is StatusCode::CREATED (remove the CONFLICT branch) so the
test strictly verifies the success path for the unique-email signups performed
by the TestRequest::post loop.

In `@tests/auth0_endpoints/tokens.rs`:
- Around line 50-62: The current JWT checks only verify dot-count for
body.access_token and body.id_token (variables parts and id_parts); enhance them
by also asserting each split segment is non-empty to catch values like "..":
after splitting into parts/id_parts, iterate over each segment and assert it is
not empty (include a clear message referencing which token and which segment
failed) for both body.access_token and body.id_token.

In `@tests/common/auth0_test_helpers.rs`:
- Around line 71-79: Replace the logic that derives role_str from token claims
(the block that reads
claims.custom_claims.get("https://test-tenant.auth0.com/role") and sets
role_str) so the test helper no longer trusts Auth0 claims for role; instead
query the database for the user role (or set a fixed safe default such as
"renter") and assign that to role_str. Update the helper that constructs test
identities in tests/common/auth0_test_helpers.rs to remove use of the
claims-derived role and use the DB lookup or fixed default path when populating
role_str.

In `@tests/common/mocks/mod.rs`:
- Around line 1-25: The file repeats #[allow(dead_code, unused_imports)] on
every pub mod and pub use; consolidate by applying #[allow(dead_code,
unused_imports)] once at the top of the module so you can remove the per-item
attributes on auth_repo, category_repo, equipment_repo, message_repo, user_repo,
utils and the corresponding pub use lines (MockAuthRepo, MockCategoryRepo,
MockEquipmentRepo, MockMessageRepo, MockUserRepo, haversine_km); ensure the
single module-level attribute covers the entire file to keep warnings suppressed
while the mocks stabilize.

In `@tests/core_api/admin/user.rs`:
- Around line 160-190: The pagination test currently only checks page sizes;
update the test code that builds and reads page1, page2, page3 (variables named
page1, page2, page3) to extract each user's unique ID (from
pageN["users"][i]["id"]) into three Vec/HashSet collections and assert that the
intersection between page1 & page2, page1 & page3, and page2 & page3 is empty
(i.e., no shared IDs) to ensure pages are disjoint; keep the existing size
assertions and add these ID-overlap assertions after reading page1/page2/page3.

In `@tests/core_api/conversation.rs`:
- Around line 676-839: Add tests that assert the DB role wins over JWT claims by
duplicating each admin_* test (admin_can_access_foreign_conversation,
admin_can_send_message_to_foreign_conversation,
admin_can_list_foreign_conversation_messages) but push a User with a non-Admin
Role into user_repo while creating a token with create_auth0_token(...,
"admin"); wire the repo into app_with_auth0_data_and_message_repo and call the
same endpoints, then assert the request is rejected (e.g. StatusCode::FORBIDDEN)
to ensure authorization reads role from the DB (user_repo / User.role) rather
than the token claim.

In `@tests/core_api/equipment_extended/mod.rs`:
- Around line 81-82: Replace the bare unwrap() on HttpAuth0ApiClient::new so
test bootstrap fails with a clear message: change the
Arc::new(HttpAuth0ApiClient::new(auth0_config.clone()).unwrap()) used to
initialize auth0_api_client (as Arc<dyn Auth0ApiClient>) to call expect(...)
with a descriptive message (e.g., "failed to create HttpAuth0ApiClient for
tests") so any construction error surfaces actionable context.

In `@tests/core_api/equipment_photos/management.rs`:
- Around line 15-27: Extract the repeated test setup into a shared helper in
tests/common: create a function (e.g., common::init_test_env or
common::setup_with_fixtures) that calls setup_test_db().await and
setup_app(...).await and constructs the repositories via
UserRepositoryImpl::new, EquipmentRepositoryImpl::new,
CategoryRepositoryImpl::new; also move creation of fixtures::test_owner,
fixtures::test_category, fixtures::test_equipment and their repository create
calls into that helper and return the app, repos, and created entities so tests
simply call the helper instead of duplicating the DB/repo/bootstrap sequence
used around setup_test_db, setup_app, UserRepositoryImpl,
EquipmentRepositoryImpl, CategoryRepositoryImpl and
fixtures::test_owner/test_category/test_equipment.

In `@tests/core_api/system.rs`:
- Around line 17-29: Extract the repeated Actix app bootstrap into a reusable
helper (e.g., tests::common::init_test_app) that accepts the prebuilt state
(from app_state/MockUserRepo/MockEquipmentRepo) and returns the initialized test
service; move the shared setup that calls
App::new().wrap(cors_middleware(&security_config())).wrap(security_headers()).app_data(web::Data::new(common::test_auth_config())).app_data(web::Data::new(state)).configure(routes::configure)
into that helper, export it from tests/common, and update each system test (the
occurrences around the provided snippet and the other ranges) to call
init_test_app(state). Ensure the helper is async and returns the same type used
by actix_test::init_service so tests compile without further changes.

In `@tests/core_api/user/equipment.rs`:
- Around line 28-33: Extract the repeated test bootstrap into a shared helper in
tests/common (or a local module) by creating a function that runs
setup_test_db().await, calls setup_app(pool.clone()).await, and constructs the
repositories (UserRepositoryImpl::new(pool.clone()),
EquipmentRepositoryImpl::new(pool.clone()),
CategoryRepositoryImpl::new(pool.clone())), then return the app, test_db/pool,
and repo instances; update the tests that duplicate lines (including the
occurrences around lines 71-76 and 111-116) to call this helper to remove the
repeated setup code and centralize fixture creation.

In `@tests/core_api/user/profile.rs`:
- Around line 137-155: After each request that asserts StatusCode::BAD_REQUEST
(the two calls using actix_test::call_service that set_json with "username":
"ab" and the long_username), add a repository read of the user (using the same
user.id used in the request) and assert that user.username remains unchanged;
locate the test variables user, token, app and the response resp and, after each
assert_eq!(resp.status(), StatusCode::BAD_REQUEST), call your user repo read
method (e.g., repo.get_by_id or equivalent in this test harness) and assert
equality with the original user.username. Apply the same extra verification to
the other similar block referenced (the tests at the later block around the
second location).

In `@tests/core_api/users.rs`:
- Around line 118-127: In the admin_can_update_other_users_profile test, after
calling actix_test::call_service and asserting StatusCode::OK, read and
deserialize the response body JSON (from update_response) and assert the
returned payload contains the updated fields (e.g., that "full_name" == "Updated
By Admin" and optionally the "id" matches target_id). Locate the test by the
function name admin_can_update_other_users_profile and the variables
update_response and target_id; add assertions against the deserialized JSON to
ensure the update actually changed the stored values. Ensure assertions fail the
test when the payload does not reflect the update.
```

---

## Detailed Inline Comments

### `docs/review.md`

_⚠️ Potential issue_ | _🟡 Minor_

**Use fenced code blocks for these snippets to avoid broken Markdown parsing.**

The current `*` / `_` marker usage triggers markdownlint MD037 and makes examples harder to read correctly.




Also applies to: 357-359

---

### `src/api/dtos/common.rs`

_⚠️ Potential issue_ | _🟠 Major_

**`PaginationParams` is missing required DTO derives and field validations.**

This DTO currently omits `Serialize` and `ToSchema`, and `page`/`limit` have no validation constraints despite deriving `Validate`.

---

### `src/application/user_service.rs`

_⚠️ Potential issue_ | _🟠 Major_

---

### `src/config/auth0_config.rs`

_⚠️ Potential issue_ | _🟠 Major_

**Redact secrets instead of deriving `Debug` on auth config structs.**

`AuthConfig` and `Auth0Config` include secret fields (`jwt_secret`, `auth0_client_secret`). Deriving `Debug` here can leak them through logs.

---

### `src/config/mod.rs`

_⚠️ Potential issue_ | _🟠 Major_

**Avoid `Debug` on top-level config containing secrets.**

`AppConfig` debug output can transitively expose sensitive auth fields (e.g., JWT/Auth0 secrets) if config gets logged.

---

### `src/config/mod.rs`

_⚠️ Potential issue_ | _🟡 Minor_

---

### `src/infrastructure/auth0/client.rs`

_⚠️ Potential issue_ | _🟡 Minor_

**`domain()` relies on a stronger invariant than `new()` enforces.**

`new()` only rejects `None`; `Some("")` or whitespace still passes and yields invalid URLs. Tighten validation to trimmed non-empty domain to match this method’s assumption.

---

### `src/infrastructure/auth0/dtos.rs`

_⚠️ Potential issue_ | _🟠 Major_

**Keep HTTP-status fallback when Auth0 error code is unrecognized.**

Currently, any parseable-but-unknown error code becomes `InternalError`, which can misclassify 401/429/5xx responses. Preserve status-aware fallback behavior for unknown codes.

---

### `src/infrastructure/auth0/requests.rs`

_⚠️ Potential issue_ | _🟠 Major_

---

### `src/infrastructure/auth0/requests.rs`

_⚠️ Potential issue_ | _🟡 Minor_

---

### `src/infrastructure/repositories/equipment/mod.rs`

_⚠️ Potential issue_ | _🟠 Major_

---

### `src/infrastructure/repositories/equipment/photo.rs`

_⚠️ Potential issue_ | _🟠 Major_

---

### `src/security/rate_limit.rs`

_⚠️ Potential issue_ | _🟠 Major_

---

### `tests/auth0_endpoints/login.rs`

_⚠️ Potential issue_ | _🟡 Minor_

**Remove unused imports flagged by CI pipeline.**

The following imports are unused and causing CI warnings:
- Line 2: `crate::common`
- Line 3: `crate::common::mocks::*`
- Line 5: `chrono::Utc`
- Line 6: `rust_backend::domain::*`
- Line 7: `AppError` and `AppResult`

---

### `tests/auth0_endpoints/signup.rs`

_⚠️ Potential issue_ | _🟡 Minor_

**Validate the `username` field in the username-specific test.**

The test name says username is returned, but it currently only checks `201`.

---

### `tests/core_api.rs`

_⚠️ Potential issue_ | _🟡 Minor_

**Remove underscore prefix from used parameters.**

Parameters `_email`, `_password`, and `_username` are actually used in the function body but have underscore prefixes, which conventionally indicates unused parameters. This is misleading.

---

### `tests/core_api/messages/message.rs`

_⚠️ Potential issue_ | _🟡 Minor_

**Fix the ordering comment to match the assertion behavior.**

Line 79 says “oldest first,” but the test asserts newest-first ordering.

---


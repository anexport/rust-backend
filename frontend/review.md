Starting CodeRabbit review in plain text mode...

Connecting to review service
Setting up
Analyzing
Reviewing

============================================================================
File: src/api/routes/mod.rs
Line: 56 to 59
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/mod.rs around lines 56 - 59, The readiness probe currently discards the underlying sqlx error via the closure in map_err, so update the error handling on sqlx::query_scalar(...).fetch_one(&state.db_pool).await.map_err(...) to preserve and include the original sqlx::Error (e) when constructing AppError::InternalError(anyhow::anyhow!(...)), e.g. by passing the error into the anyhow message or wrapping it (e.g. "database is not ready: {e}" or using anyhow::Context) so the original error is not lost; locate this logic around the sqlx::query_scalar, fetch_one and map_err call to implement the change.



============================================================================
File: src/api/routes/ws/hub.rs
Line: 14 to 34
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/ws/hub.rs around lines 14 - 34, The helpers read_sessions and write_sessions currently spin-wait using std::thread::yield_now on a tokio::sync::RwLock (sessions), which blocks the async executor; fix by choosing one approach: either make these helpers async and use self.sessions.read().await / self.sessions.write().await and update all call-sites (register, prune_user, broadcast_to_users) to be async so they await the locks, or change sessions to use std::sync::RwLock> so synchronous read_sessions/write_sessions can use blocking std locks safely; update the type of sessions and any imports accordingly and ensure no .await points occur while holding a std lock if you take that route.



============================================================================
File: src/application/user_service.rs
Line: 123
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/user_service.rs at line 123, The my_equipment construction currently sets photos: Vec::new() which leaves photo lists always empty; either populate this field by calling the photo loader (e.g., fetch_equipment_photos or get_photos_for_equipment) for each equipment item and map the results into the photos Vec, or add a clear TODO comment explaining photos are intentionally omitted and must be fetched via a separate endpoint; update the struct initialization in user_service.rs (the code creating my_equipment) to call the photo-fetch function or replace Vec::new() with a TODO note so intent is explicit.



============================================================================
File: src/application/user_service.rs
Line: 123
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/user_service.rs at line 123, The my_equipment struct is always initialized with photos: Vec::new(), which likely omits expected photo data; either mark this intentional with a clear TODO comment inside the builder that explains why photos are empty, or replace the placeholder with a call to your photo loader (e.g., fetch_photos_for_equipment or PhotoService::get_by_equipment_id) and await/handle errors before assigning the resulting Vec to photos; locate the construction of my_equipment in the function that returns/creates it and update that assignment accordingly.



============================================================================
File: src/infrastructure/repositories/message_repository.rs
Line: 111 to 114
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/infrastructure/repositories/message_repository.rs around lines 111 - 114, Capture the result of sqlx::query(...).execute(&mut *tx).await into a variable and assert rows were affected (e.g., check result.rows_affected() > 0) and return an appropriate error if zero to avoid silently updating no conversation for message.conversation_id; alternatively, if your schema already defines a FOREIGN KEY (messages.conversation_id -> conversations.id) in the migrations, you can skip the guard—verify the migration for that FK and if absent either add the FK or implement the rows_affected() check near the existing sqlx::query call that updates conversations.



============================================================================
File: src/security/mod.rs
Line: 5
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/security/mod.rs at line 5, The code uses tokio::sync::RwLock but all methods (read_entries, write_entries, ensure_allowed, record_success, record_failure, enforce_fixed_window) are synchronous and currently spin on try_read()/try_write(); change the import to std::sync::RwLock and replace the try_* spin-loops with direct .read().unwrap() / .write().unwrap() (or .expect("...")) calls inside those functions so synchronous locking is correct and avoids busy-waiting; alternatively, if you intend async callers, make those methods async and switch to .read().await / .write().await, but the straightforward fix is the std::sync::RwLock swap and removing the spin-loops.



============================================================================
File: src/security/mod.rs
Line: 82 to 92
Type: refactor_suggestion

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/security/mod.rs around lines 82 - 92, cleanup_expired_entries creates a TOCTOU gap and doubles locking by acquiring a write lock then returning, allowing other threads to mutate entries before callers like enforce_fixed_window re-acquire a lock; fix by folding the cleanup logic into the caller's existing lock scope (or change cleanup_expired_entries to accept a &mut Entries so callers can invoke it while holding write_entries()), i.e. move the retain logic that checks state.locked_until / state.next_allowed_at > now into the same critical section where enforce_fixed_window and the other affected functions operate so no second lock acquisition is needed and the cleanup guarantee holds.



============================================================================
File: src/application/equipment_service.rs
Line: 54 to 60
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/equipment_service.rs around lines 54 - 60, The current list implementation calls self.equipment_repo.search(...) and then self.equipment_repo.count_search(...), causing two DB round-trips and a TOCTOU race; fix by altering the repository API to return rows plus total in one query (e.g. add or change a method like search_with_total or make search return (Vec, i64)) where the SQL uses COUNT(*) OVER() (or a CTE/RETURNING) so equipment_service.rs assigns let (rows, total) = self.equipment_repo.search_with_total(&search, limit, offset).await?; compute total_pages from that single total; if changing the repo is out of scope, wrap both calls in a single transaction or add a comment documenting the race and the recommended refactor.



============================================================================
File: src/api/routes/ws/mod.rs
Line: 582 to 586
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/ws/mod.rs around lines 582 - 586, Replace the hardcoded URI in test_db_pool with an explicit, credential-free PgConnectOptions built via PgConnectOptions::new() and call PgPoolOptions::new().connect_lazy_with(...) (instead of connect_lazy) so the pool is created infallibly without embedding username/password; e.g., in test_db_pool construct options with host "127.0.0.1", port 1, and database "test_db" and pass it to connect_lazy_with, and add a short comment above test_db_pool explaining that port 1 is deliberately used to produce an unconnectable lazy pool (so tests can satisfy the type system without a live DB) and that credentials are intentionally omitted.



============================================================================
File: src/security/mod.rs
Line: 152
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/security/mod.rs at line 152, The failure counter update is inconsistent with enforce_fixed_window: replace the panic-prone increment (entry.failures += 1) with a saturating increment to avoid u32 overflow panics; update the code that modifies entry.failures to use saturating_add (i.e., set entry.failures to entry.failures.saturating_add(1)) so it matches enforce_fixed_window's overflow-safe behavior and keeps semantics consistent.



============================================================================
File: src/security/mod.rs
Line: 62 to 80
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/security/mod.rs around lines 62 - 80, The current read_entries and write_entries spin on try_read/try_write with std::thread::yield_now(), which will block tokio worker threads and is inefficient for long-held locks (see cleanup_expired_entries); remove these helpers and either 1) switch the underlying lock to std::sync::RwLock and delete read_entries/write_entries, replacing call sites with entries.read().unwrap() and entries.write().unwrap(), or 2) if you must remain async, make the helpers async (fn read_entries(&self) -> impl Future / async fn) and use self.entries.read().await and self.entries.write().await at call sites so tasks are properly parked; update callers (e.g., cleanup_expired_entries) accordingly.



============================================================================
File: src/application/user_service.rs
Line: 106 to 111
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/user_service.rs around lines 106 - 111, Confirm the order returned by e.coordinates_tuple() and ensure the mapping to crate::api::dtos::Coordinates uses the correct ordering; if coordinates_tuple() actually returns (longitude, latitude) (as in geo-types where x=lon, y=lat), change the destructuring so the first element maps to longitude and the second to latitude when constructing Coordinates, otherwise keep as-is—verify the definition of coordinates_tuple() and adjust the mapping in the block that constructs crate::api::dtos::Coordinates accordingly.



============================================================================
File: src/main.rs
Line: 178 to 180
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/main.rs around lines 178 - 180, The call to capture_unexpected_5xx(&path, &method, status, &request_id) currently ignores any returned Err; change it to explicitly handle the Result and log failures so operators see when the error-tracking backend fails — e.g., replace the let _ = ... with a match or if let Err(e) = capture_unexpected_5xx(...) and emit a clear error-level log that includes the path, method, status/request_id and the error details; keep the original call site (capture_unexpected_5xx with variables path, method, status, request_id) so only the return handling changes.



============================================================================
File: src/api/routes/equipment.rs
Line: 140 to 145
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/equipment.rs around lines 140 - 145, The client_ip function currently uses ConnectionInfo::realip_remote_addr which is unsafe for rate-limiting; change client_ip to first use request.peer_addr() (the TCP peer) for the client's IP, and only fall back to ConnectionInfo::realip_remote_addr in cases where you explicitly verify the request actually came from a trusted proxy: check that request.peer_addr() is Some and its IP is in your configured trusted-proxies list before trusting X-Forwarded-For; update the client_ip function (and any callers) to perform that trusted-proxy check and document the requirement so rate-limiting uses the verified IP source.



============================================================================
File: src/api/routes/equipment.rs
Line: 34 to 35
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/equipment.rs around lines 34 - 35, The current use of client_ip(&request) can return None and causes LoginThrottle::key("equipment_public_list", ip.as_deref()) to create a shared or empty throttle bucket; update the flow in equipment list handling so you resolve a concrete IP before calling LoginThrottle::key — e.g., change client_ip logic or add a guard after client_ip(&request) to attempt a peer_addr fallback (or call realip_remote_addr explicitly), and if no resolvable IP is available return early with a 429 Too Many Requests (or other configured error) instead of passing None into LoginThrottle::key; ensure references to client_ip and LoginThrottle::key are updated so the throttle key always receives Some(ip) and never None.



============================================================================
File: tests/equipment_search_tests.rs
Line: 751 to 755
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @tests/equipment_search_tests.rs around lines 751 - 755, The test_db_pool helper uses PgPoolOptions::new().connect_lazy(...) with an intentionally-unreachable port (1) but lacks documentation and a short-circuit timeout; update test_db_pool to add a clear comment stating "port 1 is intentionally unreachable to ensure tests do not connect to a real DB" and configure PgPoolOptions to set an acquire_timeout to a near-zero value (e.g., 1ms or similar) before calling connect_lazy so any accidental pool acquisition immediately errors instead of hanging; reference the test_db_pool function, PgPoolOptions::new(), connect_lazy and the acquire_timeout option when making this change.



============================================================================
File: src/api/routes/equipment.rs
Line: 36 to 40
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/equipment.rs around lines 36 - 40, The handler currently calls state.login_throttle.enforce_fixed_window with authentication-focused config (state.security.login_max_failures, state.security.login_lockout_seconds) and uses the ? operator which fails closed on any throttle backend error; change it to use a dedicated public API rate-limit config (e.g., state.security.api_rate_limit_requests and state.security.api_rate_limit_window_seconds or similarly named fields) when calling state.login_throttle.enforce_fixed_window, and replace the ? propagation with explicit error handling: on Ok enforce result proceed normally, on Err log the error (including context from enforce_fixed_window) and continue processing (fail-open) so the public listing endpoint still serves when the throttle store is unavailable. Ensure you update any config struct or defaults to provide the new api_rate_limit_* values referenced by the call.



============================================================================
File: src/application/auth_service.rs
Line: 182
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/auth_service.rs at line 182, The code now uses Role::to_string() for UserResponse.role but the removed role_as_str helper may have returned different casing/strings; inspect the Display/ToString impl for Role and compare it to the previous role_as_str mapping and either restore a deterministic mapper (reintroduce role_as_str or implement a custom conversion used by UserResponse) if they differ, then add a unit test that constructs a Role (for each variant if applicable), serializes the UserResponse (or calls the same conversion used by UserResponse.role) and asserts the exact expected string value to prevent silent wire-format changes; reference Role::to_string(), the former role_as_str helper, and the UserResponse.role field when making the change.



============================================================================
File: tests/auth0_endpoints_tests.rs
Line: 531 to 535
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @tests/auth0_endpoints_tests.rs around lines 531 - 535, The test_db_pool function currently constructs a lazy PgPool with an unreachable DSN using port 1 which masks accidental DB access; update test_db_pool (the PgPoolOptions::new().connect_lazy(...) call) to either use a valid PostgreSQL port (e.g., change "postgres://postgres:postgres@127.0.0.1:1/test_db" to use port 5432 or read the DSN from an env var) or, if you intentionally want a "fail-loud" sentinel, add a clear comment inside test_db_pool explaining that port 1 is deliberate to ensure tests fail at connection time if real DB access occurs; make sure the chosen approach is documented in the function to avoid confusion.



============================================================================
File: review.md
Line: 354 to 360
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @review.md around lines 354 - 360, Section 4.6 duplicates content from 2.2; remove the standalone Section 4.6 and fold its unique advice into the Fix block of 2.2 by referencing WsConnectionHub::broadcast_to_users: mention that the only reason broadcast_to_users takes a write lock is the Vec::retain() pruning of dead senders, and instruct to split send (use a read lock to iterate and send) from prune (perform retain under a short write lock) or move pruning to a periodic background task; update the summary table and priority ordering to reflect the consolidated note.



============================================================================
File: review.md
Line: 441 to 446
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @review.md around lines 441 - 446, The summary table in review.md has mismatched and missing low-severity entries causing wrong references to body sections; update the table so it lists all nine low-severity items (4.1–4.9) and matches each row to the correct body topic: add a row for "anyhow + thiserror both used" (body 4.2) and a row for "find_all unused by application code" (body 4.5), then renumber the existing rows to align 4.1→4.9 with the body (so logging.json_format becomes 4.8 and db_pool becomes 4.9) and verify each table entry’s description and file/location (e.g., the entries currently labeled 4.2..4.6) match the corresponding body text to restore correct cross-references.



============================================================================
File: src/infrastructure/repositories/traits.rs
Line: 72 to 75
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/infrastructure/repositories/traits.rs around lines 72 - 75, The code currently returns Err(AppError::BadRequest(...)) for "equipment search filters are not supported by this repository implementation" which misclassifies a server-side capability gap as a client 400; change the error variant to one that denotes server-side lack of support (e.g. AppError::NotImplemented, AppError::Unsupported, or AppError::Internal depending on what your AppError enum exposes) while keeping the existing message; update the Err(...) expression in traits.rs where AppError::BadRequest is used so callers/handlers receive the correct semantic variant.



============================================================================
File: review.md
Line: 450 to 461
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @review.md around lines 450 - 461, The priority list omitted Issue 2.3 (redundant DB calls in can_access_conversation) which affects hot-path methods list_messages, send_message, mark_as_read, and participant_ids; update Section 7 to insert a new item for "Fix redundant DB calls in can_access_conversation" between the transaction fix (Add transaction to create_message) and the LoginThrottle TTL fix so it reads after item 5 and before item 6, and include a short rationale noting it reduces repeated DB lookups on every message operation.



============================================================================
File: review.md
Line: 104 to 111
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @review.md around lines 104 - 111, Update the wording in Section 2.2 to clarify that the problem is the use of the blocking std::sync::RwLock in an async context, not merely that broadcast_to_users takes a write lock; note that WsConnectionHub::broadcast_to_users takes a write lock on sessions to call retain (which prunes dead senders) and that holding a std::sync::RwLock across async execution is unsafe for Tokio. Recommend concrete fixes: replace the sessions: Arc> with tokio::sync::RwLock or use dashmap::DashMap to avoid a global lock, or split the prune (retain) step from the read-only send loop so read access doesn't require a write lock.



============================================================================
File: src/infrastructure/repositories/traits.rs
Line: 77 to 80
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/infrastructure/repositories/traits.rs around lines 77 - 80, The default implementation of count_search currently loads up to i32::MAX rows via search (using i64::from(i32::MAX)) and returns items.len(), which risks OOM, incorrectly fails when params.has_filters() causes search to return Err(BadRequest), and uses an undocumented magic limit and truncating cast; change the default for the trait method count_search(&self, params: &EquipmentSearchParams) -> AppResult to return a clear "not implemented / unsupported" error (e.g., Err(AppError::NotImplemented or a repository-specific NotImplemented variant) ) so concrete repository implementations must provide an efficient COUNT query, and remove the call to search and the magic i32::MAX usage; ensure references to search, has_filters, and BadRequest remain untouched in callers but not used in the default impl.



============================================================================
File: tests/core_api_tests.rs
Line: 1846
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @tests/core_api_tests.rs at line 1846, The current test ready_endpoint_checks_dependencies only asserts an INTERNAL_SERVER_ERROR and uses test_db_pool() pointed at an unreachable address; update the failure-path assertion to expect SERVICE_UNAVAILABLE (503) to reflect dependency-unreachable semantics (or adjust the /ready handler to return 503) and add a separate happy-path test (e.g., ready_endpoint_happy_path) that constructs a mock/in-memory db_pool which returns Ok(()) on ping and asserts a 200 OK response; reference the existing ready_endpoint_checks_dependencies and test_db_pool symbols when locating and changing the tests and add the new test that uses the mock db pool to exercise the success branch.



Review completed: 26 findings ✔

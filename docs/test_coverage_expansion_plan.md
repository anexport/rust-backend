# Test Coverage Expansion Plan

## Executive Summary
Following a comprehensive `cargo llvm-cov` analysis, the application demonstrates a strong overall test coverage of **84.29%**. However, specific critical paths related to real-time communication (WebSockets), identity provisioning edge cases, and application bootstrapping remain under-tested. 

This document serves as a detailed execution plan for an AI agent or developer to systematically close these coverage gaps and elevate the system's resilience. The goal is to tackle the lowest-scoring modules by introducing targeted integration and unit tests, rather than pursuing arbitrary line-coverage metrics.

---

## Area 1: WebSocket Lifecycle & Event Loop (0% - 51% Coverage)

**Target Modules:**
- `src/api/routes/ws/handlers.rs` (Currently 0%)
- `src/api/routes/ws/mod.rs` (Currently ~51%)

**Objective:**
Validate the actual Actix WebSocket connection lifecycle, message routing, ping/pong heartbeats, and timeout mechanisms. While payload serialization is tested elsewhere, the actual asynchronous event loop (`ws_loop`) and its dispatcher (`handle_text_message`) are entirely untested.

**Technical Approach:**
Utilize `actix_test::TestServer` alongside the Actix Web Client (`awc`) to establish real HTTP upgrades to WebSockets in a localized test harness. 

**Specific Test Cases to Implement:**
Create a new integration test file at `tests/ws_lifecycle_tests.rs`:

1.  **Connection Initialization & Authentication:**
    *   Test successful WS upgrade with a valid JWT.
    *   Test rejected WS upgrade with an invalid/missing JWT (asserting HTTP 401).
    *   Test that production environments reject `ws://` in favor of `wss://` (verifying `is_secure_ws_request` logic).
2.  **Ping/Pong Heartbeat Mechanisms:**
    *   Connect a client and send a text frame `{"type": "ping"}`. Assert the server responds immediately with `{"type": "pong"}`.
    *   *Timeout Scenario:* Connect a client and send nothing. Use Tokio's time-pausing/advancing features (or short mock timeouts) to verify the server forcibly closes the connection after the 90-second heartbeat timeout is exceeded.
3.  **Action Handlers (`handle_text_message`):**
    *   **Typing Event:** Send a valid `typing` JSON payload. Assert that the `WsConnectionHub` broadcasts this to the correct participant IDs.
    *   **Read Receipt:** Send a valid `read` JSON payload. Assert that the `message_service.mark_as_read` is triggered and the event is broadcasted.
    *   **Message Dispatch:** Send a valid `message` JSON payload. Verify that it persists via the `MessageService` and then broadcasts a `{"type": "message", "payload": ...}` event to the participants.
4.  **Error Handling & Edge Cases:**
    *   Send an unrecognized message type (e.g., `{"type": "unknown"}`). Assert the server replies with an error payload containing `UNSUPPORTED_TYPE`.
    *   Send a binary frame (instead of text) and assert the server replies with `UNSUPPORTED_BINARY`.
    *   Simulate a client abruptly closing the TCP stream without a closing handshake and ensure `prune_user` is still called on disconnect.

---

## Area 2: Just-In-Time (JIT) Auth Provisioning (37% Coverage)

**Target Module:**
- `src/application/auth_service.rs`

**Objective:**
Exhaustively test the `upsert_user_from_auth0` logic. This function bridges Auth0 JWT claims to our local PostgreSQL database. It contains complex drift-resolution logic (updating local data if Auth0 data changes) and race-condition fallbacks that are currently missed by standard API integration tests.

**Technical Approach:**
Create a dedicated unit test suite at `tests/auth_service_tests.rs`. Use the existing `mocks.rs` or connect to the isolated test database pool to precisely control repository responses.

**Specific Test Cases to Implement:**
1.  **New User Creation (Happy Path):**
    *   Provide claims for a brand-new user. Assert that `user_repo.create` and `auth_repo.upsert_identity` are called.
2.  **Data Drift Resolution (`maybe_update_user_from_claims`):**
    *   **No Drift:** Provide claims that perfectly match the existing DB record. Assert that no `UPDATE` queries are fired.
    *   **Partial Drift:** Provide claims where *only* the user's Auth0 picture has changed. Assert that `user_repo.update` is called and successfully modifies only the `avatar_url`.
    *   **Email Change:** Provide claims with a new email address. Assert the local user record updates its email to match Auth0.
3.  **Race Condition Handling (The `DatabaseError` Match Arm):**
    *   Simulate a scenario where two concurrent requests attempt to create a user for the same Auth0 `sub` simultaneously.
    *   Mock `auth_repo.upsert_identity` to return a `DatabaseError` (simulating a unique constraint violation).
    *   Assert that the service gracefully catches this, falls back to `find_identity_by_provider_id`, successfully retrieves the identity created by the concurrent thread, deletes the orphaned local user it just created, and returns a successful `Auth0UserContext` instead of a 500 Internal Server Error.
4.  **Missing Data Scenarios:**
    *   Provide Auth0 claims missing an email address. Assert it returns `AppError::BadRequest`.

---

## Area 3: Application Bootstrapping (33% Coverage)

**Target Module:**
- `src/main.rs`

**Objective:**
Validate that the application wires its dependencies (DB pools, JWKS clients, Sentry) correctly based on environment variables, without crashing at startup. Standard tests bypass `main.rs`.

**Technical Approach:**
Create a smoke test script or a specific integration test using `std::process::Command` to compile and boot the binary on a random ephemeral port.

**Specific Test Cases to Implement:**
1.  **Successful Boot & Readiness:**
    *   Spawn the backend process with a valid test `.env` configuration.
    *   Poll the `/api/v1/ready` or `/api/v1/metrics` endpoints using `reqwest` or `curl`.
    *   Assert the server returns an HTTP 200 OK.
    *   Send a SIGTERM and verify the application shuts down gracefully (testing the graceful shutdown hook in `main.rs`).
2.  **Configuration Failure:**
    *   Spawn the process with a missing or violently malformed `DATABASE_URL`.
    *   Assert the process exits with a non-zero exit code immediately, proving the application fails fast on bad configuration.

---

## Area 4: Trait Boilerplate (Coverage Noise Reduction)

**Target Module:**
- `src/infrastructure/repositories/traits.rs` (36% Coverage)

**Objective:**
Async traits in Rust generate significant hidden state-machine code. Since these files only contain definitions and default return values (which are implemented and tested in the concrete structs like `EquipmentRepository`), they falsely drag down the coverage score.

**Technical Approach:**
Do not write tests for these files. Instead, apply the coverage exclusion macro to the trait definitions.

**Action Item:**
1.  Add `#![cfg_attr(tarpaulin, skip)]` or `#[coverage(off)]` (depending on the specific llvm-cov configurations enabled) to the top of `src/infrastructure/repositories/traits.rs` or directly onto the trait definitions to instruct the coverage tool to ignore this boilerplate.

---

## Execution Guidelines for the Agent
1.  **Iterative Validation:** After implementing tests for a specific area, run `cargo llvm-cov --html` and inspect the generated HTML report for that specific file to ensure the targeted code paths have flipped from red to green.
2.  **Existing Fixtures:** Heavily utilize the existing database factories and JWT generators located in `tests/common/` to keep test setup concise.
3.  **Do Not Touch Business Logic:** Unless a bug is explicitly discovered by a new test, do not alter the source code in `src/`. The objective is strictly to expand the testing harness to cover the existing logic.
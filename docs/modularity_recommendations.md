# Backend Codebase Modularization Recommendations

This document outlines potential areas for modularization within the backend codebase to improve maintainability and testability, based on file size, complexity, and cohesion analysis.

## Identified Areas for Improvement

### 1. WebSocket Handling (`src/api/routes/ws.rs`)

*   **Current State:** The `ws.rs` file is the largest in the project (1107 lines), mixing WebSocket connection management, authentication, message routing, and business logic. This leads to low cohesion and reduced maintainability.
*   **Recommendations:**
    *   **Extract WebSocket Hub:** Move the `WsConnectionHub` struct and its methods to a new file, e.g., `src/api/routes/ws/hub.rs`.
    *   **Separate Message DTOs:** Create a new file for WebSocket message structures, e.g., `src/api/routes/ws/messages.rs`.
    *   **Isolate Message Handlers:** Extract the logic for handling different message types (e.g., `handle_text_message` and its sub-handlers) into a dedicated module, e.g., `src/api/routes/ws/handlers.rs`.
    *   **Refactor Main Module:** The `src/api/routes/ws/mod.rs` file would then be responsible for the WebSocket upgrade route, coordinating the setup, and spawning the main WebSocket loop.

### 2. Error Handling (`src/error/app_error.rs`)

*   **Current State:** The `app_error.rs` file (737 lines) is extensive due to comprehensive `From` implementations for various error types (SQLx, anyhow, domain errors) and mapping logic. While cohesive, its size can impact readability.
*   **Recommendations:**
    *   **Database Error Mapping:** Move the `map_database_error` and related logic to a new file, e.g., `src/error/db_mapping.rs`.
    *   **Validation Error Handling:** Extract the `collect_validation_issues` and custom validation error logic into a separate file, e.g., `src/error/validation_mapping.rs`.

### 3. Auth0 Infrastructure (`src/infrastructure/auth0_api.rs` & `src/infrastructure/auth0_db.rs`)

*   **Current State:** Both files (`auth0_api.rs` at 583 lines, `auth0_db.rs` at 613 lines) are large and contain significant overlap in their interaction with Auth0. They also include numerous data transfer objects (DTOs).
*   **Recommendations:**
    *   **Consolidate Auth0 Logic:** Create a new top-level module `src/infrastructure/auth0/`.
    *   **Separate Concerns:** Within this module, create distinct files for:
        *   The core `Auth0ApiClient` trait and its HTTP implementation (`client.rs`).
        *   Shared DTOs (e.g., `token.rs`, `user.rs`).
        *   Specific API interaction logic if it diverges significantly between database and general API calls (though ideally unified).
        *   Error handling specific to Auth0 interactions (`errors.rs`).

## Next Steps

The proposed refactoring aims to improve code organization, reduce file complexity, and enhance the overall maintainability and testability of the backend. Prioritization can be given to the WebSocket module due to its significant size and mix of responsibilities.

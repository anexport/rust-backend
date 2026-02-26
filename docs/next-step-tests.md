# Next-step Tests for Core Equipment Logic

## Coverage snapshot
- `/tests/core_api_tests.rs` already exercise equipment CRUD flows, auth, and search filters through the Actix stack with mocked repos, so pretty good API-level regression protection.
- `/tests/equipment_search_tests.rs` covers radius filtering, category/min-max pricing, availability flags, invalid coordinates, and undefined optional filters, validating search-related parameters.
- `/tests/repository_integration_tests.rs` plus `/tests/phase1_db_integration_tests.rs` repeatedly exercise repository CRUD, create/update/delete sequences, and ensure the database honors constraints and cascade deletes.
- Domain-level helpers such as `src/domain/equipment.rs` have serialization/coordinate parsing unit tests, making sure enums stay lowercase and coordinate strings split cleanly.

## Identified gaps and risks
- `src/application/equipment_service.rs` lacks standalone tests for service validation, authorization, pagination math, and coordinate handling—business rules live here but are only indirectly covered through integration tests.
- API routes skip explicit coverage for update/delete failure cases (404, unauthorized, forbidden) and the photo endpoints (add/delete) that wire into the service.
- Repository tests do not cover negative paths such as creating equipment with `None` coordinates, counting when the owner has zero items, or the formatting path executed by `set_coordinates`.
- Search logic lacks tests for pagination limits, zero-radius queries, and mixing filters when a referenced category does not exist.
- Domain helper `set_coordinates` and related validation never reject out-of-range lat/lng values before persisting.

## High-leverage next steps
1. Add focused service-layer tests for `EquipmentService::create`, `update`, and `list`, verifying validation errors (daily rate <= 0, invalid condition), ownership/`admin` override paths, `is_available` toggling, and pagination/total page math without spinning up Actix or SQLx.
2. Extend `tests/core_api_tests.rs` (or add a new suite) to hit update/delete with 401/403/404 semantics plus the `/equipment/{id}/photos` routes for both success and auth failures, ensuring the route wiring stays solid.
3. Create repository unit/integration tests that explicitly cover coordinate `None` handling, `count_by_owner` returning 0, and verify `EquipmentRepositoryImpl::create` persists coordinates only when both lat/lng are provided.
4. Expand search tests with scenarios covering `radius_km=0`, pagination bounds (`limit` beyond available records), and combinations of filters where `category_id` is missing or invalid to lock down filtering logic.
5. Add domain unit tests for `Equipment::set_coordinates` to reject out-of-range latitude/longitude (±90/±180) and to ensure formatting round-trips when coordinates are present.

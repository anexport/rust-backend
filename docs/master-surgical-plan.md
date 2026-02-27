═══════════════════════════════════════════════════════════  
 MASTER SURGICAL PLAN  
 ═══════════════════════════════════════════════════════════

Total Files to Split: 35  
 Total New Files to Create: 91
Total Files to Update (imports): ~120

Estimated Outcome:
Before: 123 files, 31,541 total lines, 36 over limit
After: 214 files, ~28,000 total lines, 0 over limit

═══════════════════════════════════════════════════════════

## EMERGENCY OPERATIONS (Priority 1)

═══════════════════════════════════════════════════════════

### Test Files (5 EMERGENCY)

1. tests/equipment_search_tests.rs (2,526 → ~2,000 lines across 6 files)
2. tests/core_api_tests.rs (2,254 → ~2,250 lines across 5 files)
3. tests/auth_middleware_tests.rs (1,268 → ~1,300 lines across 4 files)
4. tests/auth0_endpoints_tests.rs (1,234 → ~1,250 lines across 4 files)
5. tests/repository_integration_tests.rs (1,135 → ~1,150 lines across 6 files)

### Backend Files (3 EMERGENCY)

6. src/infrastructure/auth0/db.rs (613 → ~186 lines across 4 files)
7. src/error/app_error.rs (612 → ~161 lines across 3 files)
8. src/infrastructure/auth0/client.rs (581 → ~228 lines across 3 files)

═══════════════════════════════════════════════════════════

## CRITICAL OPERATIONS (Priority 2)

═══════════════════════════════════════════════════════════

### Test Files (8 CRITICAL)

9. tests/admin_routes_tests.rs (796 → ~1,000 lines across 4 files)
10. tests/message_routes_tests.rs (737 → ~950 lines across 4 files)
11. tests/message_service_tests.rs (661 → ~750 lines across 4 files)
12. tests/user_routes_tests.rs (619 → ~650 lines across 3 files)
13. tests/equipment_photos_tests.rs (566 → ~600 lines across 3 files)
14. tests/equipment_extended_api_tests.rs (551 → ~580 lines across 3 files)
15. tests/ws_lifecycle_tests.rs (513 → ~750 lines across 5 files)
16. tests/ws_security_tests.rs (462 → ~760 lines across 7 files)
17. tests/common/mocks.rs (518 → ~705 lines across 6 files)

### Backend Files (4 CRITICAL)

18. src/infrastructure/repositories/equipment_repository.rs (389 → ~260 lines across 3 files)
19. src/application/equipment_service.rs (388 → ~280 lines across 3 files)
20. src/application/admin_service.rs (370 → ~200 lines across 3 files)
21. src/config/app_config.rs (464 → ~178 lines across 5 files)
22. src/security/mod.rs (356 → ~124 lines across 5 files)

═══════════════════════════════════════════════════════════

## WARNING OPERATIONS (Priority 3)

═══════════════════════════════════════════════════════════

### Backend Files (7 WARNING)

23. src/api/routes/auth.rs (359 → ~290 lines across 2 files)
24. src/api/routes/ws/mod.rs (246 → ~160 lines across 2 files)
25. src/infrastructure/repositories/user_repository.rs (244 → ~160 lines across 2 files)
26. src/api/routes/equipment.rs (235 → ~180 lines across 2 files)
27. src/infrastructure/repositories/traits.rs (233 → EXEMPT - trait registry)
28. src/utils/auth0_claims.rs (326 → ~127 lines across 2 files)
29. src/domain/errors.rs (258 → ~62 lines across 2 files)

### Frontend Files (4 WARNING)

30. frontend/src/app/admin/users/page.tsx (229 → ~65 lines across 3 files)
31. frontend/src/app/equipment/new/page.tsx (228 → ~60 lines across 3 files)
32. frontend/src/app/admin/categories/page.tsx (219 → ~35 lines across 3 files)
33. frontend/src/components/ui/dropdown-menu.tsx (257 → EXEMPT - UI barrel file)
34. src/domain/equipment.rs (247 → ~70 lines across 4 files - extract tests)
35. tests/common/mod.rs (216 → ~145 lines across 4 files)

═══════════════════════════════════════════════════════════

## NEW SHARED HELPER FILES TO CREATE

═══════════════════════════════════════════════════════════

Test Helpers:

1. tests/common/auth0_test_helpers.rs
2. tests/common/equipment_search_helpers.rs
3. tests/common/admin_test_helpers.rs
4. tests/common/message_test_helpers.rs
5. tests/common/message_service_helpers.rs
6. tests/common/equipment_photo_helpers.rs
7. tests/common/equipment_auth0_mocks.rs
8. tests/common/repository_helpers.rs
9. tests/common/ws_test_helpers.rs

Backend Modules: 10. src/infrastructure/auth0/dtos.rs 11. src/infrastructure/auth0/requests.rs 12. src/infrastructure/auth0/trait.rs 13. src/infrastructure/auth0_api/dtos.rs 14. tests/auth0_client_tests.rs 15. src/error/conversions.rs 16. tests/auth0_claims_tests.rs 17. tests/domain_error_tests.rs 18. tests/config_tests.rs 19. tests/error_tests.rs 20. tests/common/test_db.rs 21. tests/common/fixtures.rs 22. tests/common/factory.rs 23. tests/common/mocks/user_repo.rs 24. tests/common/mocks/auth_repo.rs 25. tests/common/mocks/equipment_repo.rs 26. tests/common/mocks/category_repo.rs 27. tests/common/mocks/message_repo.rs 28. src/config/auth0_config.rs 29. src/config/security_config.rs 30. src/config/defaults.rs 31. src/security/cors.rs 32. src/security/headers.rs 33. src/security/rate_limit.rs 34. src/security/login_throttle.rs 35. tests/security_tests.rs 36. src/setup/auth0.rs 37. src/setup/shutdown.rs 38. src/middleware/request_logger.rs 39. src/setup/state.rs 40. tests/main_tests.rs 41. src/infrastructure/equipment_query_builder.rs 42. src/infrastructure/equipment_photo_repository.rs 43. src/application/equipment_auth.rs 44. src/application/equipment_mapper.rs 45. src/application/admin_mappers.rs 46. src/application/admin_category_service.rs 47. src/utils/password_validator.rs 48. src/infrastructure/ws/auth.rs 49. src/infrastructure/auth_repository.rs 50. src/api/routes/category.rs 51. src/domain/equipment/condition.rs 52. src/domain/equipment/equipment_photo.rs 53. tests/domain/equipment_tests.rs 54. tests/admin/category_management_tests.rs 55. tests/admin/equipment_management_tests.rs 56. tests/admin/user_management_tests.rs 57. tests/message/conversation_tests.rs 58. tests/message/message_tests.rs 59. tests/message/read_receipt_tests.rs 60. tests/message_service/conversation_tests.rs 61. tests/message_service/message_tests.rs 62. tests/message_service/read_tests.rs 63. tests/user/profile_tests.rs 64. tests/user/equipment_tests.rs 65. tests/equipment/authorization_tests.rs 66. tests/equipment/photo_operations_tests.rs 67. tests/equipment/crud_tests.rs 68. tests/ws/connection_tests.rs 69. tests/ws/heartbeat_tests.rs 70. tests/ws/action_handlers_tests.rs 71. tests/ws/error_handling_tests.rs 72. tests/ws/validation_tests.rs 73. tests/ws/injection_tests.rs 74. tests/ws/ordering_tests.rs 75. tests/ws/isolation_tests.rs 76. tests/ws/hub_tests.rs 77. tests/ws/connection_security_tests.rs 78. tests/equipment_search/geospatial_tests.rs 79. tests/equipment_search/pagination_tests.rs 80. tests/equipment_search/filter_tests.rs 81. tests/equipment_search/availability_tests.rs 82. tests/equipment_search/validation_tests.rs 83. tests/core_api/equipment_routes_tests.rs 84. tests/core_api/category_routes_tests.rs 85. tests/core_api/user_routes_tests.rs 86. tests/core_api/auth_routes_tests.rs 87. tests/auth_middleware/jwt_validation_tests.rs 88. tests/auth_middleware/provisioning_tests.rs 89. tests/auth_middleware/authorization_tests.rs 90. tests/auth0_endpoints/signup_tests.rs 91. tests/auth0_endpoints/login_tests.rs 92. tests/auth0_endpoints/integration_tests.rs 93. tests/repository/user_tests.rs 94. tests/repository/auth_tests.rs 95. tests/repository/equipment_tests.rs 96. tests/repository/message_tests.rs 97. tests/repository/category_tests.rs

Frontend: 98. frontend/src/hooks/use-admin-users.ts 99. frontend/src/components/user-table-row.tsx 100. frontend/src/hooks/use-new-equipment-form.ts 101. frontend/src/components/equipment-form-fields.tsx 102. frontend/src/hooks/use-admin-categories.ts 103. frontend/src/components/category-table-row.tsx 104. frontend/src/domain/equipment/condition.rs 105. frontend/src/domain/equipment/equipment_photo.rs 106. tests/domain/equipment_tests.rs 107. frontend/src/middleware/request_logger.rs

═══════════════════════════════════════════════════════════

## EXEMPTIONS (No Surgery Needed)

═══════════════════════════════════════════════════════════

1. frontend/src/components/ui/dropdown-menu.tsx - UI primitive barrel file
2. src/infrastructure/repositories/traits.rs - Trait registry file
3. tests/rate_limiting_tests.rs - Below 400 line threshold (376 lines)
4. tests/config_tests.rs - Below 400 line threshold (294 lines)
5. tests/equipment_service_tests.rs - Below 400 line threshold (286 lines)
6. tests/db_pool_tests.rs - Below 400 line threshold (249 lines)
7. tests/auth_service_unit_tests.rs - Below 400 line threshold (247 lines)
8. tests/repository_traits_defaults_tests.rs - Below 400 line threshold (224 lines)

═══════════════════════════════════════════════════════════

---

RECONNAISSANCE COMPLETE

35 files require surgical intervention.

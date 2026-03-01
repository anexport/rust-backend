// DTO validation tests
//
// This module contains tests for Data Transfer Object (DTO) validation
// across all API endpoints. Each test file validates:
// - Valid inputs pass validation
// - Invalid inputs (boundary cases) fail validation
// - Serialization/deserialization roundtrips

pub mod auth_dto_tests;
pub mod common_tests;
pub mod equipment_dto_tests;
pub mod message_dto_tests;
pub mod user_dto_tests;

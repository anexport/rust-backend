// DTO validation tests
//
// This module runs all DTO validation tests for the API.
// Each test validates:
// - Valid inputs pass validation
// - Invalid inputs (boundary cases) fail validation
// - Serialization/deserialization roundtrips

mod dto;

// Re-export all test modules
pub use dto::auth_dto_tests;
pub use dto::common_tests;
pub use dto::equipment_dto_tests;
pub use dto::message_dto_tests;
pub use dto::user_dto_tests;

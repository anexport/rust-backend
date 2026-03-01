// Tests for common DTOs in src/api/dtos/common.rs
// Tests PaginationParams validation and ErrorResponse serialization

use rust_backend::api::dtos::common::{ErrorResponse, PaginationParams};
use serde_json;
use validator::Validate;

#[test]
fn test_pagination_params_valid_values() {
    // Test valid page and limit values
    let params = PaginationParams { page: 1, limit: 20 };
    assert!(params.validate().is_ok());
}

#[test]
fn test_pagination_params_default_values() {
    // Test that default values (page=1, limit=20) are valid
    let json = r#"{}"#;
    let params: PaginationParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.page, 1);
    assert_eq!(params.limit, 20);
    assert!(params.validate().is_ok());
}

#[test]
fn test_pagination_params_boundary_min_page() {
    // Test minimum page value (1) - should be valid
    let params = PaginationParams { page: 1, limit: 20 };
    assert!(params.validate().is_ok());
}

#[test]
fn test_pagination_params_boundary_min_limit() {
    // Test minimum limit value (1) - should be valid
    let params = PaginationParams { page: 1, limit: 1 };
    assert!(params.validate().is_ok());
}

#[test]
fn test_pagination_params_boundary_max_limit() {
    // Test maximum limit value (100) - should be valid
    let params = PaginationParams {
        page: 1,
        limit: 100,
    };
    assert!(params.validate().is_ok());
}

#[test]
fn test_pagination_params_invalid_zero_page() {
    // Test page value 0 - should fail validation
    let params = PaginationParams { page: 0, limit: 20 };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("page"));
}

#[test]
fn test_pagination_params_invalid_negative_page() {
    // Test negative page value - should fail validation
    let params = PaginationParams {
        page: -1,
        limit: 20,
    };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("page"));
}

#[test]
fn test_pagination_params_invalid_zero_limit() {
    // Test limit value 0 - should fail validation
    let params = PaginationParams { page: 1, limit: 0 };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("limit"));
}

#[test]
fn test_pagination_params_invalid_negative_limit() {
    // Test negative limit value - should fail validation
    let params = PaginationParams { page: 1, limit: -1 };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("limit"));
}

#[test]
fn test_pagination_params_invalid_limit_exceeds_max() {
    // Test limit value 101 - should fail validation (max is 100)
    let params = PaginationParams {
        page: 1,
        limit: 101,
    };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("limit"));
}

#[test]
fn test_pagination_params_invalid_limit_far_exceeds_max() {
    // Test very large limit value - should fail validation
    let params = PaginationParams {
        page: 1,
        limit: 1000,
    };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("limit"));
}

#[test]
fn test_pagination_params_both_invalid() {
    // Test both page and limit invalid - should fail validation
    let params = PaginationParams { page: 0, limit: 0 };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("page"));
    assert!(errors.contains_key("limit"));
}

#[test]
fn test_pagination_params_deserialization_from_json() {
    // Test deserialization from JSON
    let json = r#"{"page": 5, "limit": 50}"#;
    let params: PaginationParams = serde_json::from_str(json).unwrap();
    assert_eq!(params.page, 5);
    assert_eq!(params.limit, 50);
    assert!(params.validate().is_ok());
}

#[test]
fn test_pagination_params_serialization_to_json() {
    // Test serialization to JSON
    let params = PaginationParams { page: 3, limit: 15 };
    let json = serde_json::to_string(&params).unwrap();
    let deserialized: PaginationParams = serde_json::from_str(&json).unwrap();
    assert_eq!(params.page, deserialized.page);
    assert_eq!(params.limit, deserialized.limit);
}

#[test]
fn test_pagination_params_roundtrip() {
    // Test serialization/deserialization roundtrip
    let original = PaginationParams {
        page: 10,
        limit: 25,
    };
    let json = serde_json::to_string(&original).unwrap();
    let deserialized: PaginationParams = serde_json::from_str(&json).unwrap();
    assert_eq!(original.page, deserialized.page);
    assert_eq!(original.limit, deserialized.limit);
}

#[test]
fn test_error_response_creation() {
    // Test ErrorResponse creation
    let error = ErrorResponse {
        error: "BadRequest".to_string(),
        message: "Invalid input data".to_string(),
    };
    assert_eq!(error.error, "BadRequest");
    assert_eq!(error.message, "Invalid input data");
}

#[test]
fn test_error_response_serialization() {
    // Test ErrorResponse serialization to JSON
    let error = ErrorResponse {
        error: "NotFound".to_string(),
        message: "Resource not found".to_string(),
    };
    let json = serde_json::to_string(&error).unwrap();
    assert!(json.contains("NotFound"));
    assert!(json.contains("Resource not found"));
}

#[test]
fn test_pagination_params_with_large_valid_page() {
    // Test with a large but valid page number
    let params = PaginationParams {
        page: 99999,
        limit: 20,
    };
    assert!(params.validate().is_ok());
}

#[test]
fn test_pagination_params_validation_error_message_content() {
    // Test that validation errors contain useful information
    let params = PaginationParams {
        page: -5,
        limit: 150,
    };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    // Both fields should have validation errors
    assert!(errors.contains_key("page"));
    assert!(errors.contains_key("limit"));
}

#[test]
fn test_pagination_params_only_page_invalid() {
    // Test when only page is invalid but limit is valid
    let params = PaginationParams { page: 0, limit: 50 };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("page"));
    assert!(!errors.contains_key("limit"));
}

#[test]
fn test_pagination_params_only_limit_invalid() {
    // Test when only limit is invalid but page is valid
    let params = PaginationParams { page: 5, limit: 0 };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(!errors.contains_key("page"));
    assert!(errors.contains_key("limit"));
}

#[test]
fn test_pagination_params_edge_case_limit_just_above_max() {
    // Test limit value just above max (101 vs 100)
    let params = PaginationParams {
        page: 1,
        limit: 101,
    };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("limit"));
}

#[test]
fn test_pagination_params_edge_case_limit_just_below_min() {
    // Test limit value just below min (0 vs 1)
    let params = PaginationParams { page: 1, limit: 0 };
    let result = params.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("limit"));
}

// Tests for user DTOs in src/api/dtos/user_dto.rs
// Tests UpdateUserRequest username validation

use chrono::Utc;
use rust_backend::api::dtos::user_dto::{
    PublicProfileResponse, UpdateUserRequest, UserProfileResponse,
};
use serde_json;
use uuid::Uuid;
use validator::Validate;

#[test]
fn test_update_user_request_all_none_valid() {
    // Test update request with all None values (valid - all fields optional)
    let request = UpdateUserRequest {
        username: None,
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_valid_username() {
    // Test valid username
    let request = UpdateUserRequest {
        username: Some("validuser".to_string()),
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_min_length() {
    // Test username with minimum valid length (3 characters)
    let request = UpdateUserRequest {
        username: Some("abc".to_string()),
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_max_length() {
    // Test username with maximum valid length (50 characters)
    let request = UpdateUserRequest {
        username: Some("a".repeat(50)),
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_too_short() {
    // Test username too short (2 characters, min is 3)
    let request = UpdateUserRequest {
        username: Some("ab".to_string()),
        full_name: None,
        avatar_url: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("username"));
}

#[test]
fn test_update_user_request_username_empty() {
    // Test empty username
    let request = UpdateUserRequest {
        username: Some("".to_string()),
        full_name: None,
        avatar_url: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("username"));
}

#[test]
fn test_update_user_request_username_too_long() {
    // Test username too long (51 characters, max is 50)
    let request = UpdateUserRequest {
        username: Some("a".repeat(51)),
        full_name: None,
        avatar_url: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("username"));
}

#[test]
fn test_update_user_request_username_with_numbers() {
    // Test username with numbers
    let request = UpdateUserRequest {
        username: Some("user123".to_string()),
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_with_underscores() {
    // Test username with underscores
    let request = UpdateUserRequest {
        username: Some("user_name".to_string()),
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_with_hyphens() {
    // Test username with hyphens
    let request = UpdateUserRequest {
        username: Some("user-name".to_string()),
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_whitespace() {
    // Test username with spaces - validation doesn't prohibit this
    let request = UpdateUserRequest {
        username: Some("user name".to_string()),
        full_name: None,
        avatar_url: None,
    };
    // The length validation allows this
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_special_chars() {
    // Test username with special characters - validation doesn't prohibit this
    let request = UpdateUserRequest {
        username: Some("user@name!".to_string()),
        full_name: None,
        avatar_url: None,
    };
    // The length validation allows this
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_full_name_valid() {
    // Test valid full name (no length constraints)
    let request = UpdateUserRequest {
        username: None,
        full_name: Some("John Doe".to_string()),
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_full_name_empty() {
    // Test empty full name (valid - no validation)
    let request = UpdateUserRequest {
        username: None,
        full_name: Some("".to_string()),
        avatar_url: None,
    };
    // No validation on full_name, so this should pass
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_full_name_long() {
    // Test long full name
    let request = UpdateUserRequest {
        username: None,
        full_name: Some("Very Long Full Name That Could Include Middle Names And More".to_string()),
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_avatar_url_valid() {
    // Test valid avatar URL (no URL validation, only optional)
    let request = UpdateUserRequest {
        username: None,
        full_name: None,
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_avatar_url_invalid() {
    // Test invalid avatar URL (no URL validation)
    let request = UpdateUserRequest {
        username: None,
        full_name: None,
        avatar_url: Some("not-a-url".to_string()),
    };
    // No URL validation, so this should pass
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_all_fields_valid() {
    // Test update request with all fields set and valid
    let request = UpdateUserRequest {
        username: Some("newusername".to_string()),
        full_name: Some("New Full Name".to_string()),
        avatar_url: Some("https://example.com/new-avatar.jpg".to_string()),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_multiple_fields_invalid() {
    // Test update request with username invalid and other fields valid
    let request = UpdateUserRequest {
        username: Some("ab".to_string()), // Too short
        full_name: Some("Valid Name".to_string()),
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("username"));
    assert!(!errors.contains_key("full_name"));
    assert!(!errors.contains_key("avatar_url"));
}

#[test]
fn test_update_user_request_deserialization() {
    // Test deserialization from JSON
    let json = r#"{
        "username": "testuser",
        "full_name": "Test User",
        "avatar_url": "https://example.com/avatar.jpg"
    }"#;
    let request: UpdateUserRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.username, Some("testuser".to_string()));
    assert_eq!(request.full_name, Some("Test User".to_string()));
    assert_eq!(
        request.avatar_url,
        Some("https://example.com/avatar.jpg".to_string())
    );
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_deserialization_partial() {
    // Test deserialization with partial fields
    let json = r#"{
        "username": "testuser"
    }"#;
    let request: UpdateUserRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.username, Some("testuser".to_string()));
    assert_eq!(request.full_name, None);
    assert_eq!(request.avatar_url, None);
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_deserialization_empty() {
    // Test deserialization with no fields
    let json = r#"{}"#;
    let request: UpdateUserRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.username, None);
    assert_eq!(request.full_name, None);
    assert_eq!(request.avatar_url, None);
    assert!(request.validate().is_ok());
}

#[test]
fn test_user_profile_response_creation() {
    // Test UserProfileResponse creation
    let id = Uuid::new_v4();
    let profile = UserProfileResponse {
        id,
        email: "test@example.com".to_string(),
        role: "owner".to_string(),
        username: Some("testuser".to_string()),
        full_name: Some("Test User".to_string()),
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
        created_at: Utc::now(),
    };
    assert_eq!(profile.email, "test@example.com");
    assert_eq!(profile.role, "owner");
}

#[test]
fn test_user_profile_response_serialization() {
    // Test UserProfileResponse serialization
    let id = Uuid::new_v4();
    let profile = UserProfileResponse {
        id,
        email: "test@example.com".to_string(),
        role: "owner".to_string(),
        username: Some("testuser".to_string()),
        full_name: Some("Test User".to_string()),
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
        created_at: Utc::now(),
    };
    let json = serde_json::to_string(&profile).unwrap();
    assert!(json.contains("test@example.com"));
    assert!(json.contains("owner"));
}

#[test]
fn test_public_profile_response_creation() {
    // Test PublicProfileResponse creation
    let id = Uuid::new_v4();
    let profile = PublicProfileResponse {
        id,
        username: Some("testuser".to_string()),
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
    };
    assert_eq!(profile.username, Some("testuser".to_string()));
    assert_eq!(
        profile.avatar_url,
        Some("https://example.com/avatar.jpg".to_string())
    );
}

#[test]
fn test_public_profile_response_none_fields() {
    // Test PublicProfileResponse with None fields
    let id = Uuid::new_v4();
    let profile = PublicProfileResponse {
        id,
        username: None,
        avatar_url: None,
    };
    assert_eq!(profile.username, None);
    assert_eq!(profile.avatar_url, None);
}

#[test]
fn test_public_profile_response_serialization() {
    // Test PublicProfileResponse serialization
    let id = Uuid::new_v4();
    let profile = PublicProfileResponse {
        id,
        username: Some("testuser".to_string()),
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
    };
    let json = serde_json::to_string(&profile).unwrap();
    assert!(json.contains("testuser"));
}

#[test]
fn test_update_user_request_username_exactly_min() {
    // Test username with exactly minimum length
    let request = UpdateUserRequest {
        username: Some("abc".to_string()),
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_exactly_max() {
    // Test username with exactly maximum length
    let request = UpdateUserRequest {
        username: Some("x".repeat(50)),
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_just_below_min() {
    // Test username with one character below minimum
    let request = UpdateUserRequest {
        username: Some("ab".to_string()),
        full_name: None,
        avatar_url: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("username"));
}

#[test]
fn test_update_user_request_username_just_above_max() {
    // Test username with one character above maximum
    let request = UpdateUserRequest {
        username: Some("y".repeat(51)),
        full_name: None,
        avatar_url: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("username"));
}

#[test]
fn test_update_user_request_only_username_valid() {
    // Test update request with only username
    let request = UpdateUserRequest {
        username: Some("validusername".to_string()),
        full_name: None,
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_only_full_name() {
    // Test update request with only full name
    let request = UpdateUserRequest {
        username: None,
        full_name: Some("John Doe".to_string()),
        avatar_url: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_only_avatar_url() {
    // Test update request with only avatar URL
    let request = UpdateUserRequest {
        username: None,
        full_name: None,
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_user_request_username_single_char() {
    // Test username with single character (too short)
    let request = UpdateUserRequest {
        username: Some("a".to_string()),
        full_name: None,
        avatar_url: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("username"));
}

#[test]
fn test_update_user_request_validation_error_message_content() {
    // Test that validation errors contain useful information
    let request = UpdateUserRequest {
        username: Some("ab".to_string()),
        full_name: None,
        avatar_url: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("username"));
}

#[test]
fn test_user_profile_response_with_timestamps() {
    // Test UserProfileResponse with created_at timestamp
    let id = Uuid::new_v4();
    let now = Utc::now();
    let profile = UserProfileResponse {
        id,
        email: "test@example.com".to_string(),
        role: "renter".to_string(),
        username: None,
        full_name: None,
        avatar_url: None,
        created_at: now,
    };
    assert_eq!(profile.created_at, now);
}

#[test]
fn test_user_profile_response_none_optional_fields() {
    // Test UserProfileResponse with all optional fields as None
    let id = Uuid::new_v4();
    let profile = UserProfileResponse {
        id,
        email: "test@example.com".to_string(),
        role: "admin".to_string(),
        username: None,
        full_name: None,
        avatar_url: None,
        created_at: Utc::now(),
    };
    assert_eq!(profile.username, None);
    assert_eq!(profile.full_name, None);
    assert_eq!(profile.avatar_url, None);
}

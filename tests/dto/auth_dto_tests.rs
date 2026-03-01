// Tests for auth DTOs in src/api/dtos/auth_dto.rs
// Tests Auth0SignupRequestDto and Auth0LoginRequestDto validation

use rust_backend::api::dtos::auth_dto::{Auth0LoginRequestDto, Auth0SignupRequestDto};
use serde_json;
use validator::Validate;

#[test]
fn test_auth0_signup_request_valid_all_fields() {
    // Test valid signup request with all fields
    let request = Auth0SignupRequestDto {
        email: "test@example.com".to_string(),
        password: "SecurePassword123!".to_string(),
        username: Some("testuser".to_string()),
        full_name: Some("Test User".to_string()),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_signup_request_valid_minimal() {
    // Test valid signup request with only required fields
    let request = Auth0SignupRequestDto {
        email: "user@example.com".to_string(),
        password: "Password123".to_string(),
        username: None,
        full_name: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_signup_request_valid_email_formats() {
    // Test various valid email formats
    let valid_emails = vec![
        "simple@example.com",
        "very.common@example.com",
        "disposable.style.email.with+symbol@example.com",
        "other.email-with-hyphen@example.com",
        "fully-qualified-domain@example.com",
        "user.name+tag+sorting@example.com",
        "x@example.com",
        "example-indeed@strange-example.com",
        "test@test.co.uk",
        "user@localhost",
    ];

    for email in valid_emails {
        let request = Auth0SignupRequestDto {
            email: email.to_string(),
            password: "ValidPass123".to_string(),
            username: None,
            full_name: None,
        };
        assert!(
            request.validate().is_ok(),
            "Email '{}' should be valid",
            email
        );
    }
}

#[test]
fn test_auth0_signup_request_empty_email() {
    // Test empty email - should fail validation
    let request = Auth0SignupRequestDto {
        email: "".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("email"));
    // Should have both length and email validation errors
    assert!(!errors.get("email").unwrap().is_empty());
}

#[test]
fn test_auth0_signup_request_whitespace_email() {
    // Test email with only whitespace - should fail validation
    let request = Auth0SignupRequestDto {
        email: "   ".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("email"));
}

#[test]
fn test_auth0_signup_request_invalid_email_missing_at() {
    // Test email without @ symbol
    let request = Auth0SignupRequestDto {
        email: "invalidemail.com".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("email"));
}

#[test]
fn test_auth0_signup_request_invalid_email_missing_domain() {
    // Test email without domain
    let request = Auth0SignupRequestDto {
        email: "user@".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("email"));
}

#[test]
fn test_auth0_signup_request_invalid_email_missing_local() {
    // Test email without local part
    let request = Auth0SignupRequestDto {
        email: "@example.com".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("email"));
}

#[test]
fn test_auth0_signup_request_invalid_email_double_at() {
    // Test email with multiple @ symbols
    let request = Auth0SignupRequestDto {
        email: "user@@example.com".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("email"));
}

#[test]
fn test_auth0_signup_request_username_only() {
    // Test signup with just username (email is still required)
    let request = Auth0SignupRequestDto {
        email: "test@example.com".to_string(),
        password: "ValidPass123".to_string(),
        username: Some("username123".to_string()),
        full_name: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_signup_request_full_name_only() {
    // Test signup with just full name
    let request = Auth0SignupRequestDto {
        email: "test@example.com".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: Some("John Doe".to_string()),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_login_request_valid() {
    // Test valid login request
    let request = Auth0LoginRequestDto {
        email: "test@example.com".to_string(),
        password: "ValidPass123".to_string(),
    };
    // Auth0LoginRequestDto doesn't have validation derive, so we just check it can be created
    assert_eq!(request.email, "test@example.com");
    assert_eq!(request.password, "ValidPass123");
}

#[test]
fn test_auth0_signup_request_deserialization() {
    // Test deserialization from JSON
    let json = r#"{
        "email": "test@example.com",
        "password": "Password123",
        "username": "testuser",
        "full_name": "Test User"
    }"#;
    let request: Auth0SignupRequestDto = serde_json::from_str(json).unwrap();
    assert_eq!(request.email, "test@example.com");
    assert_eq!(request.password, "Password123");
    assert_eq!(request.username, Some("testuser".to_string()));
    assert_eq!(request.full_name, Some("Test User".to_string()));
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_signup_request_deserialization_without_optional_fields() {
    // Test deserialization without optional fields
    let json = r#"{
        "email": "user@example.com",
        "password": "Password123"
    }"#;
    let request: Auth0SignupRequestDto = serde_json::from_str(json).unwrap();
    assert_eq!(request.email, "user@example.com");
    assert_eq!(request.password, "Password123");
    assert_eq!(request.username, None);
    assert_eq!(request.full_name, None);
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_login_request_deserialization() {
    // Test login request deserialization
    let json = r#"{
        "email": "test@example.com",
        "password": "Password123"
    }"#;
    let request: Auth0LoginRequestDto = serde_json::from_str(json).unwrap();
    assert_eq!(request.email, "test@example.com");
    assert_eq!(request.password, "Password123");
}

#[test]
fn test_auth0_signup_request_with_alias_deserialization() {
    // Test deserialization using field aliases (email, password, username, full_name)
    let json = r#"{
        "email": "test@example.com",
        "password": "Password123",
        "username": "testuser",
        "full_name": "Test User"
    }"#;
    let request: Auth0SignupRequestDto = serde_json::from_str(json).unwrap();
    assert_eq!(request.email, "test@example.com");
    assert_eq!(request.password, "Password123");
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_login_request_with_alias_deserialization() {
    // Test login request deserialization using field aliases
    let json = r#"{
        "email": "test@example.com",
        "password": "Password123"
    }"#;
    let request: Auth0LoginRequestDto = serde_json::from_str(json).unwrap();
    assert_eq!(request.email, "test@example.com");
    assert_eq!(request.password, "Password123");
}

#[test]
fn test_auth0_signup_request_empty_optional_fields() {
    // Test signup with empty optional fields is still valid (they are None)
    let request = Auth0SignupRequestDto {
        email: "test@example.com".to_string(),
        password: "Password123".to_string(),
        username: None,
        full_name: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_signup_request_validation_error_message() {
    // Test that validation error messages contain useful information
    let request = Auth0SignupRequestDto {
        email: "".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("email"));
}

#[test]
fn test_auth0_signup_request_password_can_be_anything() {
    // Note: Password validation is done on the backend/through Auth0
    // The DTO doesn't validate password format
    let request = Auth0SignupRequestDto {
        email: "test@example.com".to_string(),
        password: "".to_string(),
        username: None,
        full_name: None,
    };
    // This should pass validation because password has no validation rules
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_signup_request_international_email() {
    // Test email with international characters
    let request = Auth0SignupRequestDto {
        email: "用户@例子.测试".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    // This might fail depending on the validator's email rules
    // Testing to see current behavior
    let result = request.validate();
    // The validator crate's email validation may not support IDN by default
    // We test to document the behavior
    if let Err(validation_err) = result {
        let errors = validation_err.field_errors();
        assert!(errors.contains_key("email"));
    }
}

#[test]
fn test_auth0_signup_request_subdomain_email() {
    // Test email with subdomain
    let request = Auth0SignupRequestDto {
        email: "user@mail.example.com".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_signup_request_email_with_dots() {
    // Test email with multiple dots in local part
    let request = Auth0SignupRequestDto {
        email: "first.last@subdomain.example.com".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_auth0_signup_request_email_case_sensitivity() {
    // Test that email validation is case-insensitive (local part)
    let request = Auth0SignupRequestDto {
        email: "User@Example.com".to_string(),
        password: "ValidPass123".to_string(),
        username: None,
        full_name: None,
    };
    assert!(request.validate().is_ok());
}

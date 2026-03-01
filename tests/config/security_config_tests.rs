//! Tests for SecurityConfig validation and Debug implementation
//!
//! This module tests that:
//! - SecurityConfig::validate() enforces security constraints
//! - Debug output redacts sensitive fields
//! - All validation rules are properly enforced

use rust_backend::config::SecurityConfig;

#[test]
fn test_security_config_validate_with_valid_values() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    assert!(
        config.validate().is_ok(),
        "Valid config should pass validation"
    );
}

#[test]
fn test_security_config_validate_fails_with_zero_rate_limit_per_minute() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 0, // Invalid
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let result = config.validate();
    assert!(result.is_err(), "Zero rate limit should fail validation");
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("global_rate_limit_per_minute must be greater than 0"));
}

#[test]
fn test_security_config_validate_fails_with_excessive_rate_limit_per_minute() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 60_001, // Exceeds limit
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let result = config.validate();
    assert!(
        result.is_err(),
        "Excessive rate limit should fail validation"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("global_rate_limit_per_minute must not exceed 60,000"));
}

#[test]
fn test_security_config_validate_accepts_max_rate_limit_per_minute() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 60_000, // Maximum allowed
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    assert!(
        config.validate().is_ok(),
        "Max rate limit should be accepted"
    );
}

#[test]
fn test_security_config_validate_fails_with_zero_burst_size() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 0, // Invalid
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let result = config.validate();
    assert!(result.is_err(), "Zero burst size should fail validation");
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("global_rate_limit_burst_size must be greater than 0"));
}

#[test]
fn test_security_config_validate_accepts_large_burst_size() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 1000, // Large but valid
        global_rate_limit_authenticated_per_minute: 1000,
    };

    assert!(
        config.validate().is_ok(),
        "Large burst size should be accepted"
    );
}

#[test]
fn test_security_config_validate_accepts_low_rate_limit() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 1, // Minimum allowed
        global_rate_limit_burst_size: 1,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    assert!(
        config.validate().is_ok(),
        "Minimum rate limit should be accepted"
    );
}

#[test]
fn test_security_config_validate_burst_size_larger_than_rate_limit() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 10,
        global_rate_limit_burst_size: 50, // Burst larger than per-minute rate
        global_rate_limit_authenticated_per_minute: 1000,
    };

    // This is technically valid (burst can be larger than per-minute rate)
    assert!(
        config.validate().is_ok(),
        "Burst size larger than rate limit should be accepted"
    );
}

#[test]
fn test_security_config_validate_no_constraint_on_authenticated_rate_limit() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 0, // No constraint on this field
    };

    // There's no validation for global_rate_limit_authenticated_per_minute
    assert!(
        config.validate().is_ok(),
        "Authenticated rate limit can be zero"
    );
}

#[test]
fn test_security_config_validate_accepts_zero_login_failures() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 0, // No lockout
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    // There's no validation for login_max_failures
    assert!(
        config.validate().is_ok(),
        "Zero login failures should be accepted"
    );
}

#[test]
fn test_security_config_validate_accepts_zero_lockout_seconds() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 0, // No lockout
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    // There's no validation for login_lockout_seconds
    assert!(
        config.validate().is_ok(),
        "Zero lockout seconds should be accepted"
    );
}

#[test]
fn test_security_config_validate_accepts_zero_backoff_ms() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 0, // No backoff
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    // There's no validation for login_backoff_base_ms
    assert!(
        config.validate().is_ok(),
        "Zero backoff ms should be accepted"
    );
}

#[test]
fn test_security_config_debug_shows_all_fields() {
    let config = SecurityConfig {
        cors_allowed_origins: vec![
            "http://localhost:3000".to_string(),
            "https://example.com".to_string(),
        ],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let debug_output = format!("{:?}", config);

    // Verify all field names are present
    assert!(debug_output.contains("cors_allowed_origins"));
    assert!(debug_output.contains("metrics_allow_private_only"));
    assert!(debug_output.contains("metrics_admin_token"));
    assert!(debug_output.contains("login_max_failures"));
    assert!(debug_output.contains("login_lockout_seconds"));
    assert!(debug_output.contains("login_backoff_base_ms"));
    assert!(debug_output.contains("global_rate_limit_per_minute"));
    assert!(debug_output.contains("global_rate_limit_burst_size"));
    assert!(debug_output.contains("global_rate_limit_authenticated_per_minute"));
}

#[test]
fn test_security_config_debug_shows_cors_origins() {
    let config = SecurityConfig {
        cors_allowed_origins: vec![
            "http://localhost:3000".to_string(),
            "https://app.example.com".to_string(),
        ],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let debug_output = format!("{:?}", config);

    // Verify origins are shown (not redacted)
    assert!(debug_output.contains("http://localhost:3000"));
    assert!(debug_output.contains("https://app.example.com"));
}

#[test]
fn test_security_config_debug_shows_metrics_allow_private_only() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let debug_output = format!("{:?}", config);

    assert!(
        debug_output.contains("true"),
        "metrics_allow_private_only should be shown"
    );
}

#[test]
fn test_security_config_debug_redacts_metrics_admin_token_when_set() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: Some("secret-admin-token-123".to_string()),
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let debug_output = format!("{:?}", config);

    // Token should be redacted
    assert!(
        debug_output.contains("[REDACTED]"),
        "Admin token should be redacted"
    );
    assert!(
        !debug_output.contains("secret-admin-token-123"),
        "Actual token should not appear"
    );
}

#[test]
fn test_security_config_debug_with_none_metrics_admin_token() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let debug_output = format!("{:?}", config);

    // None should be shown as None, not redacted
    assert!(debug_output.contains("None"), "None token should be shown");
    assert!(
        !debug_output.contains("[REDACTED]"),
        "None should not be redacted"
    );
}

#[test]
fn test_security_config_debug_shows_numeric_values() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 10,
        login_lockout_seconds: 600,
        login_backoff_base_ms: 500,
        global_rate_limit_per_minute: 1000,
        global_rate_limit_burst_size: 100,
        global_rate_limit_authenticated_per_minute: 5000,
    };

    let debug_output = format!("{:?}", config);

    // Verify numeric values are shown
    assert!(
        debug_output.contains("10"),
        "login_max_failures should be shown"
    );
    assert!(
        debug_output.contains("600"),
        "login_lockout_seconds should be shown"
    );
    assert!(
        debug_output.contains("500"),
        "login_backoff_base_ms should be shown"
    );
    assert!(
        debug_output.contains("1000"),
        "global_rate_limit_per_minute should be shown"
    );
    assert!(
        debug_output.contains("100"),
        "global_rate_limit_burst_size should be shown"
    );
    assert!(
        debug_output.contains("5000"),
        "global_rate_limit_authenticated_per_minute should be shown"
    );
}

#[test]
fn test_security_config_debug_struct_name() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let debug_output = format!("{:?}", config);

    assert!(
        debug_output.contains("SecurityConfig"),
        "Struct name should be present"
    );
}

#[test]
fn test_security_config_debug_with_empty_cors_origins() {
    let config = SecurityConfig {
        cors_allowed_origins: vec![],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let debug_output = format!("{:?}", config);

    // Empty origins should be shown as empty list
    assert!(debug_output.contains("cors_allowed_origins"));
}

#[test]
fn test_security_config_validate_with_single_cors_origin() {
    let config = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    assert!(
        config.validate().is_ok(),
        "Single CORS origin should be valid"
    );
}

#[test]
fn test_security_config_validate_with_multiple_cors_origins() {
    let config = SecurityConfig {
        cors_allowed_origins: vec![
            "http://localhost:3000".to_string(),
            "https://app.example.com".to_string(),
            "https://admin.example.com".to_string(),
            "https://api.example.com".to_string(),
        ],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    assert!(
        config.validate().is_ok(),
        "Multiple CORS origins should be valid"
    );
}

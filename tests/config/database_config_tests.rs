//! Tests for DatabaseConfig Debug implementation
//!
//! This module tests that:
//! - DatabaseConfig Debug output redacts the database URL
//! - All other fields are displayed correctly

use rust_backend::config::DatabaseConfig;

#[test]
fn test_database_config_debug_redacts_url() {
    let config = DatabaseConfig {
        url: "postgres://user:password123@localhost:5432/mydb".to_string(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout_seconds: 30,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let debug_output = format!("{:?}", config);

    // URL should be redacted
    assert!(
        debug_output.contains("[REDACTED]"),
        "URL should be redacted in Debug output"
    );
    // The actual URL should NOT appear
    assert!(
        !debug_output.contains("postgres://user:password123@localhost:5432/mydb"),
        "Actual URL should not appear in Debug output"
    );
    assert!(
        !debug_output.contains("password123"),
        "Password should not appear in Debug output"
    );
}

#[test]
fn test_database_config_debug_shows_other_fields() {
    let config = DatabaseConfig {
        url: "postgres://localhost/test".to_string(),
        max_connections: 15,
        min_connections: 3,
        acquire_timeout_seconds: 45,
        idle_timeout_seconds: 900,
        max_lifetime_seconds: 3600,
        test_before_acquire: false,
    };

    let debug_output = format!("{:?}", config);

    // Verify all non-sensitive fields are present
    assert!(
        debug_output.contains("max_connections"),
        "max_connections should be shown"
    );
    assert!(
        debug_output.contains("15"),
        "max_connections value should be shown"
    );
    assert!(
        debug_output.contains("min_connections"),
        "min_connections should be shown"
    );
    assert!(
        debug_output.contains("3"),
        "min_connections value should be shown"
    );
    assert!(
        debug_output.contains("acquire_timeout_seconds"),
        "acquire_timeout_seconds should be shown"
    );
    assert!(
        debug_output.contains("45"),
        "acquire_timeout_seconds value should be shown"
    );
    assert!(
        debug_output.contains("idle_timeout_seconds"),
        "idle_timeout_seconds should be shown"
    );
    assert!(
        debug_output.contains("900"),
        "idle_timeout_seconds value should be shown"
    );
    assert!(
        debug_output.contains("max_lifetime_seconds"),
        "max_lifetime_seconds should be shown"
    );
    assert!(
        debug_output.contains("3600"),
        "max_lifetime_seconds value should be shown"
    );
    assert!(
        debug_output.contains("test_before_acquire"),
        "test_before_acquire should be shown"
    );
    assert!(
        debug_output.contains("false"),
        "test_before_acquire value should be shown"
    );
}

#[test]
fn test_database_config_debug_struct_name() {
    let config = DatabaseConfig {
        url: "postgres://localhost/test".to_string(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout_seconds: 30,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let debug_output = format!("{:?}", config);

    // Verify struct name is present
    assert!(
        debug_output.contains("DatabaseConfig"),
        "Debug output should contain struct name"
    );
}

#[test]
fn test_database_config_debug_with_complex_password() {
    let config = DatabaseConfig {
        url: "postgres://user:P@ssw0rd!#$@localhost:5432/mydb?sslmode=require".to_string(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout_seconds: 30,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let debug_output = format!("{:?}", config);

    // Complex password should be redacted
    assert!(
        debug_output.contains("[REDACTED]"),
        "URL with complex password should be redacted"
    );
    assert!(
        !debug_output.contains("P@ssw0rd!#$"),
        "Complex password should not appear"
    );
    // Connection details that are not sensitive should still appear in other fields
    assert!(debug_output.contains("max_connections"));
}

#[test]
fn test_database_config_debug_with_url_containing_special_chars() {
    let config = DatabaseConfig {
        url: "postgresql://user:secret%20key@host.example.com:5432/database_name".to_string(),
        max_connections: 20,
        min_connections: 5,
        acquire_timeout_seconds: 60,
        idle_timeout_seconds: 1200,
        max_lifetime_seconds: 7200,
        test_before_acquire: false,
    };

    let debug_output = format!("{:?}", config);

    // Password with URL encoding should be redacted
    assert!(
        debug_output.contains("[REDACTED]"),
        "URL with encoded password should be redacted"
    );
    assert!(
        !debug_output.contains("secret%20key"),
        "Encoded password should not appear"
    );
    assert!(
        !debug_output.contains("secret"),
        "Partial password should not appear"
    );
}

#[test]
fn test_database_config_debug_with_connection_string_parameters() {
    let config = DatabaseConfig {
        url: "postgres://user:pass@localhost:5432/db?sslmode=require&connect_timeout=10"
            .to_string(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout_seconds: 30,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let debug_output = format!("{:?}", config);

    // URL with query parameters should be redacted
    assert!(
        debug_output.contains("[REDACTED]"),
        "URL with parameters should be redacted"
    );
    assert!(
        !debug_output.contains("sslmode=require"),
        "Query parameters should not appear"
    );
}

#[test]
fn test_database_config_debug_display_bool_true() {
    let config = DatabaseConfig {
        url: "postgres://localhost/test".to_string(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout_seconds: 30,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let debug_output = format!("{:?}", config);

    // Verify boolean is displayed as "true"
    assert!(
        debug_output.contains("true"),
        "test_before_acquire: true should be shown"
    );
}

#[test]
fn test_database_config_debug_with_zero_values() {
    let config = DatabaseConfig {
        url: "postgres://localhost/test".to_string(),
        max_connections: 0,
        min_connections: 0,
        acquire_timeout_seconds: 0,
        idle_timeout_seconds: 0,
        max_lifetime_seconds: 0,
        test_before_acquire: false,
    };

    let debug_output = format!("{:?}", config);

    // Even with zero values, fields should be shown
    assert!(
        debug_output.contains("max_connections"),
        "Field names should still appear"
    );
    assert!(debug_output.contains("0"), "Zero values should be shown");
}

#[test]
fn test_database_config_debug_with_large_values() {
    let config = DatabaseConfig {
        url: "postgres://localhost/test".to_string(),
        max_connections: 1000,
        min_connections: 100,
        acquire_timeout_seconds: 3600,
        idle_timeout_seconds: 86400,
        max_lifetime_seconds: 604800,
        test_before_acquire: true,
    };

    let debug_output = format!("{:?}", config);

    // Large values should be shown
    assert!(
        debug_output.contains("1000"),
        "Large max_connections should be shown"
    );
    assert!(
        debug_output.contains("100"),
        "Large min_connections should be shown"
    );
    assert!(
        debug_output.contains("3600"),
        "Large acquire_timeout should be shown"
    );
    assert!(
        debug_output.contains("86400"),
        "Large idle_timeout should be shown"
    );
    assert!(
        debug_output.contains("604800"),
        "Large max_lifetime should be shown"
    );
}

#[test]
fn test_database_config_debug_redacts_url_with_ipv6() {
    let config = DatabaseConfig {
        url: "postgres://user:password@[::1]:5432/mydb".to_string(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout_seconds: 30,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let debug_output = format!("{:?}", config);

    // URL with IPv6 address should be redacted
    assert!(
        debug_output.contains("[REDACTED]"),
        "URL with IPv6 should be redacted"
    );
    assert!(
        !debug_output.contains("password"),
        "Password should not appear"
    );
    assert!(
        !debug_output.contains("[::1]"),
        "IPv6 address should not appear in URL"
    );
}

#[test]
fn test_database_config_debug_with_socket_url() {
    let config = DatabaseConfig {
        url: "postgres://user:password@/var/run/postgresql/mydb".to_string(),
        max_connections: 10,
        min_connections: 2,
        acquire_timeout_seconds: 30,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let debug_output = format!("{:?}", config);

    // Unix socket URL should be redacted
    assert!(
        debug_output.contains("[REDACTED]"),
        "Socket URL should be redacted"
    );
    assert!(
        !debug_output.contains("password"),
        "Password should not appear"
    );
}

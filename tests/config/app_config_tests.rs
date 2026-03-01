//! Tests for AppConfig configuration loading and validation
//!
//! This module tests that:
//! - AppConfig::from_env() loads configuration from environment variables
//! - AppConfig::validate() checks required values and security constraints
//! - Configuration defaults are applied correctly
//! - Invalid configurations are rejected

use once_cell::sync::Lazy;
use rust_backend::config::{AppConfig, Auth0Config, AuthConfig, SecurityConfig};
use std::env;
use std::sync::Mutex;

static SERIALIZE: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn cleanup_env_vars() {
    env::remove_var("DATABASE_URL");
    env::remove_var("JWT_SECRET");
    env::remove_var("AUTH0_DOMAIN");
    env::remove_var("AUTH0_AUDIENCE");
    env::remove_var("AUTH0_ISSUER");
    env::remove_var("AUTH0_JWKS_CACHE_TTL_SECS");
    env::remove_var("AUTH0_CLIENT_ID");
    env::remove_var("AUTH0_CONNECTION");
    env::remove_var("AUTH0_CLIENT_SECRET");
    env::remove_var("SENTRY_DSN");
    env::remove_var("APP_HOST");
    env::remove_var("APP_PORT");
    env::remove_var("APP_ENVIRONMENT");
    env::remove_var("APP_DATABASE__URL");
    env::remove_var("APP_DATABASE__MAX_CONNECTIONS");
    env::remove_var("APP_DATABASE__MIN_CONNECTIONS");
    env::remove_var("APP_AUTH__JWT_SECRET");
    env::remove_var("APP_SECURITY__GLOBAL_RATE_LIMIT_PER_MINUTE");
}

#[test]
fn test_app_config_from_env_loads_database_url() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://test-host/testdb");
    env::set_var("JWT_SECRET", "test-secret-key");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "test-api");

    let config = AppConfig::from_env().expect("Failed to load config");

    let db_url = config.database.url;

    cleanup_env_vars();

    assert_eq!(db_url, "postgres://test-host/testdb");
}

#[test]
fn test_app_config_from_env_loads_jwt_secret() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "my-secret-jwt-key");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "test-api");

    let config = AppConfig::from_env().expect("Failed to load config");

    let jwt_secret = config.auth.jwt_secret;

    cleanup_env_vars();

    assert_eq!(jwt_secret, "my-secret-jwt-key");
}

#[test]
fn test_app_config_from_env_with_app_prefix() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "test-api");
    env::set_var("APP_SECURITY__GLOBAL_RATE_LIMIT_PER_MINUTE", "500");

    let config = AppConfig::from_env().expect("Failed to load config");

    let rate_limit = config.security.global_rate_limit_per_minute;

    cleanup_env_vars();

    assert_eq!(rate_limit, 500);
}

#[test]
fn test_app_config_from_env_with_auth0_prefix() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "custom.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "custom-api");
    env::set_var("AUTH0_JWKS_CACHE_TTL_SECS", "7200");

    let config = AppConfig::from_env().expect("Failed to load config");

    let domain = config.auth0.auth0_domain;
    let audience = config.auth0.auth0_audience;
    let ttl_secs = config.auth0.jwks_cache_ttl_secs;

    cleanup_env_vars();

    assert_eq!(domain, Some("custom.auth0.com".to_string()));
    assert_eq!(audience, Some("custom-api".to_string()));
    assert_eq!(ttl_secs, 7200);
}

#[test]
fn test_app_config_from_env_normalizes_empty_auth0_strings() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "   "); // Empty after trim
    env::set_var("AUTH0_AUDIENCE", ""); // Empty string
    env::set_var("AUTH0_CLIENT_SECRET", "  "); // Empty after trim

    let config = AppConfig::from_env().expect("Failed to load config");

    let domain = config.auth0.auth0_domain;
    let audience = config.auth0.auth0_audience;
    let client_secret = config.auth0.auth0_client_secret;

    cleanup_env_vars();

    // Empty strings should be normalized to None
    assert_eq!(domain, None);
    assert_eq!(audience, None);
    assert_eq!(client_secret, None);
}

#[test]
fn test_app_config_validate_requires_jwt_secret() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    // JWT_SECRET not set

    let config = AppConfig::from_env().expect("Failed to load config");

    cleanup_env_vars();

    let result = config.validate();
    assert!(result.is_err(), "Validation should fail without JWT_SECRET");
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("JWT_SECRET must be set"));
}

#[test]
fn test_app_config_validate_rejects_default_placeholder() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "change-me-in-production");

    let config = AppConfig::from_env().expect("Failed to load config");

    cleanup_env_vars();

    let result = config.validate();
    assert!(
        result.is_err(),
        "Validation should fail with placeholder JWT_SECRET"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("must be set to a secure value"));
}

#[test]
fn test_app_config_validate_accepts_valid_jwt_secret() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "proper-secure-random-key");

    let config = AppConfig::from_env().expect("Failed to load config");

    cleanup_env_vars();

    assert!(
        config.validate().is_ok(),
        "Validation should succeed with valid JWT_SECRET"
    );
}

#[test]
fn test_app_config_validate_rejects_whitespace_only_jwt_secret() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "   "); // Whitespace only

    let config = AppConfig::from_env().expect("Failed to load config");

    cleanup_env_vars();

    let result = config.validate();
    assert!(
        result.is_err(),
        "Validation should fail with whitespace-only JWT_SECRET"
    );
}

#[test]
fn test_app_config_validate_trims_whitespace() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "  my-secret-key  "); // Has whitespace around it

    let config = AppConfig::from_env().expect("Failed to load config");

    cleanup_env_vars();

    // Should succeed - whitespace is trimmed during validation
    assert!(config.validate().is_ok());
}

#[test]
fn test_app_config_validate_calls_security_validate() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("APP_SECURITY__GLOBAL_RATE_LIMIT_PER_MINUTE", "0"); // Invalid

    let config = AppConfig::from_env().expect("Failed to load config");

    cleanup_env_vars();

    let result = config.validate();
    assert!(
        result.is_err(),
        "Validation should fail with invalid security config"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("global_rate_limit_per_minute"));
}

#[test]
fn test_app_config_validate_calls_auth0_validate() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    // AUTH0_AUDIENCE not set - should fail validation

    let config = AppConfig::from_env().expect("Failed to load config");

    cleanup_env_vars();

    let result = config.validate();
    assert!(
        result.is_err(),
        "Validation should fail with incomplete Auth0 config"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("AUTH0_AUDIENCE is required"));
}

#[test]
fn test_app_config_from_env_uses_default_auth0_connection() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "test-api");

    let config = AppConfig::from_env().expect("Failed to load config");

    let connection = config.auth0.auth0_connection;

    cleanup_env_vars();

    // Default connection should be used
    assert_eq!(connection, "Username-Password-Authentication");
}

#[test]
fn test_app_config_from_env_override_auth0_connection() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "test-api");
    env::set_var("AUTH0_CONNECTION", "Custom-Connection");

    let config = AppConfig::from_env().expect("Failed to load config");

    let connection = config.auth0.auth0_connection;

    cleanup_env_vars();

    assert_eq!(connection, "Custom-Connection");
}

#[test]
fn test_app_config_from_env_normalizes_empty_auth0_connection() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "test-api");
    env::set_var("AUTH0_CONNECTION", "   "); // Empty after trim

    let config = AppConfig::from_env().expect("Failed to load config");

    let connection = config.auth0.auth0_connection;

    cleanup_env_vars();

    // Empty connection should fall back to default
    assert_eq!(connection, "Username-Password-Authentication");
}

#[test]
fn test_app_config_from_env_normalizes_auth0_strings_with_whitespace() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "  test.auth0.com  ");
    env::set_var("AUTH0_AUDIENCE", "  test-api  ");
    env::set_var("AUTH0_ISSUER", "  https://custom.issuer.com  ");

    let config = AppConfig::from_env().expect("Failed to load config");

    let domain = config.auth0.auth0_domain;
    let audience = config.auth0.auth0_audience;
    let issuer = config.auth0.auth0_issuer;

    cleanup_env_vars();

    // Whitespace should be trimmed
    assert_eq!(domain, Some("test.auth0.com".to_string()));
    assert_eq!(audience, Some("test-api".to_string()));
    assert_eq!(issuer, Some("https://custom.issuer.com".to_string()));
}

#[test]
fn test_app_config_from_env_with_sentry_dsn() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "test-api");
    env::set_var("SENTRY_DSN", "https://key@sentry.io/123");

    let config = AppConfig::from_env().expect("Failed to load config");

    let sentry_dsn = config.sentry.dsn;

    cleanup_env_vars();

    assert_eq!(sentry_dsn, Some("https://key@sentry.io/123".to_string()));
}

#[test]
fn test_app_config_from_env_normalizes_empty_sentry_dsn() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "test-api");
    env::set_var("SENTRY_DSN", "   "); // Empty after trim

    let config = AppConfig::from_env().expect("Failed to load config");

    let sentry_dsn = config.sentry.dsn;

    cleanup_env_vars();

    // Empty DSN should be normalized to None
    assert_eq!(sentry_dsn, None);
}

#[test]
fn test_app_config_from_env_invalid_type_fails() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    cleanup_env_vars();

    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "test-api");
    env::set_var("APP_PORT", "not-a-number"); // Invalid type

    let result = AppConfig::from_env();

    cleanup_env_vars();

    assert!(result.is_err(), "Should fail with invalid type");
}

#[test]
fn test_app_config_validate_with_empty_auth0_config() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    // Create a config with disabled Auth0 (all empty)
    let config = AppConfig {
        host: "0.0.0.0".to_string(),
        port: 8080,
        environment: "test".to_string(),
        database: rust_backend::config::DatabaseConfig {
            url: "postgres://localhost/test".to_string(),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout_seconds: 30,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 1800,
            test_before_acquire: true,
        },
        auth: AuthConfig {
            jwt_secret: "test-secret".to_string(),
            jwt_kid: "v1".to_string(),
            previous_jwt_secrets: vec![],
            previous_jwt_kids: vec![],
            jwt_expiration_seconds: 900,
            refresh_token_expiration_days: 7,
            issuer: "test".to_string(),
            audience: "test".to_string(),
        },
        auth0: Auth0Config {
            auth0_domain: None,
            auth0_audience: None,
            auth0_issuer: None,
            jwks_cache_ttl_secs: 3600,
            auth0_client_id: None,
            auth0_client_secret: None,
            auth0_connection: "Username-Password-Authentication".to_string(),
        },
        security: SecurityConfig {
            cors_allowed_origins: vec!["http://localhost:3000".to_string()],
            metrics_allow_private_only: true,
            metrics_admin_token: None,
            login_max_failures: 5,
            login_lockout_seconds: 300,
            login_backoff_base_ms: 200,
            global_rate_limit_per_minute: 300,
            global_rate_limit_burst_size: 30,
            global_rate_limit_authenticated_per_minute: 1000,
        },
        logging: rust_backend::config::LoggingConfig {
            level: "info".to_string(),
            json_format: false,
        },
        sentry: rust_backend::config::SentryConfig { dsn: None },
    };

    // Should validate successfully with disabled Auth0
    assert!(config.validate().is_ok());
}

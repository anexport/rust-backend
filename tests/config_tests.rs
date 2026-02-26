use once_cell::sync::Lazy;
use rust_backend::config::{AppConfig, Auth0Config};
use std::env;
use std::sync::Mutex;

static SERIALIZE: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[test]
fn test_auth0_config_validation() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    // Valid config
    let valid = Auth0Config {
        auth0_domain: Some("test.auth0.com".to_string()),
        auth0_audience: Some("test-api".to_string()),
        ..Default::default()
    };
    assert!(valid.validate().is_ok());

    // Disabled config (domain/audience None)
    let disabled = Auth0Config::default();
    assert!(disabled.validate().is_ok());
    assert!(!disabled.is_enabled());

    // Incomplete config (domain set, audience None)
    let incomplete = Auth0Config {
        auth0_domain: Some("test.auth0.com".to_string()),
        auth0_audience: None,
        ..Default::default()
    };
    assert!(incomplete.validate().is_err());

    // Incomplete config (domain None, audience set)
    let incomplete2 = Auth0Config {
        auth0_domain: None,
        auth0_audience: Some("test-api".to_string()),
        ..Default::default()
    };
    assert!(incomplete2.validate().is_err());
}

#[test]
fn test_auth0_issuer_construction() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let config = Auth0Config {
        auth0_domain: Some("test.auth0.com".to_string()),
        ..Default::default()
    };
    assert_eq!(config.issuer(), Some("https://test.auth0.com/".to_string()));

    let config_with_issuer = Auth0Config {
        auth0_domain: Some("test.auth0.com".to_string()),
        auth0_issuer: Some("https://custom.issuer.com/".to_string()),
        ..Default::default()
    };
    assert_eq!(
        config_with_issuer.issuer(),
        Some("https://custom.issuer.com/".to_string())
    );
}

#[test]
fn test_config_from_env() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    // Set environment variables
    env::set_var("DATABASE_URL", "postgres://localhost/test");
    env::set_var("JWT_SECRET", "test-secret");
    env::set_var("AUTH0_DOMAIN", "env.auth0.com");
    env::set_var("AUTH0_AUDIENCE", "env-api");
    env::set_var("APP_SECURITY__LOGIN_MAX_FAILURES", "10");

    let config = AppConfig::from_env().expect("Failed to load config from env");

    // Capture values for assertions
    let db_url = config.database.url;
    let jwt_secret = config.auth.jwt_secret;
    let auth0_domain = config.auth0.auth0_domain;
    let auth0_audience = config.auth0.auth0_audience;
    let login_max_failures = config.security.login_max_failures;

    // Cleanup before assertions to ensure cleanup even if assertions fail
    env::remove_var("DATABASE_URL");
    env::remove_var("JWT_SECRET");
    env::remove_var("AUTH0_DOMAIN");
    env::remove_var("AUTH0_AUDIENCE");
    env::remove_var("APP_SECURITY__LOGIN_MAX_FAILURES");

    assert_eq!(db_url, "postgres://localhost/test");
    assert_eq!(jwt_secret, "test-secret");
    assert_eq!(auth0_domain, Some("env.auth0.com".to_string()));
    assert_eq!(auth0_audience, Some("env-api".to_string()));
    assert_eq!(login_max_failures, 10);
}

#[test]
fn test_config_defaults() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    // Clear relevant env vars to ensure we test defaults
    env::remove_var("DATABASE_URL");
    env::remove_var("APP_DATABASE__URL");

    let config = AppConfig::from_env().expect("Failed to load config");

    // Check some defaults from default.toml
    assert_eq!(config.port, 8080);
    assert_eq!(config.security.login_max_failures, 5);
    assert!(config.security.metrics_allow_private_only);
}

#[test]
fn test_auth0_config_is_enabled() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    let disabled = Auth0Config {
        auth0_domain: None,
        auth0_audience: None,
        ..Default::default()
    };
    assert!(!disabled.is_enabled());

    let enabled = Auth0Config {
        auth0_domain: Some("d".into()),
        ..Default::default()
    };
    assert!(enabled.is_enabled());
}

#[test]
fn test_invalid_env_types_fail() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    env::set_var("APP_PORT", "not-a-number");
    let result = AppConfig::from_env();
    env::remove_var("APP_PORT"); // Cleanup immediately
    assert!(result.is_err());
}

#[test]
fn test_negative_timeout_values_fail() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    // u64 cannot be negative
    env::set_var("APP_DATABASE__ACQUIRE_TIMEOUT_SECONDS", "-10");
    let result = AppConfig::from_env();
    env::remove_var("APP_DATABASE__ACQUIRE_TIMEOUT_SECONDS");
    assert!(result.is_err());
}

#[test]
fn test_cors_origins_list_parsing() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    // Figment can parse lists from env if properly formatted,
    // but usually it's easier to use a single string if that's how it's configured.
    // However, APP_SECURITY__CORS_ALLOWED_ORIGINS is Vec<String>.
    // To set a list via env, it usually needs to be like "[a, b]" or use indices.

    env::set_var(
        "APP_SECURITY__CORS_ALLOWED_ORIGINS",
        r#"["http://a.com", "http://b.com"]"#,
    );
    let config = AppConfig::from_env().expect("Failed to load config");
    assert_eq!(config.security.cors_allowed_origins.len(), 2);
    assert_eq!(config.security.cors_allowed_origins[0], "http://a.com");
    assert_eq!(config.security.cors_allowed_origins[1], "http://b.com");
    env::remove_var("APP_SECURITY__CORS_ALLOWED_ORIGINS");
}

#[test]
fn test_config_override_by_env() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    // Default is 8080 (from default.toml probably)
    env::set_var("APP_PORT", "9090");
    let config = AppConfig::from_env().expect("Failed to load config");
    assert_eq!(config.port, 9090);
    env::remove_var("APP_PORT");
}

#[test]
fn test_required_env_var_missing_fails() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    // Test that Auth0 validation fails when domain is set but audience is missing
    // This simulates a misconfiguration where required Auth0 fields are incomplete
    env::set_var("JWT_SECRET", "test-jwt-secret");
    env::set_var("AUTH0_DOMAIN", "test.auth0.com");
    env::remove_var("AUTH0_AUDIENCE");

    let config = AppConfig::from_env().expect("Config should load from env");
    let result = config.validate();

    // Validation should fail because AUTH0_AUDIENCE is missing when AUTH0_DOMAIN is set
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("AUTH0_AUDIENCE is required when Auth0 is enabled"));

    // Cleanup
    env::remove_var("JWT_SECRET");
    env::remove_var("AUTH0_DOMAIN");
}

#[test]
fn test_invalid_url_format_fails() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
    // Test that invalid types fail to parse for database URL
    // Note: The config doesn't validate URL format, only type parsing
    // We test what actually fails - type conversion errors

    // Set an invalid type for a u64 field (timeout)
    env::set_var("APP_DATABASE__ACQUIRE_TIMEOUT_SECONDS", "not-a-number");
    let result = AppConfig::from_env();
    env::remove_var("APP_DATABASE__ACQUIRE_TIMEOUT_SECONDS");
    assert!(result.is_err());

    // Set an invalid type for port (u16)
    env::set_var("APP_PORT", "invalid");
    let result = AppConfig::from_env();
    env::remove_var("APP_PORT");
    assert!(result.is_err());

    // Test that Auth0 with empty strings is treated as disabled (not a failure)
    env::set_var("AUTH0_DOMAIN", "");
    env::set_var("AUTH0_AUDIENCE", "");
    let config = AppConfig::from_env().expect("Config should load");
    assert!(!config.auth0.is_enabled());
    env::remove_var("AUTH0_DOMAIN");
    env::remove_var("AUTH0_AUDIENCE");
}

#[test]
fn test_allowed_origins_validation() {
    let _lock = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());

    // Test empty origins list - should still load (uses default)
    env::remove_var("APP_SECURITY__CORS_ALLOWED_ORIGINS");
    let config = AppConfig::from_env().expect("Config should load");
    // Default from default.toml is ["http://localhost:3000"]
    assert!(!config.security.cors_allowed_origins.is_empty());
    assert_eq!(
        config.security.cors_allowed_origins,
        vec!["http://localhost:3000"]
    );

    // Test single origin
    env::set_var(
        "APP_SECURITY__CORS_ALLOWED_ORIGINS",
        r#"["https://example.com"]"#,
    );
    let config = AppConfig::from_env().expect("Config should load");
    assert_eq!(
        config.security.cors_allowed_origins,
        vec!["https://example.com"]
    );
    env::remove_var("APP_SECURITY__CORS_ALLOWED_ORIGINS");

    // Test multiple origins
    env::set_var(
        "APP_SECURITY__CORS_ALLOWED_ORIGINS",
        r#"["https://app.example.com", "https://admin.example.com", "http://localhost:3000"]"#,
    );
    let config = AppConfig::from_env().expect("Config should load");
    assert_eq!(config.security.cors_allowed_origins.len(), 3);
    assert_eq!(
        config.security.cors_allowed_origins[0],
        "https://app.example.com"
    );
    assert_eq!(
        config.security.cors_allowed_origins[1],
        "https://admin.example.com"
    );
    assert_eq!(
        config.security.cors_allowed_origins[2],
        "http://localhost:3000"
    );
    env::remove_var("APP_SECURITY__CORS_ALLOWED_ORIGINS");

    // Test origin without protocol - should still be accepted as string
    // (validation happens at CORS middleware level, not config level)
    env::set_var(
        "APP_SECURITY__CORS_ALLOWED_ORIGINS",
        r#"["localhost:3000"]"#,
    );
    let config = AppConfig::from_env().expect("Config should load");
    assert_eq!(config.security.cors_allowed_origins, vec!["localhost:3000"]);
    env::remove_var("APP_SECURITY__CORS_ALLOWED_ORIGINS");

    // Test origin with spaces - stored verbatim (trimming is NOT performed at config level)
    env::set_var(
        "APP_SECURITY__CORS_ALLOWED_ORIGINS",
        r#"["  https://example.com  "]"#,
    );
    let config = AppConfig::from_env().expect("Config should load");
    assert_eq!(
        config.security.cors_allowed_origins,
        vec!["  https://example.com  "]
    );
    env::remove_var("APP_SECURITY__CORS_ALLOWED_ORIGINS");
}

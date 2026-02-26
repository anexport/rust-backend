use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Auth0 configuration is incomplete: {0}")]
    Auth0Config(String),
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_environment")]
    pub environment: String,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub auth0: Auth0Config,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub sentry: SentryConfig,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    #[serde(default = "default_db_acquire_timeout_seconds")]
    pub acquire_timeout_seconds: u64,
    #[serde(default = "default_db_idle_timeout_seconds")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_db_max_lifetime_seconds")]
    pub max_lifetime_seconds: u64,
    #[serde(default = "default_db_test_before_acquire")]
    pub test_before_acquire: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    #[serde(default = "default_jwt_kid")]
    pub jwt_kid: String,
    #[serde(default)]
    pub previous_jwt_secrets: Vec<String>,
    #[serde(default)]
    pub previous_jwt_kids: Vec<String>,
    pub jwt_expiration_seconds: u64,
    pub refresh_token_expiration_days: u64,
    pub issuer: String,
    pub audience: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Auth0Config {
    pub auth0_domain: Option<String>,
    pub auth0_audience: Option<String>,
    pub auth0_issuer: Option<String>,
    #[serde(default = "default_jwks_cache_ttl_secs")]
    pub jwks_cache_ttl_secs: u64,
    #[serde(default)]
    pub auth0_client_id: Option<String>,
    #[serde(default)]
    pub auth0_client_secret: Option<String>,
    #[serde(default = "default_auth0_connection")]
    pub auth0_connection: String,
}

impl Auth0Config {
    fn non_empty(value: Option<&str>) -> Option<&str> {
        value.and_then(|v| {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
    }

    pub fn is_enabled(&self) -> bool {
        Self::non_empty(self.auth0_domain.as_deref()).is_some()
            || Self::non_empty(self.auth0_audience.as_deref()).is_some()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.is_enabled() {
            return Ok(());
        }

        if Self::non_empty(self.auth0_domain.as_deref()).is_none() {
            return Err(ConfigError::Auth0Config(
                "AUTH0_DOMAIN is required when Auth0 is enabled".to_string(),
            ));
        }

        if Self::non_empty(self.auth0_audience.as_deref()).is_none() {
            return Err(ConfigError::Auth0Config(
                "AUTH0_AUDIENCE is required when Auth0 is enabled".to_string(),
            ));
        }

        Ok(())
    }

    pub fn issuer(&self) -> Option<String> {
        Self::non_empty(self.auth0_issuer.as_deref())
            .map(|issuer| issuer.to_string())
            .or_else(|| {
                Self::non_empty(self.auth0_domain.as_deref())
                    .map(|domain| format!("https://{}/", domain))
            })
    }
}

fn default_jwks_cache_ttl_secs() -> u64 {
    3600
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(default = "default_cors_allowed_origins")]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default = "default_metrics_allow_private_only")]
    pub metrics_allow_private_only: bool,
    #[serde(default)]
    pub metrics_admin_token: Option<String>,
    #[serde(default = "default_login_max_failures")]
    pub login_max_failures: u32,
    #[serde(default = "default_login_lockout_seconds")]
    pub login_lockout_seconds: u64,
    #[serde(default = "default_login_backoff_base_ms")]
    pub login_backoff_base_ms: u64,
    // Global rate limiting configuration
    #[serde(default = "default_global_rate_limit_per_minute")]
    pub global_rate_limit_per_minute: u32,
    #[serde(default = "default_global_rate_limit_burst_size")]
    pub global_rate_limit_burst_size: u32,
    #[serde(default = "default_global_rate_limit_authenticated_per_minute")]
    pub global_rate_limit_authenticated_per_minute: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub json_format: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SentryConfig {
    #[serde(default)]
    pub dsn: Option<String>,
}

impl SentryConfig {
    pub fn is_enabled(&self) -> bool {
        self.dsn
            .as_ref()
            .map(|d| !d.trim().is_empty())
            .unwrap_or(false)
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self, Box<figment::Error>> {
        let mut config: Self = Figment::new()
            .merge(Toml::file("config/default.toml"))
            .merge(Toml::file("config/development.toml").nested())
            .merge(Env::prefixed("APP_").split("__"))
            .merge(Env::prefixed("DATABASE_").split("__"))
            .merge(Env::prefixed("AUTH_").split("__"))
            .merge(Env::prefixed("AUTH0_").split("__"))
            .merge(Env::prefixed("SECURITY_").split("__"))
            .merge(Env::prefixed("LOGGING_").split("__"))
            .merge(Env::prefixed("SENTRY_").split("__"))
            .merge(
                Env::raw()
                    .only(&[
                        "DATABASE_URL",
                        "JWT_SECRET",
                        "AUTH0_DOMAIN",
                        "AUTH0_AUDIENCE",
                        "AUTH0_ISSUER",
                        "AUTH0_JWKS_CACHE_TTL_SECS",
                        "AUTH0_CLIENT_ID",
                        "AUTH0_CONNECTION",
                        "AUTH0_CLIENT_SECRET",
                    ])
                    .map(|key| match key.as_str() {
                        "DATABASE_URL" => "database.url".into(),
                        "JWT_SECRET" => "auth.jwt_secret".into(),
                        "AUTH0_DOMAIN" => "auth0.auth0_domain".into(),
                        "AUTH0_AUDIENCE" => "auth0.auth0_audience".into(),
                        "AUTH0_ISSUER" => "auth0.auth0_issuer".into(),
                        "AUTH0_JWKS_CACHE_TTL_SECS" => "auth0.jwks_cache_ttl_secs".into(),
                        "AUTH0_CLIENT_ID" => "auth0.auth0_client_id".into(),
                        "AUTH0_CONNECTION" => "auth0.auth0_connection".into(),
                        "AUTH0_CLIENT_SECRET" => "auth0.auth0_client_secret".into(),
                        "SENTRY_DSN" => "sentry.dsn".into(),
                        _ => key.into(),
                    }),
            )
            .extract()
            .map_err(Box::new)?;

        config.auth0.auth0_domain = normalize_optional_string(config.auth0.auth0_domain);
        config.auth0.auth0_audience = normalize_optional_string(config.auth0.auth0_audience);
        config.auth0.auth0_issuer = normalize_optional_string(config.auth0.auth0_issuer);
        config.auth0.auth0_client_id = normalize_optional_string(config.auth0.auth0_client_id);
        config.auth0.auth0_client_secret =
            normalize_optional_string(config.auth0.auth0_client_secret);
        config.sentry.dsn = normalize_optional_string(config.sentry.dsn);
        if config.auth0.auth0_connection.trim().is_empty() {
            config.auth0.auth0_connection = default_auth0_connection();
        }

        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate JWT_SECRET is set and not a placeholder
        let jwt_secret = self.auth.jwt_secret.trim();
        if jwt_secret.is_empty() {
            return Err(ConfigError::Auth0Config(
                "JWT_SECRET must be set via environment variable".to_string(),
            ));
        }

        // Reject the insecure default placeholder (trim to catch spaces around it)
        if jwt_secret == "change-me-in-production" {
            return Err(ConfigError::Auth0Config(
                "JWT_SECRET must be set to a secure value, not the default placeholder".to_string(),
            ));
        }

        self.auth0.validate()
    }
}

fn default_jwt_kid() -> String {
    "v1".to_string()
}

fn default_cors_allowed_origins() -> Vec<String> {
    vec!["http://localhost:3000".to_string()]
}

fn default_metrics_allow_private_only() -> bool {
    true
}

fn default_login_max_failures() -> u32 {
    5
}

fn default_login_lockout_seconds() -> u64 {
    300
}

fn default_login_backoff_base_ms() -> u64 {
    200
}

fn default_environment() -> String {
    "development".to_string()
}

fn default_db_acquire_timeout_seconds() -> u64 {
    10
}

fn default_db_idle_timeout_seconds() -> u64 {
    600
}

fn default_db_max_lifetime_seconds() -> u64 {
    1800
}

fn default_db_test_before_acquire() -> bool {
    true
}

fn default_auth0_connection() -> String {
    "Username-Password-Authentication".to_string()
}

fn default_global_rate_limit_per_minute() -> u32 {
    300 // 300 requests per minute for anonymous users
}

fn default_global_rate_limit_burst_size() -> u32 {
    30 // Allow burst of up to 30 requests
}

fn default_global_rate_limit_authenticated_per_minute() -> u32 {
    1000 // 1000 requests per minute for authenticated users (higher limit)
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{Auth0Config, ConfigError};

    #[test]
    fn validate_succeeds_when_auth0_disabled() {
        let config = Auth0Config::default();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_succeeds_when_domain_and_audience_present() {
        let config = Auth0Config {
            auth0_domain: Some("tenant.auth0.com".to_string()),
            auth0_audience: Some("api://audience".to_string()),
            ..Default::default()
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_fails_when_domain_missing_and_auth0_enabled() {
        let config = Auth0Config {
            auth0_domain: None,
            auth0_audience: Some("api://audience".to_string()),
            ..Default::default()
        };

        let result = config.validate();

        assert!(matches!(
            result,
            Err(ConfigError::Auth0Config(msg))
            if msg == "AUTH0_DOMAIN is required when Auth0 is enabled"
        ));
    }

    #[test]
    fn validate_fails_when_audience_missing_and_auth0_enabled() {
        let config = Auth0Config {
            auth0_domain: Some("tenant.auth0.com".to_string()),
            auth0_audience: None,
            ..Default::default()
        };

        let result = config.validate();

        assert!(matches!(
            result,
            Err(ConfigError::Auth0Config(msg))
            if msg == "AUTH0_AUDIENCE is required when Auth0 is enabled"
        ));
    }

    #[test]
    fn is_enabled_is_true_when_domain_or_audience_is_set() {
        let domain_only = Auth0Config {
            auth0_domain: Some("tenant.auth0.com".to_string()),
            auth0_audience: None,
            ..Default::default()
        };
        let audience_only = Auth0Config {
            auth0_domain: None,
            auth0_audience: Some("api://audience".to_string()),
            ..Default::default()
        };
        let disabled = Auth0Config::default();

        assert!(domain_only.is_enabled());
        assert!(audience_only.is_enabled());
        assert!(!disabled.is_enabled());
    }

    #[test]
    fn issuer_prefers_explicit_then_falls_back_to_domain_then_none() {
        let explicit_issuer = Auth0Config {
            auth0_domain: Some("tenant.auth0.com".to_string()),
            auth0_audience: Some("api://audience".to_string()),
            auth0_issuer: Some("https://custom-issuer.example.com/".to_string()),
            ..Default::default()
        };
        let domain_fallback = Auth0Config {
            auth0_domain: Some("tenant.auth0.com".to_string()),
            auth0_audience: Some("api://audience".to_string()),
            auth0_issuer: None,
            ..Default::default()
        };
        let no_issuer_or_domain = Auth0Config::default();

        assert_eq!(
            explicit_issuer.issuer(),
            Some("https://custom-issuer.example.com/".to_string())
        );
        assert_eq!(
            domain_fallback.issuer(),
            Some("https://tenant.auth0.com/".to_string())
        );
        assert_eq!(no_issuer_or_domain.issuer(), None);
    }

    #[test]
    fn empty_auth0_strings_are_treated_as_disabled() {
        let config = Auth0Config {
            auth0_domain: Some(String::new()),
            auth0_audience: Some(String::new()),
            auth0_issuer: Some(String::new()),
            ..Default::default()
        };

        assert!(!config.is_enabled());
        assert_eq!(config.issuer(), None);
    }

    #[test]
    fn validate_fails_when_domain_or_audience_are_blank() {
        let missing_domain = Auth0Config {
            auth0_domain: Some("   ".to_string()),
            auth0_audience: Some("api://audience".to_string()),
            ..Default::default()
        };
        let missing_audience = Auth0Config {
            auth0_domain: Some("tenant.auth0.com".to_string()),
            auth0_audience: Some(String::new()),
            ..Default::default()
        };

        assert!(matches!(
            missing_domain.validate(),
            Err(ConfigError::Auth0Config(msg))
            if msg == "AUTH0_DOMAIN is required when Auth0 is enabled"
        ));
        assert!(matches!(
            missing_audience.validate(),
            Err(ConfigError::Auth0Config(msg))
            if msg == "AUTH0_AUDIENCE is required when Auth0 is enabled"
        ));
    }
}

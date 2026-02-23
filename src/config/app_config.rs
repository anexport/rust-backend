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
    pub app: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub auth0: Auth0Config,
    pub security: SecurityConfig,
    pub oauth: OAuthConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_environment")]
    pub environment: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
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
    pub fn is_enabled(&self) -> bool {
        self.auth0_domain.is_some() || self.auth0_audience.is_some()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.is_enabled() {
            return Ok(());
        }

        if self.auth0_domain.is_none() {
            return Err(ConfigError::Auth0Config(
                "AUTH0_DOMAIN is required when Auth0 is enabled".to_string(),
            ));
        }

        if self.auth0_audience.is_none() {
            return Err(ConfigError::Auth0Config(
                "AUTH0_AUDIENCE is required when Auth0 is enabled".to_string(),
            ));
        }

        Ok(())
    }

    pub fn issuer(&self) -> Option<String> {
        if let Some(ref issuer) = self.auth0_issuer {
            Some(issuer.clone())
        } else if let Some(ref domain) = self.auth0_domain {
            Some(format!("https://{}/", domain))
        } else {
            None
        }
    }
}

fn default_jwks_cache_ttl_secs() -> u64 {
    3600
}

#[derive(Debug, Deserialize, Clone)]
pub struct OAuthConfig {
    pub google_client_id: String,
    pub google_client_secret: String,
    pub github_client_id: String,
    pub github_client_secret: String,
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
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub json_format: bool,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, Box<figment::Error>> {
        Figment::new()
            .merge(Toml::file("config/default.toml"))
            .merge(Toml::file("config/development.toml").nested())
            .merge(Env::prefixed("APP_").split("__"))
            .merge(Env::prefixed("DATABASE_").split("__"))
            .merge(Env::prefixed("AUTH_").split("__"))
            .merge(Env::prefixed("AUTH0_").split("__"))
            .merge(Env::prefixed("SECURITY_").split("__"))
            .merge(Env::prefixed("OAUTH_").split("__"))
            .merge(Env::prefixed("LOGGING_").split("__"))
            .merge(
                Env::raw()
                    .only(&["database.url"])
                    .map(|_| "DATABASE_URL".into()),
            )
            .merge(
                Env::raw()
                    .only(&["auth.jwt_secret"])
                    .map(|_| "JWT_SECRET".into()),
            )
            .merge(
                Env::raw()
                    .only(&["auth0.auth0_domain"])
                    .map(|_| "AUTH0_DOMAIN".into()),
            )
            .merge(
                Env::raw()
                    .only(&["auth0.auth0_audience"])
                    .map(|_| "AUTH0_AUDIENCE".into()),
            )
            .merge(
                Env::raw()
                    .only(&["auth0.auth0_issuer"])
                    .map(|_| "AUTH0_ISSUER".into()),
            )
            .merge(
                Env::raw()
                    .only(&["auth0.jwks_cache_ttl_secs"])
                    .map(|_| "AUTH0_JWKS_CACHE_TTL_SECS".into()),
            )
            .merge(
                Env::raw()
                    .only(&["auth0.auth0_client_id"])
                    .map(|_| "AUTH0_CLIENT_ID".into()),
            )
            .merge(
                Env::raw()
                    .only(&["auth0.auth0_connection"])
                    .map(|_| "AUTH0_CONNECTION".into()),
            )
            .merge(
                Env::raw()
                    .only(&["auth0.auth0_client_secret"])
                    .map(|_| "AUTH0_CLIENT_SECRET".into()),
            )
            .extract()
            .map_err(Box::new)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
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

fn default_auth0_connection() -> String {
    "Username-Password-Authentication".to_string()
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
}

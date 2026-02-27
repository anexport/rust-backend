pub mod auth0_config;
pub mod database_config;
pub mod defaults;
pub mod security_config;

use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::Deserialize;

pub use auth0_config::{Auth0Config, AuthConfig, ConfigError};
pub use database_config::DatabaseConfig;
pub use security_config::SecurityConfig;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    #[serde(default = "defaults::default_host")]
    pub host: String,
    #[serde(default = "defaults::default_port")]
    pub port: u16,
    #[serde(default = "defaults::default_environment")]
    pub environment: String,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub auth0: Auth0Config,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub sentry: SentryConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "defaults::default_logging_level")]
    pub level: String,
    #[serde(default = "defaults::default_logging_json_format")]
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
                        "SENTRY_DSN",
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

        config.auth0.auth0_domain = defaults::normalize_optional_string(config.auth0.auth0_domain);
        config.auth0.auth0_audience =
            defaults::normalize_optional_string(config.auth0.auth0_audience);
        config.auth0.auth0_issuer = defaults::normalize_optional_string(config.auth0.auth0_issuer);
        config.auth0.auth0_client_id =
            defaults::normalize_optional_string(config.auth0.auth0_client_id);
        config.auth0.auth0_client_secret =
            defaults::normalize_optional_string(config.auth0.auth0_client_secret);
        config.sentry.dsn = defaults::normalize_optional_string(config.sentry.dsn);
        if config.auth0.auth0_connection.trim().is_empty() {
            config.auth0.auth0_connection = defaults::default_auth0_connection();
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

use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub app: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub security: SecurityConfig,
    pub oauth: OAuthConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
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
            .extract()
            .map_err(Box::new)
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

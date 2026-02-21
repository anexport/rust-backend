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

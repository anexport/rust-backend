use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Auth0 configuration is incomplete: {0}")]
    Auth0Config(String),
}

#[derive(Deserialize, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    #[serde(default = "crate::config::defaults::default_jwt_kid")]
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

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("jwt_secret", &"[REDACTED]")
            .field("jwt_kid", &self.jwt_kid)
            .field("previous_jwt_secrets", &"[REDACTED]")
            .field("previous_jwt_kids", &self.previous_jwt_kids)
            .field("jwt_expiration_seconds", &self.jwt_expiration_seconds)
            .field(
                "refresh_token_expiration_days",
                &self.refresh_token_expiration_days,
            )
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

#[derive(Deserialize, Clone)]
pub struct Auth0Config {
    pub auth0_domain: Option<String>,
    pub auth0_audience: Option<String>,
    pub auth0_issuer: Option<String>,
    #[serde(default = "crate::config::defaults::default_jwks_cache_ttl_secs")]
    pub jwks_cache_ttl_secs: u64,
    pub auth0_client_id: Option<String>,
    pub auth0_client_secret: Option<String>,
    pub auth0_connection: String,
}

impl std::fmt::Debug for Auth0Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth0Config")
            .field("auth0_domain", &self.auth0_domain)
            .field("auth0_audience", &self.auth0_audience)
            .field("auth0_issuer", &self.auth0_issuer)
            .field("jwks_cache_ttl_secs", &self.jwks_cache_ttl_secs)
            .field("auth0_client_id", &self.auth0_client_id)
            .field(
                "auth0_client_secret",
                &self.auth0_client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("auth0_connection", &self.auth0_connection)
            .finish()
    }
}

impl Default for Auth0Config {
    fn default() -> Self {
        Self {
            auth0_domain: None,
            auth0_audience: None,
            auth0_issuer: None,
            jwks_cache_ttl_secs: crate::config::defaults::default_jwks_cache_ttl_secs(),
            auth0_client_id: None,
            auth0_client_secret: None,
            auth0_connection: crate::config::defaults::default_auth0_connection(),
        }
    }
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

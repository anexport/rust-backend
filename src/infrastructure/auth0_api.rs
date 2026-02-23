use async_trait::async_trait;
use reqwest::{Client, header::{CONTENT_TYPE, ACCEPT}};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::config::Auth0Config;
use crate::error::{AppError, AppResult};

/// Response from Auth0 signup endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth0SignupResponse {
    #[serde(rename = "_id")]
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
    pub picture: Option<String>,
    pub name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Response from Auth0 token endpoint for password grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth0TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Option<String>,
}

/// Error response from Auth0 API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth0ErrorResponse {
    pub code: String,
    pub description: String,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub error_description: String,
    #[serde(default)]
    pub name: String,
}

impl Auth0ErrorResponse {
    /// Maps Auth0 error codes to AppError variants
    pub fn to_app_error(&self) -> AppError {
        match self.code.as_str() {
            "auth_id_already_exists"
            | "user_exists"
            | "email_already_exists" => AppError::Conflict(self.description.clone()),

            "invalid_password"
            | "password_not_strong_enough"
            | "password_same_as_email"
            | "password_too_common" => AppError::BadRequest(self.description.clone()),

            "invalid_grant"
            | "invalid_user_password"
            | "wrong_email_or_password" => AppError::Unauthorized,

            "invalid_signup"
            | "bad_request" => AppError::BadRequest(self.description.clone()),

            "access_denied"
            | "unauthorized" => AppError::Unauthorized,

            _ => {
                error!(
                    code = %self.code,
                    description = %self.description,
                    "Unexpected Auth0 error"
                );
                AppError::InternalError(anyhow::anyhow!(
                    "Auth0 error: {} - {}",
                    self.code,
                    self.description
                ))
            }
        }
    }
}

/// Request body for Auth0 signup
#[derive(Debug, Serialize)]
struct Auth0SignupRequest {
    email: String,
    password: String,
    connection: String,
    username: Option<String>,
    user_metadata: Option<serde_json::Value>,
}

/// Request body for Auth0 password grant (login)
#[derive(Debug, Serialize)]
struct Auth0PasswordGrantRequest {
    grant_type: String,
    username: String,
    password: String,
    client_id: String,
    client_secret: String,
    audience: String,
}

/// Trait for Auth0 API operations
#[async_trait]
pub trait Auth0ApiClient: Send + Sync {
    /// Register a new user with email/password
    async fn signup(
        &self,
        email: &str,
        password: &str,
        username: Option<&str>,
    ) -> AppResult<Auth0SignupResponse>;

    /// Authenticate a user with email/password using password grant
    async fn password_grant(
        &self,
        email: &str,
        password: &str,
    ) -> AppResult<Auth0TokenResponse>;
}

/// HTTP-based Auth0 API client
pub struct HttpAuth0ApiClient {
    config: Auth0Config,
    client: Client,
}

impl HttpAuth0ApiClient {
    /// Create a new Auth0 API client
    ///
    /// Requires the following config fields:
    /// - auth0_domain: Auth0 tenant domain (e.g., "tenant.auth0.com")
    /// - auth0_audience: API audience
    ///
    /// Client credentials must also be available in config:
    /// - auth0_client_id: Auth0 Application Client ID
    /// - auth0_client_secret: Auth0 Application Client Secret
    pub fn new(config: Auth0Config) -> AppResult<Self> {
        if config.auth0_domain.is_none() {
            return Err(AppError::InternalError(anyhow::anyhow!(
                "Auth0 domain not configured"
            )));
        }

        Ok(Self {
            config,
            client: Client::new(),
        })
    }

    fn domain(&self) -> &str {
        self.config
            .auth0_domain
            .as_deref()
            .expect("domain checked in constructor")
    }

    fn audience(&self) -> &str {
        self.config
            .auth0_audience
            .as_deref()
            .unwrap_or("")
    }

    fn signup_url(&self) -> String {
        format!("https://{}/dbconnections/signup", self.domain())
    }

    fn oauth_token_url(&self) -> String {
        format!("https://{}/oauth/token", self.domain())
    }

    async fn handle_error(&self, response: reqwest::Response) -> AppError {
        let status = response.status();

        // Try to parse the error response
        let error_body = match response.json::<Auth0ErrorResponse>().await {
            Ok(err) => err.to_app_error(),
            Err(_) => {
                // If we can't parse the error, return a generic error
                error!(
                    status = %status,
                    "Auth0 API request failed with unparsable error"
                );
                AppError::InternalError(anyhow::anyhow!(
                    "Auth0 API request failed with status: {}",
                    status
                ))
            }
        };

        error_body
    }
}

#[async_trait]
impl Auth0ApiClient for HttpAuth0ApiClient {
    async fn signup(
        &self,
        email: &str,
        password: &str,
        username: Option<&str>,
    ) -> AppResult<Auth0SignupResponse> {
        let request = Auth0SignupRequest {
            email: email.to_string(),
            password: password.to_string(),
            connection: "Username-Password-Authentication".to_string(),
            username: username.map(|u| u.to_string()),
            user_metadata: None,
        };

        let response = self
            .client
            .post(&self.signup_url())
            .header(CONTENT_TYPE, "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!(
                    error = %e,
                    url = %self.signup_url(),
                    "Failed to send signup request to Auth0"
                );
                AppError::InternalError(anyhow::anyhow!("Failed to send signup request: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(self.handle_error(response).await);
        }

        response
            .json::<Auth0SignupResponse>()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to parse Auth0 signup response");
                AppError::InternalError(anyhow::anyhow!("Failed to parse signup response: {}", e))
            })
    }

    async fn password_grant(
        &self,
        email: &str,
        password: &str,
    ) -> AppResult<Auth0TokenResponse> {
        // For password grant, we need client credentials
        let client_id = std::env::var("AUTH0_CLIENT_ID")
            .map_err(|_| AppError::InternalError(anyhow::anyhow!("AUTH0_CLIENT_ID not configured")))?;
        let client_secret = std::env::var("AUTH0_CLIENT_SECRET").map_err(|_| {
            AppError::InternalError(anyhow::anyhow!("AUTH0_CLIENT_SECRET not configured"))
        })?;

        let request = Auth0PasswordGrantRequest {
            grant_type: "password".to_string(),
            username: email.to_string(),
            password: password.to_string(),
            client_id,
            client_secret,
            audience: self.audience().to_string(),
        };

        let response = self
            .client
            .post(&self.oauth_token_url())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                error!(
                    error = %e,
                    url = %self.oauth_token_url(),
                    "Failed to send password grant request to Auth0"
                );
                AppError::InternalError(anyhow::anyhow!(
                    "Failed to send login request: {}",
                    e
                ))
            })?;

        if !response.status().is_success() {
            return Err(self.handle_error(response).await);
        }

        response
            .json::<Auth0TokenResponse>()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to parse Auth0 token response");
                AppError::InternalError(anyhow::anyhow!("Failed to parse token response: {}", e))
            })
    }
}

/// Disabled Auth0 API client for when Auth0 is not configured
pub struct DisabledAuth0ApiClient;

#[async_trait]
impl Auth0ApiClient for DisabledAuth0ApiClient {
    async fn signup(
        &self,
        _email: &str,
        _password: &str,
        _username: Option<&str>,
    ) -> AppResult<Auth0SignupResponse> {
        Err(AppError::ServiceUnavailable {
            service: "Auth0".to_string(),
            message: "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE.".to_string(),
        })
    }

    async fn password_grant(
        &self,
        _email: &str,
        _password: &str,
    ) -> AppResult<Auth0TokenResponse> {
        Err(AppError::ServiceUnavailable {
            service: "Auth0".to_string(),
            message: "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE.".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_user_exists_to_conflict() {
        let err = Auth0ErrorResponse {
            code: "user_exists".to_string(),
            description: "The user already exists.".to_string(),
            error: String::new(),
            error_description: String::new(),
            name: String::new(),
        };
        assert!(matches!(err.to_app_error(), AppError::Conflict(_)));
    }

    #[test]
    fn maps_invalid_password_to_bad_request() {
        let err = Auth0ErrorResponse {
            code: "invalid_password".to_string(),
            description: "Password is too weak.".to_string(),
            error: String::new(),
            error_description: String::new(),
            name: String::new(),
        };
        assert!(matches!(err.to_app_error(), AppError::BadRequest(_)));
    }

    #[test]
    fn maps_invalid_grant_to_unauthorized() {
        let err = Auth0ErrorResponse {
            code: "invalid_grant".to_string(),
            description: "Wrong email or password.".to_string(),
            error: String::new(),
            error_description: String::new(),
            name: String::new(),
        };
        assert!(matches!(err.to_app_error(), AppError::Unauthorized));
    }

    #[test]
    fn maps_unknown_error_to_internal_error() {
        let err = Auth0ErrorResponse {
            code: "unknown_error".to_string(),
            description: "Something went wrong.".to_string(),
            error: String::new(),
            error_description: String::new(),
            name: String::new(),
        };
        assert!(matches!(err.to_app_error(), AppError::InternalError(_)));
    }
}

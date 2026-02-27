use async_trait::async_trait;
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};
use tracing::error;

use crate::config::Auth0Config;
use crate::error::{AppError, AppResult};

use super::dtos::{Auth0ErrorResponse, Auth0SignupResponse, Auth0TokenResponse};
use super::requests::{Auth0PasswordGrantRequest, Auth0SignupRequest};
use super::traits::Auth0ApiClient;

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

    pub(crate) fn domain(&self) -> &str {
        self.config
            .auth0_domain
            .as_deref()
            .expect("domain checked in constructor")
    }

    pub(crate) fn signup_url(&self) -> String {
        format!("https://{}/dbconnections/signup", self.domain())
    }

    pub(crate) fn oauth_token_url(&self) -> String {
        format!("https://{}/oauth/token", self.domain())
    }

    pub(crate) async fn handle_error(&self, response: reqwest::Response) -> AppError {
        let status = response.status();

        // Try to parse the error response
        let error_body = match response.json::<Auth0ErrorResponse>().await {
            Ok(err) => {
                let description = err.description_or_error_description().to_string();

                // Log full Auth0 error details server-side for debugging
                error!(
                    status = %status,
                    code = %err.code_or_error(),
                    description = %description,
                    "Auth0 API error response"
                );

                // Map to generic error messages to avoid info leak
                err.to_app_error()
            }
            Err(_) => {
                // If we can't parse the error, return a generic error
                error!(
                    status = %status,
                    "Auth0 API request failed with unparsable error"
                );
                match status.as_u16() {
                    401 | 403 => AppError::Unauthorized,
                    409 => AppError::Conflict("Resource already exists".to_string()),
                    429 => AppError::RateLimited,
                    500..=599 => AppError::ServiceUnavailable {
                        service: "Auth0".to_string(),
                        message: "Authentication service temporarily unavailable".to_string(),
                    },
                    _ => AppError::BadRequest("Invalid request".to_string()),
                }
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
        let client_id =
            self.config
                .auth0_client_id
                .clone()
                .ok_or_else(|| AppError::ServiceUnavailable {
                    service: "Auth0".to_string(),
                    message: "AUTH0_CLIENT_ID is not configured".to_string(),
                })?;

        let request = Auth0SignupRequest {
            client_id,
            email: email.to_string(),
            password: password.to_string(),
            connection: self.config.auth0_connection.clone(),
            username: username.map(|u| u.to_string()),
            user_metadata: None,
        };

        let response = self
            .client
            .post(self.signup_url())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
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

        response.json::<Auth0SignupResponse>().await.map_err(|e| {
            error!(error = %e, "Failed to parse Auth0 signup response");
            AppError::InternalError(anyhow::anyhow!("Failed to parse signup response: {}", e))
        })
    }

    async fn password_grant(&self, email: &str, password: &str) -> AppResult<Auth0TokenResponse> {
        // For password grant, we need client credentials
        let client_id = self.config.auth0_client_id.clone().ok_or_else(|| {
            AppError::InternalError(anyhow::anyhow!("AUTH0_CLIENT_ID not configured"))
        })?;
        let client_secret = self.config.auth0_client_secret.clone().ok_or_else(|| {
            AppError::InternalError(anyhow::anyhow!("AUTH0_CLIENT_SECRET not configured"))
        })?;

        let audience = self.config.auth0_audience.clone().filter(|s| !s.is_empty());

        let request = Auth0PasswordGrantRequest {
            grant_type: "password".to_string(),
            username: email.to_string(),
            password: password.to_string(),
            client_id,
            client_secret,
            audience,
        };

        let response = self
            .client
            .post(self.oauth_token_url())
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
                AppError::InternalError(anyhow::anyhow!("Failed to send login request: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(self.handle_error(response).await);
        }

        response.json::<Auth0TokenResponse>().await.map_err(|e| {
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
            message: "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE."
                .to_string(),
        })
    }

    async fn password_grant(&self, _email: &str, _password: &str) -> AppResult<Auth0TokenResponse> {
        Err(AppError::ServiceUnavailable {
            service: "Auth0".to_string(),
            message: "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE."
                .to_string(),
        })
    }
}

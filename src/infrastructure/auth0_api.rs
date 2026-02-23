use async_trait::async_trait;
use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};
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
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
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
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub error_description: String,
    #[serde(default)]
    pub name: String,
}

impl Auth0ErrorResponse {
    fn code_or_error(&self) -> &str {
        if self.code.is_empty() {
            self.error.as_str()
        } else {
            self.code.as_str()
        }
    }

    fn description_or_error_description(&self) -> &str {
        if self.description.is_empty() {
            if self.error_description.is_empty() {
                "Auth0 request failed"
            } else {
                self.error_description.as_str()
            }
        } else {
            self.description.as_str()
        }
    }

    /// Maps Auth0 error codes to AppError variants
    pub fn to_app_error(&self) -> AppError {
        let code = self.code_or_error();
        let description = self.description_or_error_description();

        match code {
            "auth_id_already_exists" | "user_exists" | "email_already_exists" => {
                AppError::Conflict(description.to_string())
            }

            "invalid_password"
            | "password_not_strong_enough"
            | "password_same_as_email"
            | "password_too_common" => AppError::BadRequest(description.to_string()),

            "invalid_grant" | "invalid_user_password" | "wrong_email_or_password" => {
                AppError::Unauthorized
            }

            "invalid_signup" | "bad_request" | "invalid_request" | "invalid_body" => {
                AppError::BadRequest(description.to_string())
            }

            "access_denied" | "unauthorized" => AppError::Unauthorized,

            _ => {
                error!(
                    code = %self.code,
                    description = %description,
                    "Unexpected Auth0 error"
                );
                AppError::InternalError(anyhow::anyhow!("Auth0 error: {} - {}", code, description))
            }
        }
    }
}

/// Request body for Auth0 signup
#[derive(Debug, Serialize)]
struct Auth0SignupRequest {
    client_id: String,
    email: String,
    password: String,
    connection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
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
    async fn password_grant(&self, email: &str, password: &str) -> AppResult<Auth0TokenResponse>;
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
            Ok(err) => {
                let description = err.description_or_error_description().to_string();
                let mapped = err.to_app_error();

                error!(
                    status = %status,
                    code = %err.code_or_error(),
                    description = %description,
                    "Auth0 API error response"
                );

                if matches!(mapped, AppError::InternalError(_)) {
                    match status.as_u16() {
                        400 => AppError::BadRequest(description),
                        401 | 403 => AppError::Unauthorized,
                        409 => AppError::Conflict(description),
                        429 => AppError::RateLimited,
                        500..=599 => AppError::ServiceUnavailable {
                            service: "Auth0".to_string(),
                            message: description,
                        },
                        _ => mapped,
                    }
                } else {
                    mapped
                }
            }
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
            .post(&self.signup_url())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Auth0Config;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn auth0_error(code: &str, description: &str) -> Auth0ErrorResponse {
        Auth0ErrorResponse {
            code: code.to_string(),
            description: description.to_string(),
            error: String::new(),
            error_description: String::new(),
            name: String::new(),
        }
    }

    fn client_with_domain(domain: &str) -> HttpAuth0ApiClient {
        HttpAuth0ApiClient::new(Auth0Config {
            auth0_domain: Some(domain.to_string()),
            ..Default::default()
        })
        .expect("client should construct with domain")
    }

    #[test]
    fn new_fails_without_domain() {
        let result = HttpAuth0ApiClient::new(Auth0Config {
            auth0_domain: None,
            ..Default::default()
        });

        assert!(matches!(result, Err(AppError::InternalError(_))));
    }

    #[test]
    fn builds_signup_and_token_urls_from_domain() {
        let client = client_with_domain("tenant.auth0.com");

        assert_eq!(
            client.signup_url(),
            "https://tenant.auth0.com/dbconnections/signup"
        );
        assert_eq!(
            client.oauth_token_url(),
            "https://tenant.auth0.com/oauth/token"
        );
    }

    #[test]
    fn maps_user_exists_to_conflict() {
        let err = auth0_error("user_exists", "The user already exists.");
        assert!(matches!(err.to_app_error(), AppError::Conflict(_)));
    }

    #[test]
    fn maps_invalid_password_to_bad_request() {
        let err = auth0_error("invalid_password", "Password is too weak.");
        assert!(matches!(err.to_app_error(), AppError::BadRequest(_)));
    }

    #[test]
    fn maps_invalid_grant_to_unauthorized() {
        let err = auth0_error("invalid_grant", "Wrong email or password.");
        assert!(matches!(err.to_app_error(), AppError::Unauthorized));
    }

    #[test]
    fn maps_auth_id_already_exists_to_conflict() {
        let err = auth0_error("auth_id_already_exists", "Account already exists.");
        assert!(matches!(err.to_app_error(), AppError::Conflict(_)));
    }

    #[test]
    fn maps_invalid_signup_to_bad_request() {
        let err = auth0_error("invalid_signup", "Invalid signup payload.");
        assert!(matches!(err.to_app_error(), AppError::BadRequest(_)));
    }

    #[test]
    fn maps_bad_request_to_bad_request() {
        let err = auth0_error("bad_request", "Bad request.");
        assert!(matches!(err.to_app_error(), AppError::BadRequest(_)));
    }

    #[test]
    fn maps_access_denied_to_unauthorized() {
        let err = auth0_error("access_denied", "Denied.");
        assert!(matches!(err.to_app_error(), AppError::Unauthorized));
    }

    #[test]
    fn maps_unknown_error_to_internal_error() {
        let err = auth0_error("unknown_error", "Something went wrong.");
        assert!(matches!(err.to_app_error(), AppError::InternalError(_)));
    }

    #[test]
    fn signup_response_parses_minimal_payload() {
        let payload = r#"{
            "_id":"auth0|123",
            "email":"user@example.com",
            "email_verified":false
        }"#;

        let parsed: Auth0SignupResponse =
            serde_json::from_str(payload).expect("minimal payload should deserialize");

        assert_eq!(parsed.id, "auth0|123");
        assert_eq!(parsed.email, "user@example.com");
        assert!(!parsed.email_verified);
    }

    #[tokio::test]
    async fn disabled_client_signup_returns_service_unavailable() {
        let client = DisabledAuth0ApiClient;

        let result = client.signup("user@example.com", "password", None).await;

        assert!(matches!(
            result,
            Err(AppError::ServiceUnavailable { service, message })
            if service == "Auth0"
                && message == "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE."
        ));
    }

    #[tokio::test]
    async fn disabled_client_password_grant_returns_service_unavailable() {
        let client = DisabledAuth0ApiClient;

        let result = client.password_grant("user@example.com", "password").await;

        assert!(matches!(
            result,
            Err(AppError::ServiceUnavailable { service, message })
            if service == "Auth0"
                && message == "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE."
        ));
    }

    #[tokio::test]
    async fn handle_error_returns_internal_error_for_unparsable_payload() {
        let client = client_with_domain("tenant.auth0.com");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("address should exist");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept should succeed");
            let mut buffer = [0_u8; 1024];
            let _ = socket.read(&mut buffer).await;
            socket
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\nnot-json",
                )
                .await
                .expect("response should write");
        });

        let response = reqwest::Client::new()
            .get(format!("http://{}/error", addr))
            .send()
            .await
            .expect("request should succeed");

        let result = client.handle_error(response).await;
        server.await.expect("server task should complete");

        assert!(matches!(result, AppError::InternalError(_)));
    }

    #[tokio::test]
    async fn handle_error_400_unknown_code_maps_to_bad_request() {
        let client = client_with_domain("tenant.auth0.com");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("address should exist");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept should succeed");
            let mut buffer = [0_u8; 1024];
            let _ = socket.read(&mut buffer).await;
            let payload =
                r#"{"code":"unknown_code","description":"Custom Auth0 validation failure"}"#;
            let response = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("response should write");
        });

        let response = reqwest::Client::new()
            .get(format!("http://{}/error", addr))
            .send()
            .await
            .expect("request should succeed");

        let result = client.handle_error(response).await;
        server.await.expect("server task should complete");

        assert!(matches!(
            result,
            AppError::BadRequest(message) if message == "Custom Auth0 validation failure"
        ));
    }
}

use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};

use super::dtos::{PasswordGrantResponse, SignupResponse};
use super::requests::{PasswordGrantRequest, SignupRequest};
use crate::config::Auth0Config;
use crate::error::{AppError, AppResult};

/// Auth0 API client for Database Connection operations.
///
/// Handles:
/// - POST /dbconnections/signup - Register new users
/// - POST /oauth/token (Password Grant) - Authenticate users
pub struct Auth0ApiClient {
    config: Auth0Config,
    client: Client,
}

impl Auth0ApiClient {
    /// Create a new Auth0 API client.
    ///
    /// # Arguments
    /// * `config` - Auth0 configuration containing domain, client_id, and connection
    pub fn new(config: Auth0Config) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    /// Get the connection name from config or use default.
    fn connection(&self) -> &str {
        &self.config.auth0_connection
    }

    /// Get the base URL for Auth0 API calls.
    fn base_url(&self) -> AppResult<String> {
        let domain =
            self.config
                .auth0_domain
                .as_ref()
                .ok_or_else(|| AppError::ServiceUnavailable {
                    service: "auth0".to_string(),
                    message: "AUTH0_DOMAIN is not configured".to_string(),
                })?;
        Ok(format!("https://{}", domain))
    }

    /// Register a new user with Auth0 Database Connection.
    ///
    /// # Arguments
    /// * `request` - Signup request containing email, password, and optional user data
    ///
    /// # Returns
    /// User information from Auth0 on success
    pub async fn signup(&self, request: SignupRequest) -> AppResult<SignupResponse> {
        let client_id =
            self.config
                .auth0_client_id
                .as_ref()
                .ok_or_else(|| AppError::ServiceUnavailable {
                    service: "auth0".to_string(),
                    message: "AUTH0_CLIENT_ID is not configured".to_string(),
                })?;

        let url = format!("{}/dbconnections/signup", self.base_url()?);

        // Use connection from request if provided, otherwise use config default
        let connection = request
            .connection
            .as_deref()
            .unwrap_or_else(|| self.connection());

        let mut payload = serde_json::json!({
            "client_id": client_id,
            "email": request.email,
            "password": request.password,
            "connection": connection,
        });

        if let Some(username) = request.username {
            payload["username"] = serde_json::Value::String(username);
        }

        if let Some(metadata) = request.user_metadata {
            payload["user_metadata"] = serde_json::to_value(metadata).map_err(|e| {
                AppError::InternalError(anyhow::anyhow!("Failed to serialize user_metadata: {}", e))
            })?;
        }

        if let Some(given_name) = request.given_name {
            payload["given_name"] = serde_json::Value::String(given_name);
        }

        if let Some(family_name) = request.family_name {
            payload["family_name"] = serde_json::Value::String(family_name);
        }

        if let Some(name) = request.name {
            payload["name"] = serde_json::Value::String(name);
        }

        let response = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::ServiceUnavailable {
                service: "auth0".to_string(),
                message: format!("Failed to connect to Auth0: {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            return match status.as_u16() {
                400 => Err(AppError::BadRequest(format!(
                    "Invalid signup request: {}",
                    error_text
                ))),
                409 => Err(AppError::Conflict("User already exists".to_string())),
                _ => Err(AppError::ServiceUnavailable {
                    service: "auth0".to_string(),
                    message: format!("Auth0 signup failed: {}", error_text),
                }),
            };
        }

        response
            .json()
            .await
            .map_err(|e| AppError::ServiceUnavailable {
                service: "auth0".to_string(),
                message: format!("Invalid response from Auth0: {}", e),
            })
    }

    /// Authenticate a user using the Password Grant flow.
    ///
    /// # Arguments
    /// * `request` - Password grant request containing username/email and password
    ///
    /// # Returns
    /// Token response containing access_token, id_token, refresh_token, etc.
    pub async fn password_grant(
        &self,
        request: PasswordGrantRequest,
    ) -> AppResult<PasswordGrantResponse> {
        let client_id =
            self.config
                .auth0_client_id
                .as_ref()
                .ok_or_else(|| AppError::ServiceUnavailable {
                    service: "auth0".to_string(),
                    message: "AUTH0_CLIENT_ID is not configured".to_string(),
                })?;

        let url = format!("{}/oauth/token", self.base_url()?);

        let mut payload = serde_json::json!({
            "client_id": client_id,
            "password": request.password,
            "grant_type": request.grant_type,
        });

        // Use username as the identifier (can be email or actual username)
        payload["username"] = serde_json::Value::String(request.username);

        if let Some(audience) = request.audience {
            payload["audience"] = serde_json::Value::String(audience);
        }

        if let Some(connection) = request.connection {
            payload["connection"] = serde_json::Value::String(connection);
        }

        let response = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::ServiceUnavailable {
                service: "auth0".to_string(),
                message: format!("Failed to connect to Auth0: {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            return match status.as_u16() {
                401 => Err(AppError::Unauthorized),
                403 => Err(AppError::Forbidden("Invalid credentials".to_string())),
                400 => Err(AppError::BadRequest(format!(
                    "Invalid authentication request: {}",
                    error_text
                ))),
                _ => Err(AppError::ServiceUnavailable {
                    service: "auth0".to_string(),
                    message: format!("Auth0 authentication failed: {}", error_text),
                }),
            };
        }

        response
            .json()
            .await
            .map_err(|e| AppError::ServiceUnavailable {
                service: "auth0".to_string(),
                message: format!("Invalid response from Auth0: {}", e),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Auth0Config;
    use crate::error::AppError;

    #[tokio::test]
    async fn test_signup_fails_when_client_id_missing_before_network_call() {
        let client = Auth0ApiClient::new(Auth0Config {
            auth0_domain: Some("example.auth0.com".to_string()),
            auth0_client_id: None,
            ..Default::default()
        });

        let result = client
            .signup(SignupRequest::new(
                "test@example.com".to_string(),
                "password123".to_string(),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AppError::ServiceUnavailable { service, message })
            if service == "auth0" && message == "AUTH0_CLIENT_ID is not configured"
        ));
    }

    #[tokio::test]
    async fn test_signup_fails_when_domain_missing_before_network_call() {
        let client = Auth0ApiClient::new(Auth0Config {
            auth0_domain: None,
            auth0_client_id: Some("client-id".to_string()),
            ..Default::default()
        });

        let result = client
            .signup(SignupRequest::new(
                "test@example.com".to_string(),
                "password123".to_string(),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AppError::ServiceUnavailable { service, message })
            if service == "auth0" && message == "AUTH0_DOMAIN is not configured"
        ));
    }

    #[tokio::test]
    async fn test_password_grant_fails_when_client_id_missing_before_network_call() {
        let client = Auth0ApiClient::new(Auth0Config {
            auth0_domain: Some("example.auth0.com".to_string()),
            auth0_client_id: None,
            ..Default::default()
        });

        let result = client
            .password_grant(PasswordGrantRequest::new(
                "test@example.com".to_string(),
                "password123".to_string(),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AppError::ServiceUnavailable { service, message })
            if service == "auth0" && message == "AUTH0_CLIENT_ID is not configured"
        ));
    }

    #[tokio::test]
    async fn test_password_grant_fails_when_domain_missing_before_network_call() {
        let client = Auth0ApiClient::new(Auth0Config {
            auth0_domain: None,
            auth0_client_id: Some("client-id".to_string()),
            ..Default::default()
        });

        let result = client
            .password_grant(PasswordGrantRequest::new(
                "test@example.com".to_string(),
                "password123".to_string(),
            ))
            .await;

        assert!(matches!(
            result,
            Err(AppError::ServiceUnavailable { service, message })
            if service == "auth0" && message == "AUTH0_DOMAIN is not configured"
        ));
    }
}

use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};
use serde::{Deserialize, Serialize};

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

/// Request body for POST /dbconnections/signup
#[derive(Debug, Serialize, Clone)]
pub struct SignupRequest {
    /// User's email address
    pub email: String,
    /// User's password
    pub password: String,
    /// The name of the connection (typically "Username-Password-Authentication")
    pub connection: Option<String>,
    /// Optional username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional user metadata (custom attributes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<serde_json::Value>,
    /// Optional given (first) name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Optional family (last) name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Optional full name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl SignupRequest {
    /// Create a minimal signup request with just email and password.
    pub fn new(email: String, password: String) -> Self {
        Self {
            email,
            password,
            connection: None,
            username: None,
            user_metadata: None,
            given_name: None,
            family_name: None,
            name: None,
        }
    }

    /// Set the connection name.
    pub fn with_connection(mut self, connection: String) -> Self {
        self.connection = Some(connection);
        self
    }

    /// Set the username.
    pub fn with_username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    /// Set user metadata.
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.user_metadata = Some(metadata);
        self
    }

    /// Set the given name.
    pub fn with_given_name(mut self, given_name: String) -> Self {
        self.given_name = Some(given_name);
        self
    }

    /// Set the family name.
    pub fn with_family_name(mut self, family_name: String) -> Self {
        self.family_name = Some(family_name);
        self
    }

    /// Set the full name.
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }
}

/// Response from POST /dbconnections/signup
#[derive(Debug, Deserialize, Clone)]
pub struct SignupResponse {
    /// User's Auth0 ID
    #[serde(rename = "_id")]
    pub id: String,
    /// User's email address
    pub email: String,
    /// Whether the email has been verified
    pub email_verified: bool,
    /// Username (if set)
    pub username: Option<String>,
    /// User's given (first) name
    pub given_name: Option<String>,
    /// User's family (last) name
    pub family_name: Option<String>,
    /// User's full name
    pub name: Option<String>,
    /// User's nickname
    pub nickname: Option<String>,
    /// URL to user's picture
    pub picture: Option<String>,
    /// User's connection name
    pub connection: String,
    /// User metadata (custom attributes)
    pub user_metadata: Option<serde_json::Value>,
    /// Timestamp of user creation
    pub created_at: Option<String>,
    /// Timestamp of last update
    pub updated_at: Option<String>,
}

/// Request body for POST /oauth/token (Password Grant)
#[derive(Debug, Serialize, Clone)]
pub struct PasswordGrantRequest {
    /// Username or email
    pub username: String,
    /// User's password
    pub password: String,
    /// Grant type, must be "password"
    pub grant_type: String,
    /// Optional audience for the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Optional connection name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
}

impl PasswordGrantRequest {
    /// Create a new password grant request.
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            grant_type: "password".to_string(),
            audience: None,
            connection: None,
        }
    }

    /// Set the audience.
    pub fn with_audience(mut self, audience: String) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Set the connection name.
    pub fn with_connection(mut self, connection: String) -> Self {
        self.connection = Some(connection);
        self
    }
}

/// Response from POST /oauth/token (Password Grant)
#[derive(Debug, Deserialize, Clone)]
pub struct PasswordGrantResponse {
    /// Access token for API calls
    pub access_token: String,
    /// ID token containing user claims
    pub id_token: String,
    /// Refresh token for obtaining new access tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Token expiration time in seconds
    pub expires_in: u64,
    /// Token type (typically "Bearer")
    pub token_type: String,
    /// Token scope
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Auth0Config;
    use crate::error::AppError;

    #[test]
    fn test_signup_request_builder() {
        let request = SignupRequest::new("test@example.com".to_string(), "password123".to_string())
            .with_connection("Username-Password-Authentication".to_string())
            .with_username("testuser".to_string())
            .with_name("Test User".to_string());

        assert_eq!(request.email, "test@example.com");
        assert_eq!(request.password, "password123");
        assert_eq!(
            request.connection,
            Some("Username-Password-Authentication".to_string())
        );
        assert_eq!(request.username, Some("testuser".to_string()));
        assert_eq!(request.name, Some("Test User".to_string()));
    }

    #[test]
    fn test_password_grant_request_builder() {
        let request =
            PasswordGrantRequest::new("test@example.com".to_string(), "password123".to_string())
                .with_audience("https://api.example.com".to_string())
                .with_connection("Username-Password-Authentication".to_string());

        assert_eq!(request.username, "test@example.com");
        assert_eq!(request.password, "password123");
        assert_eq!(request.grant_type, "password");
        assert_eq!(
            request.audience,
            Some("https://api.example.com".to_string())
        );
        assert_eq!(
            request.connection,
            Some("Username-Password-Authentication".to_string())
        );
    }

    #[test]
    fn test_signup_request_serialization_minimal() {
        let request = SignupRequest::new("test@example.com".to_string(), "password123".to_string());
        let json = serde_json::to_value(request).unwrap();

        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["password"], "password123");
        assert!(json.get("username").is_none());
        assert!(json.get("name").is_none());
    }

    #[test]
    fn test_signup_request_serialization_full() {
        let request = SignupRequest::new("test@example.com".to_string(), "password123".to_string())
            .with_username("testuser".to_string())
            .with_metadata(serde_json::json!({
                "plan": "pro",
                "marketing_opt_in": true
            }))
            .with_name("Test User".to_string())
            .with_given_name("Test".to_string())
            .with_family_name("User".to_string());
        let json = serde_json::to_value(request).unwrap();

        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["username"], "testuser");
        assert_eq!(json["name"], "Test User");
        assert_eq!(json["given_name"], "Test");
        assert_eq!(json["family_name"], "User");
        assert_eq!(json["user_metadata"]["plan"], "pro");
        assert_eq!(json["user_metadata"]["marketing_opt_in"], true);
    }

    #[test]
    fn test_password_grant_request_serialization_without_optional_fields() {
        let request =
            PasswordGrantRequest::new("test@example.com".to_string(), "password123".to_string());
        let json = serde_json::to_value(request).unwrap();

        assert_eq!(json["username"], "test@example.com");
        assert_eq!(json["password"], "password123");
        assert_eq!(json["grant_type"], "password");
        assert!(json.get("audience").is_none());
        assert!(json.get("connection").is_none());
    }

    #[test]
    fn test_password_grant_request_serialization_with_optional_fields() {
        let request =
            PasswordGrantRequest::new("test@example.com".to_string(), "password123".to_string())
                .with_audience("https://api.example.com".to_string())
                .with_connection("Username-Password-Authentication".to_string());
        let json = serde_json::to_value(request).unwrap();

        assert_eq!(json["username"], "test@example.com");
        assert_eq!(json["password"], "password123");
        assert_eq!(json["grant_type"], "password");
        assert_eq!(json["audience"], "https://api.example.com");
        assert_eq!(json["connection"], "Username-Password-Authentication");
    }

    #[test]
    fn test_signup_response_deserialization_failure_branch() {
        let invalid = serde_json::json!({
            "email": "test@example.com",
            "email_verified": true
        });

        let result = serde_json::from_value::<SignupResponse>(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_grant_response_deserialization_failure_branch() {
        let invalid = serde_json::json!({
            "access_token": "token",
            "expires_in": "not-a-number"
        });

        let result = serde_json::from_value::<PasswordGrantResponse>(invalid);
        assert!(result.is_err());
    }

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

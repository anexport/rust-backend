use crate::error::AppError;
use serde::{Deserialize, Serialize};
use tracing::error;

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
    pub fn code_or_error(&self) -> &str {
        if self.code.is_empty() {
            self.error.as_str()
        } else {
            self.code.as_str()
        }
    }

    pub fn description_or_error_description(&self) -> &str {
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

        // Log the full error details server-side for debugging
        error!(
            code = %self.code,
            description = %description,
            "Auth0 API error"
        );

        match code {
            "auth_id_already_exists" | "user_exists" | "email_already_exists" => {
                AppError::Conflict("Email already registered".to_string())
            }

            "invalid_password"
            | "password_not_strong_enough"
            | "password_same_as_email"
            | "password_too_common" => {
                AppError::BadRequest("Password does not meet security requirements".to_string())
            }

            "invalid_grant" | "invalid_user_password" | "wrong_email_or_password" => {
                AppError::Unauthorized
            }

            "invalid_signup" | "bad_request" | "invalid_request" | "invalid_body" => {
                AppError::BadRequest("Invalid request".to_string())
            }

            "access_denied" | "unauthorized" => AppError::Unauthorized,

            _ => AppError::InternalError(anyhow::anyhow!("Authentication service error")),
        }
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
}

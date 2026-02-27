use serde::Serialize;

/// Request body for Auth0 signup
#[derive(Debug, Serialize)]
pub struct Auth0SignupRequest {
    pub client_id: String,
    pub email: String,
    pub password: String,
    pub connection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_metadata: Option<serde_json::Value>,
}

/// Request body for Auth0 password grant (login)
#[derive(Debug, Serialize)]
pub struct Auth0PasswordGrantRequest {
    pub grant_type: String,
    pub username: String,
    pub password: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

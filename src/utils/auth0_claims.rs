use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth0Claims {
    #[serde(alias = "iss")]
    pub iss: String,
    #[serde(alias = "sub")]
    pub sub: String,
    #[serde(alias = "aud")]
    pub aud: Audience,
    pub exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, alias = "email_verified")]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub picture: Option<String>,
    #[serde(flatten)]
    pub custom_claims: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Audience::Single(s) => s == expected,
            Audience::Multiple(v) => v.iter().any(|s| s == expected),
        }
    }

    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Audience::Single(s) => vec![s.clone()],
            Audience::Multiple(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Auth0UserContext {
    pub user_id: Uuid,
    pub auth0_sub: String,
    pub role: String,
    pub email: Option<String>,
}

pub fn map_auth0_role(claims: &Auth0Claims, namespace: &str) -> String {
    let namespaced_roles_key = format!("https://{}/roles", namespace);

    if let Some(roles_value) = claims.custom_claims.get(&namespaced_roles_key) {
        if let Some(role) = extract_role_from_value(roles_value) {
            return role;
        }
    }

    if let Some(roles_value) = claims.custom_claims.get("roles") {
        if let Some(role) = extract_role_from_value(roles_value) {
            return role;
        }
    }

    let namespaced_role_key = format!("https://{}/role", namespace);
    if let Some(role_value) = claims.custom_claims.get(&namespaced_role_key) {
        if let Some(role) = role_value.as_str() {
            return role.to_string();
        }
    }

    if let Some(role_value) = claims.custom_claims.get("role") {
        if let Some(role) = role_value.as_str() {
            return role.to_string();
        }
    }

    "renter".to_string()
}

fn extract_role_from_value(value: &serde_json::Value) -> Option<String> {
    if let Some(role_str) = value.as_str() {
        return Some(role_str.to_string());
    }

    if let Some(arr) = value.as_array() {
        if let Some(first) = arr.first() {
            if let Some(role) = first.as_str() {
                return Some(role.to_string());
            }
        }
    }

    None
}

impl Auth0UserContext {
    pub fn from_claims(claims: &Auth0Claims, user_id: Uuid, namespace: &str) -> Self {
        Self {
            user_id,
            auth0_sub: claims.sub.clone(),
            role: map_auth0_role(claims, namespace),
            email: claims.email.clone(),
        }
    }

    pub fn from_claims_with_role(
        claims: &Auth0Claims,
        user_id: Uuid,
        _namespace: &str,
        role: String,
    ) -> Self {
        Self {
            user_id,
            auth0_sub: claims.sub.clone(),
            role,
            email: claims.email.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create test claims with custom claims.
    ///
    /// # DB-based Role System
    /// In the new DB-based role system, Auth0 token claims are used only for
    /// NEW users during initial account creation. Once a user exists in the
    /// database, the role from the database is the source of truth and takes
    /// precedence over any token claims.
    ///
    /// The `map_auth0_role` function is still used to map Auth0 token claims
    /// to a role string for new user creation.
    fn test_claims_with_custom(
        custom: std::collections::HashMap<String, serde_json::Value>,
    ) -> Auth0Claims {
        Auth0Claims {
            iss: "https://test.auth0.com/".to_string(),
            sub: "auth0|abc123".to_string(),
            aud: Audience::Single("test-api".to_string()),
            exp: 9999999999,
            iat: 1111111111,
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Test User".to_string()),
            picture: None,
            custom_claims: custom,
        }
    }

    /// Tests that role is correctly mapped from namespaced roles array claim.
    /// This applies to NEW users during initial account creation.
    #[test]
    fn maps_role_from_namespaced_roles_array() {
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "https://myapp.com/roles".to_string(),
            serde_json::json!(["owner", "admin"]),
        );
        let claims = test_claims_with_custom(custom);

        let role = map_auth0_role(&claims, "myapp.com");
        assert_eq!(role, "owner");
    }

    /// Tests that role is correctly mapped from namespaced roles string claim.
    /// This applies to NEW users during initial account creation.
    #[test]
    fn maps_role_from_namespaced_roles_string() {
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "https://myapp.com/roles".to_string(),
            serde_json::json!("renter"),
        );
        let claims = test_claims_with_custom(custom);

        let role = map_auth0_role(&claims, "myapp.com");
        assert_eq!(role, "renter");
    }

    /// Tests that role is correctly mapped from non-namespaced roles claim.
    /// This applies to NEW users during initial account creation.
    #[test]
    fn maps_role_from_non_namespaced_roles_claim() {
        let mut custom = std::collections::HashMap::new();
        custom.insert("roles".to_string(), serde_json::json!(["admin"]));
        let claims = test_claims_with_custom(custom);

        let role = map_auth0_role(&claims, "myapp.com");
        assert_eq!(role, "admin");
    }

    /// Tests that role is correctly mapped from namespaced single role claim.
    /// This applies to NEW users during initial account creation.
    #[test]
    fn maps_role_from_namespaced_single_role_claim() {
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "https://myapp.com/role".to_string(),
            serde_json::json!("owner"),
        );
        let claims = test_claims_with_custom(custom);

        let role = map_auth0_role(&claims, "myapp.com");
        assert_eq!(role, "owner");
    }

    /// Tests that role defaults to "renter" when no role claim is present.
    /// This applies to NEW users during initial account creation.
    #[test]
    fn defaults_to_renter_when_no_role_claim() {
        let claims = test_claims_with_custom(std::collections::HashMap::new());

        let role = map_auth0_role(&claims, "myapp.com");
        assert_eq!(role, "renter");
    }

    #[test]
    fn audience_single_contains() {
        let aud = Audience::Single("test-api".to_string());
        assert!(aud.contains("test-api"));
        assert!(!aud.contains("other-api"));
    }

    #[test]
    fn audience_multiple_contains() {
        let aud = Audience::Multiple(vec!["api1".to_string(), "api2".to_string()]);
        assert!(aud.contains("api1"));
        assert!(aud.contains("api2"));
        assert!(!aud.contains("api3"));
    }

    /// Tests that user context is correctly created from claims using
    /// `from_claims`, which derives the role from Auth0 token claims.
    ///
    /// # Note
    /// This method is primarily used for NEW users. For existing users,
    /// `from_claims_with_role` should be used with the role from the database.
    #[test]
    fn creates_user_context_from_claims() {
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "https://myapp.com/roles".to_string(),
            serde_json::json!(["owner"]),
        );
        let claims = test_claims_with_custom(custom);
        let user_id = Uuid::new_v4();

        let context = Auth0UserContext::from_claims(&claims, user_id, "myapp.com");

        assert_eq!(context.user_id, user_id);
        assert_eq!(context.auth0_sub, "auth0|abc123");
        assert_eq!(context.role, "owner");
        assert_eq!(context.email, Some("test@example.com".to_string()));
    }

    /// Tests that user context is correctly created from claims with an
    /// explicit role using `from_claims_with_role`.
    ///
    /// # DB-based Role System
    /// This method is used for EXISTING users, where the role comes from
    /// the database instead of being derived from token claims. The database
    /// role is the source of truth and overrides any role claims in the token.
    #[test]
    fn creates_user_context_from_claims_with_db_role() {
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "https://myapp.com/roles".to_string(),
            serde_json::json!(["renter"]), // Token says "renter"
        );
        let claims = test_claims_with_custom(custom);
        let user_id = Uuid::new_v4();

        // Use database role "admin" which overrides token claim "renter"
        let context = Auth0UserContext::from_claims_with_role(
            &claims,
            user_id,
            "myapp.com",
            "admin".to_string(),
        );

        assert_eq!(context.user_id, user_id);
        assert_eq!(context.auth0_sub, "auth0|abc123");
        assert_eq!(context.role, "admin"); // DB role, not token role
        assert_eq!(context.email, Some("test@example.com".to_string()));
    }

    /// Tests that `from_claims` and `from_claims_with_role` produce different
    /// results when token claims and database roles differ.
    ///
    /// # DB-based Role System
    /// For NEW users: `from_claims` uses token claims
    /// For EXISTING users: `from_claims_with_role` uses DB role (overrides token)
    #[test]
    fn from_claims_vs_from_claims_with_role() {
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "https://myapp.com/roles".to_string(),
            serde_json::json!(["owner"]),
        );
        let claims = test_claims_with_custom(custom);
        let user_id = Uuid::new_v4();

        // For NEW user - role from token claims
        let new_user_context = Auth0UserContext::from_claims(&claims, user_id, "myapp.com");
        assert_eq!(new_user_context.role, "owner");

        // For EXISTING user - role from database (override)
        let existing_user_context = Auth0UserContext::from_claims_with_role(
            &claims,
            user_id,
            "myapp.com",
            "renter".to_string(),
        );
        assert_eq!(existing_user_context.role, "renter"); // DB role overrides token
    }
}

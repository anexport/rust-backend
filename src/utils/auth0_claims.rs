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
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn maps_role_from_non_namespaced_roles_claim() {
        let mut custom = std::collections::HashMap::new();
        custom.insert("roles".to_string(), serde_json::json!(["admin"]));
        let claims = test_claims_with_custom(custom);

        let role = map_auth0_role(&claims, "myapp.com");
        assert_eq!(role, "admin");
    }

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
}

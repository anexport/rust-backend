use std::sync::{Arc, Mutex};

mod common;

use crate::common::mocks::{MockAuthRepo, MockUserRepo};
use actix_rt::test;
use actix_web::{dev::Payload, http::header::AUTHORIZATION, test as actix_test, web, FromRequest};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rust_backend::domain::{AuthIdentity, AuthProvider, Role, User};
use rust_backend::error::{AppError, AppResult};
use rust_backend::middleware::auth::{
    Auth0AuthenticatedUser, JitUserProvisioningService, UserProvisioningService,
};
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims};
use rust_backend::utils::auth0_jwks::{Jwk, Jwks, JwksProvider};
use uuid::Uuid;

// Mock JWKS client for testing
struct MockJwksClient {
    test_keys: Mutex<Vec<(String, Vec<u8>)>>,
}

impl MockJwksClient {
    fn new() -> Self {
        // Create test RSA keys (simplified for testing)
        let test_modulus = vec![0x00u8; 256]; // 2048-bit modulus (simplified)
        Self {
            test_keys: Mutex::new(vec![("test-key-id".to_string(), test_modulus.clone())]),
        }
    }

    fn add_key(&self, kid: String, modulus: Vec<u8>) {
        self.test_keys
            .lock()
            .expect("test_keys mutex poisoned")
            .push((kid, modulus));
    }

    pub fn get_signing_key(&self, kid: &str) -> AppResult<Vec<u8>> {
        self.test_keys
            .lock()
            .expect("test_keys mutex poisoned")
            .iter()
            .find(|(k, _)| k == kid)
            .map(|(_, modulus)| modulus.clone())
            .ok_or(AppError::Unauthorized)
    }

    pub fn fetch_jwks(&self) -> AppResult<Jwks> {
        let keys = self.test_keys.lock().expect("test_keys mutex poisoned");
        Ok(Jwks {
            keys: keys
                .iter()
                .map(|(kid, modulus)| Jwk {
                    kid: kid.clone(),
                    n: URL_SAFE_NO_PAD.encode(modulus),
                    e: "AQAB".to_string(),
                    kty: "RSA".to_string(),
                    alg: Some("RS256".to_string()),
                    use_: Some("sig".to_string()),
                })
                .collect(),
        })
    }

    pub fn get_decoding_key(&self, kid: &str) -> AppResult<jsonwebtoken::DecodingKey> {
        let modulus_bytes = self.get_signing_key(kid)?;
        let jwks = self.fetch_jwks()?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or(AppError::Unauthorized)?;

        let e_bytes = URL_SAFE_NO_PAD
            .decode(&jwk.e)
            .map_err(|e| AppError::InternalError(anyhow::anyhow!("Invalid JWK exponent: {}", e)))?;

        jsonwebtoken::DecodingKey::from_rsa_components(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modulus_bytes),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e_bytes),
        )
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to create decoding key: {}", e))
        })
    }
}

// Helper to create a valid Auth0 token
fn create_valid_auth0_token(sub: &str, email: Option<String>, exp: i64, key_id: &str) -> String {
    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: sub.to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: exp as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email,
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    // For testing, we'll use HS256 with a test secret
    // In real scenarios, Auth0 uses RS256
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(key_id.to_string());

    encode(
        &header,
        &claims,
        &EncodingKey::from_secret("test-secret".as_bytes()),
    )
    .expect("Failed to encode test token")
}

fn test_auth0_config() -> rust_backend::config::Auth0Config {
    rust_backend::config::Auth0Config {
        auth0_domain: Some("test-tenant.auth0.com".to_string()),
        auth0_audience: Some("rust-backend-test".to_string()),
        auth0_issuer: Some("https://test-tenant.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: Some("test-client-id".to_string()),
        auth0_client_secret: Some("test-client-secret".to_string()),
        auth0_connection: "Username-Password-Authentication".to_string(),
    }
}

fn create_valid_rs256_auth0_token(sub: &str) -> String {
    let claims = Auth0Claims {
        iss: "https://test-tenant.auth0.com/".to_string(),
        sub: sub.to_string(),
        aud: Audience::Single("rust-backend-test".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("extractor@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Extractor User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-id".to_string());

    let private_key_pem = include_str!("test_private_key.pem");
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .expect("failed to load test private key");

    encode(&header, &claims, &encoding_key).expect("failed to encode RS256 test token")
}

struct StaticJwksProvider {
    key: jsonwebtoken::DecodingKey,
}

impl StaticJwksProvider {
    fn new() -> Self {
        let public_key_pem = include_str!("test_public_key.pem");
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .expect("failed to load test public key");
        Self { key }
    }
}

#[async_trait]
impl JwksProvider for StaticJwksProvider {
    async fn get_decoding_key(&self, kid: &str) -> AppResult<jsonwebtoken::DecodingKey> {
        if kid == "test-key-id" {
            Ok(self.key.clone())
        } else {
            Err(AppError::Unauthorized)
        }
    }
}

struct FailingProvisioningService;

#[async_trait]
impl UserProvisioningService for FailingProvisioningService {
    async fn provision_user(
        &self,
        _claims: &Auth0Claims,
    ) -> AppResult<rust_backend::utils::auth0_claims::Auth0UserContext> {
        Err(AppError::Forbidden("provisioning failed".to_string()))
    }
}

struct SuccessProvisioningService {
    user_id: Uuid,
}

#[async_trait]
impl UserProvisioningService for SuccessProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> AppResult<rust_backend::utils::auth0_claims::Auth0UserContext> {
        Ok(rust_backend::utils::auth0_claims::Auth0UserContext {
            user_id: self.user_id,
            auth0_sub: claims.sub.clone(),
            role: "owner".to_string(),
            email: claims.email.clone(),
        })
    }
}

// ============================================================================
// TEST: User provisioning tests
// ============================================================================

#[test]
async fn user_provisioning_with_existing_identity_reuses_user() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    // Create an existing user and identity
    let existing_user_id = Uuid::new_v4();
    user_repo.push(User {
        id: existing_user_id,
        email: "existing@example.com".to_string(),
        role: Role::Owner,
        username: Some("existing-user".to_string()),
        full_name: Some("Existing User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let existing_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: existing_user_id,
        provider: AuthProvider::Auth0,
        provider_id: Some("auth0|existing123".to_string()),
        password_hash: None,
        verified: true,
        created_at: Utc::now(),
    };

    auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned")
        .push(existing_identity);

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|existing123".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("existing@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Existing User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should find existing identity");

    assert_eq!(user_context.user_id, existing_user_id);
    assert_eq!(user_context.auth0_sub, "auth0|existing123");
}

#[test]
async fn user_provisioning_with_existing_email_creates_new_identity() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    // Create an existing user with email (but no Auth0 identity)
    let existing_user_id = Uuid::new_v4();
    user_repo.push(User {
        id: existing_user_id,
        email: "existing@example.com".to_string(),
        role: Role::Renter,
        username: Some("existing-email-user".to_string()),
        full_name: Some("Existing Email User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|new-identity".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("existing@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Existing Email User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should create new identity for existing user");

    assert_eq!(user_context.user_id, existing_user_id);
    assert_eq!(user_context.auth0_sub, "auth0|new-identity");

    // Verify the new identity was created
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert_eq!(
        identities[0].provider_id,
        Some("auth0|new-identity".to_string())
    );
}

#[test]
async fn user_provisioning_creates_new_user_when_none_exist() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|brand-new".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("brandnew@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Brand New User".to_string()),
        picture: Some("https://example.com/avatar.jpg".to_string()),
        custom_claims: std::collections::HashMap::new(),
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should create new user and identity");

    assert_eq!(user_context.auth0_sub, "auth0|brand-new");
    assert_eq!(user_context.role, "renter"); // Default role

    // Verify the new user was created
    let users = user_repo.users.lock().expect("users mutex poisoned");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "brandnew@example.com");
    assert_eq!(users[0].role, Role::Renter);
    assert_eq!(users[0].full_name, Some("Brand New User".to_string()));
    assert_eq!(
        users[0].avatar_url,
        Some("https://example.com/avatar.jpg".to_string())
    );

    // Verify the new identity was created
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].provider, AuthProvider::Auth0);
    assert_eq!(
        identities[0].provider_id,
        Some("auth0|brand-new".to_string())
    );
    assert!(identities[0].verified);
}

#[test]
async fn user_provisioning_without_email_returns_bad_request() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    // Create claims without email
    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|no-email".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: None,
        email_verified: Some(true),
        name: Some("No Email User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let result = provisioning_service.provision_user(&claims).await;
    assert!(matches!(
        result,
        Err(AppError::BadRequest(message)) if message == "Email is required from Auth0"
    ));

    // Verify no user was created when email is missing.
    let users = user_repo.users.lock().expect("users mutex poisoned");
    assert!(users.is_empty());
}

#[test]
async fn user_provisioning_with_custom_role_maps_correctly() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-app.com/roles".to_string(),
        serde_json::json!(["owner", "admin"]),
    );

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|role-test".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("owner@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Owner User".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with role");

    assert_eq!(user_context.role, "owner");
}

#[test]
async fn user_provisioning_with_non_namespaced_role_maps_correctly() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert("roles".to_string(), serde_json::json!(["admin"]));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|non-namespaced".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("admin@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Admin User".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with non-namespaced role");

    assert_eq!(user_context.role, "admin");
}

#[test]
async fn user_provisioning_defaults_to_renter_when_no_role_claim() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|no-role".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("norole@example.com".to_string()),
        email_verified: Some(true),
        name: Some("No Role User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with default role");

    assert_eq!(user_context.role, "renter");
}

// ============================================================================
// TEST: Auth0 Claims validation tests
// ============================================================================

#[test]
async fn audience_single_contains_matching_audience() {
    let aud = Audience::Single("test-api".to_string());
    assert!(aud.contains("test-api"));
    assert!(!aud.contains("other-api"));
}

#[test]
async fn audience_multiple_contains_matching_audience() {
    let aud = Audience::Multiple(vec!["api1".to_string(), "api2".to_string()]);
    assert!(aud.contains("api1"));
    assert!(aud.contains("api2"));
    assert!(!aud.contains("api3"));
}

#[test]
async fn token_with_multiple_audiences_can_be_constructed() {
    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|multi-aud".to_string(),
        aud: Audience::Multiple(vec!["test-api".to_string(), "other-api".to_string()]),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("multiaud@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Multi Aud User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key-id".to_string());

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret("test-secret".as_bytes()),
    )
    .expect("Failed to encode test token");

    // Token should be parseable (not validating here, just ensuring it can be created)
    assert!(!token.is_empty());
    assert!(token.contains('.'));
}

// ============================================================================
// TEST: Mock JWKS Client tests
// ============================================================================

#[test]
async fn mock_jwks_client_returns_valid_key() {
    let client = MockJwksClient::new();
    let key: AppResult<Vec<u8>> = client.get_signing_key("test-key-id");

    assert!(key.is_ok());
    assert_eq!(key.unwrap().len(), 256);
}

#[test]
async fn mock_jwks_client_returns_error_for_unknown_key() {
    let client = MockJwksClient::new();
    let key: AppResult<Vec<u8>> = client.get_signing_key("unknown-key-id");

    assert!(key.is_err());
}

#[test]
async fn mock_jwks_client_key_rotation_adds_new_key() {
    let client = MockJwksClient::new();
    let new_key_modulus = vec![0x01u8; 256];
    client.add_key("new-key-id".to_string(), new_key_modulus);

    let key: AppResult<Vec<u8>> = client.get_signing_key("new-key-id");
    assert!(key.is_ok());
    assert_eq!(key.unwrap(), vec![0x01u8; 256]);
}

#[test]
async fn mock_jwks_client_fetch_returns_all_keys() {
    let client = MockJwksClient::new();
    client.add_key("second-key".to_string(), vec![0x02u8; 256]);

    let jwks = client.fetch_jwks().unwrap();
    assert_eq!(jwks.keys.len(), 2);
    assert_eq!(jwks.keys[0].kid, "test-key-id");
    assert_eq!(jwks.keys[1].kid, "second-key");
}

#[test]
async fn mock_jwks_client_get_decoding_key_for_known_key() {
    let client = MockJwksClient::new();

    let decoding_key: AppResult<jsonwebtoken::DecodingKey> = client.get_decoding_key("test-key-id");
    assert!(decoding_key.is_ok());
}

#[test]
async fn mock_jwks_client_get_decoding_key_for_unknown_key() {
    let client = MockJwksClient::new();

    let decoding_key: AppResult<jsonwebtoken::DecodingKey> = client.get_decoding_key("unknown-key");
    assert!(decoding_key.is_err());
}

// ============================================================================
// TEST: Token creation and validation
// ============================================================================

#[test]
async fn create_valid_token_with_all_fields() {
    let exp = (Utc::now() + Duration::hours(1)).timestamp();
    let token = create_valid_auth0_token(
        "auth0|test123",
        Some("test@example.com".to_string()),
        exp,
        "test-key-id",
    );

    // Token should have 3 parts separated by '.'
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    // Token should be base64 encoded
    assert!(!token.is_empty());
}

#[test]
async fn create_expired_token() {
    let exp = (Utc::now() - Duration::hours(1)).timestamp();
    let token = create_valid_auth0_token(
        "auth0|expired",
        Some("expired@example.com".to_string()),
        exp,
        "test-key-id",
    );

    assert!(!token.is_empty());

    // The token should fail when trying to decode with proper validation
    let decoded = jsonwebtoken::decode::<Auth0Claims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret("test-secret".as_bytes()),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
    );

    assert!(decoded.is_err());
    assert_eq!(
        decoded.unwrap_err().kind(),
        &jsonwebtoken::errors::ErrorKind::ExpiredSignature
    );
}

#[test]
async fn create_token_with_wrong_audience() {
    let exp = (Utc::now() + Duration::hours(1)).timestamp();

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|wrong-aud".to_string(),
        aud: Audience::Single("wrong-audience".to_string()),
        exp: exp as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("wrong@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Wrong Audience".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key-id".to_string());

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret("test-secret".as_bytes()),
    )
    .expect("Failed to encode test token");

    // Token should succeed without audience validation
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_aud = false; // Disable audience validation
    validation.validate_exp = true; // Still validate expiration

    let decoded = jsonwebtoken::decode::<Auth0Claims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret("test-secret".as_bytes()),
        &validation,
    );

    // Should succeed when audience validation is disabled
    assert!(decoded.is_ok());
}

#[test]
async fn create_token_with_wrong_issuer() {
    let exp = (Utc::now() + Duration::hours(1)).timestamp();

    let claims = Auth0Claims {
        iss: "https://wrong-issuer.com/".to_string(),
        sub: "auth0|wrong-iss".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: exp as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("wrongiss@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Wrong Issuer".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key-id".to_string());

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret("test-secret".as_bytes()),
    )
    .expect("Failed to encode test token");

    assert!(!token.is_empty());
}

#[test]
async fn create_token_not_yet_valid() {
    let exp = (Utc::now() + Duration::hours(2)).timestamp();

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|future".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: exp as u64,
        iat: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        email: Some("future@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Future User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key-id".to_string());

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret("test-secret".as_bytes()),
    )
    .expect("Failed to encode test token");

    // Token should fail nbf validation
    let decoded = jsonwebtoken::decode::<Auth0Claims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret("test-secret".as_bytes()),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
    );

    assert!(decoded.is_err());
}

// ============================================================================
// TEST: Invalid token formats
// ============================================================================

#[test]
async fn invalid_jwt_formats_fail_to_decode() {
    let invalid_tokens = vec![
        "not-a-jwt",
        "invalid",
        "",
        "only.one.part",
        "still.only.two.parts",
    ];

    for token in invalid_tokens {
        let decoded = jsonwebtoken::decode::<Auth0Claims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret("test-secret".as_bytes()),
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
        );

        assert!(decoded.is_err(), "Failed for token: {}", token);
    }
}

#[test]
async fn corrupted_signature_fails_to_validate() {
    let exp = (Utc::now() + Duration::hours(1)).timestamp();
    let mut token = create_valid_auth0_token(
        "auth0|corrupt",
        Some("corrupt@example.com".to_string()),
        exp,
        "test-key-id",
    );

    // Corrupt the last character of the signature
    if let Some(last_char) = token.chars().last() {
        let corrupted: String = token.chars().take(token.len() - 1).collect();
        let new_last = if last_char == 'A' { 'B' } else { 'A' };
        token = format!("{}{}", corrupted, new_last);
    }

    // Token should fail signature validation
    let decoded = jsonwebtoken::decode::<Auth0Claims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret("test-secret".as_bytes()),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
    );

    assert!(decoded.is_err());
    assert_eq!(
        decoded.unwrap_err().kind(),
        &jsonwebtoken::errors::ErrorKind::InvalidSignature
    );
}

// ============================================================================
// TEST: Email verification handling
// ============================================================================

#[test]
async fn user_provisioning_with_verified_email_creates_verified_identity() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|verified".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("verified@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Verified User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with verified email");

    // Verify the identity was created as verified
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert!(identities[0].verified);
}

#[test]
async fn user_provisioning_with_unverified_email_creates_unverified_identity() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|unverified".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("unverified@example.com".to_string()),
        email_verified: Some(false), // Explicitly unverified
        name: Some("Unverified User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with unverified email");

    // Verify the identity was created as unverified
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert!(!identities[0].verified);
}

// ============================================================================
// TEST: User attributes from claims
// ============================================================================

#[test]
async fn user_provisioning_copies_name_from_claims() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|with-name".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("withname@example.com".to_string()),
        email_verified: Some(true),
        name: Some("John Doe".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with name");

    // Verify the user was created with the name
    let users = user_repo.users.lock().expect("users mutex poisoned");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].full_name, Some("John Doe".to_string()));
}

#[test]
async fn user_provisioning_copies_avatar_from_claims() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|with-avatar".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("withavatar@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Avatar User".to_string()),
        picture: Some("https://cdn.auth0.com/avatar.jpg".to_string()),
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with avatar");

    // Verify the user was created with the avatar
    let users = user_repo.users.lock().expect("users mutex poisoned");
    assert_eq!(users.len(), 1);
    assert_eq!(
        users[0].avatar_url,
        Some("https://cdn.auth0.com/avatar.jpg".to_string())
    );
}

// ============================================================================
// TEST: Identity provider attribute validation
// ============================================================================

#[test]
async fn user_provisioning_sets_auth0_provider() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|provider-test".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("provider@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Provider Test".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with Auth0 provider");

    // Verify the identity was created with Auth0 provider
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].provider, AuthProvider::Auth0);
    assert!(identities[0].password_hash.is_none()); // OAuth identities don't have passwords
}

// ============================================================================
// TEST: Custom claims handling
// ============================================================================

#[test]
async fn user_provisioning_with_non_standard_custom_claim() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-app.com/roles".to_string(),
        serde_json::json!("renter"),
    );

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|custom-claim".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("custom@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Custom Claim".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should handle custom claims");

    // Role should be extracted from custom claims
    assert_eq!(user_context.role, "renter");
}

// ============================================================================
// TEST: Multiple custom role claim formats
// ============================================================================

#[test]
async fn user_provisioning_with_role_as_single_string() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-app.com/role".to_string(),
        serde_json::json!("admin"),
    );

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|single-role".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("singlerole@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Single Role".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should handle single string role");

    assert_eq!(user_context.role, "admin");
}

#[test]
async fn user_provisioning_with_non_namespaced_role_as_single_string() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert("role".to_string(), serde_json::json!("owner"));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|non-ns-role".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("nonnsrole@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Non Namespaced Role".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should handle non-namespaced single role");

    assert_eq!(user_context.role, "owner");
}

// ============================================================================
// TEST: Auth0AuthenticatedUser extractor branches
// ============================================================================

#[test]
async fn auth0_authenticated_user_rejects_malformed_or_non_bearer_authorization() {
    let requests = vec![
        actix_test::TestRequest::default()
            .insert_header((AUTHORIZATION, "Basic token"))
            .to_http_request(),
        actix_test::TestRequest::default()
            .insert_header((AUTHORIZATION, "Bearer "))
            .to_http_request(),
    ];

    for request in requests {
        let mut payload = Payload::None;
        let result = Auth0AuthenticatedUser::from_request(&request, &mut payload).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
}

#[test]
async fn auth0_authenticated_user_returns_internal_error_when_app_data_missing() {
    let request = actix_test::TestRequest::default()
        .insert_header((AUTHORIZATION, "Bearer any-token"))
        .to_http_request();

    let mut payload = Payload::None;
    let result = Auth0AuthenticatedUser::from_request(&request, &mut payload).await;
    assert!(matches!(result, Err(AppError::InternalError(_))));
}

#[test]
async fn auth0_authenticated_user_propagates_provisioning_failure() {
    let token = create_valid_rs256_auth0_token("auth0|provision-fail");
    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider::new());
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(FailingProvisioningService);

    let request = actix_test::TestRequest::default()
        .insert_header((AUTHORIZATION, format!("Bearer {token}")))
        .app_data(web::Data::new(jwks_provider))
        .app_data(web::Data::new(test_auth0_config()))
        .app_data(web::Data::new(provisioning_service))
        .to_http_request();

    let mut payload = Payload::None;
    let result = Auth0AuthenticatedUser::from_request(&request, &mut payload).await;
    assert!(
        matches!(result, Err(AppError::Forbidden(message)) if message == "provisioning failed")
    );
}

#[test]
async fn auth0_authenticated_user_valid_flow_returns_user_context() {
    let token = create_valid_rs256_auth0_token("auth0|valid-flow");
    let expected_user_id = Uuid::new_v4();

    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider::new());
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(SuccessProvisioningService {
            user_id: expected_user_id,
        });

    let request = actix_test::TestRequest::default()
        .insert_header((AUTHORIZATION, format!("Bearer {token}")))
        .app_data(web::Data::new(jwks_provider))
        .app_data(web::Data::new(test_auth0_config()))
        .app_data(web::Data::new(provisioning_service))
        .to_http_request();

    let mut payload = Payload::None;
    let extracted = Auth0AuthenticatedUser::from_request(&request, &mut payload)
        .await
        .expect("extractor should succeed");

    assert_eq!(extracted.0.user_id, expected_user_id);
    assert_eq!(extracted.0.auth0_sub, "auth0|valid-flow");
    assert_eq!(extracted.0.role, "owner");
}

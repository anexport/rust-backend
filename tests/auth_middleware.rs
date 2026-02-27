use std::sync::{Arc, Mutex};

mod common;

#[path = "auth_middleware/provisioning.rs"]
pub mod provisioning;
#[path = "auth_middleware/jwks.rs"]
pub mod jwks;
#[path = "auth_middleware/jwt_validation.rs"]
pub mod jwt_validation;
#[path = "auth_middleware/extractor.rs"]
pub mod extractor;

use crate::common::mocks::{MockAuthRepo, MockUserRepo};
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
pub struct MockJwksClient {
    pub test_keys: Mutex<Vec<(String, Vec<u8>)>>,
}

impl MockJwksClient {
    pub fn new() -> Self {
        // Create test RSA keys (simplified for testing)
        let test_modulus = vec![0x00u8; 256]; // 2048-bit modulus (simplified)
        Self {
            test_keys: Mutex::new(vec![("test-key-id".to_string(), test_modulus.clone())]),
        }
    }

    pub fn add_key(&self, kid: String, modulus: Vec<u8>) {
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

#[async_trait]
impl JwksProvider for MockJwksClient {
    async fn get_decoding_key(&self, kid: &str) -> AppResult<jsonwebtoken::DecodingKey> {
        self.get_decoding_key(kid)
    }
}

// Helper to create a valid Auth0 token
pub fn create_valid_auth0_token(sub: &str, email: Option<String>, exp: i64, key_id: &str) -> String {
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

pub fn test_auth0_config() -> rust_backend::config::Auth0Config {
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

pub fn create_valid_rs256_auth0_token(sub: &str) -> String {
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

pub struct StaticJwksProvider {
    pub key: jsonwebtoken::DecodingKey,
}

impl StaticJwksProvider {
    pub fn new() -> Self {
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

pub struct FailingProvisioningService;

#[async_trait]
impl UserProvisioningService for FailingProvisioningService {
    async fn provision_user(
        &self,
        _claims: &Auth0Claims,
    ) -> AppResult<rust_backend::utils::auth0_claims::Auth0UserContext> {
        Err(AppError::Forbidden("provisioning failed".to_string()))
    }
}

pub struct SuccessProvisioningService {
    pub user_id: Uuid,
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

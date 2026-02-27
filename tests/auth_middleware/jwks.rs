use super::*;
use crate::common::mocks::*;
use crate::common;
use actix_web::{test as actix_test, App, web, http::StatusCode, dev::Payload, FromRequest};
use rust_backend::domain::*;
use rust_backend::error::{AppError, AppResult};
use rust_backend::middleware::auth::*;
use rust_backend::utils::auth0_claims::*;
use rust_backend::utils::auth0_jwks::*;
use uuid::Uuid;
use chrono::{Utc, Duration};
use std::sync::Arc;

#[actix_rt::test]
async fn audience_single_contains_matching_audience() {
    let aud = Audience::Single("test-api".to_string());
    assert!(aud.contains("test-api"));
    assert!(!aud.contains("other-api"));
}

#[actix_rt::test]
async fn audience_multiple_contains_matching_audience() {
    let aud = Audience::Multiple(vec!["api1".to_string(), "api2".to_string()]);
    assert!(aud.contains("api1"));
    assert!(aud.contains("api2"));
    assert!(!aud.contains("api3"));
}

#[actix_rt::test]
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

#[actix_rt::test]
async fn mock_jwks_client_returns_valid_key() {
    let client = MockJwksClient::new();
    let key: AppResult<Vec<u8>> = client.get_signing_key("test-key-id");

    assert!(key.is_ok());
    assert_eq!(key.unwrap().len(), 256);
}

#[actix_rt::test]
async fn mock_jwks_client_returns_error_for_unknown_key() {
    let client = MockJwksClient::new();
    let key: AppResult<Vec<u8>> = client.get_signing_key("unknown-key-id");

    assert!(key.is_err());
}

#[actix_rt::test]
async fn mock_jwks_client_key_rotation_adds_new_key() {
    let client = MockJwksClient::new();
    let new_key_modulus = vec![0x01u8; 256];
    client.add_key("new-key-id".to_string(), new_key_modulus);

    let key: AppResult<Vec<u8>> = client.get_signing_key("new-key-id");
    assert!(key.is_ok());
    assert_eq!(key.unwrap(), vec![0x01u8; 256]);
}

#[actix_rt::test]
async fn mock_jwks_client_fetch_returns_all_keys() {
    let client = MockJwksClient::new();
    client.add_key("second-key".to_string(), vec![0x02u8; 256]);

    let jwks = client.fetch_jwks().unwrap();
    assert_eq!(jwks.keys.len(), 2);
    assert_eq!(jwks.keys[0].kid, "test-key-id");
    assert_eq!(jwks.keys[1].kid, "second-key");
}

#[actix_rt::test]
async fn mock_jwks_client_get_decoding_key_for_known_key() {
    let client = MockJwksClient::new();

    let decoding_key: AppResult<jsonwebtoken::DecodingKey> = client.get_decoding_key("test-key-id");
    assert!(decoding_key.is_ok());
}

#[actix_rt::test]
async fn mock_jwks_client_get_decoding_key_for_unknown_key() {
    let client = MockJwksClient::new();

    let decoding_key: AppResult<jsonwebtoken::DecodingKey> = client.get_decoding_key("unknown-key");
    assert!(decoding_key.is_err());
}

// ============================================================================
// TEST: Token creation and validation
// ============================================================================

#[actix_rt::test]
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


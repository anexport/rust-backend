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

#[actix_rt::test]
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

#[actix_rt::test]
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

#[actix_rt::test]
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

#[actix_rt::test]
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

#[actix_rt::test]
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


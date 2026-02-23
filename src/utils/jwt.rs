use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::error::{AppError, AppResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub jti: Uuid,
    pub kid: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub role: String,
}

pub fn create_access_token(user_id: Uuid, role: &str, config: &AuthConfig) -> AppResult<String> {
    let now = Utc::now();
    let exp = now + Duration::seconds(config.jwt_expiration_seconds as i64);

    let claims = Claims {
        sub: user_id,
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
        jti: Uuid::new_v4(),
        kid: config.jwt_kid.clone(),
        iss: config.issuer.clone(),
        aud: vec![config.audience.clone()],
        role: role.to_string(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(config.jwt_kid.clone());

    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::InternalError(e.into()))
}

pub fn validate_token(token: &str, config: &AuthConfig) -> AppResult<Claims> {
    let header = decode_header(token).map_err(|_| AppError::InvalidToken)?;
    let kid = header.kid.ok_or(AppError::InvalidToken)?;

    let secret = signing_secret_for_kid(config, &kid).ok_or(AppError::InvalidToken)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[&config.audience]);

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
        _ => AppError::InvalidToken,
    })
}

fn signing_secret_for_kid(config: &AuthConfig, kid: &str) -> Option<String> {
    if kid == config.jwt_kid {
        return Some(config.jwt_secret.clone());
    }

    config
        .previous_jwt_kids
        .iter()
        .position(|existing| existing == kid)
        .and_then(|idx| config.previous_jwt_secrets.get(idx).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AuthConfig {
        AuthConfig {
            jwt_secret: "current-secret".to_string(),
            jwt_kid: "v2".to_string(),
            previous_jwt_secrets: vec!["old-secret".to_string()],
            previous_jwt_kids: vec!["v1".to_string()],
            jwt_expiration_seconds: 900,
            refresh_token_expiration_days: 7,
            issuer: "rust-backend-test".to_string(),
            audience: "rust-backend-client".to_string(),
        }
    }

    #[test]
    fn creates_token_with_all_claims() {
        let cfg = config();
        let user_id = Uuid::new_v4();
        let role = "owner";

        let token = create_access_token(user_id, role, &cfg).expect("token should be created");

        let validated = validate_token(&token, &cfg).expect("token should validate");

        assert_eq!(validated.sub, user_id);
        assert_eq!(validated.role, role);
        assert_eq!(validated.kid, cfg.jwt_kid);
        assert_eq!(validated.iss, cfg.issuer);
        assert_eq!(validated.aud, vec![cfg.audience]);

        let now = Utc::now().timestamp() as usize;
        assert!(validated.iat <= now);
        assert!(validated.iat > 0);
    }

    #[test]
    fn validates_valid_token() {
        let cfg = config();
        let user_id = Uuid::new_v4();

        let token = create_access_token(user_id, "renter", &cfg).expect("token should be created");

        let validated = validate_token(&token, &cfg).expect("valid token should pass validation");

        assert_eq!(validated.sub, user_id);
        assert_eq!(validated.role, "renter");
    }

    #[test]
    fn rejects_expired_token() {
        let cfg = config();
        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            exp: (now - Duration::minutes(5)).timestamp() as usize,
            iat: (now - Duration::minutes(10)).timestamp() as usize,
            jti: Uuid::new_v4(),
            kid: cfg.jwt_kid.clone(),
            iss: cfg.issuer.clone(),
            aud: vec![cfg.audience.clone()],
            role: "renter".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(cfg.jwt_kid.clone());

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .expect("token should encode");

        let result = validate_token(&token, &cfg);
        assert!(matches!(result, Err(AppError::TokenExpired)));
    }

    #[test]
    fn rejects_token_with_invalid_signature() {
        let cfg = config();
        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            exp: (now + Duration::minutes(5)).timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: Uuid::new_v4(),
            kid: cfg.jwt_kid.clone(),
            iss: cfg.issuer.clone(),
            aud: vec![cfg.audience.clone()],
            role: "renter".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(cfg.jwt_kid.clone());

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("wrong-secret".as_bytes()),
        )
        .expect("token should encode");

        let result = validate_token(&token, &cfg);
        assert!(matches!(result, Err(AppError::InvalidToken)));
    }

    #[test]
    fn validates_token_signed_with_previous_key_id() {
        let cfg = config();
        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            exp: (now + Duration::minutes(5)).timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: Uuid::new_v4(),
            kid: "v1".to_string(),
            iss: cfg.issuer.clone(),
            aud: vec![cfg.audience.clone()],
            role: "renter".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("v1".to_string());

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("old-secret".as_bytes()),
        )
        .expect("token should encode with old secret");

        let validated = validate_token(&token, &cfg).expect("old key token should validate");
        assert_eq!(validated.sub, claims.sub);
        assert_eq!(validated.kid, "v1");
    }

    #[test]
    fn rejects_token_with_unknown_key_id() {
        let cfg = config();
        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            exp: (now + Duration::minutes(5)).timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: Uuid::new_v4(),
            kid: "v3".to_string(),
            iss: cfg.issuer.clone(),
            aud: vec![cfg.audience.clone()],
            role: "renter".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("v3".to_string());

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("unknown-secret".as_bytes()),
        )
        .expect("token should encode");

        let result = validate_token(&token, &cfg);
        assert!(matches!(result, Err(AppError::InvalidToken)));
    }

    #[test]
    fn validates_correct_audience() {
        let cfg = config();
        let user_id = Uuid::new_v4();

        let token = create_access_token(user_id, "owner", &cfg).expect("token should be created");

        let validated = validate_token(&token, &cfg).expect("token with correct audience should validate");
        assert_eq!(validated.aud, vec![cfg.audience]);
    }

    #[test]
    fn rejects_token_with_wrong_audience() {
        let cfg = config();
        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            exp: (now + Duration::minutes(5)).timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: Uuid::new_v4(),
            kid: cfg.jwt_kid.clone(),
            iss: cfg.issuer.clone(),
            aud: vec!["wrong-audience".to_string()],
            role: "renter".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(cfg.jwt_kid.clone());

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .expect("token should encode");

        let result = validate_token(&token, &cfg);
        assert!(matches!(result, Err(AppError::InvalidToken)));
    }

    #[test]
    fn validates_correct_issuer() {
        let cfg = config();
        let user_id = Uuid::new_v4();

        let token = create_access_token(user_id, "renter", &cfg).expect("token should be created");

        let validated = validate_token(&token, &cfg).expect("token with correct issuer should validate");
        assert_eq!(validated.iss, cfg.issuer);
    }

    #[test]
    fn rejects_token_with_wrong_issuer() {
        let cfg = config();
        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            exp: (now + Duration::minutes(5)).timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: Uuid::new_v4(),
            kid: cfg.jwt_kid.clone(),
            iss: "wrong-issuer".to_string(),
            aud: vec![cfg.audience.clone()],
            role: "renter".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(cfg.jwt_kid.clone());

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .expect("token should encode");

        let result = validate_token(&token, &cfg);
        assert!(matches!(result, Err(AppError::InvalidToken)));
    }

    #[test]
    fn jti_is_unique_across_multiple_tokens() {
        let cfg = config();
        let user_id = Uuid::new_v4();

        let token1 = create_access_token(user_id, "owner", &cfg).expect("token1 should be created");
        let token2 = create_access_token(user_id, "owner", &cfg).expect("token2 should be created");

        let claims1 = validate_token(&token1, &cfg).expect("token1 should validate");
        let claims2 = validate_token(&token2, &cfg).expect("token2 should validate");

        assert_ne!(claims1.jti, claims2.jti, "JTI should be unique for each token");
    }

    #[test]
    fn jti_is_valid_uuid() {
        let cfg = config();
        let user_id = Uuid::new_v4();

        let token = create_access_token(user_id, "renter", &cfg).expect("token should be created");

        let claims = validate_token(&token, &cfg).expect("token should validate");

        let _ = Uuid::parse_str(&claims.jti.to_string())
            .expect("JTI should be a valid UUID");
    }

    #[test]
    fn expires_at_expected_time() {
        let cfg = config();
        let user_id = Uuid::new_v4();
        let before_creation = Utc::now();

        let token = create_access_token(user_id, "owner", &cfg).expect("token should be created");

        let after_creation = Utc::now();

        let claims = validate_token(&token, &cfg).expect("token should validate");

        let expected_exp = before_creation.timestamp() as usize + cfg.jwt_expiration_seconds as usize;
        assert!(
            claims.exp >= expected_exp,
            "Token should expire at least {} seconds from before creation",
            cfg.jwt_expiration_seconds
        );

        let max_expected_exp = after_creation.timestamp() as usize + cfg.jwt_expiration_seconds as usize + 1;
        assert!(
            claims.exp <= max_expected_exp,
            "Token should not expire much later than expected"
        );
    }
}

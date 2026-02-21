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
}

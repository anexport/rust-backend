use std::future::{ready, Ready};

use actix_web::{dev::Payload, http::header::AUTHORIZATION, web, FromRequest, HttpRequest};

use crate::error::{AppError, AppResult};
use crate::utils::jwt::{validate_token, Claims};

pub struct AuthenticatedUser(pub Claims);

impl FromRequest for AuthenticatedUser {
    type Error = AppError;
    type Future = Ready<AppResult<Self>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let config = match req.app_data::<web::Data<crate::config::AuthConfig>>() {
            Some(config) => config,
            None => {
                return ready(Err(AppError::InternalError(anyhow::anyhow!(
                    "missing AuthConfig app data"
                ))))
            }
        };

        let token = match req.headers().get(AUTHORIZATION) {
            Some(header) => match header.to_str() {
                Ok(value) => match value.strip_prefix("Bearer ") {
                    Some(token) if !token.is_empty() => token,
                    _ => return ready(Err(AppError::Unauthorized)),
                },
                Err(_) => return ready(Err(AppError::Unauthorized)),
            },
            None => return ready(Err(AppError::Unauthorized)),
        };

        ready(validate_token(token, config.get_ref()).map(AuthenticatedUser))
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{test::TestRequest, web, FromRequest};
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use uuid::Uuid;

    use super::AuthenticatedUser;
    use crate::config::AuthConfig;
    use crate::error::AppError;
    use crate::utils::jwt::{create_access_token, Claims};

    fn test_config() -> AuthConfig {
        AuthConfig {
            jwt_secret: "test-secret".to_string(),
            jwt_kid: "v1".to_string(),
            previous_jwt_secrets: Vec::new(),
            previous_jwt_kids: Vec::new(),
            jwt_expiration_seconds: 900,
            refresh_token_expiration_days: 7,
            issuer: "rust-backend-test".to_string(),
            audience: "rust-backend-client".to_string(),
        }
    }

    fn expired_token(config: &AuthConfig, sub: Uuid) -> String {
        let now = Utc::now();
        let claims = Claims {
            sub,
            exp: (now - Duration::minutes(5)).timestamp() as usize,
            iat: (now - Duration::minutes(10)).timestamp() as usize,
            jti: Uuid::new_v4(),
            kid: config.jwt_kid.clone(),
            iss: config.issuer.clone(),
            aud: vec![config.audience.clone()],
            role: "owner".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(config.jwt_kid.clone());

        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )
        .expect("expired token should encode")
    }

    fn wrong_secret_token(config: &AuthConfig, sub: Uuid) -> String {
        let now = Utc::now();
        let claims = Claims {
            sub,
            exp: (now + Duration::minutes(5)).timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: Uuid::new_v4(),
            kid: config.jwt_kid.clone(),
            iss: config.issuer.clone(),
            aud: vec![config.audience.clone()],
            role: "owner".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(config.jwt_kid.clone());

        encode(
            &header,
            &claims,
            &EncodingKey::from_secret("wrong-secret".as_bytes()),
        )
        .expect("wrong-secret token should encode")
    }

    #[actix_web::test]
    async fn valid_bearer_token_is_accepted() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let token = create_access_token(user_id, "owner", &config).expect("token should encode");

        let req = TestRequest::default()
            .app_data(web::Data::new(config))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = AuthenticatedUser::from_request(&req, &mut payload).await;

        let auth = result.expect("extractor should succeed");
        assert_eq!(auth.0.sub, user_id);
    }

    #[actix_web::test]
    async fn missing_authorization_header_returns_unauthorized() {
        let config = test_config();
        let req = TestRequest::default()
            .app_data(web::Data::new(config))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = AuthenticatedUser::from_request(&req, &mut payload).await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[actix_web::test]
    async fn malformed_authorization_header_returns_unauthorized() {
        let config = test_config();
        let req = TestRequest::default()
            .app_data(web::Data::new(config))
            .insert_header(("Authorization", "Token abc"))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = AuthenticatedUser::from_request(&req, &mut payload).await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[actix_web::test]
    async fn expired_token_returns_token_expired() {
        let config = test_config();
        let token = expired_token(&config, Uuid::new_v4());

        let req = TestRequest::default()
            .app_data(web::Data::new(config))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = AuthenticatedUser::from_request(&req, &mut payload).await;

        assert!(matches!(result, Err(AppError::TokenExpired)));
    }

    #[actix_web::test]
    async fn wrong_secret_token_returns_invalid_token() {
        let config = test_config();
        let token = wrong_secret_token(&config, Uuid::new_v4());

        let req = TestRequest::default()
            .app_data(web::Data::new(config))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_http_request();
        let mut payload = actix_web::dev::Payload::None;

        let result = AuthenticatedUser::from_request(&req, &mut payload).await;

        assert!(matches!(result, Err(AppError::InvalidToken)));
    }
}

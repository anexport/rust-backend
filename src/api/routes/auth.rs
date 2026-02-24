use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::api::routes::AppState;
use crate::config::{Auth0Config, AuthConfig};
use crate::error::{AppError, AppResult};
use crate::infrastructure::auth0_api::Auth0SignupResponse;
use crate::middleware::auth::Auth0AuthenticatedUser;
use crate::utils::auth0_claims::{Audience, Auth0Claims};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/auth0/signup", web::post().to(auth0_signup))
            .route("/auth0/login", web::post().to(auth0_login))
            .route("/me", web::get().to(me)),
    );
}

const PROVISIONING_CLAIMS_TTL_SECS: u64 = 300;
const PROVISIONING_CONTEXT_DEFAULT: &str = "auth0-signup-provisioning";

async fn me(state: web::Data<AppState>, auth: Auth0AuthenticatedUser) -> AppResult<HttpResponse> {
    let result = state.auth_service.me(auth.0.user_id).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// Auth0 Database Connection Signup
///
/// This endpoint creates a user in Auth0 using a Database Connection.
/// The user can then authenticate using /auth/auth0/login.
#[derive(Debug, Deserialize, Validate)]
struct Auth0SignupRequestDto {
    #[serde(alias = "email")]
    #[validate(length(min = 1, message = "Email is required"))]
    #[validate(email(message = "Invalid email format"))]
    email: String,
    #[serde(alias = "password")]
    password: String,
    #[serde(alias = "username")]
    username: Option<String>,
    #[serde(alias = "full_name")]
    _full_name: Option<String>,
}

async fn auth0_signup(
    state: web::Data<AppState>,
    request: HttpRequest,
    payload: web::Json<Auth0SignupRequestDto>,
) -> AppResult<HttpResponse> {
    tracing::info!(
        email = %payload.email,
        username = ?payload.username,
        "Processing Auth0 signup request"
    );

    payload.validate()?;

    // Validate password
    if payload.password.len() < 12 {
        return Err(AppError::BadRequest(format!(
            "Password is too short ({} chars). It must be at least 12 characters.",
            payload.password.len()
        )));
    }

    let ip = client_ip(&request);
    let throttle_key = crate::security::LoginThrottle::key("auth0_signup", ip.as_deref());
    state.login_throttle.ensure_allowed(&throttle_key)?;

    // Call Auth0 to create user
    let auth0_response = state
        .auth0_api_client
        .signup(
            &payload.email,
            &payload.password,
            payload.username.as_deref(),
        )
        .await
        .map_err(|e| match e {
            AppError::Conflict(_) => {
                state.login_throttle.record_failure(&throttle_key);
                AppError::Conflict("Email already registered".to_string())
            }
            _ => {
                state.login_throttle.record_failure(&throttle_key);
                e
            }
        })?;

    state.login_throttle.record_success(&throttle_key);

    // Create local user and identity using the Auth0 user ID
    // The JIT provisioning will handle this on first API call, but we create it now
    // to ensure that user record exists before they make any API calls.
    let auth0_config = request
        .app_data::<web::Data<Auth0Config>>()
        .map(web::Data::get_ref);
    let auth_config = request
        .app_data::<web::Data<AuthConfig>>()
        .map(web::Data::get_ref);
    let issued_at = chrono::Utc::now().timestamp().max(0) as u64;
    let claims = provisioning_claims(&auth0_response, auth0_config, auth_config, issued_at);

    // Use the auth service to provision the user from Auth0
    // This will create local user and auth_identity records
    state.auth_service.upsert_user_from_auth0(&claims).await?;

    // Return minimal success response
    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": auth0_response.id,
        "email": auth0_response.email,
        "email_verified": auth0_response.email_verified,
    })))
}

fn provisioning_claims(
    auth0_response: &Auth0SignupResponse,
    auth0_config: Option<&Auth0Config>,
    auth_config: Option<&AuthConfig>,
    issued_at: u64,
) -> Auth0Claims {
    let issuer = auth0_config
        .and_then(Auth0Config::issuer)
        .or_else(|| auth_config.map(|c| c.issuer.clone()))
        .unwrap_or_else(|| PROVISIONING_CONTEXT_DEFAULT.to_string());
    let audience = auth0_config
        .and_then(|c| c.auth0_audience.clone())
        .or_else(|| auth_config.map(|c| c.audience.clone()))
        .unwrap_or_else(|| PROVISIONING_CONTEXT_DEFAULT.to_string());

    Auth0Claims {
        iss: issuer,
        sub: auth0_response.id.clone(),
        aud: Audience::Single(audience),
        exp: issued_at.saturating_add(PROVISIONING_CLAIMS_TTL_SECS),
        iat: issued_at,
        email: Some(auth0_response.email.clone()),
        email_verified: Some(auth0_response.email_verified),
        name: auth0_response.name.clone(),
        picture: auth0_response.picture.clone(),
        custom_claims: std::collections::HashMap::new(),
    }
}

/// Auth0 Database Connection Login (Password Grant)
///
/// This endpoint authenticates a user using Auth0 Password Grant flow.
/// Returns Auth0 access token and ID token which can be used with the API.
#[derive(Debug, Deserialize)]
struct Auth0LoginRequestDto {
    #[serde(alias = "email")]
    email: String,
    #[serde(alias = "password")]
    password: String,
}

#[derive(Debug, Serialize)]
struct Auth0LoginResponse {
    access_token: String,
    id_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
    token_type: String,
}

async fn auth0_login(
    state: web::Data<AppState>,
    request: HttpRequest,
    payload: web::Json<Auth0LoginRequestDto>,
) -> AppResult<HttpResponse> {
    let ip = client_ip(&request);
    let throttle_key = crate::security::LoginThrottle::key(&payload.email, ip.as_deref());
    state.login_throttle.ensure_allowed(&throttle_key)?;

    // Call Auth0 to authenticate
    let auth0_response = state
        .auth0_api_client
        .password_grant(&payload.email, &payload.password)
        .await
        .inspect_err(|_| {
            let _ = state.login_throttle.record_failure(&throttle_key);
        })?;

    state.login_throttle.record_success(&throttle_key);

    let response = Auth0LoginResponse {
        access_token: auth0_response.access_token.clone(),
        id_token: auth0_response.id_token.clone(),
        refresh_token: auth0_response.refresh_token.clone(),
        expires_in: auth0_response.expires_in,
        token_type: auth0_response.token_type,
    };

    Ok(HttpResponse::Ok().json(response))
}

fn client_ip(request: &HttpRequest) -> Option<String> {
    request
        .connection_info()
        .realip_remote_addr()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::{client_ip, provisioning_claims, PROVISIONING_CLAIMS_TTL_SECS};
    use crate::config::{Auth0Config, AuthConfig};
    use crate::infrastructure::auth0_api::Auth0SignupResponse;
    use crate::utils::auth0_claims::Audience;

    #[test]
    fn client_ip_returns_none_without_forwarded_address() {
        let request = actix_web::test::TestRequest::default().to_http_request();
        assert_eq!(client_ip(&request), None);
    }

    #[test]
    fn client_ip_uses_forwarded_address_when_present() {
        let request = actix_web::test::TestRequest::default()
            .insert_header(("x-forwarded-for", "203.0.113.10"))
            .to_http_request();
        assert_eq!(client_ip(&request), Some("203.0.113.10".to_string()));
    }

    #[test]
    fn provisioning_claims_use_auth0_config_values_when_available() {
        let signup = Auth0SignupResponse {
            id: "auth0|abc".to_string(),
            email: "user@example.com".to_string(),
            email_verified: true,
            username: None,
            picture: None,
            name: Some("User".to_string()),
            created_at: None,
            updated_at: None,
        };
        let auth0_config = Auth0Config {
            auth0_domain: Some("tenant.auth0.com".to_string()),
            auth0_audience: Some("api-aud".to_string()),
            auth0_issuer: Some("https://tenant.auth0.com/".to_string()),
            jwks_cache_ttl_secs: 3600,
            auth0_client_id: None,
            auth0_client_secret: None,
            auth0_connection: "Username-Password-Authentication".to_string(),
        };

        let claims = provisioning_claims(&signup, Some(&auth0_config), None, 1_000);

        assert_eq!(claims.iss, "https://tenant.auth0.com/");
        match claims.aud {
            Audience::Single(value) => assert_eq!(value, "api-aud"),
            Audience::Multiple(_) => panic!("expected single audience"),
        }
        assert_eq!(claims.iat, 1_000);
        assert_eq!(claims.exp, 1_000 + PROVISIONING_CLAIMS_TTL_SECS);
    }

    #[test]
    fn provisioning_claims_fall_back_to_auth_config_values() {
        let signup = Auth0SignupResponse {
            id: "auth0|def".to_string(),
            email: "fallback@example.com".to_string(),
            email_verified: false,
            username: None,
            picture: None,
            name: None,
            created_at: None,
            updated_at: None,
        };
        let auth_config = AuthConfig {
            jwt_secret: "secret".to_string(),
            jwt_kid: "v1".to_string(),
            previous_jwt_secrets: Vec::new(),
            previous_jwt_kids: Vec::new(),
            jwt_expiration_seconds: 900,
            refresh_token_expiration_days: 7,
            issuer: "rust-backend-test".to_string(),
            audience: "rust-backend-client".to_string(),
        };

        let claims = provisioning_claims(&signup, None, Some(&auth_config), 42);

        assert_eq!(claims.iss, "rust-backend-test");
        match claims.aud {
            Audience::Single(value) => assert_eq!(value, "rust-backend-client"),
            Audience::Multiple(_) => panic!("expected single audience"),
        }
        assert_eq!(claims.exp, 42 + PROVISIONING_CLAIMS_TTL_SECS);
    }

    #[test]
    fn signup_request_validation_rejects_naive_at_dot_email() {
        let dto = super::Auth0SignupRequestDto {
            email: "@.".to_string(),
            password: "SecurePassword123!".to_string(),
            username: None,
            _full_name: None,
        };

        let result = validator::Validate::validate(&dto);
        assert!(result.is_err());
    }
}

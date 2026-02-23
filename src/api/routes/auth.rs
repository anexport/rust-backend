use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::api::routes::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::Auth0AuthenticatedUser;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/auth0/signup", web::post().to(auth0_signup))
            .route("/auth0/login", web::post().to(auth0_login))
            .route("/me", web::get().to(me)),
    );
}

async fn me(state: web::Data<AppState>, request: HttpRequest) -> AppResult<HttpResponse> {
    use actix_web::dev::Payload;

    // Fall back to Auth0 authentication
    let mut payload = Payload::None;
    let auth: Auth0AuthenticatedUser =
        <Auth0AuthenticatedUser as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await?;
    let result = state.auth_service.me(auth.0.user_id).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// Auth0 Database Connection Signup
///
/// This endpoint creates a user in Auth0 using a Database Connection.
/// The user can then authenticate using /auth/auth0/login.
#[derive(Debug, Deserialize)]
struct Auth0SignupRequestDto {
    #[serde(alias = "email")]
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

    // Validate email format (basic check)
    let email = &payload.email;
    if email.is_empty() {
        return Err(AppError::BadRequest("Email is required".to_string()));
    }
    if !email.contains('@') || !email.contains('.') {
        return Err(AppError::BadRequest(format!(
            "Invalid email format: '{}' (must contain '@' and '.')",
            email
        )));
    }

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
    let claims = crate::utils::auth0_claims::Auth0Claims {
        iss: "https://dev-r6elgiuf266abffs.us.auth0.com/".to_string(),
        sub: auth0_response.id.clone(),
        aud: crate::utils::auth0_claims::Audience::Single(
            "https://api.your-app.example".to_string(),
        ),
        exp: u64::MAX,
        iat: chrono::Utc::now().timestamp() as u64,
        email: Some(auth0_response.email.clone()),
        email_verified: Some(auth0_response.email_verified),
        name: auth0_response.name.clone(),
        picture: auth0_response.picture.clone(),
        custom_claims: std::collections::HashMap::new(),
    };

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
    use super::client_ip;

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
}

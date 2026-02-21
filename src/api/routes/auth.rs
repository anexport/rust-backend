use std::net::IpAddr;

use actix_governor::{Governor, GovernorConfigBuilder, KeyExtractor, SimpleKeyExtractionError};
use actix_web::dev::ServiceRequest;
use actix_web::{
    cookie::{Cookie, SameSite},
    web, HttpRequest, HttpResponse,
};
use tracing::{info, warn};
use validator::Validate;

use crate::api::dtos::{
    AuthResponse, LoginRequest, OAuthCallbackRequest, RefreshRequest, RegisterRequest,
    SessionAuthResponse,
};
use crate::api::routes::AppState;
use crate::error::{AppError, AppResult};
use crate::infrastructure::oauth::OAuthProviderKind;
use crate::middleware::auth::AuthenticatedUser;

#[derive(Clone, Copy)]
struct ClientIpExtractor;

impl KeyExtractor for ClientIpExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        if let Some(value) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
        {
            return Ok(value);
        }

        if let Some(value) = req
            .connection_info()
            .realip_remote_addr()
            .and_then(|value| value.parse::<IpAddr>().ok())
        {
            return Ok(value);
        }

        Ok(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    let auth_governor = Box::leak(Box::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(10)
            .key_extractor(ClientIpExtractor)
            .finish()
            .expect("auth governor config must be valid"),
    ));

    cfg.service(
        web::scope("/auth")
            .wrap(Governor::new(auth_governor))
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/oauth/google", web::post().to(oauth_google))
            .route("/oauth/github", web::post().to(oauth_github))
            .route("/refresh", web::post().to(refresh))
            .route("/me", web::get().to(me))
            .route("/verify-email", web::post().to(verify_email)),
    );
}

async fn register(
    state: web::Data<AppState>,
    payload: web::Json<RegisterRequest>,
) -> AppResult<HttpResponse> {
    let result = state.auth_service.register(payload.into_inner()).await?;
    Ok(HttpResponse::Created().json(result))
}

async fn login(
    state: web::Data<AppState>,
    request: HttpRequest,
    payload: web::Json<LoginRequest>,
) -> AppResult<HttpResponse> {
    let input = payload.into_inner();
    let ip = request.peer_addr().map(|addr| addr.ip().to_string());
    let key = crate::security::LoginThrottle::key(&input.email, ip.as_deref());
    state.login_throttle.ensure_allowed(&key)?;

    let issued = state
        .auth_service
        .issue_session_tokens(&input.email, &input.password, ip)
        .await
        .map_err(|error| match error {
            AppError::Unauthorized => {
                state.metrics.record_auth_failure();
                warn!(email = %input.email, "login failed");
                state.login_throttle.record_failure(&key)
            }
            other => other,
        })?;
    state.login_throttle.record_success(&key);
    info!(user_id = %issued.user.id, "login succeeded");

    let csrf_token = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok()
        .cookie(refresh_cookie(&issued.refresh_token))
        .cookie(csrf_cookie(&csrf_token))
        .json(AuthResponse {
            access_token: issued.access_token,
            user: issued.user,
        }))
}

async fn me(state: web::Data<AppState>, auth: AuthenticatedUser) -> AppResult<HttpResponse> {
    let result = state.auth_service.me(auth.0.sub).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn verify_email(
    state: web::Data<AppState>,
    auth: AuthenticatedUser,
) -> AppResult<HttpResponse> {
    state.auth_service.verify_email(auth.0.sub).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn refresh(
    state: web::Data<AppState>,
    request: HttpRequest,
    payload: Option<web::Json<RefreshRequest>>,
) -> AppResult<HttpResponse> {
    if request.cookie("refresh_token").is_some() {
        validate_csrf_cookie_request(&request)?;
    }

    let refresh_token = request
        .cookie("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| payload.as_ref().map(|json| json.refresh_token.clone()))
        .ok_or(AppError::Unauthorized)?;

    if let Some(json) = &payload {
        json.validate()?;
    }

    let ip = request.peer_addr().map(|addr| addr.ip().to_string());
    let refreshed = state
        .auth_service
        .refresh_session_tokens(&refresh_token, ip)
        .await
        .map_err(|error| {
            if matches!(error, AppError::Unauthorized) {
                state.metrics.record_auth_failure();
                warn!("refresh failed");
            }
            error
        })?;
    info!(user_id = %refreshed.user.id, "refresh succeeded");

    let csrf_token = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok()
        .cookie(refresh_cookie(&refreshed.refresh_token))
        .cookie(csrf_cookie(&csrf_token))
        .json(SessionAuthResponse {
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token,
            user: refreshed.user,
        }))
}

async fn logout(
    state: web::Data<AppState>,
    request: HttpRequest,
    payload: Option<web::Json<RefreshRequest>>,
) -> AppResult<HttpResponse> {
    if request.cookie("refresh_token").is_some() {
        validate_csrf_cookie_request(&request)?;
    }

    let refresh_token = request
        .cookie("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| payload.as_ref().map(|json| json.refresh_token.clone()))
        .ok_or(AppError::Unauthorized)?;

    if let Some(json) = &payload {
        json.validate()?;
    }

    state
        .auth_service
        .logout(&refresh_token)
        .await
        .map_err(|error| {
            if matches!(error, AppError::Unauthorized) {
                state.metrics.record_auth_failure();
                warn!("logout failed");
            }
            error
        })?;
    info!("logout succeeded");
    Ok(HttpResponse::NoContent().finish())
}

async fn oauth_google(
    state: web::Data<AppState>,
    request: HttpRequest,
    payload: web::Json<OAuthCallbackRequest>,
) -> AppResult<HttpResponse> {
    let payload = payload.into_inner();
    payload.validate()?;
    validate_oauth_state(&request, payload.state.as_deref())?;

    let ip = request.peer_addr().map(|addr| addr.ip().to_string());
    let issued = state
        .auth_service
        .oauth_login(OAuthProviderKind::Google, &payload.code, ip)
        .await?;

    let csrf_token = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok()
        .cookie(refresh_cookie(&issued.refresh_token))
        .cookie(csrf_cookie(&csrf_token))
        .json(SessionAuthResponse {
            access_token: issued.access_token,
            refresh_token: issued.refresh_token,
            user: issued.user,
        }))
}

async fn oauth_github(
    state: web::Data<AppState>,
    request: HttpRequest,
    payload: web::Json<OAuthCallbackRequest>,
) -> AppResult<HttpResponse> {
    let payload = payload.into_inner();
    payload.validate()?;
    validate_oauth_state(&request, payload.state.as_deref())?;

    let ip = request.peer_addr().map(|addr| addr.ip().to_string());
    let issued = state
        .auth_service
        .oauth_login(OAuthProviderKind::GitHub, &payload.code, ip)
        .await?;

    let csrf_token = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok()
        .cookie(refresh_cookie(&issued.refresh_token))
        .cookie(csrf_cookie(&csrf_token))
        .json(SessionAuthResponse {
            access_token: issued.access_token,
            refresh_token: issued.refresh_token,
            user: issued.user,
        }))
}

fn refresh_cookie(token: &str) -> Cookie<'static> {
    Cookie::build("refresh_token", token.to_string())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .finish()
}

fn csrf_cookie(token: &str) -> Cookie<'static> {
    Cookie::build("csrf_token", token.to_string())
        .http_only(false)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .finish()
}

fn validate_csrf_cookie_request(request: &HttpRequest) -> AppResult<()> {
    let csrf_cookie_value = request
        .cookie("csrf_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or(AppError::Unauthorized)?;
    let csrf_header = request
        .headers()
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    if csrf_cookie_value != csrf_header {
        return Err(AppError::Unauthorized);
    }

    Ok(())
}

fn validate_oauth_state(request: &HttpRequest, state: Option<&str>) -> AppResult<()> {
    let state = state.ok_or(AppError::Unauthorized)?;
    if state.is_empty() {
        return Err(AppError::Unauthorized);
    }

    if let Some(cookie_state) = request.cookie("oauth_state") {
        if cookie_state.value() != state {
            return Err(AppError::Unauthorized);
        }
    }

    Ok(())
}

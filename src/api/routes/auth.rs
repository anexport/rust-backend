use actix_web::{
    cookie::{Cookie, SameSite},
    web, HttpRequest, HttpResponse,
};
use validator::Validate;

use crate::api::dtos::{
    AuthResponse, LoginRequest, OAuthCallbackRequest, RefreshRequest, RegisterRequest,
    SessionAuthResponse,
};
use crate::api::routes::{user_id_from_header, AppState};
use crate::error::{AppError, AppResult};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
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
            AppError::Unauthorized => state.login_throttle.record_failure(&key),
            other => other,
        })?;
    state.login_throttle.record_success(&key);

    let csrf_token = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok()
        .cookie(refresh_cookie(&issued.refresh_token))
        .cookie(csrf_cookie(&csrf_token))
        .json(AuthResponse {
            access_token: issued.access_token,
            user: issued.user,
        }))
}

async fn me(state: web::Data<AppState>, request: HttpRequest) -> AppResult<HttpResponse> {
    let user_id = user_id_from_header(&request)?;
    let result = state.auth_service.me(user_id).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn verify_email(state: web::Data<AppState>, request: HttpRequest) -> AppResult<HttpResponse> {
    let user_id = user_id_from_header(&request)?;
    state.auth_service.verify_email(user_id).await?;
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
        .await?;

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

async fn logout(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    state.auth_service.logout_not_implemented()?;
    Err(AppError::BadRequest(
        "logout with session revocation is pending phase 2".to_string(),
    ))
}

async fn oauth_google(payload: web::Json<OAuthCallbackRequest>) -> AppResult<HttpResponse> {
    payload.validate()?;

    Err(AppError::BadRequest(
        "google oauth callback will be implemented in phase 2".to_string(),
    ))
}

async fn oauth_github(payload: web::Json<OAuthCallbackRequest>) -> AppResult<HttpResponse> {
    payload.validate()?;

    Err(AppError::BadRequest(
        "github oauth callback will be implemented in phase 2".to_string(),
    ))
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

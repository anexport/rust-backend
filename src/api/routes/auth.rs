use actix_web::{web, HttpRequest, HttpResponse};
use validator::Validate;

use crate::api::dtos::{LoginRequest, OAuthCallbackRequest, RegisterRequest};
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
    payload: web::Json<LoginRequest>,
) -> AppResult<HttpResponse> {
    let result = state.auth_service.login(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
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

async fn refresh(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    state.auth_service.refresh_not_implemented()?;
    Err(AppError::BadRequest(
        "refresh token flow is pending phase 2".to_string(),
    ))
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

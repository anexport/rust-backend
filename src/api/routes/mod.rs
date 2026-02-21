use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use uuid::Uuid;

use crate::application::{
    AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use crate::config::SecurityConfig;
use crate::error::{AppError, AppResult};
use crate::security::LoginThrottle;

pub mod auth;
pub mod equipment;
pub mod messages;
pub mod users;
pub mod ws;

#[derive(Clone)]
pub struct AppState {
    pub auth_service: Arc<AuthService>,
    pub user_service: Arc<UserService>,
    pub category_service: Arc<CategoryService>,
    pub equipment_service: Arc<EquipmentService>,
    pub message_service: Arc<MessageService>,
    pub security: SecurityConfig,
    pub login_throttle: Arc<LoginThrottle>,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(auth::configure)
            .configure(users::configure)
            .configure(equipment::configure)
            .configure(messages::configure),
    )
    .configure(ws::configure)
    .route("/health", web::get().to(health))
    .route("/ready", web::get().to(ready))
    .route("/metrics", web::get().to(metrics));
}

pub fn user_id_from_header(request: &HttpRequest) -> AppResult<Uuid> {
    let header = request
        .headers()
        .get("x-user-id")
        .ok_or(AppError::Unauthorized)?;

    let raw = header.to_str().map_err(|_| AppError::Unauthorized)?;
    Uuid::parse_str(raw).map_err(|_| AppError::Unauthorized)
}

async fn health() -> &'static str {
    "ok"
}

async fn ready() -> &'static str {
    "ready"
}

async fn metrics(state: web::Data<AppState>, request: HttpRequest) -> AppResult<HttpResponse> {
    if let Some(token) = state
        .security
        .metrics_admin_token
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        let admin_header = request
            .headers()
            .get("x-admin-token")
            .and_then(|value| value.to_str().ok());
        if admin_header == Some(token) {
            return Ok(HttpResponse::Ok().body("metrics-not-implemented"));
        }
    }

    if state.security.metrics_allow_private_only {
        let ip = request
            .peer_addr()
            .map(|addr| addr.ip())
            .ok_or(AppError::Unauthorized)?;

        if !is_private_or_loopback(ip) {
            return Err(AppError::Unauthorized);
        }
    }

    Ok(HttpResponse::Ok().body("metrics-not-implemented"))
}

fn is_private_or_loopback(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

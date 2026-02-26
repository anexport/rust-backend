use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};

use crate::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use crate::config::SecurityConfig;
use crate::error::{AppError, AppResult};
use crate::infrastructure::auth0_api::Auth0ApiClient;
use crate::observability::AppMetrics;
use crate::security::LoginThrottle;
use sqlx::PgPool;

pub mod admin;
pub mod auth;
pub mod equipment;
pub mod messages;
pub mod users;
pub mod ws;

#[derive(Clone)]
pub struct AppState {
    pub auth_service: Arc<AuthService>,
    pub admin_service: Arc<AdminService>,
    pub user_service: Arc<UserService>,
    pub category_service: Arc<CategoryService>,
    pub equipment_service: Arc<EquipmentService>,
    pub message_service: Arc<MessageService>,
    pub security: SecurityConfig,
    pub login_throttle: Arc<LoginThrottle>,
    pub app_environment: String,
    pub metrics: Arc<AppMetrics>,
    pub db_pool: PgPool,
    pub ws_hub: ws::WsConnectionHub,
    pub auth0_api_client: Arc<dyn Auth0ApiClient>,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .configure(auth::configure)
            .configure(admin::configure)
            .configure(users::configure)
            .configure(equipment::configure)
            .configure(messages::configure),
    )
    .configure(ws::configure)
    .route("/health", web::get().to(health))
    .route("/ready", web::get().to(ready))
    .route("/metrics", web::get().to(metrics));
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Health check passed")
    ),
    tag = "health"
)]
async fn health() -> &'static str {
    "ok"
}

#[utoipa::path(
    get,
    path = "/ready",
    responses(
        (status = 200, description = "Readiness check passed"),
        (status = 503, description = "Service not ready"),
    ),
    tag = "health"
)]
async fn ready(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db_pool)
        .await
        .map_err(|e| AppError::ServiceUnavailable {
            service: "database".to_string(),
            message: format!("Service not ready: {e}"),
        })?;
    Ok(HttpResponse::Ok().body("ready"))
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
            let (db_size, db_idle) = pool_stats(&state);
            return Ok(HttpResponse::Ok()
                .content_type("text/plain; version=0.0.4")
                .body(state.metrics.render_prometheus(db_size, db_idle)));
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

    let (db_size, db_idle) = pool_stats(&state);
    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(state.metrics.render_prometheus(db_size, db_idle)))
}

fn is_private_or_loopback(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

fn pool_stats(state: &web::Data<AppState>) -> (u32, usize) {
    (state.db_pool.size(), state.db_pool.num_idle())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn is_private_or_loopback_ipv4_private_true() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(is_private_or_loopback(ip));
    }

    #[test]
    fn is_private_or_loopback_ipv4_public_false() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!is_private_or_loopback(ip));
    }

    #[test]
    fn is_private_or_loopback_ipv6_loopback_true() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(is_private_or_loopback(ip));
    }

    #[test]
    fn is_private_or_loopback_ipv6_unique_local_true() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        assert!(is_private_or_loopback(ip));
    }
}

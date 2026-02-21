use std::sync::Arc;

use actix_web::{web, HttpRequest};
use uuid::Uuid;

use crate::application::{
    AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use crate::error::{AppError, AppResult};

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

async fn metrics() -> &'static str {
    "metrics-not-implemented"
}

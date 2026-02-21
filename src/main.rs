use std::sync::Arc;

use actix_web::{middleware::Logger, web, App, HttpServer};
use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::AppConfig;
use rust_backend::infrastructure::db::{migrations::run_migrations, pool::create_pool};
use rust_backend::infrastructure::repositories::{
    AuthRepositoryImpl, CategoryRepositoryImpl, EquipmentRepositoryImpl, MessageRepositoryImpl,
    UserRepositoryImpl,
};
use rust_backend::security::{cors_middleware, security_headers, LoginThrottle};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let config = AppConfig::from_env().expect("failed to load application configuration");

    tracing_subscriber::registry()
        .with(EnvFilter::new(config.logging.level.clone()))
        .with(
            fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true),
        )
        .init();

    let pool = create_pool(&config.database)
        .await
        .expect("failed to create database pool");

    run_migrations(&pool)
        .await
        .expect("database migrations failed");

    let user_repo = Arc::new(UserRepositoryImpl::new(pool.clone()));
    let auth_repo = Arc::new(AuthRepositoryImpl::new(pool.clone()));
    let equipment_repo = Arc::new(EquipmentRepositoryImpl::new(pool.clone()));
    let message_repo = Arc::new(MessageRepositoryImpl::new(pool.clone()));
    let category_repo = Arc::new(CategoryRepositoryImpl::new(pool));

    let state = AppState {
        auth_service: Arc::new(AuthService::new(
            user_repo.clone(),
            auth_repo,
            config.auth.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo, equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(equipment_repo)),
        message_service: Arc::new(MessageService::new(message_repo)),
        security: config.security.clone(),
        login_throttle: Arc::new(LoginThrottle::new(&config.security)),
    };

    let bind_host = config.app.host.clone();
    let bind_port = config.app.port;
    let security_config = config.security.clone();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(cors_middleware(&security_config))
            .wrap(security_headers())
            .app_data(web::Data::new(state.clone()))
            .configure(routes::configure)
    })
    .bind((bind_host, bind_port))?
    .run()
    .await
}

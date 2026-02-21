use std::sync::Arc;
use std::time::Instant;

use actix_web::dev::Service as _;
use actix_web::{middleware::Logger, web, App, HttpServer};
use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::AppConfig;
use rust_backend::infrastructure::db::{migrations::run_migrations, pool::create_pool};
use rust_backend::infrastructure::oauth::HttpOAuthClient;
use rust_backend::infrastructure::repositories::{
    AuthRepositoryImpl, CategoryRepositoryImpl, EquipmentRepositoryImpl, MessageRepositoryImpl,
    UserRepositoryImpl,
};
use rust_backend::observability::error_tracking::capture_unexpected_5xx;
use rust_backend::observability::AppMetrics;
use rust_backend::security::{cors_middleware, security_headers, LoginThrottle};
use tracing::info;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

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
    let category_repo = Arc::new(CategoryRepositoryImpl::new(pool.clone()));

    let oauth_client = Arc::new(HttpOAuthClient::new(config.oauth.clone()));
    let state = AppState {
        auth_service: Arc::new(
            AuthService::new(user_repo.clone(), auth_repo, config.auth.clone())
                .with_oauth_client(oauth_client),
        ),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo)),
        security: config.security.clone(),
        login_throttle: Arc::new(LoginThrottle::new(&config.security)),
        app_environment: config.app.environment.clone(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: Some(pool.clone()),
        ws_hub: routes::ws::WsConnectionHub::default(),
    };

    let bind_host = config.app.host.clone();
    let bind_port = config.app.port;
    let security_config = config.security.clone();
    let auth_config = config.auth.clone();
    let metrics = state.metrics.clone();

    HttpServer::new(move || {
        let metrics = metrics.clone();
        App::new()
            .wrap(Logger::default())
            .wrap_fn(move |req, srv| {
                let request_id = Uuid::new_v4().to_string();
                let path = req.path().to_string();
                let method = req.method().to_string();
                let metrics = metrics.clone();
                let start = Instant::now();

                let fut = srv.call(req);
                async move {
                    match fut.await {
                        Ok(mut response) => {
                            response.headers_mut().insert(
                                actix_web::http::header::HeaderName::from_static("x-request-id"),
                                actix_web::http::header::HeaderValue::from_str(&request_id)
                                    .unwrap_or_else(|_| {
                                        actix_web::http::header::HeaderValue::from_static(
                                            "invalid-request-id",
                                        )
                                    }),
                            );

                            let status = response.status().as_u16();
                            let latency_ms = start.elapsed().as_millis() as u64;
                            metrics.record_request(status, latency_ms);

                            info!(
                                request_id = %request_id,
                                method = %method,
                                path = %path,
                                status = status,
                                latency_ms = latency_ms,
                                "request completed"
                            );

                            if status >= 500 {
                                capture_unexpected_5xx(&path, &method, status, &request_id);
                            }
                            Ok(response)
                        }
                        Err(error) => Err(error),
                    }
                }
            })
            .wrap(cors_middleware(&security_config))
            .wrap(security_headers())
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(auth_config.clone()))
            .configure(routes::configure)
    })
    .bind((bind_host, bind_port))?
    .run()
    .await
}

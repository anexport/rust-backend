use std::sync::Arc;
use std::time::Instant;

use actix_web::dev::Service as _;
use actix_web::{middleware::Logger, web, App, HttpServer};
use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::AppConfig;
use rust_backend::infrastructure::auth0_api::{
    Auth0ApiClient, DisabledAuth0ApiClient, HttpAuth0ApiClient,
};
use rust_backend::infrastructure::db::{migrations::run_migrations, pool::create_pool};
use rust_backend::infrastructure::repositories::{
    AuthRepositoryImpl, CategoryRepositoryImpl, EquipmentRepositoryImpl, MessageRepositoryImpl,
    UserRepositoryImpl,
};
use rust_backend::middleware::auth::JitUserProvisioningService;
use rust_backend::observability::error_tracking::capture_unexpected_5xx;
use rust_backend::observability::AppMetrics;
use rust_backend::security::{cors_middleware, security_headers, LoginThrottle};
use rust_backend::utils::auth0_jwks::{Auth0JwksClient, JwksProvider};
use tracing::{error, info};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

fn build_auth0_api_client(
    auth0_config: &rust_backend::config::Auth0Config,
) -> Arc<dyn Auth0ApiClient> {
    if auth0_config.is_enabled() {
        match HttpAuth0ApiClient::new(auth0_config.clone()) {
            Ok(client) => Arc::new(client),
            Err(e) => {
                info!(
                    "Auth0 is enabled but client creation failed: {}. Using disabled client.",
                    e
                );
                Arc::new(DisabledAuth0ApiClient)
            }
        }
    } else {
        info!("Auth0 is not configured. Using disabled client.");
        Arc::new(DisabledAuth0ApiClient)
    }
}

fn build_jwks_provider(auth0_config: &rust_backend::config::Auth0Config) -> Arc<dyn JwksProvider> {
    if auth0_config.is_enabled() {
        match Auth0JwksClient::new(auth0_config) {
            Ok(client) => Arc::new(client),
            Err(e) => {
                panic!("Failed to create Auth0 JWKS client: {}", e);
            }
        }
    } else {
        panic!("Auth0 must be configured for authentication");
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let config = AppConfig::from_env().expect("failed to load application configuration");

    let dsn = config.sentry.dsn.as_deref().unwrap_or("");
    let _guard = sentry::init((dsn, sentry::ClientOptions {
        release: sentry::release_name!(),
        send_default_pii: true,
        ..Default::default()
    }));

    if config.logging.json_format {
        tracing_subscriber::registry()
            .with(EnvFilter::new(config.logging.level.clone()))
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true),
            )
            .with(sentry::integrations::tracing::layer())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(EnvFilter::new(config.logging.level.clone()))
            .with(fmt::layer())
            .with(sentry::integrations::tracing::layer())
            .init();
    }

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

    // Create Auth0 API client if configured
    let auth0_api_client = build_auth0_api_client(&config.auth0);

    // Create Auth0 JWKS client for token validation
    let jwks_client = build_jwks_provider(&config.auth0);

    // Create user provisioning service for JIT user creation
    let user_repo_for_provisioning = user_repo.clone();
    let auth_repo_for_provisioning = Arc::new(AuthRepositoryImpl::new(pool.clone()));
    let auth0_namespace = config.auth0.auth0_domain.clone().unwrap_or_default();
    let provisioning_service: Arc<dyn rust_backend::middleware::auth::UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo_for_provisioning,
            auth_repo_for_provisioning,
            auth0_namespace.clone(),
        ));

    let state = AppState {
        auth_service: Arc::new(
            AuthService::new(user_repo.clone(), auth_repo).with_auth0_namespace(auth0_namespace),
        ),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo)),
        security: config.security.clone(),
        login_throttle: Arc::new(LoginThrottle::new(&config.security)),
        app_environment: config.app.environment.clone(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: pool.clone(),
        ws_hub: routes::ws::WsConnectionHub::default(),
        auth0_api_client,
    };

    let bind_host = config.app.host.clone();
    let bind_port = config.app.port;
    let security_config = config.security.clone();
    let auth_config = config.auth.clone();
    let auth0_config = config.auth0.clone();
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
                                if let Err(capture_error) =
                                    capture_unexpected_5xx(&path, &method, status, &request_id)
                                {
                                    error!(
                                        request_id = %request_id,
                                        method = %method,
                                        path = %path,
                                        status = status,
                                        error = %capture_error,
                                        "failed to capture unexpected 5xx"
                                    );
                                }
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
            .app_data(web::Data::new(auth0_config.clone()))
            .app_data(web::Data::new(jwks_client.clone()))
            .app_data(web::Data::new(provisioning_service.clone()))
            .configure(routes::configure)
    })
    .bind((bind_host, bind_port))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::{build_auth0_api_client, build_jwks_provider};
    use rust_backend::config::Auth0Config;
    use rust_backend::error::AppError;

    fn panic_message(err: Box<dyn std::any::Any + Send>) -> String {
        match err.downcast::<String>() {
            Ok(message) => *message,
            Err(err) => match err.downcast::<&'static str>() {
                Ok(message) => (*message).to_string(),
                Err(_) => "unknown panic payload".to_string(),
            },
        }
    }

    #[actix_web::test]
    async fn build_auth0_api_client_enabled_success_uses_http_client() {
        let config = Auth0Config {
            auth0_domain: Some("tenant.example.com".to_string()),
            auth0_audience: Some("api://test".to_string()),
            auth0_client_id: None,
            ..Default::default()
        };

        let client = build_auth0_api_client(&config);
        let signup_result = client.signup("a@example.com", "Password123!", None).await;

        assert!(matches!(
            signup_result,
            Err(AppError::ServiceUnavailable { message, .. })
                if message == "AUTH0_CLIENT_ID is not configured"
        ));
    }

    #[actix_web::test]
    async fn build_auth0_api_client_enabled_failure_falls_back_to_disabled_client() {
        let config = Auth0Config {
            auth0_domain: None,
            auth0_audience: Some("api://test".to_string()),
            ..Default::default()
        };

        let client = build_auth0_api_client(&config);
        let signup_result = client.signup("a@example.com", "Password123!", None).await;

        assert!(matches!(
            signup_result,
            Err(AppError::ServiceUnavailable { message, .. })
                if message == "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE."
        ));
    }

    #[actix_web::test]
    async fn build_auth0_api_client_disabled_uses_disabled_client() {
        let config = Auth0Config::default();

        let client = build_auth0_api_client(&config);
        let signup_result = client.signup("a@example.com", "Password123!", None).await;

        assert!(matches!(
            signup_result,
            Err(AppError::ServiceUnavailable { message, .. })
                if message == "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE."
        ));
    }

    #[test]
    fn build_jwks_provider_enabled_success_builds_client() {
        let config = Auth0Config {
            auth0_domain: Some("tenant.example.com".to_string()),
            auth0_audience: Some("api://test".to_string()),
            ..Default::default()
        };

        let result = std::panic::catch_unwind(|| build_jwks_provider(&config));
        assert!(result.is_ok());
    }

    #[test]
    fn build_jwks_provider_enabled_failure_panics_when_client_creation_fails() {
        let config = Auth0Config {
            auth0_domain: None,
            auth0_audience: Some("api://test".to_string()),
            ..Default::default()
        };

        let result = std::panic::catch_unwind(|| build_jwks_provider(&config));
        assert!(result.is_err());
        let panic_payload = match result {
            Ok(_) => panic!("expected panic"),
            Err(payload) => payload,
        };
        let panic_text = panic_message(panic_payload);
        assert!(panic_text.contains("Failed to create Auth0 JWKS client"));
    }

    #[test]
    fn build_jwks_provider_disabled_panics() {
        let config = Auth0Config::default();

        let result = std::panic::catch_unwind(|| build_jwks_provider(&config));
        assert!(result.is_err());
        let panic_payload = match result {
            Ok(_) => panic!("expected panic"),
            Err(payload) => payload,
        };
        let panic_text = panic_message(panic_payload);
        assert!(panic_text.contains("Auth0 must be configured for authentication"));
    }
}

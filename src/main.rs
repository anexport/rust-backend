use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tracing::{error, info, warn};

use actix_web::dev::Service as _;
use actix_web::{middleware::Logger, web, App, HttpServer};
use rust_backend::api::openapi;
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
use rust_backend::middleware::request_logging::{
    self, get_client_ip, get_user_agent, get_user_id_from_request,
};
use rust_backend::observability::error_tracking::capture_unexpected_5xx;
use rust_backend::observability::AppMetrics;
use rust_backend::security::{
    cors_middleware, global_rate_limiting, security_headers, LoginThrottle,
};
use rust_backend::utils::auth0_jwks::{Auth0JwksClient, JwksProvider};
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

async fn handle_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(unix)]
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }

    info!("Received shutdown signal, draining connections for 30 seconds...");
}

fn build_jwks_provider(
    auth0_config: &rust_backend::config::Auth0Config,
) -> Result<Arc<dyn JwksProvider>, rust_backend::error::AppError> {
    if !auth0_config.is_enabled() {
        return Err(rust_backend::error::AppError::ServiceUnavailable {
            service: "auth0".to_string(),
            message: "Auth0 must be configured for authentication".to_string(),
        });
    }

    match Auth0JwksClient::new(auth0_config) {
        Ok(client) => Ok(Arc::new(client)),
        Err(e) => Err(rust_backend::error::AppError::InternalError(
            anyhow::anyhow!("Failed to create Auth0 JWKS client: {}", e),
        )),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let config = AppConfig::from_env().expect("failed to load application configuration");

    let dsn = config.sentry.dsn.as_deref().unwrap_or("");
    let _guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            send_default_pii: true,
            ..Default::default()
        },
    ));

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
    let jwks_client = build_jwks_provider(&config.auth0).expect("failed to create JWKS provider");

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

    let server = HttpServer::new(move || {
        let metrics = metrics.clone();
        App::new()
            .wrap(Logger::default())
            .wrap_fn(move |req, srv| {
                let request_id = Uuid::new_v4().to_string();
                let path = req.path().to_string();
                let method = req.method().to_string();
                let query = req.query_string().to_string();
                let client_ip = get_client_ip(&req);
                let user_agent = get_user_agent(&req);
                let user_id = get_user_id_from_request(&req);
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
                            let status_class = request_logging::get_status_class(status);

                            metrics.record_request(status, latency_ms);

                            // Log with enhanced context for audit trail
                            let log_level = if status >= 500 {
                                "error"
                            } else if status >= 400 {
                                "warn"
                            } else {
                                "info"
                            };

                            match log_level {
                                "error" => {
                                    error!(
                                        request_id = %request_id,
                                        user_id = %user_id,
                                        client_ip = %client_ip,
                                        user_agent = %user_agent,
                                        method = %method,
                                        path = %path,
                                        query = %query,
                                        status = status,
                                        status_class = %status_class,
                                        latency_ms = latency_ms,
                                        "request failed with server error"
                                    );
                                }
                                "warn" => {
                                    warn!(
                                        request_id = %request_id,
                                        user_id = %user_id,
                                        client_ip = %client_ip,
                                        user_agent = %user_agent,
                                        method = %method,
                                        path = %path,
                                        query = %query,
                                        status = status,
                                        status_class = %status_class,
                                        latency_ms = latency_ms,
                                        "request failed with client error"
                                    );
                                }
                                _ => {
                                    info!(
                                        request_id = %request_id,
                                        user_id = %user_id,
                                        client_ip = %client_ip,
                                        user_agent = %user_agent,
                                        method = %method,
                                        path = %path,
                                        query = %query,
                                        status = status,
                                        status_class = %status_class,
                                        latency_ms = latency_ms,
                                        "request completed"
                                    );
                                }
                            }

                            // Warn about slow requests (> 1 second)
                            if latency_ms > 1000 {
                                warn!(
                                    request_id = %request_id,
                                    path = %path,
                                    latency_ms = latency_ms,
                                    "slow request detected (>1s)"
                                );
                            }

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
                        Err(error) => {
                            error!(
                                request_id = %request_id,
                                user_id = %user_id,
                                client_ip = %client_ip,
                                user_agent = %user_agent,
                                method = %method,
                                path = %path,
                                query = %query,
                                error = %error,
                                "request failed with error"
                            );
                            Err(error)
                        }
                    }
                }
            })
            .wrap(cors_middleware(&security_config))
            .wrap(global_rate_limiting(&security_config))
            .wrap(security_headers())
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(auth_config.clone()))
            .app_data(web::Data::new(auth0_config.clone()))
            .app_data(web::Data::new(jwks_client.clone()))
            .app_data(web::Data::new(provisioning_service.clone()))
            .configure(routes::configure)
            .configure(openapi::configure_swagger_ui)
    })
    .bind((bind_host, bind_port))?
    .disable_signals()
    .shutdown_timeout(30)
    .run();

    let server_handle = server.handle();
    actix_web::rt::spawn(async move {
        handle_shutdown().await;
        server_handle.stop(true).await;
    });

    server.await
}

#[cfg(test)]
mod tests {
    use super::{build_auth0_api_client, build_jwks_provider};
    use rust_backend::config::Auth0Config;
    use rust_backend::error::AppError;

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

        let result = build_jwks_provider(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn build_jwks_provider_enabled_failure_returns_error() {
        let config = Auth0Config {
            auth0_domain: None,
            auth0_audience: Some("api://test".to_string()),
            ..Default::default()
        };

        let result = build_jwks_provider(&config);
        assert!(result.is_err());
        assert!(matches!(result, Err(AppError::InternalError(_))));
    }

    #[test]
    fn build_jwks_provider_disabled_returns_service_unavailable() {
        let config = Auth0Config::default();

        let result = build_jwks_provider(&config);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(AppError::ServiceUnavailable { service, .. }) if service == "auth0"
        ));
    }
}

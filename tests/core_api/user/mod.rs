use super::*;
use crate::common;
use actix_web::{test as actix_test, web, App};
use common::auth0_test_helpers::{test_auth0_config, MockJwksProvider, MockProvisioningService};
use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::SecurityConfig;
use rust_backend::infrastructure::auth0_api::DisabledAuth0ApiClient;
use rust_backend::infrastructure::repositories::{
    AuthRepositoryImpl, CategoryRepositoryImpl, EquipmentRepositoryImpl, MessageRepositoryImpl,
    UserRepositoryImpl,
};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_jwks::JwksProvider;
use std::sync::Arc;

pub async fn setup_app(
    db_pool: sqlx::PgPool,
) -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    let user_repo = Arc::new(UserRepositoryImpl::new(db_pool.clone()));
    let equipment_repo = Arc::new(EquipmentRepositoryImpl::new(db_pool.clone()));
    let category_repo = Arc::new(CategoryRepositoryImpl::new(db_pool.clone()));
    let auth_repo = Arc::new(AuthRepositoryImpl::new(db_pool.clone()));
    let message_repo = Arc::new(MessageRepositoryImpl::new(db_pool.clone()));

    let security = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let state = AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo.clone())),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo.clone())),
        equipment_service: Arc::new(EquipmentService::new(
            user_repo.clone(),
            equipment_repo.clone(),
        )),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo.clone())),
        security: security.clone(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(&security)),
        app_environment: "test".to_string(),
        metrics: Arc::new(rust_backend::observability::AppMetrics::default()),
        db_pool: db_pool.clone(),
        ws_hub: routes::ws::WsConnectionHub::default(),
        auth0_api_client: Arc::new(DisabledAuth0ApiClient),
    };

    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(MockJwksProvider::new());
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(MockProvisioningService {
            db_pool: db_pool.clone(),
        });

    actix_test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .app_data(web::Data::new(test_auth0_config()))
            .app_data(web::Data::new(jwks_provider))
            .app_data(web::Data::new(provisioning_service))
            .configure(routes::configure),
    )
    .await
}

pub mod equipment;
pub mod profile;

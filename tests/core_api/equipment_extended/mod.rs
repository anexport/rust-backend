use super::*;
use crate::common;
use actix_web::web;
use rust_backend::api::routes::ws::WsConnectionHub;
use rust_backend::api::routes::AppState;
use rust_backend::infrastructure::auth0_api::{Auth0ApiClient, HttpAuth0ApiClient};
use rust_backend::infrastructure::repositories::{
    AuthRepositoryImpl, CategoryRepositoryImpl, EquipmentRepositoryImpl, MessageRepositoryImpl,
    UserRepositoryImpl,
};
use std::sync::Arc;

pub use common::app_helpers::{setup_app, setup_app_with_state};
pub use common::auth0_test_helpers::create_auth0_token;
pub use common::fixtures::{
    test_equipment_basic as test_equipment, test_user_with_role as test_user,
};

pub fn security_config() -> rust_backend::config::SecurityConfig {
    rust_backend::config::SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    }
}

pub fn app_with_auth0_data(
    db_pool: sqlx::PgPool,
) -> (
    web::Data<AppState>,
    web::Data<rust_backend::config::Auth0Config>,
    web::Data<Arc<dyn rust_backend::utils::auth0_jwks::JwksProvider>>,
    web::Data<Arc<dyn rust_backend::middleware::auth::UserProvisioningService>>,
) {
    let user_repo = Arc::new(UserRepositoryImpl::new(db_pool.clone()));
    let equipment_repo = Arc::new(EquipmentRepositoryImpl::new(db_pool.clone()));
    let category_repo = Arc::new(CategoryRepositoryImpl::new(db_pool.clone()));
    let auth_repo = Arc::new(AuthRepositoryImpl::new(db_pool.clone()));
    let message_repo = Arc::new(MessageRepositoryImpl::new(db_pool.clone()));

    let security = security_config();
    let auth0_config = common::auth0_test_helpers::test_auth0_config();

    let state = AppState {
        auth_service: Arc::new(rust_backend::application::AuthService::new(
            user_repo.clone(),
            auth_repo,
        )),
        admin_service: Arc::new(rust_backend::application::AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(rust_backend::application::UserService::new(
            user_repo.clone(),
            equipment_repo.clone(),
        )),
        category_service: Arc::new(rust_backend::application::CategoryService::new(
            category_repo,
        )),
        equipment_service: Arc::new(rust_backend::application::EquipmentService::new(
            user_repo.clone(),
            equipment_repo,
        )),
        message_service: Arc::new(rust_backend::application::MessageService::new(
            user_repo,
            message_repo,
        )),
        security: security.clone(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(&security)),
        app_environment: "test".to_string(),
        metrics: Arc::new(rust_backend::observability::AppMetrics::default()),
        db_pool,
        ws_hub: WsConnectionHub::default(),
        auth0_api_client: Arc::new(HttpAuth0ApiClient::new(auth0_config.clone()).unwrap())
            as Arc<dyn Auth0ApiClient>,
    };

    (
        web::Data::new(state.clone()),
        web::Data::new(auth0_config),
        web::Data::new(
            Arc::new(common::auth0_test_helpers::MockJwksProvider::new())
                as Arc<dyn rust_backend::utils::auth0_jwks::JwksProvider>,
        ),
        web::Data::new(
            Arc::new(common::auth0_test_helpers::MockProvisioningService {
                db_pool: state.db_pool.clone(),
            }) as Arc<dyn rust_backend::middleware::auth::UserProvisioningService>,
        ),
    )
}

pub mod auth;
pub mod photos;

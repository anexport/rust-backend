#![allow(dead_code)]

use std::env;

use chrono::Utc;
use once_cell::sync::Lazy;
use rust_backend::config::AuthConfig;
use rust_backend::infrastructure::db::migrations::run_migrations;
use sqlx::postgres::{PgConnection, PgPool, PgPoolOptions};
use sqlx::Connection;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

pub mod app_helpers;
pub mod auth0_test_helpers;
pub mod fixtures;
pub mod mocks;
pub mod repository_helpers;

static TEST_DB_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub struct TestDb {
    pool: PgPool,
    url: String,
    _db_lock_conn: PgConnection,
    _lock: MutexGuard<'static, ()>,
}

impl TestDb {
    /// Creates a new test database connection.
    /// Returns `None` if DATABASE_URL is not set (skips test locally).
    /// Panics in CI environments to catch configuration issues.
    pub async fn new() -> Option<Self> {
        dotenvy::dotenv().ok();
        let url = env::var("TEST_DATABASE_URL")
            .ok()
            .or_else(|| env::var("DATABASE_URL").ok());

        let url = match url {
            Some(u) => u,
            None => {
                // In CI, panic to catch missing DB configuration
                if env::var("CI").is_ok() {
                    panic!(
                        "DATABASE_URL or TEST_DATABASE_URL not set in CI. \
                        Integration tests require a database connection."
                    );
                }
                // Locally, skip silently
                eprintln!("Skipping test: DATABASE_URL or TEST_DATABASE_URL not set (run locally)");
                return None;
            }
        };

        let lock = Lazy::force(&TEST_DB_MUTEX).lock().await;

        // Cross-process lock to serialize DB reset/migration among different test binaries.
        let mut db_lock_conn = PgConnection::connect(&url).await.ok()?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(42_i64)
            .execute(&mut db_lock_conn)
            .await
            .ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .ok()?;

        run_migrations(&pool).await.ok()?;
        reset_database(&pool).await.ok()?;

        Some(Self {
            pool,
            url,
            _db_lock_conn: db_lock_conn,
            _lock: lock,
        })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }
}

pub fn test_auth_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: "integration-secret".to_string(),
        jwt_kid: "v1".to_string(),
        previous_jwt_secrets: Vec::new(),
        previous_jwt_kids: Vec::new(),
        jwt_expiration_seconds: 900,
        refresh_token_expiration_days: 7,
        issuer: "rust-backend-test".to_string(),
        audience: "rust-backend-client".to_string(),
    }
}

#[allow(dead_code)]
pub async fn insert_owner_user(pool: &PgPool, email: &str) -> Result<Uuid, sqlx::Error> {
    let user_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO profiles (id, email, role, username, full_name, created_at, updated_at)
        VALUES ($1, $2, 'owner', $3, $4, $5, $6)
        "#,
    )
    .bind(user_id)
    .bind(email)
    .bind("phase1-owner")
    .bind("Phase1 Owner")
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(user_id)
}

pub async fn insert_category(pool: &PgPool, name: &str) -> Result<Uuid, sqlx::Error> {
    let category_id = Uuid::new_v4();
    sqlx::query("INSERT INTO categories (id, name) VALUES ($1, $2)")
        .bind(category_id)
        .bind(name)
        .execute(pool)
        .await?;
    Ok(category_id)
}

pub async fn setup_test_db() -> TestDb {
    TestDb::new().await.expect("Test DB required")
}

pub fn create_app_state(pool: PgPool) -> rust_backend::api::routes::AppState {
    use rust_backend::application::{
        AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
    };
    use rust_backend::config::SecurityConfig;
    use rust_backend::infrastructure::repositories::{
        AuthRepositoryImpl, CategoryRepositoryImpl, EquipmentRepositoryImpl, MessageRepositoryImpl,
        UserRepositoryImpl,
    };
    use rust_backend::observability::AppMetrics;
    use rust_backend::security::LoginThrottle;
    use std::sync::Arc;

    let user_repo = Arc::new(UserRepositoryImpl::new(pool.clone()));
    let auth_repo = Arc::new(AuthRepositoryImpl::new(pool.clone()));
    let equipment_repo = Arc::new(EquipmentRepositoryImpl::new(pool.clone()));
    let message_repo = Arc::new(MessageRepositoryImpl::new(pool.clone()));
    let category_repo = Arc::new(CategoryRepositoryImpl::new(pool.clone()));

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

    rust_backend::api::routes::AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo)),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo)),
        security: security.clone(),
        login_throttle: Arc::new(LoginThrottle::new(&security)),
        app_environment: "test".to_string(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: pool,
        ws_hub: rust_backend::api::routes::ws::WsConnectionHub::default(),
        auth0_api_client: Arc::new(rust_backend::infrastructure::auth0_api::DisabledAuth0ApiClient),
    }
}

async fn reset_database(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        TRUNCATE TABLE
            messages,
            conversation_participants,
            conversations,
            equipment_photos,
            equipment,
            categories,
            user_sessions,
            auth_identities,
            renter_profiles,
            owner_profiles,
            profiles
        RESTART IDENTITY CASCADE
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

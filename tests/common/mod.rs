use std::env;

use chrono::Utc;
use once_cell::sync::Lazy;
use rust_backend::config::AuthConfig;
use rust_backend::infrastructure::db::migrations::run_migrations;
use sqlx::postgres::{PgConnection, PgPool, PgPoolOptions};
use sqlx::Connection;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

pub mod fixtures;

static TEST_DB_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub struct TestDb {
    pool: PgPool,
    url: String,
    _db_lock_conn: PgConnection,
    _lock: MutexGuard<'static, ()>,
}

impl TestDb {
    pub async fn new() -> Option<Self> {
        dotenvy::dotenv().ok();
        let url = env::var("TEST_DATABASE_URL")
            .ok()
            .or_else(|| env::var("DATABASE_URL").ok())?;

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

    pub fn url(&self) -> &str {
        &self.url
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
pub async fn insert_category(pool: &PgPool, name: &str) -> Result<Uuid, sqlx::Error> {
    let category_id = Uuid::new_v4();
    sqlx::query("INSERT INTO categories (id, name) VALUES ($1, $2)")
        .bind(category_id)
        .bind(name)
        .execute(pool)
        .await?;
    Ok(category_id)
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

use super::traits::{AuthRepository, UserRepository};
use crate::domain::{AuthIdentity, User};
use crate::error::AppResult;
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

pub struct UserRepositoryImpl {
    pool: PgPool,
}

impl UserRepositoryImpl {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for UserRepositoryImpl {
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, role, username, full_name, avatar_url, created_at, updated_at FROM profiles WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, role, username, full_name, avatar_url, created_at, updated_at FROM profiles WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    async fn find_by_username(&self, username: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, role, username, full_name, avatar_url, created_at, updated_at FROM profiles WHERE username = $1"
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    async fn create(&self, user: &User) -> AppResult<User> {
        let created = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO profiles (id, email, role, username, full_name, avatar_url, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, email, role, username, full_name, avatar_url, created_at, updated_at
            "#
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(user.role)
        .bind(&user.username)
        .bind(&user.full_name)
        .bind(&user.avatar_url)
        .bind(user.created_at)
        .bind(user.updated_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(created)
    }

    async fn update(&self, user: &User) -> AppResult<User> {
        let updated = sqlx::query_as::<_, User>(
            r#"
            UPDATE profiles
            SET email = $2, role = $3, username = $4, full_name = $5, avatar_url = $6
            WHERE id = $1
            RETURNING id, email, role, username, full_name, avatar_url, created_at, updated_at
            "#,
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(user.role)
        .bind(&user.username)
        .bind(&user.full_name)
        .bind(&user.avatar_url)
        .fetch_one(&self.pool)
        .await?;
        Ok(updated)
    }

    async fn delete(&self, id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM profiles WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

pub struct AuthRepositoryImpl {
    pool: PgPool,
}

impl AuthRepositoryImpl {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthRepository for AuthRepositoryImpl {
    async fn create_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
        let created = sqlx::query_as::<_, AuthIdentity>(
            r#"
            INSERT INTO auth_identities (id, user_id, provider, provider_id, password_hash, verified, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, user_id, provider, provider_id, password_hash, verified, created_at
            "#
        )
        .bind(identity.id)
        .bind(identity.user_id)
        .bind(identity.provider)
        .bind(&identity.provider_id)
        .bind(&identity.password_hash)
        .bind(identity.verified)
        .bind(identity.created_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(created)
    }

    async fn find_identity_by_user_id(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> AppResult<Option<AuthIdentity>> {
        let identity = sqlx::query_as::<_, AuthIdentity>(
            "SELECT id, user_id, provider, provider_id, password_hash, verified, created_at FROM auth_identities WHERE user_id = $1 AND provider = $2::auth_provider"
        )
        .bind(user_id)
        .bind(provider)
        .fetch_optional(&self.pool)
        .await?;
        Ok(identity)
    }

    async fn find_identity_by_provider_id(
        &self,
        provider: &str,
        provider_id: &str,
    ) -> AppResult<Option<AuthIdentity>> {
        let identity = sqlx::query_as::<_, AuthIdentity>(
            "SELECT id, user_id, provider, provider_id, password_hash, verified, created_at FROM auth_identities WHERE provider = $1::auth_provider AND provider_id = $2"
        )
        .bind(provider)
        .bind(provider_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(identity)
    }

    async fn upsert_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
        let created = sqlx::query_as::<_, AuthIdentity>(
            r#"
            INSERT INTO auth_identities (id, user_id, provider, provider_id, password_hash, verified, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (provider, provider_id) WHERE provider_id IS NOT NULL
            DO UPDATE SET verified = EXCLUDED.verified
            RETURNING id, user_id, provider, provider_id, password_hash, verified, created_at
            "#
        )
        .bind(identity.id)
        .bind(identity.user_id)
        .bind(identity.provider)
        .bind(&identity.provider_id)
        .bind(&identity.password_hash)
        .bind(identity.verified)
        .bind(identity.created_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(created)
    }
}

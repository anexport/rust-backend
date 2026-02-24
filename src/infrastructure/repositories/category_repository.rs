use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::Category;
use crate::error::{AppError, AppResult};

use super::traits::CategoryRepository;

pub struct CategoryRepositoryImpl {
    pool: PgPool,
}

impl CategoryRepositoryImpl {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CategoryRepository for CategoryRepositoryImpl {
    async fn find_all(&self) -> AppResult<Vec<Category>> {
        let categories = sqlx::query_as::<_, Category>(
            "SELECT id, name, parent_id, created_at FROM categories ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(categories)
    }

    async fn count_all(&self) -> AppResult<i64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*)::BIGINT FROM categories")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<Category>> {
        let category = sqlx::query_as::<_, Category>(
            "SELECT id, name, parent_id, created_at FROM categories WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(category)
    }

    async fn find_children(&self, parent_id: Uuid) -> AppResult<Vec<Category>> {
        let children = sqlx::query_as::<_, Category>(
            "SELECT id, name, parent_id, created_at FROM categories WHERE parent_id = $1 ORDER BY name ASC",
        )
        .bind(parent_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(children)
    }

    async fn create(&self, category: &Category) -> AppResult<Category> {
        let created = sqlx::query_as::<_, Category>(
            r#"
            INSERT INTO categories (id, name, parent_id, created_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, parent_id, created_at
            "#,
        )
        .bind(category.id)
        .bind(&category.name)
        .bind(category.parent_id)
        .bind(category.created_at)
        .fetch_one(&self.pool)
        .await
        .map_err(map_unique_violation)?;
        Ok(created)
    }

    async fn update(&self, category: &Category) -> AppResult<Category> {
        let updated = sqlx::query_as::<_, Category>(
            r#"
            UPDATE categories
            SET name = $2, parent_id = $3
            WHERE id = $1
            RETURNING id, name, parent_id, created_at
            "#,
        )
        .bind(category.id)
        .bind(&category.name)
        .bind(category.parent_id)
        .fetch_optional(&self.pool)
        .await?;
        updated.ok_or_else(|| AppError::NotFound("category not found".to_string()))
    }

    async fn delete(&self, id: Uuid) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM categories WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_delete_fk_violation)?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("category not found".to_string()));
        }
        Ok(())
    }
}

fn map_unique_violation(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.code().as_deref() == Some("23505") {
            return AppError::Conflict("category already exists".to_string());
        }
    }

    error.into()
}

fn map_delete_fk_violation(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.code().as_deref() == Some("23503") {
            return AppError::Conflict(
                "category is still referenced by child categories or equipment".to_string(),
            );
        }
    }

    error.into()
}

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::Category;
use crate::error::AppResult;

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
}

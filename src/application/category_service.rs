use std::sync::Arc;

use uuid::Uuid;

use crate::api::dtos::CategoryResponse;
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::CategoryRepository;

#[derive(Clone)]
pub struct CategoryService {
    category_repo: Arc<dyn CategoryRepository>,
}

impl CategoryService {
    pub fn new(category_repo: Arc<dyn CategoryRepository>) -> Self {
        Self { category_repo }
    }

    pub async fn list(&self) -> AppResult<Vec<CategoryResponse>> {
        let categories = self.category_repo.find_all().await?;

        Ok(categories
            .into_iter()
            .map(|category| CategoryResponse {
                id: category.id,
                name: category.name,
                parent_id: category.parent_id,
                created_at: category.created_at,
                children: Vec::new(),
            })
            .collect())
    }

    pub async fn get_by_id(&self, id: Uuid) -> AppResult<CategoryResponse> {
        let category = self
            .category_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("category not found".to_string()))?;

        let children = self.category_repo.find_children(id).await?;

        Ok(CategoryResponse {
            id: category.id,
            name: category.name,
            parent_id: category.parent_id,
            created_at: category.created_at,
            children: children
                .into_iter()
                .map(|child| CategoryResponse {
                    id: child.id,
                    name: child.name,
                    parent_id: child.parent_id,
                    created_at: child.created_at,
                    children: Vec::new(),
                })
                .collect(),
        })
    }
}

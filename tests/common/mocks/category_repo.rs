#![allow(dead_code)]

use async_trait::async_trait;
use rust_backend::domain::Category;
use rust_backend::error::AppResult;
use rust_backend::infrastructure::repositories::CategoryRepository;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Default)]
pub struct MockCategoryRepo {
    pub categories: Mutex<Vec<Category>>,
}

#[async_trait]
impl CategoryRepository for MockCategoryRepo {
    async fn find_all(&self) -> AppResult<Vec<Category>> {
        Ok(self
            .categories
            .lock()
            .expect("categories mutex poisoned")
            .clone())
    }

    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<Category>> {
        Ok(self
            .categories
            .lock()
            .expect("categories mutex poisoned")
            .iter()
            .find(|c| c.id == id)
            .cloned())
    }

    async fn find_children(&self, parent_id: Uuid) -> AppResult<Vec<Category>> {
        Ok(self
            .categories
            .lock()
            .expect("categories mutex poisoned")
            .iter()
            .filter(|c| c.parent_id == Some(parent_id))
            .cloned()
            .collect())
    }

    async fn create(&self, category: &Category) -> AppResult<Category> {
        self.categories
            .lock()
            .expect("categories mutex poisoned")
            .push(category.clone());
        Ok(category.clone())
    }
}

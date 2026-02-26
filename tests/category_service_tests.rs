use std::sync::{Arc, Mutex};

mod common;

use crate::common::mocks::MockCategoryRepo;
use actix_rt::test;
use chrono::{Duration, Utc};
use rust_backend::application::CategoryService;
use rust_backend::domain::Category;
use uuid::Uuid;

#[test]
async fn get_by_id_returns_category_with_children() {
    let parent_id = Uuid::new_v4();
    let child_id = Uuid::new_v4();
    let created_at = Utc::now() - Duration::days(1);

    let repo = Arc::new(MockCategoryRepo {
        categories: Mutex::new(vec![
            Category {
                id: parent_id,
                name: "Audio".to_string(),
                parent_id: None,
                created_at,
            },
            Category {
                id: child_id,
                name: "Microphones".to_string(),
                parent_id: Some(parent_id),
                created_at,
            },
        ]),
    });

    let service = CategoryService::new(repo);
    let response = service
        .get_by_id(parent_id)
        .await
        .expect("category response should be returned");

    assert_eq!(response.id, parent_id);
    assert_eq!(response.children.len(), 1);
    assert_eq!(response.children[0].id, child_id);
}

#[test]
async fn list_returns_all_categories() {
    let repo = Arc::new(MockCategoryRepo {
        categories: Mutex::new(vec![
            Category {
                id: Uuid::new_v4(),
                name: "Audio".to_string(),
                parent_id: None,
                created_at: Utc::now(),
            },
            Category {
                id: Uuid::new_v4(),
                name: "Lighting".to_string(),
                parent_id: None,
                created_at: Utc::now(),
            },
        ]),
    });

    let service = CategoryService::new(repo);
    let response = service.list().await.expect("categories should be returned");

    assert_eq!(response.len(), 2);
}

use super::*;
use crate::common::fixtures;
use crate::common::fixtures::next_id;
use crate::common::repository_helpers::create_category;
use crate::common::TestDb;
use chrono::{Duration, Utc};
use rust_backend::domain::*;
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::*;
use rust_decimal::Decimal;
use uuid::Uuid;

#[tokio::test]
async fn category_repository_find_all() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let cat1 = Category {
        id: Uuid::new_v4(),
        name: "Camping".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    create_category(&db, &cat1).await.unwrap();

    let cat2 = Category {
        id: Uuid::new_v4(),
        name: "Water Sports".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    create_category(&db, &cat2).await.unwrap();

    let categories = repo.find_all().await.unwrap();
    assert_eq!(categories.len(), 2);
}

#[tokio::test]
async fn category_repository_hierarchy_queries() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let parent = Category {
        id: Uuid::new_v4(),
        name: "Water Sports".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_parent = create_category(&db, &parent).await.unwrap();

    let child1 = Category {
        id: Uuid::new_v4(),
        name: "Kayaking".to_string(),
        parent_id: Some(created_parent.id),
        created_at: Utc::now(),
    };
    create_category(&db, &child1).await.unwrap();

    let child2 = Category {
        id: Uuid::new_v4(),
        name: "Surfing".to_string(),
        parent_id: Some(created_parent.id),
        created_at: Utc::now(),
    };
    create_category(&db, &child2).await.unwrap();

    let children = repo.find_children(created_parent.id).await.unwrap();
    assert_eq!(children.len(), 2);
    assert!(children.iter().any(|c| c.name == "Kayaking"));
    assert!(children.iter().any(|c| c.name == "Surfing"));
}

#[tokio::test]
async fn category_repository_orphan_category_prevention() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let parent = Category {
        id: Uuid::new_v4(),
        name: "Water Sports".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_parent = create_category(&db, &parent).await.unwrap();

    let child = Category {
        id: Uuid::new_v4(),
        name: "Kayaking".to_string(),
        parent_id: Some(created_parent.id),
        created_at: Utc::now(),
    };
    create_category(&db, &child).await.unwrap();

    // Deleting a parent with existing children should fail due to FK enforcement.
    let delete_result = sqlx::query("DELETE FROM categories WHERE id = $1")
        .bind(created_parent.id)
        .execute(db.pool())
        .await;
    assert!(delete_result.is_err());

    // Child remains, proving orphan categories are prevented.
    let found_child = repo.find_by_id(child.id).await.unwrap();
    assert!(found_child.is_some());
}

#[tokio::test]
async fn category_repository_tree_structure_validation() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let root = Category {
        id: Uuid::new_v4(),
        name: "Outdoors".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_root = create_category(&db, &root).await.unwrap();

    let level1 = Category {
        id: Uuid::new_v4(),
        name: "Water Sports".to_string(),
        parent_id: Some(created_root.id),
        created_at: Utc::now(),
    };
    let created_level1 = create_category(&db, &level1).await.unwrap();

    let level2 = Category {
        id: Uuid::new_v4(),
        name: "Kayaking".to_string(),
        parent_id: Some(created_level1.id),
        created_at: Utc::now(),
    };
    create_category(&db, &level2).await.unwrap();

    // Verify tree structure: root has 1 child, level1 has 1 child, level2 has no children
    let root_children = repo.find_children(created_root.id).await.unwrap();
    assert_eq!(root_children.len(), 1);
    assert_eq!(root_children[0].id, created_level1.id);

    let level1_children = repo.find_children(created_level1.id).await.unwrap();
    assert_eq!(level1_children.len(), 1);
    assert_eq!(level1_children[0].id, level2.id);

    let level2_children = repo.find_children(level2.id).await.unwrap();
    assert_eq!(level2_children.len(), 0);
}

#[tokio::test]
async fn category_repository_create_duplicate_key_maps_to_conflict() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let first = Category {
        id: Uuid::new_v4(),
        name: format!("Duplicate Category {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    repo.create(&first).await.unwrap();

    let duplicate = Category {
        id: first.id,
        name: format!("Different Name {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let result = repo.create(&duplicate).await;

    assert!(matches!(
        result,
        Err(AppError::Conflict(message)) if message == "category already exists"
    ));
}

#[tokio::test]
async fn category_repository_delete_parent_with_references_maps_to_conflict() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let parent = Category {
        id: Uuid::new_v4(),
        name: format!("Parent {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_parent = repo.create(&parent).await.unwrap();

    let child = Category {
        id: Uuid::new_v4(),
        name: format!("Child {}", next_id()),
        parent_id: Some(created_parent.id),
        created_at: Utc::now(),
    };
    repo.create(&child).await.unwrap();

    let result = repo.delete(created_parent.id).await;
    assert!(matches!(
        result,
        Err(AppError::Conflict(message))
            if message == "category is still referenced by child categories or equipment"
    ));
}

// Helper function to create categories directly via SQL for testing

use std::sync::Arc;

use crate::common::mocks::MockCategoryRepo;
use actix_rt::test;
use chrono::Utc;
use rust_backend::application::validate_category_parent;
use rust_backend::domain::Category;
use rust_backend::error::AppError;
use uuid::Uuid;

fn test_category(id: Uuid, name: &str, parent_id: Option<Uuid>) -> Category {
    Category {
        id,
        name: name.to_string(),
        parent_id,
        created_at: Utc::now(),
    }
}

#[test]
async fn validate_category_parent_accepts_none_parent() {
    let repo = Arc::new(MockCategoryRepo::default());
    let category_id = Uuid::new_v4();

    let result = validate_category_parent(&*repo, Some(category_id), None).await;
    assert!(result.is_ok());
}

#[test]
async fn validate_category_parent_rejects_self_as_parent() {
    let repo = Arc::new(MockCategoryRepo::default());
    let category_id = Uuid::new_v4();

    let result = validate_category_parent(&*repo, Some(category_id), Some(category_id)).await;
    assert!(matches!(result, Err(AppError::BadRequest(_))));
    if let Err(AppError::BadRequest(msg)) = result {
        assert!(msg.contains("cannot be its own parent"));
    }
}

#[test]
async fn validate_category_parent_rejects_parent_not_found() {
    let repo = Arc::new(MockCategoryRepo::default());
    let category_id = Uuid::new_v4();
    let nonexistent_parent = Uuid::new_v4();

    let result =
        validate_category_parent(&*repo, Some(category_id), Some(nonexistent_parent)).await;
    assert!(matches!(result, Err(AppError::BadRequest(_))));
    if let Err(AppError::BadRequest(msg)) = result {
        assert!(msg.contains("parent category not found"));
    }
}

#[test]
async fn validate_category_parent_accepts_valid_parent() {
    let repo = Arc::new(MockCategoryRepo::default());
    let parent_id = Uuid::new_v4();
    let child_id = Uuid::new_v4();

    repo.categories
        .lock()
        .unwrap()
        .push(test_category(parent_id, "Parent", None));

    let result = validate_category_parent(&*repo, Some(child_id), Some(parent_id)).await;
    assert!(result.is_ok());
}

#[test]
async fn validate_category_parent_rejects_cycle_parent_to_child() {
    let repo = Arc::new(MockCategoryRepo::default());
    let parent_id = Uuid::new_v4();
    let child_id = Uuid::new_v4();

    // Create: parent <- child (child is under parent)
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(parent_id, "Parent", None));
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(child_id, "Child", Some(parent_id)));

    // Try to make parent's parent be child (creates cycle: child -> parent -> child)
    let result = validate_category_parent(&*repo, Some(parent_id), Some(child_id)).await;
    assert!(matches!(result, Err(AppError::BadRequest(_))));
    if let Err(AppError::BadRequest(msg)) = result {
        assert!(msg.contains("cycle"));
    }
}

#[test]
async fn validate_category_parent_rejects_deep_cycle() {
    let repo = Arc::new(MockCategoryRepo::default());
    let cat1 = Uuid::new_v4();
    let cat2 = Uuid::new_v4();
    let cat3 = Uuid::new_v4();

    // Create: cat1 <- cat2 <- cat3 (cat3 is child of cat2, cat2 is child of cat1)
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(cat1, "Cat1", None));
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(cat2, "Cat2", Some(cat1)));
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(cat3, "Cat3", Some(cat2)));

    // Try to make cat1's parent be cat3 (creates deep cycle: cat3 -> cat1 -> cat2 -> cat3)
    let result = validate_category_parent(&*repo, Some(cat1), Some(cat3)).await;
    assert!(matches!(result, Err(AppError::BadRequest(_))));
    if let Err(AppError::BadRequest(msg)) = result {
        assert!(msg.contains("cycle"));
    }
}

#[test]
async fn validate_category_parent_accepts_multiple_siblings() {
    let repo = Arc::new(MockCategoryRepo::default());
    let parent_id = Uuid::new_v4();
    let child1 = Uuid::new_v4();
    let child2 = Uuid::new_v4();
    let child3 = Uuid::new_v4();

    repo.categories
        .lock()
        .unwrap()
        .push(test_category(parent_id, "Parent", None));
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(child1, "Child1", Some(parent_id)));
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(child2, "Child2", Some(parent_id)));

    // Add third child
    let result = validate_category_parent(&*repo, Some(child3), Some(parent_id)).await;
    assert!(result.is_ok());
}

#[test]
async fn validate_category_parent_accepts_grandchild() {
    let repo = Arc::new(MockCategoryRepo::default());
    let parent_id = Uuid::new_v4();
    let child_id = Uuid::new_v4();
    let grandchild_id = Uuid::new_v4();

    repo.categories
        .lock()
        .unwrap()
        .push(test_category(parent_id, "Parent", None));
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(child_id, "Child", Some(parent_id)));

    // Add grandchild - should be valid
    let result = validate_category_parent(&*repo, Some(grandchild_id), Some(child_id)).await;
    assert!(result.is_ok());
}

#[test]
async fn validate_category_parent_accepts_none_category_id_with_parent() {
    let repo = Arc::new(MockCategoryRepo::default());
    let parent_id = Uuid::new_v4();

    repo.categories
        .lock()
        .unwrap()
        .push(test_category(parent_id, "Parent", None));

    // When creating a new category (category_id = None), any valid parent is OK
    let result = validate_category_parent(&*repo, None, Some(parent_id)).await;
    assert!(result.is_ok());
}

#[test]
async fn validate_category_parent_rejects_grandparent_as_parent() {
    let repo = Arc::new(MockCategoryRepo::default());
    let grandparent_id = Uuid::new_v4();
    let parent_id = Uuid::new_v4();
    let child_id = Uuid::new_v4();

    // Create: grandparent <- parent <- child (grandparent is root)
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(grandparent_id, "Grandparent", None));
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(parent_id, "Parent", Some(grandparent_id)));
    repo.categories
        .lock()
        .unwrap()
        .push(test_category(child_id, "Child", Some(parent_id)));

    // Try to make child the parent of grandparent (creates cycle: grandparent -> ... -> child -> grandparent)
    let result = validate_category_parent(&*repo, Some(grandparent_id), Some(child_id)).await;
    assert!(matches!(result, Err(AppError::BadRequest(_))));
    if let Err(AppError::BadRequest(msg)) = result {
        assert!(msg.contains("cycle"));
    }
}

use crate::common::fixtures;
use crate::common::fixtures::next_id;
use crate::common::repository_helpers::create_category;
use crate::common::TestDb;
use chrono::Utc;
use rust_backend::domain::*;
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::*;
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

#[tokio::test]
async fn category_repository_count_all_returns_zero_when_empty() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let count = repo.count_all().await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn category_repository_count_all_returns_actual_count() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let cat1 = Category {
        id: Uuid::new_v4(),
        name: format!("Category {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    repo.create(&cat1).await.unwrap();

    let cat2 = Category {
        id: Uuid::new_v4(),
        name: format!("Category {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    repo.create(&cat2).await.unwrap();

    let cat3 = Category {
        id: Uuid::new_v4(),
        name: format!("Category {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    repo.create(&cat3).await.unwrap();

    let count = repo.count_all().await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
async fn category_repository_find_by_id_returns_none_for_nonexistent() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    let found = repo.find_by_id(non_existent_id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn category_repository_find_by_id_returns_existing_category() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let category = Category {
        id: Uuid::new_v4(),
        name: format!("Test Category {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created = repo.create(&category).await.unwrap();

    let found = repo.find_by_id(created.id).await.unwrap();
    assert!(found.is_some());
    let found_category = found.unwrap();
    assert_eq!(found_category.id, created.id);
    assert_eq!(found_category.name, created.name);
    assert_eq!(found_category.parent_id, created.parent_id);
}

#[tokio::test]
async fn category_repository_create() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let category = Category {
        id: Uuid::new_v4(),
        name: format!("New Category {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };

    let created = repo.create(&category).await.unwrap();
    assert_eq!(created.id, category.id);
    assert_eq!(created.name, category.name);
    assert_eq!(created.parent_id, category.parent_id);

    let found = repo.find_by_id(created.id).await.unwrap();
    assert!(found.is_some());
}

#[tokio::test]
async fn category_repository_create_with_parent() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let parent = Category {
        id: Uuid::new_v4(),
        name: format!("Parent Category {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_parent = repo.create(&parent).await.unwrap();

    let child = Category {
        id: Uuid::new_v4(),
        name: format!("Child Category {}", next_id()),
        parent_id: Some(created_parent.id),
        created_at: Utc::now(),
    };
    let created_child = repo.create(&child).await.unwrap();

    assert_eq!(created_child.parent_id, Some(created_parent.id));

    let children = repo.find_children(created_parent.id).await.unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].id, created_child.id);
}

#[tokio::test]
async fn category_repository_update_name() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let category = Category {
        id: Uuid::new_v4(),
        name: format!("Original Name {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created = repo.create(&category).await.unwrap();

    let mut updated = created.clone();
    updated.name = "Updated Name".to_string();
    let updated_category = repo.update(&updated).await.unwrap();

    assert_eq!(updated_category.id, created.id);
    assert_eq!(updated_category.name, "Updated Name");
    assert_eq!(updated_category.parent_id, created.parent_id);

    let found = repo.find_by_id(created.id).await.unwrap().unwrap();
    assert_eq!(found.name, "Updated Name");
}

#[tokio::test]
async fn category_repository_update_parent() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let parent1 = Category {
        id: Uuid::new_v4(),
        name: format!("Parent 1 {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_parent1 = repo.create(&parent1).await.unwrap();

    let parent2 = Category {
        id: Uuid::new_v4(),
        name: format!("Parent 2 {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_parent2 = repo.create(&parent2).await.unwrap();

    let category = Category {
        id: Uuid::new_v4(),
        name: format!("Child Category {}", next_id()),
        parent_id: Some(created_parent1.id),
        created_at: Utc::now(),
    };
    let created = repo.create(&category).await.unwrap();

    // Move category from parent1 to parent2
    let mut updated = created.clone();
    updated.parent_id = Some(created_parent2.id);
    let updated_category = repo.update(&updated).await.unwrap();

    assert_eq!(updated_category.parent_id, Some(created_parent2.id));

    let children_of_parent1 = repo.find_children(created_parent1.id).await.unwrap();
    assert!(children_of_parent1.is_empty());

    let children_of_parent2 = repo.find_children(created_parent2.id).await.unwrap();
    assert_eq!(children_of_parent2.len(), 1);
}

#[tokio::test]
async fn category_repository_update_nonexistent_returns_not_found() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    let category = Category {
        id: non_existent_id,
        name: "Test Category".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };

    let result = repo.update(&category).await;
    assert!(matches!(result, Err(AppError::NotFound(_))));
}

#[tokio::test]
async fn category_repository_delete_removes_category() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let category = Category {
        id: Uuid::new_v4(),
        name: format!("Deletable Category {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created = repo.create(&category).await.unwrap();

    repo.delete(created.id).await.unwrap();

    let found = repo.find_by_id(created.id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn category_repository_delete_nonexistent_returns_not_found() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    let result = repo.delete(non_existent_id).await;
    assert!(matches!(result, Err(AppError::NotFound(_))));
}

#[tokio::test]
async fn category_repository_delete_with_equipment_returns_conflict() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(db.pool().clone());

    let owner = fixtures::test_owner();
    let created_owner = user_repo.create(&owner).await.unwrap();

    let category = Category {
        id: Uuid::new_v4(),
        name: format!("Category with Equipment {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_category = category_repo.create(&category).await.unwrap();

    let equipment = fixtures::test_equipment(created_owner.id, created_category.id);
    equipment_repo.create(&equipment).await.unwrap();

    // Deleting a category with equipment should fail
    let result = category_repo.delete(created_category.id).await;
    assert!(matches!(
        result,
        Err(AppError::Conflict(message))
            if message == "category is still referenced by child categories or equipment"
    ));
}

#[tokio::test]
async fn category_repository_find_children_of_nonexistent_returns_empty() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    let children = repo.find_children(non_existent_id).await.unwrap();
    assert!(children.is_empty());
}

// Helper function to create categories directly via SQL for testing

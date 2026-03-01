use crate::common::fixtures;
use crate::common::repository_helpers::create_category;
use crate::common::TestDb;
use chrono::Utc;
use rust_backend::domain::*;
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::*;
use uuid::Uuid;

#[tokio::test]
async fn equipment_repository_create_with_coordinates() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let mut equipment = fixtures::test_equipment(created_user.id, created_category.id);
    equipment.set_coordinates(40.7128, -74.0060).unwrap();

    let created = equipment_repo.create(&equipment).await.unwrap();

    assert_eq!(created.id, equipment.id);
    assert_eq!(created.title, equipment.title);
    // Coordinates are stored in PostGIS format, not as plain text
    // The repository returns coordinates::text which gives WKT representation
    assert!(created.coordinates.is_some());
}

#[tokio::test]
async fn equipment_repository_negative_and_edge_cases() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let owner = fixtures::test_owner();
    let created_owner = user_repo.create(&owner).await.unwrap();
    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // 1. find_by_owner/count_by_owner returns 0 for new owner
    let found = equipment_repo
        .find_by_owner(created_owner.id, 10, 0)
        .await
        .unwrap();
    assert!(found.is_empty());
    let count = equipment_repo
        .count_by_owner(created_owner.id)
        .await
        .unwrap();
    assert_eq!(count, 0);

    // 2. create with None coordinates
    let mut equipment = fixtures::test_equipment(created_owner.id, created_category.id);
    equipment.coordinates = None;
    let created = equipment_repo.create(&equipment).await.unwrap();
    assert!(created.coordinates.is_none());

    let found = equipment_repo
        .find_by_id(created.id)
        .await
        .unwrap()
        .unwrap();
    assert!(found.coordinates.is_none());

    // 3. count_by_owner returns 1 after creation
    let count = equipment_repo
        .count_by_owner(created_owner.id)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn equipment_repository_photo_crud_operations() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let equipment = fixtures::test_equipment(created_user.id, created_category.id);
    let created_equipment = equipment_repo.create(&equipment).await.unwrap();

    // Create primary photo
    let photo1 = EquipmentPhoto {
        id: Uuid::new_v4(),
        equipment_id: created_equipment.id,
        photo_url: "https://example.com/photo1.jpg".to_string(),
        is_primary: true,
        order_index: 0,
        created_at: Utc::now(),
    };
    let created_photo1 = equipment_repo.add_photo(&photo1).await.unwrap();
    assert_eq!(created_photo1.photo_url, photo1.photo_url);
    assert!(created_photo1.is_primary);

    // Create secondary photo
    let photo2 = EquipmentPhoto {
        id: Uuid::new_v4(),
        equipment_id: created_equipment.id,
        photo_url: "https://example.com/photo2.jpg".to_string(),
        is_primary: false,
        order_index: 1,
        created_at: Utc::now(),
    };
    equipment_repo.add_photo(&photo2).await.unwrap();

    // Find all photos
    let photos = equipment_repo
        .find_photos(created_equipment.id)
        .await
        .unwrap();
    assert_eq!(photos.len(), 2);
    assert!(photos.iter().any(|p| p.is_primary));

    // Delete a photo
    equipment_repo
        .delete_photo(created_photo1.id)
        .await
        .unwrap();

    let photos_after_delete = equipment_repo
        .find_photos(created_equipment.id)
        .await
        .unwrap();
    assert_eq!(photos_after_delete.len(), 1);
    assert_eq!(photos_after_delete[0].photo_url, photo2.photo_url);
}

#[tokio::test]
async fn equipment_repository_hard_delete() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let equipment = fixtures::test_equipment(created_user.id, created_category.id);
    let created = equipment_repo.create(&equipment).await.unwrap();

    // Verify equipment exists
    let found = equipment_repo.find_by_id(created.id).await.unwrap();
    assert!(found.is_some());

    // Hard delete
    equipment_repo.delete(created.id).await.unwrap();

    // Verify equipment is gone
    let found = equipment_repo.find_by_id(created.id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn equipment_repository_set_availability_atomic_updates_state() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let mut equipment = fixtures::test_equipment(created_user.id, created_category.id);
    equipment.is_available = true;
    let created = equipment_repo.create(&equipment).await.unwrap();

    let updated = equipment_repo
        .set_availability_atomic(created.id, false)
        .await
        .unwrap();
    assert!(!updated);

    let found = equipment_repo
        .find_by_id(created.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!found.is_available);
}

#[tokio::test]
async fn equipment_repository_set_availability_atomic_not_found() {
    let db = TestDb::new().await.expect("Test DB required");
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    let result = equipment_repo
        .set_availability_atomic(non_existent_id, true)
        .await;
    assert!(matches!(result, Err(AppError::NotFound(_))));
}

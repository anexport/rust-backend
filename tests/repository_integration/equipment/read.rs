use crate::common::fixtures;
use crate::common::repository_helpers::create_category;
use crate::common::TestDb;
use chrono::Utc;
use rust_backend::domain::EquipmentPhoto;
use rust_backend::infrastructure::repositories::*;
use uuid::Uuid;

#[tokio::test]
async fn equipment_repository_find_all() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // Create 3 equipment items
    for i in 0..3 {
        let mut eq = fixtures::test_equipment(created_user.id, created_category.id);
        eq.title = format!("Equipment {}", i);
        equipment_repo.create(&eq).await.unwrap();
    }

    let all_equipment = equipment_repo.find_all(10, 0).await.unwrap();
    assert_eq!(all_equipment.len(), 3);
}

#[tokio::test]
async fn equipment_repository_find_all_with_pagination() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // Create 15 equipment items
    for i in 0..15 {
        let mut eq = fixtures::test_equipment(created_user.id, created_category.id);
        eq.title = format!("Equipment {}", i);
        equipment_repo.create(&eq).await.unwrap();
    }

    let page1 = equipment_repo.find_all(10, 0).await.unwrap();
    assert_eq!(page1.len(), 10);

    let page2 = equipment_repo.find_all(10, 10).await.unwrap();
    assert_eq!(page2.len(), 5);
}

#[tokio::test]
async fn equipment_repository_list_all_with_owner() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_owner();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_owner();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let mut eq1 = fixtures::test_equipment(created_user1.id, created_category.id);
    eq1.title = "Equipment 1".to_string();
    equipment_repo.create(&eq1).await.unwrap();

    let mut eq2 = fixtures::test_equipment(created_user1.id, created_category.id);
    eq2.title = "Equipment 2".to_string();
    equipment_repo.create(&eq2).await.unwrap();

    let mut eq3 = fixtures::test_equipment(created_user2.id, created_category.id);
    eq3.title = "Equipment 3".to_string();
    equipment_repo.create(&eq3).await.unwrap();

    let with_owner = equipment_repo
        .list_all_with_owner(10, 0, None)
        .await
        .unwrap();
    assert_eq!(with_owner.len(), 3);
    assert!(with_owner
        .iter()
        .any(|e| e.owner_email == created_user1.email));
    assert!(with_owner
        .iter()
        .any(|e| e.owner_email == created_user2.email));
}

#[tokio::test]
async fn equipment_repository_list_all_with_owner_search() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let mut eq1 = fixtures::test_equipment(created_user.id, created_category.id);
    eq1.title = "Digital Camera".to_string();
    equipment_repo.create(&eq1).await.unwrap();

    let mut eq2 = fixtures::test_equipment(created_user.id, created_category.id);
    eq2.title = "Video Camera".to_string();
    equipment_repo.create(&eq2).await.unwrap();

    let mut eq3 = fixtures::test_equipment(created_user.id, created_category.id);
    eq3.title = "Tripod".to_string();
    equipment_repo.create(&eq3).await.unwrap();

    let camera_results = equipment_repo
        .list_all_with_owner(10, 0, Some("camera"))
        .await
        .unwrap();
    assert_eq!(camera_results.len(), 2);
    assert!(camera_results.iter().all(|e| e.title.contains("Camera")));
}

#[tokio::test]
async fn equipment_repository_update_photo() {
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

    let photo = EquipmentPhoto {
        id: Uuid::new_v4(),
        equipment_id: created_equipment.id,
        photo_url: "https://example.com/original.jpg".to_string(),
        is_primary: true,
        order_index: 0,
        created_at: Utc::now(),
    };
    let created_photo = equipment_repo.add_photo(&photo).await.unwrap();

    // Update photo
    let mut updated_photo = created_photo.clone();
    updated_photo.photo_url = "https://example.com/updated.jpg".to_string();
    updated_photo.is_primary = false;
    updated_photo.order_index = 5;

    let updated = equipment_repo.update_photo(&updated_photo).await.unwrap();
    assert_eq!(updated.photo_url, "https://example.com/updated.jpg");
    assert!(!updated.is_primary);
    assert_eq!(updated.order_index, 5);
}

#[tokio::test]
async fn equipment_repository_find_photo_by_id() {
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

    let photo = EquipmentPhoto {
        id: Uuid::new_v4(),
        equipment_id: created_equipment.id,
        photo_url: "https://example.com/photo.jpg".to_string(),
        is_primary: true,
        order_index: 0,
        created_at: Utc::now(),
    };
    let created_photo = equipment_repo.add_photo(&photo).await.unwrap();

    let found = equipment_repo
        .find_photo_by_id(created_photo.id)
        .await
        .unwrap();
    assert!(found.is_some());
    let found_photo = found.unwrap();
    assert_eq!(found_photo.id, created_photo.id);
    assert_eq!(found_photo.photo_url, "https://example.com/photo.jpg");

    // Test non-existent photo
    let not_found = equipment_repo
        .find_photo_by_id(Uuid::new_v4())
        .await
        .unwrap();
    assert!(not_found.is_none());
}

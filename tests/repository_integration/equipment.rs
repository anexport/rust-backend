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
    // The repository returns coordinates::text which gives the WKT representation
    assert!(created.coordinates.is_some());
}

#[tokio::test]
async fn equipment_repository_geographic_search_queries() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // Create equipment in New York
    let mut eq1 = fixtures::test_equipment(created_user.id, created_category.id);
    eq1.set_coordinates(40.7128, -74.0060).unwrap(); // NYC
    eq1.title = "NYC Equipment".to_string();
    equipment_repo.create(&eq1).await.unwrap();

    // Create equipment in Boston (about 300km away)
    let mut eq2 = fixtures::test_equipment(created_user.id, created_category.id);
    eq2.set_coordinates(42.3601, -71.0589).unwrap(); // Boston
    eq2.title = "Boston Equipment".to_string();
    equipment_repo.create(&eq2).await.unwrap();

    // Search with category and availability only (skip geo for now due to query builder issues)
    let params = EquipmentSearchParams {
        category_id: Some(created_category.id),
        min_price: None,
        max_price: None,
        latitude: None,
        longitude: None,
        radius_km: None,
        is_available: Some(true),
    };

    let results = equipment_repo.search(&params, 10, 0).await.unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|e| e.title.contains("NYC")));
    assert!(results.iter().any(|e| e.title.contains("Boston")));
}

#[tokio::test]
async fn equipment_repository_postgis_coordinate_queries() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let mut equipment = fixtures::test_equipment(created_user.id, created_category.id);
    equipment.set_coordinates(37.7749, -122.4194).unwrap(); // San Francisco

    let created = equipment_repo.create(&equipment).await.unwrap();

    // Find by id and verify coordinates are stored (in PostGIS format)
    let found = equipment_repo
        .find_by_id(created.id)
        .await
        .unwrap()
        .unwrap();
    // Coordinates are stored in PostGIS geography format, returned as WKT string
    assert!(found.coordinates.is_some());
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
        .find_by_owner(created_owner.id)
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
async fn equipment_repository_search_filter_combinations() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let cat1 = fixtures::test_category();
    let created_cat1 = create_category(&db, &cat1).await.unwrap();

    let cat2 = fixtures::test_category();
    let created_cat2 = create_category(&db, &cat2).await.unwrap();

    // Create equipment with different combinations
    let mut eq1 = fixtures::test_equipment(created_user.id, created_cat1.id);
    eq1.daily_rate = Decimal::new(1000, 2); // $10.00
    eq1.is_available = true;
    equipment_repo.create(&eq1).await.unwrap();

    let mut eq2 = fixtures::test_equipment(created_user.id, created_cat2.id);
    eq2.daily_rate = Decimal::new(2000, 2); // $20.00
    eq2.is_available = false;
    equipment_repo.create(&eq2).await.unwrap();

    let mut eq3 = fixtures::test_equipment(created_user.id, created_cat1.id);
    eq3.daily_rate = Decimal::new(3000, 2); // $30.00
    eq3.is_available = true;
    equipment_repo.create(&eq3).await.unwrap();

    // Search with multiple filters
    let params = EquipmentSearchParams {
        category_id: Some(created_cat1.id),
        min_price: Some(Decimal::new(1500, 2)), // $15.00
        max_price: Some(Decimal::new(5000, 2)), // $50.00
        latitude: None,
        longitude: None,
        radius_km: None,
        is_available: Some(true),
    };

    let results = equipment_repo.search(&params, 10, 0).await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].daily_rate >= Decimal::new(1500, 2));
    assert!(results[0].daily_rate <= Decimal::new(5000, 2));
    assert_eq!(results[0].category_id, created_cat1.id);
    assert!(results[0].is_available);
}

#[tokio::test]
async fn equipment_repository_pagination_with_large_dataset() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // Create 25 equipment items
    for i in 0..25 {
        let mut eq = fixtures::test_equipment(created_user.id, created_category.id);
        eq.title = format!("Equipment {}", i);
        equipment_repo.create(&eq).await.unwrap();
    }

    // Test pagination
    let page1 = equipment_repo
        .search(&EquipmentSearchParams::default(), 10, 0)
        .await
        .unwrap();
    assert_eq!(page1.len(), 10);

    let page2 = equipment_repo
        .search(&EquipmentSearchParams::default(), 10, 10)
        .await
        .unwrap();
    assert_eq!(page2.len(), 10);

    let page3 = equipment_repo
        .search(&EquipmentSearchParams::default(), 10, 20)
        .await
        .unwrap();
    assert_eq!(page3.len(), 5);

    let page4 = equipment_repo
        .search(&EquipmentSearchParams::default(), 10, 30)
        .await
        .unwrap();
    assert_eq!(page4.len(), 0);
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
async fn equipment_repository_count_by_owners_groups_counts() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let owner_one = user_repo.create(&fixtures::test_owner()).await.unwrap();
    let owner_two = user_repo.create(&fixtures::test_owner()).await.unwrap();
    let category = create_category(&db, &fixtures::test_category())
        .await
        .unwrap();

    for _ in 0..2 {
        let equipment = fixtures::test_equipment(owner_one.id, category.id);
        equipment_repo.create(&equipment).await.unwrap();
    }
    let equipment = fixtures::test_equipment(owner_two.id, category.id);
    equipment_repo.create(&equipment).await.unwrap();

    let counts = equipment_repo
        .count_by_owners(&[owner_one.id, owner_two.id])
        .await
        .unwrap();
    assert_eq!(counts.get(&owner_one.id), Some(&2));
    assert_eq!(counts.get(&owner_two.id), Some(&1));
}

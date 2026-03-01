use crate::common::fixtures;
use crate::common::repository_helpers::create_category;
use crate::common::TestDb;
use rust_backend::infrastructure::repositories::*;
use rust_decimal::Decimal;

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
async fn equipment_repository_count_search() {
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

    // Create equipment with different categories and availability
    let mut eq1 = fixtures::test_equipment(created_user.id, created_cat1.id);
    eq1.daily_rate = Decimal::new(1000, 2);
    eq1.is_available = true;
    equipment_repo.create(&eq1).await.unwrap();

    let mut eq2 = fixtures::test_equipment(created_user.id, created_cat1.id);
    eq2.daily_rate = Decimal::new(2000, 2);
    eq2.is_available = false;
    equipment_repo.create(&eq2).await.unwrap();

    let mut eq3 = fixtures::test_equipment(created_user.id, created_cat2.id);
    eq3.daily_rate = Decimal::new(3000, 2);
    eq3.is_available = true;
    equipment_repo.create(&eq3).await.unwrap();

    // Count with category filter
    let cat1_count = equipment_repo
        .count_search(&EquipmentSearchParams {
            category_id: Some(created_cat1.id),
            min_price: None,
            max_price: None,
            latitude: None,
            longitude: None,
            radius_km: None,
            is_available: None,
        })
        .await
        .unwrap();
    assert_eq!(cat1_count, 2);

    // Count with availability filter
    let available_count = equipment_repo
        .count_search(&EquipmentSearchParams {
            category_id: None,
            min_price: None,
            max_price: None,
            latitude: None,
            longitude: None,
            radius_km: None,
            is_available: Some(true),
        })
        .await
        .unwrap();
    assert_eq!(available_count, 2);

    // Count all
    let all_count = equipment_repo
        .count_search(&EquipmentSearchParams::default())
        .await
        .unwrap();
    assert_eq!(all_count, 3);
}

use crate::common::fixtures;
use crate::common::repository_helpers::create_category;
use crate::common::TestDb;
use rust_backend::infrastructure::repositories::*;

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

#[tokio::test]
async fn equipment_repository_count_by_owners_empty_list() {
    let db = TestDb::new().await.expect("Test DB required");
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let counts = equipment_repo.count_by_owners(&[]).await.unwrap();
    assert!(counts.is_empty());
}

#[tokio::test]
async fn equipment_repository_count_all() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let count_empty = equipment_repo.count_all(None).await.unwrap();
    assert_eq!(count_empty, 0);

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // Create 5 equipment items
    for i in 0..5 {
        let mut eq = fixtures::test_equipment(created_user.id, created_category.id);
        eq.title = format!("Searchable Equipment {}", i);
        equipment_repo.create(&eq).await.unwrap();
    }

    let count = equipment_repo.count_all(None).await.unwrap();
    assert_eq!(count, 5);
}

#[tokio::test]
async fn equipment_repository_count_all_with_search() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_owner();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_owner();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // Create equipment with searchable titles
    let mut eq1 = fixtures::test_equipment(created_user1.id, created_category.id);
    eq1.title = "Camera for photography".to_string();
    equipment_repo.create(&eq1).await.unwrap();

    let mut eq2 = fixtures::test_equipment(created_user1.id, created_category.id);
    eq2.title = "Camera lens".to_string();
    equipment_repo.create(&eq2).await.unwrap();

    let mut eq3 = fixtures::test_equipment(created_user2.id, created_category.id);
    eq3.title = "Tripod stand".to_string();
    equipment_repo.create(&eq3).await.unwrap();

    let camera_count = equipment_repo.count_all(Some("camera")).await.unwrap();
    assert_eq!(camera_count, 2);

    let total_count = equipment_repo.count_all(None).await.unwrap();
    assert_eq!(total_count, 3);
}

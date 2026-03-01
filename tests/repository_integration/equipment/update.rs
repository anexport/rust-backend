use crate::common::fixtures;
use crate::common::repository_helpers::create_category;
use crate::common::TestDb;
use rust_backend::domain::*;
use rust_backend::infrastructure::repositories::*;
use rust_decimal::Decimal;

#[tokio::test]
async fn equipment_repository_update() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let mut equipment = fixtures::test_equipment(created_user.id, created_category.id);
    let created = equipment_repo.create(&equipment).await.unwrap();

    equipment.title = "Updated Title".to_string();
    equipment.description = Some("Updated Description".to_string());
    equipment.daily_rate = Decimal::new(2500, 2);
    equipment.condition = Condition::Excellent;
    equipment.location = Some("Updated Location".to_string());
    equipment.is_available = false;

    let updated = equipment_repo.update(&equipment).await.unwrap();
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.title, "Updated Title");
    assert_eq!(updated.description, Some("Updated Description".to_string()));
    assert_eq!(updated.daily_rate, Decimal::new(2500, 2));
    assert_eq!(updated.condition, Condition::Excellent);
    assert_eq!(updated.location, Some("Updated Location".to_string()));
    assert!(!updated.is_available);

    // Verify persisted
    let found = equipment_repo
        .find_by_id(created.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.title, "Updated Title");
    assert_eq!(found.description, Some("Updated Description".to_string()));
}

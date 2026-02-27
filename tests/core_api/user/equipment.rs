use super::setup_app;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test};
use chrono::{Duration, Utc};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::infrastructure::repositories::{
    CategoryRepository, CategoryRepositoryImpl, EquipmentRepository, EquipmentRepositoryImpl,
    UserRepository, UserRepositoryImpl,
};
use uuid::Uuid;

#[actix_rt::test]
async fn test_my_equipment_unauthorized() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/users/me/equipment")
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_my_equipment_listing() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let other_owner = fixtures::test_owner();
    user_repo.create(&other_owner).await.unwrap();

    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    // Owner has 2 items
    let eq1 = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq1).await.unwrap();
    let eq2 = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq2).await.unwrap();

    // Other owner has 1 item
    let eq3 = fixtures::test_equipment(other_owner.id, cat.id);
    equipment_repo.create(&eq3).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/users/me/equipment")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let items: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i["owner_id"] == owner.id.to_string()));
}

#[actix_rt::test]
async fn test_my_equipment_ordered_by_creation_date() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    // Create equipment with different timestamps
    for i in 0..3 {
        let mut eq = fixtures::test_equipment(owner.id, cat.id);
        eq.title = format!("Equipment {}", i);
        eq.created_at = Utc::now() + Duration::minutes(i);
        equipment_repo.create(&eq).await.unwrap();
    }

    let token = create_auth0_token(owner.id, "owner");
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/users/me/equipment")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    let items: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;

    // Should be newest first
    assert_eq!(items[0]["title"], "Equipment 2");
    assert_eq!(items[1]["title"], "Equipment 1");
    assert_eq!(items[2]["title"], "Equipment 0");
}

#[actix_rt::test]
async fn test_my_equipment_pagination() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    // Create 15 equipment items with explicit timestamps to avoid race conditions
    let equipment_count = 15;
    for i in 0..equipment_count {
        let mut eq = fixtures::test_equipment(owner.id, cat.id);
        eq.title = format!("Equipment {}", i);
        eq.created_at = Utc::now() + Duration::minutes(i);
        equipment_repo.create(&eq).await.unwrap();
    }

    let token = create_auth0_token(owner.id, "owner");

    // Test that all items are returned (current behavior)
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/users/me/equipment")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let items: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;

    // Assert total count is 15
    assert_eq!(items.len(), equipment_count as usize);

    // Verify all items belong to the owner
    assert!(items.iter().all(|i| i["owner_id"] == owner.id.to_string()));

    // Verify ordering is by creation date (newest first based on SQL)
    assert_eq!(
        items[0]["title"],
        format!("Equipment {}", equipment_count - 1)
    );
    assert_eq!(
        items[equipment_count as usize - 1]["title"],
        format!("Equipment {}", 0)
    );
}

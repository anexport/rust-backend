use super::setup_app;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::infrastructure::repositories::{
    CategoryRepository, CategoryRepositoryImpl, EquipmentRepository, EquipmentRepositoryImpl,
    UserRepository, UserRepositoryImpl,
};

#[actix_rt::test]
async fn test_admin_toggle_foreign_equipment_availability() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/equipment/{}/availability", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "is_available": false }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated_eq = equipment_repo.find_by_id(eq.id).await.unwrap().unwrap();
    assert!(!updated_eq.is_available);
}

#[actix_rt::test]
async fn test_equipment_management_flow() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    // 1. Toggle availability
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/equipment/{}/availability", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "is_available": false }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated_eq = equipment_repo.find_by_id(eq.id).await.unwrap().unwrap();
    assert!(!updated_eq.is_available);

    // 2. Force delete equipment
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/admin/equipment/{}", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let deleted_eq = equipment_repo.find_by_id(eq.id).await.unwrap();
    assert!(deleted_eq.is_none());
}

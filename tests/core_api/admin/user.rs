use super::setup_app;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::domain::Role;
use rust_backend::infrastructure::repositories::{
    CategoryRepository, CategoryRepositoryImpl, EquipmentRepository, EquipmentRepositoryImpl,
    UserRepository, UserRepositoryImpl,
};
use uuid::Uuid;

#[actix_rt::test]
async fn test_admin_cannot_demote_self() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    // Try to demote self to renter
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/users/{}/role", admin.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "role": "renter" }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Verify still admin
    let user = user_repo.find_by_id(admin.id).await.unwrap().unwrap();
    assert_eq!(user.role, Role::Admin);
}

#[actix_rt::test]
async fn test_admin_update_role_owner_to_admin() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/users/{}/role", owner.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "role": "admin" }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(owner.id).await.unwrap().unwrap();
    assert_eq!(updated.role, Role::Admin);
}

#[actix_rt::test]
async fn test_user_management_flow() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let renter = fixtures::test_user();
    user_repo.create(&renter).await.unwrap();

    // 1. List users
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/users")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let list: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(list["total"], 2);

    // 2. Update role (renter -> owner)
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/users/{}/role", renter.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "role": "owner" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated_user = user_repo.find_by_id(renter.id).await.unwrap().unwrap();
    assert_eq!(updated_user.role, Role::Owner);

    // 3. Delete user
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/admin/users/{}", renter.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let deleted_user = user_repo.find_by_id(renter.id).await.unwrap();
    assert!(deleted_user.is_none());
}

#[actix_rt::test]
async fn test_get_user_detail_by_id() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let renter = fixtures::test_user();
    user_repo.create(&renter).await.unwrap();

    // Get user detail
    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/admin/users/{}", renter.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let detail: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(detail["id"], renter.id.to_string());
    assert_eq!(detail["email"], renter.email);

    // Non-existent user
    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/admin/users/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn test_user_list_pagination() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    // Create 11 more users (total 12)
    for _ in 0..11 {
        let u = fixtures::test_user();
        user_repo.create(&u).await.unwrap();
    }

    // Page 1
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/users?page=1&per_page=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let page1: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(page1["users"].as_array().unwrap().len(), 5);
    assert_eq!(page1["total"], 12);

    // Page 2
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/users?page=2&per_page=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let page2: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(page2["users"].as_array().unwrap().len(), 5);

    // Page 3
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/users?page=3&per_page=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let page3: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(page3["users"].as_array().unwrap().len(), 2);
}

#[actix_rt::test]
async fn test_delete_user_cascades_to_equipment() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
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

    // Delete user
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/admin/users/{}", owner.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let status = resp.status();
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify equipment is also gone
    let deleted_eq = equipment_repo.find_by_id(eq.id).await.unwrap();
    assert!(deleted_eq.is_none());
}

#[actix_rt::test]
async fn test_admin_can_demote_other_admin_role() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin1 = fixtures::test_admin();
    user_repo.create(&admin1).await.unwrap();
    let admin2 = fixtures::test_admin();
    user_repo.create(&admin2).await.unwrap();

    let token1 = create_auth0_token(admin1.id, "admin");

    // Try to change admin2's role to renter
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/users/{}/role", admin2.id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({ "role": "renter" }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(admin2.id).await.unwrap().unwrap();
    assert_eq!(updated.role, Role::Renter);
}

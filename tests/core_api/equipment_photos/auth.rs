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
use uuid::Uuid;

#[actix_rt::test]
async fn test_equipment_photo_authorization() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    let other_user = fixtures::test_user();
    let admin = fixtures::test_admin();
    user_repo.create(&owner).await.unwrap();
    user_repo.create(&other_user).await.unwrap();
    user_repo.create(&admin).await.unwrap();

    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let owner_token = create_auth0_token(owner.id, "owner");
    let other_token = create_auth0_token(other_user.id, "renter");
    let admin_token = create_auth0_token(admin.id, "admin");

    // 1. Other user cannot add photo
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", other_token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/hacker.jpg",
            "is_primary": true
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Owner can add photo
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", owner_token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/owner.jpg",
            "is_primary": true
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let photo: serde_json::Value = actix_test::read_body_json(resp).await;
    let photo_id = Uuid::parse_str(photo["id"].as_str().unwrap()).unwrap();

    // 3. Admin can add photo
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/admin.jpg",
            "is_primary": false
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Other user cannot delete photo
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq.id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", other_token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 5. Owner can delete photo
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq.id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", owner_token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

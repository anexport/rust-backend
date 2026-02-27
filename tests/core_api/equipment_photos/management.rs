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
async fn test_equipment_multiple_photos() {
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
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");

    // Add 3 photos
    for i in 1..=3 {
        let req = actix_test::TestRequest::post()
            .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(serde_json::json!({
                "photo_url": format!("https://example.com/p{}.jpg", i),
                "is_primary": i == 1
            }))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert_eq!(photos.len(), 3);
}

#[actix_rt::test]
async fn test_admin_photo_management() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    let admin = fixtures::test_admin();
    user_repo.create(&owner).await.unwrap();
    user_repo.create(&admin).await.unwrap();

    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let admin_token = create_auth0_token(admin.id, "admin");

    // Admin adds photo to owner's equipment
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/admin_added.jpg",
            "is_primary": false
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let photo: serde_json::Value = actix_test::read_body_json(resp).await;
    let photo_id = Uuid::parse_str(photo["id"].as_str().unwrap()).unwrap();

    // Admin deletes photo
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq.id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[actix_rt::test]
async fn test_photo_persistence_verification() {
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
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");
    let photo_url = "https://example.com/persistence_test.jpg";

    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "photo_url": photo_url,
            "is_primary": true
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify in DB
    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert_eq!(photos.len(), 1);
    assert_eq!(photos[0].photo_url, photo_url);
}

#[actix_rt::test]
async fn test_photo_associated_with_correct_equipment() {
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

    let eq1 = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq1).await.unwrap();
    let eq2 = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq2).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");

    // Add photo to eq1
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq1.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/eq1.jpg",
            "is_primary": true
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify eq2 has NO photos
    let photos2 = equipment_repo.find_photos(eq2.id).await.unwrap();
    assert!(photos2.is_empty());
}

#[actix_rt::test]
async fn test_delete_photo_leaves_other_photos_intact() {
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
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");

    // Add 3 photos
    let mut photo_ids = Vec::new();
    for i in 1..=3 {
        let req = actix_test::TestRequest::post()
            .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(serde_json::json!({
                "photo_url": format!("https://example.com/intact{}.jpg", i),
                "is_primary": i == 1
            }))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        let photo: serde_json::Value = actix_test::read_body_json(resp).await;
        photo_ids.push(Uuid::parse_str(photo["id"].as_str().unwrap()).unwrap());
    }

    // Delete 1 photo
    let req = actix_test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/equipment/{}/photos/{}",
            eq.id, photo_ids[0]
        ))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify 2 remaining
    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert_eq!(photos.len(), 2);
    assert!(!photos.iter().any(|p| p.id == photo_ids[0]));
    assert!(photos.iter().any(|p| p.id == photo_ids[1]));
    assert!(photos.iter().any(|p| p.id == photo_ids[2]));
}

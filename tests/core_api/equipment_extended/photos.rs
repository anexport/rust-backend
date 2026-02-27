use super::*;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test, App};
use chrono::Utc;
use rust_backend::api::routes;
use rust_backend::domain::{EquipmentPhoto, Role};
use rust_backend::infrastructure::repositories::{
    CategoryRepositoryImpl, EquipmentRepositoryImpl, UserRepositoryImpl,
};
use uuid::Uuid;

#[actix_rt::test]
async fn add_photo_success() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(pool.clone());

    let user_repo = UserRepositoryImpl::new(pool.clone());
    let equipment_repo = EquipmentRepositoryImpl::new(pool.clone());
    let category_repo = CategoryRepositoryImpl::new(pool.clone());

    let cat = common::fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    let owner_id = Uuid::new_v4();
    user_repo
        .create(&test_user(owner_id, Role::Owner, "o@e.c"))
        .await
        .unwrap();
    let mut eq = test_equipment(Uuid::new_v4(), owner_id);
    eq.category_id = cat.id;
    equipment_repo.create(&eq).await.unwrap();

    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(owner_id, "owner");
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({"photo_url": "http://example.com/p.jpg", "is_primary": true}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Verify in repo
    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert_eq!(photos.len(), 1);
    assert_eq!(photos[0].photo_url, "http://example.com/p.jpg");
}

#[actix_rt::test]
async fn delete_photo_success() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(pool.clone());

    let user_repo = UserRepositoryImpl::new(pool.clone());
    let equipment_repo = EquipmentRepositoryImpl::new(pool.clone());
    let category_repo = CategoryRepositoryImpl::new(pool.clone());

    let cat = common::fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    let owner_id = Uuid::new_v4();
    user_repo
        .create(&test_user(owner_id, Role::Owner, "o@e.c"))
        .await
        .unwrap();
    let mut eq = test_equipment(Uuid::new_v4(), owner_id);
    eq.category_id = cat.id;
    equipment_repo.create(&eq).await.unwrap();

    let photo_id = Uuid::new_v4();
    equipment_repo
        .add_photo(&EquipmentPhoto {
            id: photo_id,
            equipment_id: eq.id,
            photo_url: "u".to_string(),
            is_primary: true,
            order_index: 0,
            created_at: Utc::now(),
        })
        .await
        .unwrap();

    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(owner_id, "owner");
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq.id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify in repo
    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert!(photos.is_empty());
}

#[actix_rt::test]
async fn add_photo_403_forbidden() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(pool.clone());

    let user_repo = UserRepositoryImpl::new(pool.clone());
    let equipment_repo = EquipmentRepositoryImpl::new(pool.clone());
    let category_repo = CategoryRepositoryImpl::new(pool.clone());

    let cat = common::fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo
        .create(&test_user(owner_id, Role::Owner, "o@e.c"))
        .await
        .unwrap();
    user_repo
        .create(&test_user(other_id, Role::Owner, "other@e.c"))
        .await
        .unwrap();

    let mut eq = test_equipment(Uuid::new_v4(), owner_id);
    eq.category_id = cat.id;
    equipment_repo.create(&eq).await.unwrap();

    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_id, "owner");
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(
            serde_json::json!({"photo_url": "http://example.com/other.jpg", "is_primary": true}),
        )
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Verify NO mutation in repo
    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert!(
        photos.is_empty(),
        "Repository should not have been mutated on 403"
    );
}

#[actix_rt::test]
async fn delete_photo_403_forbidden() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(pool.clone());

    let user_repo = UserRepositoryImpl::new(pool.clone());
    let equipment_repo = EquipmentRepositoryImpl::new(pool.clone());
    let category_repo = CategoryRepositoryImpl::new(pool.clone());

    let cat = common::fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo
        .create(&test_user(owner_id, Role::Owner, "o@e.c"))
        .await
        .unwrap();
    user_repo
        .create(&test_user(other_id, Role::Owner, "other@e.c"))
        .await
        .unwrap();

    let mut eq = test_equipment(Uuid::new_v4(), owner_id);
    eq.category_id = cat.id;
    equipment_repo.create(&eq).await.unwrap();

    let photo_id = Uuid::new_v4();
    equipment_repo
        .add_photo(&EquipmentPhoto {
            id: photo_id,
            equipment_id: eq.id,
            photo_url: "u".to_string(),
            is_primary: true,
            order_index: 0,
            created_at: Utc::now(),
        })
        .await
        .unwrap();

    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_id, "owner");
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq.id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Verify NO mutation in repo
    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert_eq!(
        photos.len(),
        1,
        "Photo should still exist in repo after failed delete"
    );
}

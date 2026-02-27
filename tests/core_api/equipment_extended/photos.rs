use super::*;
use crate::common;
use crate::common::mocks::{MockEquipmentRepo, MockUserRepo};
use actix_web::{http::StatusCode, test as actix_test, App};
use chrono::Utc;
use rust_backend::api::routes;
use rust_backend::domain::{EquipmentPhoto, Role};
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn add_photo_success() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    let eq_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
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
        .uri(&format!("/api/v1/equipment/{}/photos", eq_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({"photo_url": "http://example.com/p.jpg", "is_primary": true}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Verify in repo
    let photos = equipment_repo.photos.lock().unwrap();
    assert_eq!(photos.len(), 1);
    assert_eq!(photos[0].photo_url, "http://example.com/p.jpg");
}

#[actix_rt::test]
async fn delete_photo_success() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    let eq_id = Uuid::new_v4();
    let photo_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
    equipment_repo.photos.lock().unwrap().push(EquipmentPhoto {
        id: photo_id,
        equipment_id: eq_id,
        photo_url: "u".to_string(),
        is_primary: true,
        order_index: 0,
        created_at: Utc::now(),
    });
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
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq_id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify in repo
    let photos = equipment_repo.photos.lock().unwrap();
    assert!(photos.is_empty());
}

#[actix_rt::test]
async fn add_photo_403_forbidden() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    user_repo.push(test_user(other_id, Role::Owner, "other@e.c"));
    let eq_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
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
        .uri(&format!("/api/v1/equipment/{}/photos", eq_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(
            serde_json::json!({"photo_url": "http://example.com/other.jpg", "is_primary": true}),
        )
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn delete_photo_403_forbidden() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    user_repo.push(test_user(other_id, Role::Owner, "other@e.c"));
    let eq_id = Uuid::new_v4();
    let photo_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
    equipment_repo.photos.lock().unwrap().push(EquipmentPhoto {
        id: photo_id,
        equipment_id: eq_id,
        photo_url: "u".to_string(),
        is_primary: true,
        order_index: 0,
        created_at: Utc::now(),
    });
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
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq_id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

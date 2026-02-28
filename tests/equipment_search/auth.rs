use crate::common::mocks::*;
use crate::equipment_search::setup::*;
use actix_web::{http::StatusCode, test as actix_test, App};
use chrono::Utc;
use rust_backend::api::routes;
use rust_backend::domain::*;
use rust_backend::security::{cors_middleware, security_headers};
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn owner_can_add_photo_to_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(owner_id, "owner");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo1.jpg",
            "is_primary": true
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(
        body.get("photo_url").and_then(serde_json::Value::as_str),
        Some("https://example.com/photo1.jpg")
    );
    assert_eq!(
        body.get("is_primary").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        body.get("order_index").and_then(serde_json::Value::as_i64),
        Some(0)
    );
}

#[actix_rt::test]
async fn owner_can_delete_photo_from_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let photo_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    equipment_repo.push_photo(EquipmentPhoto {
        id: photo_id,
        equipment_id,
        photo_url: "https://example.com/photo.jpg".to_string(),
        is_primary: false,
        order_index: 0,
        created_at: Utc::now(),
    });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(owner_id, "owner");

    let request = actix_test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/equipment/{}/photos/{}",
            equipment_id, photo_id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[actix_rt::test]
async fn non_owner_cannot_add_photo_to_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: other_id,
        email: "other@example.com".to_string(),
        role: Role::Owner,
        username: Some("other".to_string()),
        full_name: Some("Other".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(other_id, "owner");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo.jpg",
            "is_primary": false
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn admin_can_add_photo_to_other_users_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: admin_id,
        email: "admin@example.com".to_string(),
        role: Role::Admin,
        username: Some("admin".to_string()),
        full_name: Some("Admin".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(admin_id, "admin");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo.jpg",
            "is_primary": false
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[actix_rt::test]
async fn photo_order_index_increments_with_each_addition() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(owner_id, "owner");

    // Add first photo
    let request1 = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo1.jpg",
            "is_primary": false
        }))
        .to_request();
    let response1 = actix_test::call_service(&app, request1).await;
    assert_eq!(response1.status(), StatusCode::CREATED);

    let body1: serde_json::Value = actix_test::read_body_json(response1).await;
    assert_eq!(
        body1.get("order_index").and_then(serde_json::Value::as_i64),
        Some(0)
    );

    // Add second photo
    let request2 = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo2.jpg",
            "is_primary": false
        }))
        .to_request();
    let response2 = actix_test::call_service(&app, request2).await;
    assert_eq!(response2.status(), StatusCode::CREATED);

    let body2: serde_json::Value = actix_test::read_body_json(response2).await;
    assert_eq!(
        body2.get("order_index").and_then(serde_json::Value::as_i64),
        Some(1)
    );

    // Add third photo
    let request3 = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo3.jpg",
            "is_primary": false
        }))
        .to_request();
    let response3 = actix_test::call_service(&app, request3).await;
    assert_eq!(response3.status(), StatusCode::CREATED);

    let body3: serde_json::Value = actix_test::read_body_json(response3).await;
    assert_eq!(
        body3.get("order_index").and_then(serde_json::Value::as_i64),
        Some(2)
    );
}

// =============================================================================
// Availability Toggle Tests
// =============================================================================

use crate::common;
use crate::common::mocks::{MockEquipmentRepo, MockUserRepo};
use crate::equipment_search::setup::{
    app_state, app_with_auth0_data, create_auth0_token, create_equipment, get_items_array,
    get_total, security_config,
};
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::Utc;
use rust_backend::api::routes;
use rust_backend::domain::*;
use rust_backend::security::{cors_middleware, security_headers};
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn search_ignores_undefined_optional_filters_in_query_string() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
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
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Item 1",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=undefined&lng=undefined&is_available=undefined")
        .to_request();
    let response = actix_test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn search_with_invalid_category_id() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "o@e.c".to_string(),
        role: Role::Owner,
        ..User::default()
    });
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        Uuid::new_v4(),
        "Item",
        1000,
        Condition::Good,
        None,
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/equipment?category_id={}", Uuid::new_v4()))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_items_array(&body).len(), 0);
}

#[actix_rt::test]
async fn search_returns_empty_when_no_matching_results() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
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
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Expensive Camera",
        15000,
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
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    // Search for equipment with max_price 10, but cheapest is 150
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?max_price=10")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 0);
    assert_eq!(get_total(&body), 0);
}

#[actix_rt::test]
async fn search_without_filters_returns_all_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
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

    for i in 1..=5 {
        equipment_repo.push(create_equipment(
            Uuid::new_v4(),
            owner_id,
            category_id,
            &format!("Item {}", i),
            5000,
            rust_backend::domain::Condition::Good,
            Some("NYC"),
            None,
            None,
            true,
        ));
    }

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 5);
    assert_eq!(get_total(&body), 5);
}

#[actix_rt::test]
async fn owner_can_toggle_equipment_availability() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks_client, provisioning_service) =
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
            .app_data(auth0_config)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(owner_id, "owner");

    // Make unavailable
    let request = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "is_available": false
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(
        body.get("is_available")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );

    // Make available again
    let request2 = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "is_available": true
        }))
        .to_request();
    let response2 = actix_test::call_service(&app, request2).await;
    assert_eq!(response2.status(), StatusCode::OK);

    let body2: serde_json::Value = actix_test::read_body_json(response2).await;
    assert_eq!(
        body2
            .get("is_available")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
}

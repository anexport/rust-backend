use crate::common;
use crate::common::mocks::*;
use crate::equipment_search::setup::*;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::Utc;
use rust_backend::api::routes;
use rust_backend::api::routes::AppState;
use rust_backend::domain::*;
use rust_backend::security::{cors_middleware, security_headers};
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn pagination_respects_page_parameter() {
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

    // Add 5 items
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
        .uri("/api/v1/equipment?page=1&limit=2")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_page(&body), 1);
    assert_eq!(get_limit(&body), 2);
    assert_eq!(get_total(&body), 5);
    assert_eq!(get_total_pages(&body), 3);
    assert_eq!(get_items_array(&body).len(), 2);
}

#[actix_rt::test]
async fn pagination_page_defaults_to_one() {
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
        "Test Item",
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
    assert_eq!(get_page(&body), 1);
}

#[actix_rt::test]
async fn pagination_limit_defaults_to_twenty() {
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
        "Test Item",
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
    assert_eq!(get_limit(&body), 20);
}

#[actix_rt::test]
async fn pagination_limit_is_clamped_to_maximum_of_100() {
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
        "Test Item",
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
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?limit=200")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_limit(&body), 100);
}

#[actix_rt::test]
async fn pagination_minimum_limit_is_one() {
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
        "Test Item",
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
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?limit=0")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_limit(&body), 1);
}

#[actix_rt::test]
async fn pagination_negative_page_defaults_to_one() {
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
        "Test Item",
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
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?page=-1")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_page(&body), 1);
}

// =============================================================================
// Photo Management Tests
// =============================================================================

#[actix_rt::test]
async fn search_pagination_beyond_bounds() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "o@e.c".to_string(),
        role: Role::Owner,
        ..User::default()
    });

    for i in 0..5 {
        equipment_repo.push(create_equipment(
            Uuid::new_v4(),
            owner_id,
            category_id,
            &format!("Item {}", i),
            1000,
            Condition::Good,
            None,
            None,
            None,
            true,
        ));
    }

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    // Page beyond total pages
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?page=10&limit=5")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 0);
    assert_eq!(get_total(&body), 5);

    // Limit beyond available items
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?page=1&limit=100")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_items_array(&body).len(), 5);
}

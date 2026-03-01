use crate::common;
use crate::common::mocks::{MockEquipmentRepo, MockUserRepo};
use crate::equipment_search::setup::{
    app_state, create_equipment, get_items_array, security_config,
};
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::Utc;
use rust_backend::api::routes;
use rust_backend::domain::*;
use rust_backend::security::{cors_middleware, security_headers};
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn search_with_min_price_only_includes_price_at_or_above_threshold() {
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
        "At Threshold",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Above Threshold",
        7500,
        rust_backend::domain::Condition::Excellent,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Below Threshold",
        2500,
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
        .uri("/api/v1/equipment?min_price=50")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 2);

    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
        .collect();
    assert!(titles.contains(&"At Threshold"));
    assert!(titles.contains(&"Above Threshold"));
    assert!(!titles.contains(&"Below Threshold"));
}

#[actix_rt::test]
async fn search_with_max_price_only_includes_price_at_or_below_threshold() {
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
        "At Threshold",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Below Threshold",
        2500,
        rust_backend::domain::Condition::Excellent,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Above Threshold",
        10000,
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
        .uri("/api/v1/equipment?max_price=50")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 2);

    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
        .collect();
    assert!(titles.contains(&"At Threshold"));
    assert!(titles.contains(&"Below Threshold"));
    assert!(!titles.contains(&"Above Threshold"));
}

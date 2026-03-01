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
async fn search_combines_category_and_price_filters() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let cameras_id = Uuid::new_v4();
    let lenses_id = Uuid::new_v4();
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

    // Camera in price range
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        cameras_id,
        "Affordable Camera",
        3500,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));
    // Camera too expensive
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        cameras_id,
        "Expensive Camera",
        15000,
        rust_backend::domain::Condition::Excellent,
        Some("NYC"),
        None,
        None,
        true,
    ));
    // Lens in price range (wrong category)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        lenses_id,
        "Affordable Lens",
        4000,
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
        .uri(&format!(
            "/api/v1/equipment?category_id={}&min_price=30&max_price=50",
            cameras_id
        ))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("title").and_then(serde_json::Value::as_str),
        Some("Affordable Camera")
    );
}

#[actix_rt::test]
async fn search_combines_all_filters_category_price_location_availability() {
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

    // Perfect match
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Perfect Match",
        4500,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Wrong category
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        Uuid::new_v4(),
        "Wrong Category",
        4500,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Price too high
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Too Expensive",
        15000,
        rust_backend::domain::Condition::Excellent,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Too far
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Too Far",
        4500,
        rust_backend::domain::Condition::Good,
        Some("Boston"),
        Some(42.3601),
        Some(-71.0589),
        true,
    ));
    // Not available
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Not Available",
        4500,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7129),
        Some(-74.0061),
        false,
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
        .uri(&format!(
            "/api/v1/equipment?category_id={}&min_price=30&max_price=60&lat=40.7128&lng=-74.0060&radius_km=10&is_available=true",
            category_id
        ))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("title").and_then(serde_json::Value::as_str),
        Some("Perfect Match")
    );
}

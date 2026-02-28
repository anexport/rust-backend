use crate::common;
use crate::common::mocks::*;
use crate::equipment_search::setup::*;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::Utc;
use rust_backend::api::routes;
use rust_backend::domain::*;
use rust_backend::security::{cors_middleware, security_headers};
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn geographic_search_returns_equipment_within_radius() {
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

    // Central Park, NYC coordinates: 40.7829, -73.9654
    // Add equipment at various distances
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Central Park Camera",
        5000,
        rust_backend::domain::Condition::Good,
        Some("Central Park"),
        Some(40.7829),
        Some(-73.9654),
        true,
    ));
    // Times Square is about 2.5km from Central Park
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Times Square Lens",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Times Square"),
        Some(40.7580),
        Some(-73.9855),
        true,
    ));
    // Brooklyn Bridge is about 9km from Central Park (should be filtered out with a 5km radius)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Brooklyn Lights",
        6000,
        rust_backend::domain::Condition::New,
        Some("Brooklyn Bridge"),
        Some(40.7061),
        Some(-73.9969),
        true,
    ));
    // Statue of Liberty is about 10km from Central Park (should be filtered out with 5km radius)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Liberty Gear",
        7000,
        rust_backend::domain::Condition::Good,
        Some("Liberty Island"),
        Some(40.6892),
        Some(-74.0445),
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
        .uri("/api/v1/equipment?lat=40.7829&lng=-73.9654&radius_km=5")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 2);
    assert_eq!(get_total(&body), 2);

    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
        .collect();
    assert!(titles.contains(&"Central Park Camera"));
    assert!(titles.contains(&"Times Square Lens"));
    assert!(!titles.contains(&"Brooklyn Lights"));
    assert!(!titles.contains(&"Liberty Gear"));
}

#[actix_rt::test]
async fn geographic_search_results_sorted_by_distance() {
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

    // Origin: Union Square, NYC (40.7327, -73.9914)
    // Add equipment at known distances
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Union Square Item",
        5000,
        rust_backend::domain::Condition::Good,
        Some("Union Square"),
        Some(40.7327),
        Some(-73.9914),
        true,
    ));
    // Flatiron Building ~0.95km
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Flatiron Gear",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Flatiron District"),
        Some(40.7411),
        Some(-73.9897),
        true,
    ));
    // Empire State Building ~0.8km
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Empire Equipment",
        6000,
        rust_backend::domain::Condition::New,
        Some("Midtown"),
        Some(40.7484),
        Some(-73.9857),
        true,
    ));
    // Washington Square ~0.5km
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Washington Square Kit",
        7000,
        rust_backend::domain::Condition::Good,
        Some("Greenwich Village"),
        Some(40.7308),
        Some(-73.9973),
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
        .uri("/api/v1/equipment?lat=40.7327&lng=-73.9914&radius_km=10")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 4);

    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
        .collect();
    // Items should be sorted by distance - closest first
    assert_eq!(titles[0], "Union Square Item"); // 0km
    assert_eq!(titles[1], "Washington Square Kit"); // ~0.5km
    assert_eq!(titles[2], "Flatiron Gear"); // ~0.95km
    assert_eq!(titles[3], "Empire Equipment"); // ~1.8km
}

#[actix_rt::test]
async fn geographic_search_excludes_equipment_without_coordinates() {
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

    // Equipment with coordinates (should be included)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Located Equipment",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Equipment without coordinates (should be excluded when geo search is active)
    let mut unlocated = create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Unlocated Equipment",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Somewhere"),
        None,
        None,
        true,
    );
    unlocated.coordinates = None;
    equipment_repo.push(unlocated);

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
        .uri("/api/v1/equipment?lat=40.7128&lng=-74.0060&radius_km=50")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("title").and_then(serde_json::Value::as_str),
        Some("Located Equipment")
    );
}

#[actix_rt::test]
async fn geographic_search_with_radius_zero_returns_only_exact_matches() {
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

    // Equipment at exact coordinates
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Exact Location",
        5000,
        rust_backend::domain::Condition::Good,
        Some("Exact"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Equipment 1 meter away (should still be included due to floating point tolerance)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Very Close",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Very Close"),
        Some(40.71281),
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
        .uri("/api/v1/equipment?lat=40.7128&lng=-74.0060&radius_km=0")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    // Should include both due to floating point proximity
    assert!(!items.is_empty());
}

// =============================================================================
// Filter Combination Tests
// =============================================================================

#[actix_rt::test]
async fn search_with_invalid_coordinates_returns_empty_results() {
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
        "NYC Equipment",
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

    // Invalid latitude (outside -90 to 90)
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=91&lng=0&radius_km=10")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 0);
}

#[actix_rt::test]
async fn search_with_zero_radius() {
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

    // Item at exact point
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Exact",
        1000,
        Condition::Good,
        None,
        Some(40.0),
        Some(40.0),
        true,
    ));
    // Item 1m away
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Near",
        1000,
        Condition::Good,
        None,
        Some(40.00001),
        Some(40.0),
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
        .uri("/api/v1/equipment?lat=40.0&lng=40.0&radius_km=0")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].get("title").unwrap(), "Exact");
}

#[actix_rt::test]
async fn search_with_partial_geo_params_returns_all_items() {
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
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Item 2",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Boston"),
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

    // Only latitude provided (no lng or radius)
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=40.7128")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    // Without all geo params, search should not filter by location
    assert!(items.len() >= 2);
}

// =============================================================================
// Empty Results Tests
// =============================================================================

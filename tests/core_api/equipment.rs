use super::*;
use crate::common;
use crate::common::mocks::*;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::{Duration, Utc};
use rust_backend::api::routes;
use rust_backend::api::routes::AppState;
use rust_backend::domain::*;
use rust_backend::infrastructure::repositories::*;
use rust_backend::security::{cors_middleware, security_headers};
use rust_decimal::Decimal;
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn equipment_crud_flow_succeeds() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);

    let owner_id = Uuid::new_v4();
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

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let owner_token = create_auth0_token(owner_id, "owner");

    let create_request = actix_test::TestRequest::post()
        .uri("/api/v1/equipment")
        .insert_header(("Authorization", format!("Bearer {owner_token}")))
        .set_json(serde_json::json!({
            "category_id": Uuid::new_v4(),
            "title": "Cinema Camera",
            "description": "Full frame cinema camera body and accessories",
            "daily_rate": Decimal::new(9900, 2),
            "condition": "excellent",
            "location": "New York",
            "coordinates": {
                "latitude": 40.7128,
                "longitude": -74.0060
            }
        }))
        .to_request();
    let create_response = actix_test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created: serde_json::Value = actix_test::read_body_json(create_response).await;
    let equipment_id = created
        .get("id")
        .and_then(serde_json::Value::as_str)
        .expect("equipment id should exist")
        .to_string();
    assert_eq!(
        created
            .get("coordinates")
            .and_then(|value| value.get("latitude"))
            .and_then(serde_json::Value::as_f64),
        Some(40.7128)
    );
    assert_eq!(
        created
            .get("coordinates")
            .and_then(|value| value.get("longitude"))
            .and_then(serde_json::Value::as_f64),
        Some(-74.0060)
    );

    let get_request = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/equipment/{equipment_id}"))
        .to_request();
    let get_response = actix_test::call_service(&app, get_request).await;
    assert_eq!(get_response.status(), StatusCode::OK);
    let fetched: serde_json::Value = actix_test::read_body_json(get_response).await;
    assert_eq!(
        fetched
            .get("coordinates")
            .and_then(|value| value.get("latitude"))
            .and_then(serde_json::Value::as_f64),
        Some(40.7128)
    );
    assert_eq!(
        fetched
            .get("coordinates")
            .and_then(|value| value.get("longitude"))
            .and_then(serde_json::Value::as_f64),
        Some(-74.0060)
    );

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{equipment_id}"))
        .insert_header(("Authorization", format!("Bearer {owner_token}")))
        .set_json(serde_json::json!({
            "title": "Cinema Camera Updated",
            "description": "Updated description for camera package",
            "coordinates": {
                "latitude": 40.7130,
                "longitude": -74.0070
            }
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);
    let updated: serde_json::Value = actix_test::read_body_json(update_response).await;
    assert_eq!(
        updated
            .get("coordinates")
            .and_then(|value| value.get("latitude"))
            .and_then(serde_json::Value::as_f64),
        Some(40.7130)
    );
    assert_eq!(
        updated
            .get("coordinates")
            .and_then(|value| value.get("longitude"))
            .and_then(serde_json::Value::as_f64),
        Some(-74.0070)
    );

    let delete_request = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{equipment_id}"))
        .insert_header(("Authorization", format!("Bearer {owner_token}")))
        .to_request();
    let delete_response = actix_test::call_service(&app, delete_request).await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
}

#[actix_rt::test]
async fn users_me_equipment_route_wins_over_dynamic_id_route() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let user_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    user_repo.push(User {
        id: user_id,
        email: "owner-route@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner-route".to_string()),
        full_name: Some("Owner Route".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .push(Equipment {
            id: Uuid::new_v4(),
            owner_id: user_id,
            category_id: Uuid::new_v4(),
            title: "Owner item".to_string(),
            description: Some("Owned by /me user".to_string()),
            daily_rate: Decimal::new(1500, 2),
            condition: rust_backend::domain::Condition::Good,
            location: Some("New York".to_string()),
            coordinates: None,
            is_available: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .push(Equipment {
            id: Uuid::new_v4(),
            owner_id: other_user_id,
            category_id: Uuid::new_v4(),
            title: "Other owner item".to_string(),
            description: Some("Owned by another user".to_string()),
            daily_rate: Decimal::new(2200, 2),
            condition: rust_backend::domain::Condition::Good,
            location: Some("Boston".to_string()),
            coordinates: None,
            is_available: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "owner");
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/users/me/equipment")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let items: Vec<serde_json::Value> = actix_test::read_body_json(response).await;
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]
            .get("owner_id")
            .and_then(serde_json::Value::as_str)
            .expect("owner_id should be present"),
        user_id.to_string()
    );
}

#[actix_rt::test]
async fn equipment_list_filters_by_price_category_and_radius() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo.clone());

    let category_id = Uuid::new_v4();
    let other_category_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();

    let now = Utc::now();
    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .extend([
            Equipment {
                id: Uuid::new_v4(),
                owner_id,
                category_id,
                title: "Nearby good price".to_string(),
                description: Some("match".to_string()),
                daily_rate: Decimal::new(3000, 2),
                condition: rust_backend::domain::Condition::Good,
                location: Some("NYC".to_string()),
                coordinates: Some("40.7128, -74.0060".to_string()),
                is_available: true,
                created_at: now,
                updated_at: now,
            },
            Equipment {
                id: Uuid::new_v4(),
                owner_id,
                category_id,
                title: "Too expensive".to_string(),
                description: Some("price fail".to_string()),
                daily_rate: Decimal::new(12000, 2),
                condition: rust_backend::domain::Condition::Good,
                location: Some("NYC".to_string()),
                coordinates: Some("40.7130, -74.0070".to_string()),
                is_available: true,
                created_at: now,
                updated_at: now,
            },
            Equipment {
                id: Uuid::new_v4(),
                owner_id,
                category_id: other_category_id,
                title: "Wrong category".to_string(),
                description: Some("category fail".to_string()),
                daily_rate: Decimal::new(3000, 2),
                condition: rust_backend::domain::Condition::Good,
                location: Some("NYC".to_string()),
                coordinates: Some("40.7127, -74.0058".to_string()),
                is_available: true,
                created_at: now,
                updated_at: now,
            },
            Equipment {
                id: Uuid::new_v4(),
                owner_id,
                category_id,
                title: "Too far".to_string(),
                description: Some("distance fail".to_string()),
                daily_rate: Decimal::new(2500, 2),
                condition: rust_backend::domain::Condition::Good,
                location: Some("Boston".to_string()),
                coordinates: Some("42.3601, -71.0589".to_string()),
                is_available: true,
                created_at: now,
                updated_at: now,
            },
        ]);

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
            "/api/v1/equipment?category_id={category_id}&min_price=20&max_price=40&lat=40.7128&lng=-74.0060&radius_km=5"
        ))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = body
        .get("items")
        .and_then(serde_json::Value::as_array)
        .expect("items should be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("title").and_then(serde_json::Value::as_str),
        Some("Nearby good price")
    );
}

#[actix_rt::test]
async fn renter_cannot_create_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);

    let renter_id = Uuid::new_v4();
    user_repo.push(User {
        id: renter_id,
        email: "renter-create@example.com".to_string(),
        role: Role::Renter,
        username: Some("renter-create".to_string()),
        full_name: Some("Renter Create".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(renter_id, "renter");

    let create_request = actix_test::TestRequest::post()
        .uri("/api/v1/equipment")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "category_id": Uuid::new_v4(),
            "title": "Should Not Work",
            "description": "Renter cannot create equipment listing",
            "daily_rate": Decimal::new(4900, 2),
            "condition": "good",
            "location": "Austin"
        }))
        .to_request();
    let create_response = actix_test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn non_owner_cannot_update_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();

    user_repo.push(User {
        id: owner_id,
        email: "owner-update@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner-update".to_string()),
        full_name: Some("Owner Update".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: other_user_id,
        email: "other-update@example.com".to_string(),
        role: Role::Owner,
        username: Some("other-update".to_string()),
        full_name: Some("Other Update".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .push(Equipment {
            id: equipment_id,
            owner_id,
            category_id: Uuid::new_v4(),
            title: "Owner Only Item".to_string(),
            description: Some("Cannot be updated by another owner".to_string()),
            daily_rate: Decimal::new(5000, 2),
            condition: rust_backend::domain::Condition::Good,
            location: Some("Denver".to_string()),
            coordinates: None,
            is_available: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_user_id, "owner");

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{equipment_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "title": "Illegally Updated"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn admin_can_update_foreign_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let admin_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    user_repo.push(User {
        id: admin_id,
        email: "admin2@example.com".to_string(),
        role: Role::Admin,
        username: Some("admin2".to_string()),
        full_name: Some("Admin 2".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: owner_id,
        email: "owner2@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner2".to_string()),
        full_name: Some("Owner 2".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let equipment_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .push(Equipment {
            id: equipment_id,
            owner_id,
            category_id: Uuid::new_v4(),
            title: "Owned Item".to_string(),
            description: Some("Owned".to_string()),
            daily_rate: Decimal::new(1000, 2),
            condition: rust_backend::domain::Condition::Good,
            location: Some("NY".to_string()),
            coordinates: None,
            is_available: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(admin_id, "admin");

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{equipment_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "title": "Admin Updated"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);
}

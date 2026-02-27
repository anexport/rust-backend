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
async fn get_users_id_returns_public_profile() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo);

    let user_id = Uuid::new_v4();
    user_repo.push(User {
        id: user_id,
        email: "public-user@example.com".to_string(),
        role: Role::Renter,
        username: Some("public-user".to_string()),
        full_name: Some("Public User".to_string()),
        avatar_url: Some("https://example.com/public-user.png".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

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
        .uri(&format!("/api/v1/users/{user_id}"))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(
        body.get("id")
            .and_then(serde_json::Value::as_str)
            .expect("id should be present"),
        user_id.to_string()
    );
    assert_eq!(
        body.get("username")
            .and_then(serde_json::Value::as_str)
            .expect("username should be present"),
        "public-user"
    );
    assert_eq!(
        body.get("avatar_url")
            .and_then(serde_json::Value::as_str)
            .expect("avatar_url should be present"),
        "https://example.com/public-user.png"
    );
    assert!(
        body.get("email").is_none(),
        "public profile response should not expose email"
    );
}

#[actix_rt::test]
async fn admin_can_update_other_users_profile() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);

    let admin_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
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
    user_repo.push(User {
        id: target_id,
        email: "target@example.com".to_string(),
        role: Role::Renter,
        username: Some("target".to_string()),
        full_name: Some("Target".to_string()),
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

    let token = create_auth0_token(admin_id, "admin");

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{target_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "full_name": "Updated By Admin"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn non_admin_cannot_update_other_users_profile() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);

    let actor_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    user_repo.push(User {
        id: actor_id,
        email: "actor@example.com".to_string(),
        role: Role::Renter,
        username: Some("actor".to_string()),
        full_name: Some("Actor".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: target_id,
        email: "target2@example.com".to_string(),
        role: Role::Renter,
        username: Some("target2".to_string()),
        full_name: Some("Target2".to_string()),
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

    let token = create_auth0_token(actor_id, "renter");

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{target_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "full_name": "Should Fail"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::FORBIDDEN);
}

use super::*;
use crate::common;
use crate::common::mocks::*;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::Utc;
use rust_backend::api::routes;
use rust_backend::domain::*;
use rust_backend::security::{cors_middleware, security_headers};
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn admin_can_access_foreign_conversation() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

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

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

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

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/conversations/{conversation_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn admin_can_send_message_to_foreign_conversation() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: admin_id,
        email: "admin-msg@example.com".to_string(),
        role: Role::Admin,
        username: Some("admin-msg".to_string()),
        full_name: Some("Admin Msg".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

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

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": "Admin message"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[actix_rt::test]
async fn admin_can_list_foreign_conversation_messages() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: admin_id,
        email: "admin-list@example.com".to_string(),
        role: Role::Admin,
        username: Some("admin-list".to_string()),
        full_name: Some("Admin List".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

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

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

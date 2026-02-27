use super::*;
use crate::common;
use crate::common::mocks::{MockEquipmentRepo, MockUserRepo};
use actix_web::{http::StatusCode, test as actix_test, App};
use rust_backend::api::routes;
use rust_backend::domain::Role;
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn update_equipment_401_unauthorized() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(user_repo, equipment_repo);
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", Uuid::new_v4()))
        .set_json(serde_json::json!({"title": "New Title"}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn update_equipment_403_forbidden() {
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
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", eq_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({"title": "New Title"}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn update_equipment_404_not_found() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);
    let owner_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
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
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({"title": "New Title"}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn delete_equipment_403_forbidden() {
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
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}", eq_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn delete_equipment_404_not_found() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);
    let owner_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
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
        .uri(&format!("/api/v1/equipment/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

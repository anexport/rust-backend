use super::setup_app;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::infrastructure::repositories::{
    CategoryRepository, CategoryRepositoryImpl, UserRepository, UserRepositoryImpl,
};
use uuid::Uuid;

#[actix_rt::test]
async fn test_admin_category_hierarchy_validation() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let parent_cat = fixtures::test_category();
    category_repo.create(&parent_cat).await.unwrap();

    // 1. Create child with parent
    let req = actix_test::TestRequest::post()
        .uri("/api/v1/admin/categories")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "name": "Child Category",
            "parent_id": parent_cat.id
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let child: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(child["parent_id"], parent_cat.id.to_string());

    // 2. Prevent self-parenting
    let child_id = child["id"].as_str().unwrap();
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/categories/{}", child_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "name": "Self Parent",
            "parent_id": child_id
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 3. Prevent multi-node cycle (A -> B -> A)
    let parent_cat2 = fixtures::test_category();
    category_repo.create(&parent_cat2).await.unwrap();
    let mut child_cat = fixtures::test_category();
    child_cat.parent_id = Some(parent_cat2.id);
    category_repo.create(&child_cat).await.unwrap();

    // Try to set B's parent to A where A is B's child (wait, A is parent of B, try set A's parent to B)
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/categories/{}", parent_cat2.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "name": "Cycle Parent",
            "parent_id": child_cat.id
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    // This should fail if cycle detection is implemented correctly
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_category_management_flow() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    // 1. Create category
    let req = actix_test::TestRequest::post()
        .uri("/api/v1/admin/categories")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "name": "New Category" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created: serde_json::Value = actix_test::read_body_json(resp).await;
    let cat_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();

    // 2. Update category
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/categories/{}", cat_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "name": "Updated Category" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated_cat = category_repo.find_by_id(cat_id).await.unwrap().unwrap();
    assert_eq!(updated_cat.name, "Updated Category");

    // 3. Delete category
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/admin/categories/{}", cat_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let deleted_cat = category_repo.find_by_id(cat_id).await.unwrap();
    assert!(deleted_cat.is_none());
}

#[actix_rt::test]
async fn test_category_list_with_hierarchy() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let mut parent = fixtures::test_category();
    parent.name = "Parent".to_string();
    category_repo.create(&parent).await.unwrap();

    let mut child = fixtures::test_category();
    child.name = "Child".to_string();
    child.parent_id = Some(parent.id);
    category_repo.create(&child).await.unwrap();

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/categories")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let list: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert!(list.len() >= 2);

    let child_entry = list
        .iter()
        .find(|c| c["id"] == child.id.to_string())
        .unwrap();
    assert_eq!(child_entry["parent_id"], parent.id.to_string());
}

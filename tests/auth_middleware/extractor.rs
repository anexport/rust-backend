use super::*;
use actix_web::{dev::Payload, test as actix_test, web, FromRequest};
use rust_backend::error::AppError;
use rust_backend::middleware::auth::*;
use rust_backend::utils::auth0_jwks::*;
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn auth0_authenticated_user_rejects_malformed_or_non_bearer_authorization() {
    let requests = vec![
        actix_test::TestRequest::default()
            .insert_header((AUTHORIZATION, "Basic token"))
            .to_http_request(),
        actix_test::TestRequest::default()
            .insert_header((AUTHORIZATION, "Bearer "))
            .to_http_request(),
    ];

    for request in requests {
        let mut payload = Payload::None;
        let result = Auth0AuthenticatedUser::from_request(&request, &mut payload).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
}

#[actix_rt::test]
async fn auth0_authenticated_user_returns_internal_error_when_app_data_missing() {
    let request = actix_test::TestRequest::default()
        .insert_header((AUTHORIZATION, "Bearer any-token"))
        .to_http_request();

    let mut payload = Payload::None;
    let result = Auth0AuthenticatedUser::from_request(&request, &mut payload).await;
    assert!(matches!(result, Err(AppError::InternalError(_))));
}

#[actix_rt::test]
async fn auth0_authenticated_user_propagates_provisioning_failure() {
    let token = create_valid_rs256_auth0_token("auth0|provision-fail");
    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider::new());
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(FailingProvisioningService);

    let request = actix_test::TestRequest::default()
        .insert_header((AUTHORIZATION, format!("Bearer {token}")))
        .app_data(web::Data::new(jwks_provider))
        .app_data(web::Data::new(test_auth0_config()))
        .app_data(web::Data::new(provisioning_service))
        .to_http_request();

    let mut payload = Payload::None;
    let result = Auth0AuthenticatedUser::from_request(&request, &mut payload).await;
    assert!(
        matches!(result, Err(AppError::Forbidden(message)) if message == "provisioning failed")
    );
}

#[actix_rt::test]
async fn auth0_authenticated_user_valid_flow_returns_user_context() {
    let token = create_valid_rs256_auth0_token("auth0|valid-flow");
    let expected_user_id = Uuid::new_v4();

    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider::new());
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(SuccessProvisioningService {
            user_id: expected_user_id,
        });

    let request = actix_test::TestRequest::default()
        .insert_header((AUTHORIZATION, format!("Bearer {token}")))
        .app_data(web::Data::new(jwks_provider))
        .app_data(web::Data::new(test_auth0_config()))
        .app_data(web::Data::new(provisioning_service))
        .to_http_request();

    let mut payload = Payload::None;
    let extracted = Auth0AuthenticatedUser::from_request(&request, &mut payload)
        .await
        .expect("extractor should succeed");

    assert_eq!(extracted.0.user_id, expected_user_id);
    assert_eq!(extracted.0.auth0_sub, "auth0|valid-flow");
    assert_eq!(extracted.0.role, "owner");
}

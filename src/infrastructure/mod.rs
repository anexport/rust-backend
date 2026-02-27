pub mod auth0;
pub mod db;
pub mod repositories;

// Backward-compatible module paths for existing callers.
pub mod auth0_api {
    pub use super::auth0::{
        Auth0ApiClient, Auth0ErrorResponse, Auth0SignupResponse, Auth0TokenResponse,
        DisabledAuth0ApiClient, HttpAuth0ApiClient,
    };
}

// Backward-compatible module paths for existing callers.
pub mod auth0_db {
    pub use super::auth0::{
        Auth0DbClient as Auth0ApiClient, PasswordGrantRequest, PasswordGrantResponse,
        SignupRequest, SignupResponse,
    };
}

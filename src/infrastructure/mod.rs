pub mod auth0;
pub mod db;
pub mod repositories;

// Backward-compatible module paths for existing callers.
pub mod auth0_api {
    pub use super::auth0::client::*;
}

// Backward-compatible module paths for existing callers.
pub mod auth0_db {
    pub use super::auth0::db::*;
}

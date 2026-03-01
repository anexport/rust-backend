mod common;

#[path = "repository_integration/auth.rs"]
pub mod auth;
#[path = "repository_integration/category.rs"]
pub mod category;
#[path = "repository_integration/equipment/mod.rs"]
pub mod equipment;
#[path = "repository_integration/message.rs"]
pub mod message;
#[path = "repository_integration/phase1.rs"]
pub mod phase1;
#[path = "repository_integration/traits_defaults.rs"]
pub mod traits_defaults;
#[path = "repository_integration/user.rs"]
pub mod user;
#[path = "repository_integration/utils_tests.rs"]
pub mod utils_tests;

use rust_backend::domain::AuthProvider as DomainAuthProvider;

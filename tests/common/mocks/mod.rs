pub mod auth0_api;
pub mod auth_repo;
pub mod category_repo;
pub mod equipment_repo;
pub mod message_repo;
pub mod user_repo;
pub mod utils;

// Re-export all mock structs for use in tests
#[allow(unused_imports)]
pub use auth_repo::MockAuthRepo;
#[allow(unused_imports)]
pub use category_repo::MockCategoryRepo;
#[allow(unused_imports)]
pub use equipment_repo::MockEquipmentRepo;
#[allow(unused_imports)]
pub use message_repo::MockMessageRepo;
#[allow(unused_imports)]
pub use user_repo::MockUserRepo;
#[allow(unused_imports)]
pub use utils::haversine_km;
// Note: MockAuth0ApiClient and MockAuth0User are available from auth0_api
// but are not re-exported here to avoid unused warnings
// Tests can import them with: use crate::common::mocks::auth0_api::MockAuth0ApiClient;

mod common;

#[path = "repository_integration/auth.rs"]
pub mod auth;
#[path = "repository_integration/category.rs"]
pub mod category;
#[path = "repository_integration/equipment.rs"]
pub mod equipment;
#[path = "repository_integration/message.rs"]
pub mod message;
#[path = "repository_integration/phase1.rs"]
pub mod phase1;
#[path = "repository_integration/traits_defaults.rs"]
pub mod traits_defaults;
#[path = "repository_integration/user.rs"]
pub mod user;

use chrono::{Duration, Utc};
use rust_backend::domain::{
    AuthIdentity, AuthProvider as DomainAuthProvider, Category, EquipmentPhoto, Message,
};
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::{
    AuthRepository, AuthRepositoryImpl, CategoryRepository, CategoryRepositoryImpl,
    EquipmentRepository, EquipmentRepositoryImpl, EquipmentSearchParams, MessageRepository,
    MessageRepositoryImpl, UserRepository, UserRepositoryImpl,
};
use rust_decimal::Decimal;
use uuid::Uuid;

use common::fixtures;
use common::fixtures::next_id;
use common::repository_helpers::create_category;
use common::TestDb;

#![allow(dead_code)]

use async_trait::async_trait;
use rust_backend::domain::AuthIdentity;
use rust_backend::error::AppResult;
use rust_backend::infrastructure::repositories::AuthRepository;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Default)]
pub struct MockAuthRepo {
    pub identities: Mutex<Vec<AuthIdentity>>,
}

#[async_trait]
impl AuthRepository for MockAuthRepo {
    async fn create_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
        self.identities
            .lock()
            .expect("identities mutex poisoned")
            .push(identity.clone());
        Ok(identity.clone())
    }

    async fn find_identity_by_user_id(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> AppResult<Option<AuthIdentity>> {
        Ok(self
            .identities
            .lock()
            .expect("identities mutex poisoned")
            .iter()
            .find(|identity| identity.user_id == user_id && identity.provider.as_str() == provider)
            .cloned())
    }

    async fn find_identity_by_provider_id(
        &self,
        provider: &str,
        provider_id: &str,
    ) -> AppResult<Option<AuthIdentity>> {
        Ok(self
            .identities
            .lock()
            .expect("identities mutex poisoned")
            .iter()
            .find(|identity| {
                identity.provider.as_str() == provider
                    && identity.provider_id.as_deref() == Some(provider_id)
            })
            .cloned())
    }

    async fn upsert_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
        let mut identities = self.identities.lock().expect("identities mutex poisoned");
        // Use (user_id, provider) as the primary unique key for upsert, matching DB constraint
        if let Some(existing) = identities
            .iter_mut()
            .find(|i| i.user_id == identity.user_id && i.provider == identity.provider)
        {
            existing.verified = identity.verified;
            existing.provider_id = identity.provider_id.clone();
            existing.password_hash = identity.password_hash.clone();
            Ok(existing.clone())
        } else {
            identities.push(identity.clone());
            Ok(identity.clone())
        }
    }
}

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct WsConnectionHub {
    sessions: Arc<RwLock<HashMap<Uuid, Vec<mpsc::UnboundedSender<String>>>>>,
}

impl WsConnectionHub {
    pub fn register(&self, user_id: Uuid) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.entry(user_id).or_default().push(tx);
        }
        rx
    }

    pub fn prune_user(&self, user_id: Uuid) {
        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(user_sessions) = sessions.get_mut(&user_id) {
                user_sessions.retain(|sender| !sender.is_closed());
                if user_sessions.is_empty() {
                    sessions.remove(&user_id);
                }
            }
        }
    }

    pub fn broadcast_to_users(&self, user_ids: &[Uuid], payload: &str) {
        if let Ok(mut sessions) = self.sessions.write() {
            for user_id in user_ids {
                if let Some(user_sessions) = sessions.get_mut(user_id) {
                    user_sessions.retain(|sender| sender.send(payload.to_string()).is_ok());
                }
            }
            sessions.retain(|_, user_sessions| !user_sessions.is_empty());
        }
    }
}

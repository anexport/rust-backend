use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct WsConnectionHub {
    sessions: Arc<RwLock<HashMap<Uuid, Vec<mpsc::UnboundedSender<String>>>>>,
}

impl WsConnectionHub {
    fn read_sessions(
        &self,
    ) -> std::sync::RwLockReadGuard<'_, HashMap<Uuid, Vec<mpsc::UnboundedSender<String>>>> {
        self.sessions
            .read()
            .expect("websocket hub read lock poisoned")
    }

    fn write_sessions(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, HashMap<Uuid, Vec<mpsc::UnboundedSender<String>>>> {
        self.sessions
            .write()
            .expect("websocket hub write lock poisoned")
    }

    pub fn register(&self, user_id: Uuid) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut sessions = self.write_sessions();
        sessions.entry(user_id).or_default().push(tx);
        rx
    }

    pub fn prune_user(&self, user_id: Uuid) {
        let mut sessions = self.write_sessions();
        if let Some(user_sessions) = sessions.get_mut(&user_id) {
            user_sessions.retain(|sender| !sender.is_closed());
            if user_sessions.is_empty() {
                sessions.remove(&user_id);
            }
        }
    }

    pub fn broadcast_to_users(&self, user_ids: &[Uuid], payload: &str) {
        let snapshot: Vec<(Uuid, Vec<mpsc::UnboundedSender<String>>)> = {
            let sessions = self.read_sessions();
            user_ids
                .iter()
                .filter_map(|user_id| {
                    sessions
                        .get(user_id)
                        .cloned()
                        .map(|items| (*user_id, items))
                })
                .collect()
        };

        let mut prune_targets = Vec::new();
        for (user_id, senders) in snapshot {
            let mut had_closed = false;
            for sender in &senders {
                if sender.send(payload.to_string()).is_err() {
                    had_closed = true;
                }
            }
            if had_closed {
                prune_targets.push(user_id);
            }
        }

        if !prune_targets.is_empty() {
            let mut sessions = self.write_sessions();
            for user_id in prune_targets {
                if let Some(user_sessions) = sessions.get_mut(&user_id) {
                    user_sessions.retain(|sender| !sender.is_closed());
                    if user_sessions.is_empty() {
                        sessions.remove(&user_id);
                    }
                }
            }
        }
    }
}

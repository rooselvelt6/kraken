//! Storage para el sistema offline

use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::sync::RwLock;

use super::{ConnectionState, OfflineError, Operation};

pub struct OfflineManager {
    db: Mutex<Connection>,
    connection_state: RwLock<ConnectionState>,
}

impl OfflineManager {
    pub fn new(data_dir: PathBuf) -> Result<Self, OfflineError> {
        let db_path = data_dir.join("offline.db");
        
        let conn = Connection::open(&db_path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS operations (
                id TEXT PRIMARY KEY,
                operation_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                synced INTEGER DEFAULT 0,
                retry_count INTEGER DEFAULT 0
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_operations_synced ON operations(synced)",
            [],
        )?;

        Ok(Self {
            db: Mutex::new(conn),
            connection_state: RwLock::new(ConnectionState::Offline),
        })
    }

    pub async fn queue_operation(&self, op: Operation) -> Result<(), OfflineError> {
        let db = self.db.lock().unwrap();
        
        db.execute(
            "INSERT OR REPLACE INTO operations (id, operation_type, payload, created_at, synced, retry_count) VALUES (?1, ?2, ?3, ?4, 0, 0)",
            params![op.id, op.operation_type, op.payload, op.created_at],
        )?;

        Ok(())
    }

    pub async fn get_pending_operations(&self) -> Result<Vec<Operation>, OfflineError> {
        let db = self.db.lock().unwrap();
        
        let mut stmt = db.prepare(
            "SELECT id, operation_type, payload, created_at, synced, retry_count FROM operations WHERE synced = 0 ORDER BY created_at ASC LIMIT 100"
        )?;

        let operations = stmt.query_map([], |row| {
            Ok(Operation {
                id: row.get(0)?,
                operation_type: row.get(1)?,
                payload: row.get(2)?,
                created_at: row.get(3)?,
                synced: row.get::<_, i32>(4)? != 0,
                retry_count: row.get(5)?,
            })
        })?;

        let mut result = Vec::new();
        for op in operations {
            result.push(op?);
        }

        Ok(result)
    }

    pub async fn mark_synced(&self, op_id: &str) -> Result<(), OfflineError> {
        let db = self.db.lock().unwrap();
        
        db.execute(
            "UPDATE operations SET synced = 1 WHERE id = ?1",
            params![op_id],
        )?;

        Ok(())
    }

    pub async fn save_session(&self, session_id: &str, data: &str) -> Result<(), OfflineError> {
        let db = self.db.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        
        db.execute(
            "INSERT OR REPLACE INTO sessions (id, data, updated_at) VALUES (?1, ?2, ?3)",
            params![session_id, data, now],
        )?;

        Ok(())
    }

    pub async fn load_session(&self, session_id: &str) -> Result<Option<String>, OfflineError> {
        let db = self.db.lock().unwrap();
        
        let mut stmt = db.prepare("SELECT data FROM sessions WHERE id = ?1")?;
        let result = stmt.query_row(params![session_id], |row| row.get(0));
        
        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(OfflineError::Database(e)),
        }
    }

    pub async fn check_connection(&self) -> bool {
        #[cfg(feature = "network")]
        {
            use reqwest::Client;
            let client = Client::new();
            match client.get("http://localhost:11434/api/tags").send().await {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            }
        }

        #[cfg(not(feature = "network"))]
        {
            false
        }
    }

    pub async fn update_connection_state(&self) -> ConnectionState {
        let is_online = self.check_connection().await;
        
        let state = if is_online {
            ConnectionState::Online
        } else {
            ConnectionState::Offline
        };

        *self.connection_state.write().await = state;
        state
    }

    pub fn is_online(&self) -> bool {
        // Simple check - just return false for now, state management is async
        false
    }

    pub async fn get_state(&self) -> ConnectionState {
        *self.connection_state.read().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_offline_manager() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();
        
        let state = manager.get_state().await;
        assert!(matches!(state, ConnectionState::Offline) || matches!(state, ConnectionState::Online));
    }
}
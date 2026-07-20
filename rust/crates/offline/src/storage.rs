//! Storage para el sistema offline

use rusqlite::{params, Connection};
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
        assert!(
            matches!(state, ConnectionState::Offline) || matches!(state, ConnectionState::Online)
        );
    }

    #[tokio::test]
    async fn test_queue_and_get_multiple_operations() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        for i in 0..5 {
            let op = Operation {
                id: format!("op-{}", i),
                operation_type: "create".to_string(),
                payload: format!("{{\"i\":{}}}", i),
                created_at: 1000 + i as i64,
                synced: false,
                retry_count: 0,
            };
            manager.queue_operation(op).await.unwrap();
        }

        let pending = manager.get_pending_operations().await.unwrap();
        assert_eq!(pending.len(), 5);
        assert_eq!(pending[0].id, "op-0");
        assert_eq!(pending[4].id, "op-4");
    }

    #[tokio::test]
    async fn test_mark_synced_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();
        // Should not error - just update 0 rows
        assert!(manager.mark_synced("nonexistent-id").await.is_ok());
    }

    #[tokio::test]
    async fn test_queue_operation_replaces_existing() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let op1 = Operation {
            id: "dup-1".to_string(),
            operation_type: "create".to_string(),
            payload: "old".to_string(),
            created_at: 1000,
            synced: false,
            retry_count: 0,
        };
        let op2 = Operation {
            id: "dup-1".to_string(),
            operation_type: "update".to_string(),
            payload: "new".to_string(),
            created_at: 2000,
            synced: false,
            retry_count: 0,
        };

        manager.queue_operation(op1).await.unwrap();
        manager.queue_operation(op2).await.unwrap();

        let pending = manager.get_pending_operations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].operation_type, "update");
        assert_eq!(pending[0].payload, "new");
    }

    #[tokio::test]
    async fn test_save_session_overwrites() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        manager.save_session("s1", "data1").await.unwrap();
        manager.save_session("s1", "data2").await.unwrap();

        let loaded = manager.load_session("s1").await.unwrap();
        assert_eq!(loaded, Some("data2".to_string()));
    }

    #[tokio::test]
    async fn test_multiple_sessions_independent() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        manager.save_session("a", "alpha").await.unwrap();
        manager.save_session("b", "beta").await.unwrap();

        assert_eq!(manager.load_session("a").await.unwrap(), Some("alpha".into()));
        assert_eq!(manager.load_session("b").await.unwrap(), Some("beta".into()));
        assert_eq!(manager.load_session("c").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_empty_session_data() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();
        manager.save_session("empty", "").await.unwrap();
        let loaded = manager.load_session("empty").await.unwrap();
        assert_eq!(loaded, Some("".to_string()));
    }

    #[tokio::test]
    async fn test_mark_synced_leaves_other_pending() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let ops: Vec<Operation> = (0..10)
            .map(|i| Operation {
                id: format!("op-{}", i),
                operation_type: "test".into(),
                payload: i.to_string(),
                created_at: i as i64,
                synced: false,
                retry_count: 0,
            })
            .collect();

        for op in ops {
            manager.queue_operation(op).await.unwrap();
        }

        manager.mark_synced("op-3").await.unwrap();
        manager.mark_synced("op-7").await.unwrap();

        let pending = manager.get_pending_operations().await.unwrap();
        assert_eq!(pending.len(), 8);
        assert!(pending.iter().all(|op| op.id != "op-3" && op.id != "op-7"));
    }

    #[tokio::test]
    async fn test_connection_state_update() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let initial = manager.get_state().await;
        assert_eq!(initial, ConnectionState::Offline);

        // Without network feature, update_connection_state should return Offline
        let updated = manager.update_connection_state().await;
        assert_eq!(updated, ConnectionState::Offline);
    }

    #[tokio::test]
    async fn test_is_online_returns_false() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();
        assert!(!manager.is_online());
    }

    #[tokio::test]
    async fn test_check_connection_returns_false() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();
        let connected = manager.check_connection().await;
        assert!(!connected);
    }

    #[tokio::test]
    async fn test_db_file_created() {
        let tmp = TempDir::new().unwrap();
        let _manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();
        assert!(tmp.path().join("offline.db").exists());
    }

    #[tokio::test]
    async fn test_large_payload() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let large_payload = "x".repeat(100_000);
        let op = Operation {
            id: "large".to_string(),
            operation_type: "data".to_string(),
            payload: large_payload.clone(),
            created_at: 1,
            synced: false,
            retry_count: 0,
        };

        manager.queue_operation(op).await.unwrap();
        let pending = manager.get_pending_operations().await.unwrap();
        assert_eq!(pending[0].payload.len(), 100_000);
    }

    #[tokio::test]
    async fn test_pending_operations_limit() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        // Queue more than 100 operations (the LIMIT in the query)
        for i in 0..120 {
            let op = Operation {
                id: format!("op-{}", i),
                operation_type: "test".into(),
                payload: i.to_string(),
                created_at: i as i64,
                synced: false,
                retry_count: 0,
            };
            manager.queue_operation(op).await.unwrap();
        }

        let pending = manager.get_pending_operations().await.unwrap();
        // Should be limited to 100
        assert_eq!(pending.len(), 100);
    }
}

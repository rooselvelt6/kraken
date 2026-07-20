//! Sistema offline-first para Venezuela
//! Proporciona persistencia local y sincronización cuando hay conexión

mod error;
mod storage;

pub use error::OfflineError;
pub use storage::*;

/// Operación guardada para sincronización
#[derive(Debug, Clone)]
pub struct Operation {
    pub id: String,
    pub operation_type: String,
    pub payload: String,
    pub created_at: i64,
    pub synced: bool,
    pub retry_count: u32,
}

/// Estado de conexión
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Online,
    Offline,
    Syncing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_new_manager_invalid_path() {
        let result = OfflineManager::new(PathBuf::from("/tmp/nonexistent/deeply/nested/path"));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_queue_operation() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let op = Operation {
            id: "test-1".to_string(),
            operation_type: "create".to_string(),
            payload: "{}".to_string(),
            created_at: 1000,
            synced: false,
            retry_count: 0,
        };

        assert!(manager.queue_operation(op).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_pending_empty() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let pending = manager.get_pending_operations().await.unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_get_pending_with_data() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let op = Operation {
            id: "test-1".to_string(),
            operation_type: "create".to_string(),
            payload: r#"{"key":"value"}"#.to_string(),
            created_at: 1000,
            synced: false,
            retry_count: 0,
        };

        manager.queue_operation(op).await.unwrap();

        let pending = manager.get_pending_operations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "test-1");
        assert_eq!(pending[0].operation_type, "create");
        assert_eq!(pending[0].payload, r#"{"key":"value"}"#);
        assert_eq!(pending[0].created_at, 1000);
        assert!(!pending[0].synced);
        assert_eq!(pending[0].retry_count, 0);
    }

    #[tokio::test]
    async fn test_mark_synced() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let op1 = Operation {
            id: "op-1".to_string(),
            operation_type: "create".to_string(),
            payload: "{}".to_string(),
            created_at: 1000,
            synced: false,
            retry_count: 0,
        };
        let op2 = Operation {
            id: "op-2".to_string(),
            operation_type: "update".to_string(),
            payload: "{}".to_string(),
            created_at: 2000,
            synced: false,
            retry_count: 0,
        };

        manager.queue_operation(op1).await.unwrap();
        manager.queue_operation(op2).await.unwrap();
        manager.mark_synced("op-1").await.unwrap();

        let pending = manager.get_pending_operations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "op-2");
    }

    #[tokio::test]
    async fn test_save_load_session() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        manager.save_session("sess-1", "session-data").await.unwrap();
        let loaded = manager.load_session("sess-1").await.unwrap();

        assert_eq!(loaded, Some("session-data".to_string()));
    }

    #[tokio::test]
    async fn test_load_session_missing() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let loaded = manager.load_session("nonexistent").await.unwrap();
        assert_eq!(loaded, None);
    }

    #[tokio::test]
    async fn test_get_state_initial() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let state = manager.get_state().await;
        assert_eq!(state, ConnectionState::Offline);
    }

    #[tokio::test]
    async fn test_is_online() {
        let tmp = TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        assert!(!manager.is_online());
    }

    #[test]
    fn test_operation_clone() {
        let op = Operation {
            id: "clone-test".to_string(),
            operation_type: "delete".to_string(),
            payload: r#"{"x":1}"#.to_string(),
            created_at: 42,
            synced: true,
            retry_count: 3,
        };

        let cloned = op.clone();
        assert_eq!(cloned.id, op.id);
        assert_eq!(cloned.operation_type, op.operation_type);
        assert_eq!(cloned.payload, op.payload);
        assert_eq!(cloned.created_at, op.created_at);
        assert_eq!(cloned.synced, op.synced);
        assert_eq!(cloned.retry_count, op.retry_count);
    }

    #[test]
    fn test_connection_state_traits() {
        let online = ConnectionState::Online;
        let offline = ConnectionState::Offline;
        let syncing = ConnectionState::Syncing;

        // PartialEq
        assert_eq!(online, ConnectionState::Online);
        assert_ne!(online, offline);

        // Copy + Clone
        let copied: ConnectionState = online;
        let cloned = online.clone();
        assert_eq!(copied, online);
        assert_eq!(cloned, online);

        // Debug
        let debug_str = format!("{:?}", syncing);
        assert_eq!(debug_str, "Syncing");
    }

    #[test]
    fn test_operation_debug() {
        let op = Operation {
            id: "dbg".into(),
            operation_type: "t".into(),
            payload: "p".into(),
            created_at: 0,
            synced: false,
            retry_count: 0,
        };
        let debug = format!("{:?}", op);
        assert!(debug.contains("dbg"));
        assert!(debug.contains("Operation"));
    }

    #[test]
    fn test_operation_eq_by_field() {
        let op = Operation {
            id: "eq-test".into(),
            operation_type: "create".into(),
            payload: "{}".into(),
            created_at: 999,
            synced: true,
            retry_count: 5,
        };
        let cloned = op.clone();
        assert_eq!(op.id, cloned.id);
        assert_eq!(op.operation_type, cloned.operation_type);
        assert_eq!(op.payload, cloned.payload);
        assert_eq!(op.created_at, cloned.created_at);
        assert_eq!(op.synced, cloned.synced);
        assert_eq!(op.retry_count, cloned.retry_count);
    }

    #[test]
    fn test_connection_state_all_variants() {
        let states = [ConnectionState::Online, ConnectionState::Offline, ConnectionState::Syncing];
        for state in &states {
            let _ = format!("{:?}", state);
            let _ = state.clone();
            let _ = *state;
        }
        assert_eq!(ConnectionState::Online, ConnectionState::Online);
        assert_eq!(ConnectionState::Offline, ConnectionState::Offline);
        assert_eq!(ConnectionState::Syncing, ConnectionState::Syncing);
        assert_ne!(ConnectionState::Online, ConnectionState::Offline);
        assert_ne!(ConnectionState::Offline, ConnectionState::Syncing);
        assert_ne!(ConnectionState::Syncing, ConnectionState::Online);
    }

    #[test]
    fn test_operation_empty_fields() {
        let op = Operation {
            id: String::new(),
            operation_type: String::new(),
            payload: String::new(),
            created_at: 0,
            synced: false,
            retry_count: 0,
        };
        let cloned = op.clone();
        assert!(cloned.id.is_empty());
        assert!(cloned.operation_type.is_empty());
        assert!(cloned.payload.is_empty());
    }

    #[tokio::test]
    async fn test_queue_and_verify_ordering() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        // Queue in reverse order of created_at
        for i in (0..5).rev() {
            let op = Operation {
                id: format!("o-{}", i),
                operation_type: "test".into(),
                payload: i.to_string(),
                created_at: i as i64,
                synced: false,
                retry_count: 0,
            };
            manager.queue_operation(op).await.unwrap();
        }

        let pending = manager.get_pending_operations().await.unwrap();
        // Should be ordered by created_at ASC
        assert_eq!(pending.len(), 5);
        assert_eq!(pending[0].created_at, 0);
        assert_eq!(pending[4].created_at, 4);
    }

    #[tokio::test]
    async fn test_synced_ops_not_in_pending() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        for i in 0..5 {
            let op = Operation {
                id: format!("s-{}", i),
                operation_type: "test".into(),
                payload: i.to_string(),
                created_at: i as i64,
                synced: false,
                retry_count: 0,
            };
            manager.queue_operation(op).await.unwrap();
        }

        // Sync half
        for i in 0..3 {
            manager.mark_synced(&format!("s-{}", i)).await.unwrap();
        }

        let pending = manager.get_pending_operations().await.unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().all(|op| !op.synced));
    }

    #[tokio::test]
    async fn test_session_special_characters() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let data = r#"{"key": "value with unicode: ñáéíóu and \"quotes\" and \n newlines"}"#;
        manager.save_session("special", data).await.unwrap();
        let loaded = manager.load_session("special").await.unwrap();
        assert_eq!(loaded, Some(data.to_string()));
    }

    #[tokio::test]
    async fn test_large_retry_count() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let op = Operation {
            id: "retry-test".into(),
            operation_type: "test".into(),
            payload: "{}".into(),
            created_at: 1,
            synced: false,
            retry_count: u32::MAX,
        };
        manager.queue_operation(op).await.unwrap();
        let pending = manager.get_pending_operations().await.unwrap();
        assert_eq!(pending[0].retry_count, 0); // INSERT OR REPLACE sets retry_count to 0
    }

    #[tokio::test]
    async fn test_negative_timestamp() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let op = Operation {
            id: "neg-ts".into(),
            operation_type: "test".into(),
            payload: "{}".into(),
            created_at: -1000,
            synced: false,
            retry_count: 0,
        };
        manager.queue_operation(op).await.unwrap();
        let pending = manager.get_pending_operations().await.unwrap();
        assert_eq!(pending[0].created_at, -1000);
    }

    #[tokio::test]
    async fn test_is_online_always_false() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manager = OfflineManager::new(tmp.path().to_path_buf()).unwrap();
        // is_online is hardcoded to return false
        assert!(!manager.is_online());
        // Even after state update
        manager.update_connection_state().await;
        assert!(!manager.is_online());
    }

    #[tokio::test]
    async fn test_multiple_managers_same_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let m1 = OfflineManager::new(tmp.path().to_path_buf()).unwrap();
        let m2 = OfflineManager::new(tmp.path().to_path_buf()).unwrap();

        let op = Operation {
            id: "shared".into(),
            operation_type: "test".into(),
            payload: "{}".into(),
            created_at: 1,
            synced: false,
            retry_count: 0,
        };
        m1.queue_operation(op).await.unwrap();

        let pending = m2.get_pending_operations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "shared");
    }
}

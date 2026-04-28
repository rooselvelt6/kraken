//! Sistema offline-first para Venezuela
//! Proporciona persistencia local y sincronización cuando hay conexión

mod error;
mod storage;

pub use error::OfflineError;
pub use storage::*;

/// Operación guardada para sincronización
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Operation {
    pub id: String,
    pub operation_type: String,
    pub payload: String,
    pub created_at: i64,
    pub synced: bool,
    pub retry_count: u32,
}

/// Estado de conexión
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConnectionState {
    Online,
    Offline,
    Syncing,
}

/// Settings del sistema offline
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OfflineSettings {
    pub auto_sync: bool,
    pub sync_interval_secs: u64,
    pub max_queue_size: usize,
    pub remote_url: Option<String>,
}

impl Default for OfflineSettings {
    fn default() -> Self {
        Self {
            auto_sync: true,
            sync_interval_secs: 300,
            max_queue_size: 1000,
            remote_url: None,
        }
    }
}
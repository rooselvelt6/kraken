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

//! Errores del sistema offline
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OfflineError {
    #[error("Error de base de datos: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Error de red: {0}")]
    Network(String),
    #[error("Error de serialización: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("No hay conexión")]
    NoConnection,
    #[error("Cola llena")]
    QueueFull,
}
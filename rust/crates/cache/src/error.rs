use thiserror::Error;

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Error de base de datos")]
    Database,
    #[error("No encontrado")]
    NotFound,
    #[error("Expirado")]
    Expired,
}
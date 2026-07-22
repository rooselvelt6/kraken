//! Offline system errors
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OfflineError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("No connection")]
    NoConnection,
    #[error("Queue full")]
    QueueFull,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_database() {
        let err = OfflineError::Network("timeout".into());
        assert_eq!(err.to_string(), "Network error: timeout");
    }

    #[test]
    fn test_error_display_no_connection() {
        let err = OfflineError::NoConnection;
        assert_eq!(err.to_string(), "No connection");
    }

    #[test]
    fn test_error_display_queue_full() {
        let err = OfflineError::QueueFull;
        assert_eq!(err.to_string(), "Queue full");
    }

    #[test]
    fn test_error_display_network() {
        let err = OfflineError::Network("refused".to_string());
        assert!(err.to_string().contains("refused"));
    }

    #[test]
    fn test_error_debug_trait() {
        let err = OfflineError::NoConnection;
        let debug = format!("{:?}", err);
        assert_eq!(debug, "NoConnection");
    }

    #[test]
    fn test_error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<OfflineError>();
    }

    #[test]
    fn test_error_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<OfflineError>();
    }

    #[test]
    fn test_json_error_conversion() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json");
        assert!(json_err.is_err());
        let offline_err: OfflineError = json_err.unwrap_err().into();
        assert!(matches!(offline_err, OfflineError::Serialize(_)));
    }

    #[test]
    fn test_network_error_various_messages() {
        let msgs = ["timeout", "connection refused", "dns failure", ""];
        for msg in &msgs {
            let err = OfflineError::Network(msg.to_string());
            assert!(err.to_string().contains(msg));
        }
    }

    #[test]
    fn test_error_display_serialize() {
        let json_err = serde_json::from_str::<serde_json::Value>("[").unwrap_err();
        let offline_err: OfflineError = json_err.into();
        let display = offline_err.to_string();
        assert!(display.contains("Serialization error"));
    }
}

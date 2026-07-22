use thiserror::Error;

#[derive(Error, Debug)]
pub enum C2Error {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Agent not found: {0}")]
    AgentNotFound(String),
    #[error("Task not found: {0}")]
    TaskNotFound(String),
    #[error("Session error: {0}")]
    Session(String),
}

impl From<C2Error> for String {
    fn from(e: C2Error) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c2_error_display() {
        let err = C2Error::Crypto("key init failed".to_string());
        assert!(err.to_string().contains("key init failed"));
    }

    #[test]
    fn test_c2_error_agent_not_found() {
        let err = C2Error::AgentNotFound("agent-1".to_string());
        assert!(err.to_string().contains("agent-1"));
    }

    #[test]
    fn test_c2_error_into_string() {
        let err = C2Error::Transport("connection refused".to_string());
        let msg: String = err.into();
        assert!(msg.contains("connection refused"));
    }
}

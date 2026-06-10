//! Proveedores locales para Venezuela

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum ProviderError {
    Http,
    Unavailable,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Http => write!(f, "HTTP error"),
            ProviderError::Unavailable => write!(f, "Unavailable"),
        }
    }
}

impl std::error::Error for ProviderError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub url: String,
    pub available: bool,
}

/// Auto-detectar proveedores locales
pub async fn discover_providers() -> Vec<ProviderInfo> {
    let mut providers = Vec::new();
    let client = reqwest::Client::new();

    // Check Ollama
    if let Ok(resp) = client
        .get("http://localhost:11434/api/tags")
        .timeout(std::time::Duration::from_secs(1))
        .send()
        .await
    {
        if resp.status().is_success() {
            providers.push(ProviderInfo {
                name: "ollama".to_string(),
                url: "http://localhost:11434".to_string(),
                available: true,
            });
        }
    }

    // Check LM Studio
    if let Ok(resp) = client
        .get("http://localhost:1234/v1/models")
        .timeout(std::time::Duration::from_secs(1))
        .send()
        .await
    {
        if resp.status().is_success() {
            providers.push(ProviderInfo {
                name: "lmstudio".to_string(),
                url: "http://localhost:1234".to_string(),
                available: true,
            });
        }
    }

    providers
}

pub mod providers {
    use super::*;

    pub struct OllamaProvider {
        url: String,
        model: String,
    }

    impl OllamaProvider {
        pub fn new(url: &str, model: &str) -> Self {
            Self {
                url: url.to_string(),
                model: model.to_string(),
            }
        }

        pub async fn complete(&self, prompt: &str) -> Result<String, ProviderError> {
            use serde::Deserialize;

            #[derive(Serialize)]
            struct Request {
                prompt: String,
                model: String,
                stream: bool,
            }

            #[derive(Deserialize)]
            struct Response {
                response: String,
            }

            let client = reqwest::Client::new();
            let request = Request {
                prompt: prompt.to_string(),
                model: self.model.clone(),
                stream: false,
            };

            let response: Response = client
                .post(format!("{}/api/generate", self.url))
                .json(&request)
                .send()
                .await
                .map_err(|_| ProviderError::Http)?
                .json()
                .await
                .map_err(|_| ProviderError::Http)?;

            Ok(response.response)
        }
    }
}

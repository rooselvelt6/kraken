#[allow(clippy::all, clippy::field_reassign_with_default, clippy::manual_find)]
/// Graceful degradation with provider fallback chains
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderState {
    Available,
    Unavailable,
    RateLimited,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GracefulDegradation {
    provider_states: HashMap<String, ProviderState>,
    fallback_chain: Vec<String>,
}

impl GracefulDegradation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default() -> Self {
        let mut gd = GracefulDegradation::default();
        gd.fallback_chain = vec![
            "deepseek".to_string(),
            "bigpickle".to_string(),
            "ollama".to_string(),
        ];

        for provider in &gd.fallback_chain {
            gd.provider_states
                .insert(provider.clone(), ProviderState::Available);
        }

        gd
    }

    pub fn mark_unavailable(&mut self, provider: &str) {
        self.provider_states
            .insert(provider.to_string(), ProviderState::Unavailable);
    }

    pub fn mark_available(&mut self, provider: &str) {
        self.provider_states
            .insert(provider.to_string(), ProviderState::Available);
    }

    pub fn mark_rate_limited(&mut self, provider: &str) {
        self.provider_states
            .insert(provider.to_string(), ProviderState::RateLimited);
    }

    pub fn is_available(&self, provider: &str) -> bool {
        self.provider_states
            .get(provider)
            .map(|s| matches!(s, ProviderState::Available))
            .unwrap_or(false)
    }

    pub fn best_available(&self) -> Option<&str> {
        for provider in &self.fallback_chain {
            if self.is_available(provider) {
                return Some(provider);
            }
        }
        None
    }

    pub fn get_fallback(&self, failed: &str) -> Option<&str> {
        let failed_idx = self.fallback_chain.iter().position(|p| p == failed);

        if let Some(idx) = failed_idx {
            for i in (idx + 1)..self.fallback_chain.len() {
                let next_provider = &self.fallback_chain[i];
                if self.is_available(next_provider) {
                    return Some(next_provider);
                }
            }
        }
        None
    }

    pub fn all_states(&self) -> HashMap<String, String> {
        self.provider_states
            .iter()
            .map(|(k, v)| {
                let state_str = match v {
                    ProviderState::Available => "available",
                    ProviderState::Unavailable => "unavailable",
                    ProviderState::RateLimited => "rate_limited",
                };
                (k.clone(), state_str.to_string())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graceful_degradation_default() {
        let gd = GracefulDegradation::with_default();

        assert!(gd.is_available("deepseek"));
        assert!(gd.is_available("bigpickle"));

        let best = gd.best_available();
        assert!(best.is_some());
    }

    #[test]
    fn test_fallback_chain() {
        let mut gd = GracefulDegradation::with_default();

        gd.mark_unavailable("deepseek");

        let fallback = gd.get_fallback("deepseek");
        assert_eq!(fallback, Some("bigpickle"));

        gd.mark_unavailable("deepseek");
        gd.mark_unavailable("bigpickle");

        let fallback = gd.get_fallback("bigpickle");
        assert_eq!(fallback, Some("ollama"));
    }

    #[test]
    fn test_no_available_provider() {
        let mut gd = GracefulDegradation::with_default();

        gd.mark_unavailable("deepseek");
        gd.mark_unavailable("bigpickle");
        gd.mark_unavailable("ollama");

        let best = gd.best_available();
        assert!(best.is_none());
    }
}

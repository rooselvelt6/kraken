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

    #[test]
    fn test_new_creates_empty() {
        let gd = GracefulDegradation::new();
        assert!(gd.best_available().is_none());
        assert!(!gd.is_available("anything"));
    }

    #[test]
    fn test_provider_state_serialization() {
        let json = serde_json::to_string(&ProviderState::Available).unwrap();
        assert_eq!(json, "\"Available\"");
        let deserialized: ProviderState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ProviderState::Available);

        let json = serde_json::to_string(&ProviderState::Unavailable).unwrap();
        let deserialized: ProviderState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ProviderState::Unavailable);

        let json = serde_json::to_string(&ProviderState::RateLimited).unwrap();
        let deserialized: ProviderState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ProviderState::RateLimited);
    }

    #[test]
    fn test_provider_state_equality() {
        assert_eq!(ProviderState::Available, ProviderState::Available);
        assert_ne!(ProviderState::Available, ProviderState::Unavailable);
        assert_ne!(ProviderState::RateLimited, ProviderState::Unavailable);
    }

    #[test]
    fn test_mark_rate_limited() {
        let mut gd = GracefulDegradation::new();
        gd.mark_rate_limited("provider1");
        assert!(!gd.is_available("provider1"));
    }

    #[test]
    fn test_mark_unavailable_unknown_provider() {
        let mut gd = GracefulDegradation::new();
        gd.mark_unavailable("unknown");
        assert!(!gd.is_available("unknown"));
    }

    #[test]
    fn test_mark_available_restores() {
        let mut gd = GracefulDegradation::with_default();
        gd.mark_unavailable("deepseek");
        assert!(!gd.is_available("deepseek"));

        gd.mark_available("deepseek");
        assert!(gd.is_available("deepseek"));
    }

    #[test]
    fn test_best_available_first_in_chain() {
        let gd = GracefulDegradation::with_default();
        assert_eq!(gd.best_available(), Some("deepseek"));
    }

    #[test]
    fn test_best_available_skips_unavailable() {
        let mut gd = GracefulDegradation::with_default();
        gd.mark_unavailable("deepseek");
        assert_eq!(gd.best_available(), Some("bigpickle"));
    }

    #[test]
    fn test_best_available_skips_rate_limited() {
        let mut gd = GracefulDegradation::with_default();
        gd.mark_rate_limited("deepseek");
        assert_eq!(gd.best_available(), Some("bigpickle"));
    }

    #[test]
    fn test_get_fallback_unknown_provider() {
        let gd = GracefulDegradation::with_default();
        assert_eq!(gd.get_fallback("nonexistent"), None);
    }

    #[test]
    fn test_get_fallback_last_provider() {
        let gd = GracefulDegradation::with_default();
        // ollama is last in chain
        let fallback = gd.get_fallback("ollama");
        assert!(fallback.is_none());
    }

    #[test]
    fn test_get_fallback_skips_unavailable() {
        let mut gd = GracefulDegradation::with_default();
        gd.mark_unavailable("bigpickle");
        let fallback = gd.get_fallback("deepseek");
        assert_eq!(fallback, Some("ollama"));
    }

    #[test]
    fn test_get_fallback_skips_rate_limited() {
        let mut gd = GracefulDegradation::with_default();
        gd.mark_rate_limited("bigpickle");
        let fallback = gd.get_fallback("deepseek");
        assert_eq!(fallback, Some("ollama"));
    }

    #[test]
    fn test_all_states() {
        let gd = GracefulDegradation::with_default();
        let states = gd.all_states();
        assert_eq!(states.get("deepseek"), Some(&"available".to_string()));
        assert_eq!(states.get("bigpickle"), Some(&"available".to_string()));
        assert_eq!(states.get("ollama"), Some(&"available".to_string()));
    }

    #[test]
    fn test_all_states_after_changes() {
        let mut gd = GracefulDegradation::with_default();
        gd.mark_unavailable("deepseek");
        gd.mark_rate_limited("ollama");

        let states = gd.all_states();
        assert_eq!(states.get("deepseek"), Some(&"unavailable".to_string()));
        assert_eq!(states.get("bigpickle"), Some(&"available".to_string()));
        assert_eq!(states.get("ollama"), Some(&"rate_limited".to_string()));
    }

    #[test]
    fn test_graceful_degradation_serialization() {
        let gd = GracefulDegradation::with_default();
        let json = serde_json::to_string(&gd).unwrap();
        let deserialized: GracefulDegradation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fallback_chain.len(), 3);
        assert_eq!(deserialized.fallback_chain[0], "deepseek");
    }

    #[test]
    fn test_graceful_degradation_clone() {
        let gd = GracefulDegradation::with_default();
        let cloned = gd.clone();
        assert_eq!(cloned.fallback_chain.len(), 3);
        assert!(cloned.is_available("deepseek"));
    }

    #[test]
    fn test_full_cascade_failure() {
        let mut gd = GracefulDegradation::with_default();

        assert_eq!(gd.get_fallback("deepseek"), Some("bigpickle"));

        gd.mark_unavailable("bigpickle");
        assert_eq!(gd.get_fallback("deepseek"), Some("ollama"));

        gd.mark_unavailable("deepseek");
        gd.mark_unavailable("ollama");
        assert_eq!(gd.get_fallback("deepseek"), None);

        assert!(gd.best_available().is_none());
    }

    #[test]
    fn test_mark_available_on_untracked_provider() {
        let mut gd = GracefulDegradation::new();
        gd.mark_available("custom_provider");
        assert!(gd.is_available("custom_provider"));
    }
}

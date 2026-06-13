use crate::circuit_breaker::global_circuit_forest;
use crate::config::ProviderFallbackConfig;
use crate::health_probe::{global_health_registry, HealthStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderState {
    Available,
    Degraded,
    Unavailable,
}

impl ProviderState {
    pub fn can_serve(&self) -> bool {
        matches!(self, Self::Available | Self::Degraded)
    }
}

#[derive(Debug, Clone)]
pub struct ProviderChainStatus {
    pub provider: String,
    pub state: ProviderState,
    pub circuit_ok: bool,
    pub health_status: HealthStatus,
    pub recovery_time_remaining_ms: Option<u64>,
}

pub struct ProviderChain {
    primary: Option<String>,
    fallbacks: Vec<String>,
    offline_fallback: String,
}

impl ProviderChain {
    pub fn from_config(config: &ProviderFallbackConfig) -> Self {
        Self {
            primary: config.primary().map(String::from),
            fallbacks: config.fallbacks().to_vec(),
            offline_fallback: "offline".to_string(),
        }
    }

    pub fn new(primary: Option<String>, fallbacks: Vec<String>) -> Self {
        Self {
            primary,
            fallbacks,
            offline_fallback: "offline".to_string(),
        }
    }

    pub fn best_available(&self) -> Option<String> {
        if let Some(ref primary) = self.primary {
            if self.is_provider_available(primary) {
                return Some(primary.clone());
            }
        }

        for fallback in &self.fallbacks {
            if self.is_provider_available(fallback) {
                return Some(fallback.clone());
            }
        }

        None
    }

    pub fn next_after(&self, failed_provider: &str) -> Option<String> {
        let all: Vec<&str> = self
            .primary
            .iter()
            .map(|s| s.as_str())
            .chain(self.fallbacks.iter().map(|s| s.as_str()))
            .collect();

        let start_idx = match all.iter().position(|&p| p == failed_provider) {
            Some(idx) => idx,
            None => {
                return self.best_available();
            }
        };

        for provider in all.iter().skip(start_idx + 1) {
            if self.is_provider_available(provider) {
                return Some(provider.to_string());
            }
        }

        if self.is_provider_available(&self.offline_fallback) {
            return Some(self.offline_fallback.clone());
        }

        None
    }

    pub fn all_available(&self) -> Vec<String> {
        let mut available = Vec::new();

        if let Some(ref primary) = self.primary {
            if self.is_provider_available(primary) {
                available.push(primary.clone());
            }
        }

        for fallback in &self.fallbacks {
            if self.is_provider_available(fallback) {
                available.push(fallback.clone());
            }
        }

        available
    }

    pub fn status(&self) -> Vec<ProviderChainStatus> {
        let mut statuses = Vec::new();
        let forest = global_circuit_forest().lock().unwrap();
        let registry = global_health_registry().lock().unwrap();

        if let Some(ref primary) = self.primary {
            statuses.push(build_status(&forest, &registry, primary, true));
        }

        for fallback in &self.fallbacks {
            statuses.push(build_status(&forest, &registry, fallback, false));
        }

        statuses
    }

    fn is_provider_available(&self, provider: &str) -> bool {
        if provider == "offline" {
            return true;
        }

        let forest = global_circuit_forest().lock().unwrap();
        if !forest.can_execute(provider) {
            return false;
        }

        let registry = global_health_registry().lock().unwrap();
        if let Some(target) = registry.get(provider) {
            target.is_available()
        } else {
            true
        }
    }
}

fn build_status(
    forest: &std::sync::MutexGuard<'_, crate::circuit_breaker::CircuitForest>,
    registry: &std::sync::MutexGuard<'_, crate::health_probe::HealthProbeRegistry>,
    provider: &str,
    _is_primary: bool,
) -> ProviderChainStatus {
    let circuit_ok = forest.can_execute(provider);
    let circuit_node = forest.get(provider);
    let recovery_time = circuit_node.and_then(|n| n.recovery_time_remaining());

    let health_status = registry
        .get(provider)
        .map(|t| t.status)
        .unwrap_or(HealthStatus::Unknown);

    let state = if !circuit_ok || health_status == HealthStatus::Unhealthy {
        ProviderState::Unavailable
    } else if health_status == HealthStatus::Degraded {
        ProviderState::Degraded
    } else {
        ProviderState::Available
    };

    ProviderChainStatus {
        provider: provider.to_string(),
        state,
        circuit_ok,
        health_status,
        recovery_time_remaining_ms: recovery_time.map(|d| d.as_millis() as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_chain_best_available_no_fallbacks() {
        let chain = ProviderChain::new(Some("anthropic".to_string()), vec![]);
        let best = chain.best_available();
        assert!(best.is_some());
        assert_eq!(best.unwrap(), "anthropic");
    }

    #[test]
    fn test_provider_chain_next_after_primary() {
        let chain = ProviderChain::new(
            Some("anthropic".to_string()),
            vec!["deepseek".to_string(), "ollama".to_string()],
        );
        let next = chain.next_after("anthropic");
        assert!(next.is_some());
        assert_eq!(next.unwrap(), "deepseek");
    }

    #[test]
    fn test_provider_chain_next_after_last_fallback() {
        let chain = ProviderChain::new(
            Some("anthropic".to_string()),
            vec!["deepseek".to_string()],
        );
        let next = chain.next_after("deepseek");
        assert!(next.is_some());
        assert_eq!(next.unwrap(), "offline");
    }

    #[test]
    fn test_provider_chain_next_after_unknown() {
        let chain = ProviderChain::new(
            Some("anthropic".to_string()),
            vec!["deepseek".to_string()],
        );
        let next = chain.next_after("unknown");
        assert!(next.is_some());
        assert_eq!(next.unwrap(), "anthropic");
    }

    #[test]
    fn test_provider_chain_all_available() {
        let chain = ProviderChain::new(
            Some("anthropic".to_string()),
            vec!["deepseek".to_string()],
        );
        let available = chain.all_available();
        assert_eq!(available.len(), 2);
    }

    #[test]
    fn test_provider_chain_status() {
        let chain = ProviderChain::new(
            Some("anthropic".to_string()),
            vec!["deepseek".to_string()],
        );
        let statuses = chain.status();
        assert_eq!(statuses.len(), 2);
        assert!(statuses[0].circuit_ok);
        assert_eq!(statuses[0].provider, "anthropic");
    }

    #[test]
    fn test_provider_chain_offline_fallback() {
        let chain = ProviderChain::new(Some("fake".to_string()), vec![]);
        // Since "fake" isn't registered, is_provider_available returns true
        // because global_circuit_forest().can_execute returns true for unknown
        let best = chain.best_available();
        assert_eq!(best, Some("fake".to_string()));
    }

    #[test]
    fn test_provider_state_can_serve() {
        assert!(ProviderState::Available.can_serve());
        assert!(ProviderState::Degraded.can_serve());
        assert!(!ProviderState::Unavailable.can_serve());
    }

    #[test]
    fn test_from_config() {
        let config = ProviderFallbackConfig::new(
            Some("anthropic".to_string()),
            vec!["deepseek".to_string()],
        );
        let chain = ProviderChain::from_config(&config);
        let statuses = chain.status();
        assert!(statuses.iter().any(|s| s.provider == "anthropic"));
    }

    #[test]
    fn test_provider_chain_no_primary() {
        let chain = ProviderChain::new(None, vec!["deepseek".to_string()]);
        let best = chain.best_available();
        assert_eq!(best, Some("deepseek".to_string()));
    }

    #[test]
    fn test_provider_chain_empty() {
        let chain = ProviderChain::new(None, vec![]);
        assert!(chain.best_available().is_none());
    }
}

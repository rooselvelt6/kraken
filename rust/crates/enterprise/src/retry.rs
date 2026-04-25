//! Retry logic with exponential backoff and jitter

use std::time::Duration;
use serde::{Deserialize, Serialize};
use rand::Rng;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryConfig {
    pub fn new(max_retries: u32, initial_delay_ms: u64) -> Self {
        Self {
            max_retries,
            initial_delay_ms,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
    
    pub fn delay(&self, attempt: u32) -> Duration {
        let base = self.initial_delay_ms as f64 * self.backoff_multiplier.powf(attempt as f64);
        let delay_ms = base.min(self.max_delay_ms as f64) as u64;
        
        if self.jitter {
            let mut rng = rand::thread_rng();
            let jitter_range = 0.5 + rng.gen::<f64>() * 0.5;
            let jittered = (delay_ms as f64 * jitter_range) as u64;
            Duration::from_millis(jittered.max(1))
        } else {
            Duration::from_millis(delay_ms)
        }
    }
    
    pub fn should_retry(&self, attempt: u32, error: &str) -> bool {
        if attempt >= self.max_retries {
            return false;
        }
        
        let retryable_errors = [
            "timeout",
            "connection",
            "network",
            "rate_limit",
            "429",
            "503",
            "502",
            "504",
        ];
        
        let error_lower = error.to_lowercase();
        retryable_errors.iter().any(|e| error_lower.contains(e))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryStrategy {
    None,
    ExponentialBackoff,
    Linear,
    Constant,
}

impl Default for RetryStrategy {
    fn default() -> Self {
        Self::ExponentialBackoff
    }
}

// Note: retry_async is simplified - see ROADMAP-ENTERPRISE.md for full implementation
pub async fn retry_async<T, E, F, Fut>(
    config: &RetryConfig,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut attempt = 0u32;
    
    loop {
        match operation(attempt).await {
            Ok(result) => return Ok(result),
            Err(_) => {
                attempt += 1;
                
                if attempt >= config.max_retries {
                    break;
                }
                
                let delay = config.delay(attempt);
                tokio::time::sleep(delay).await;
            }
        }
    }
    
    Err(operation(attempt).await.err().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_retry_delay_calculation() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter: false,
        };
        
        let delay1 = config.delay(0);
        let delay2 = config.delay(1);
        let delay3 = config.delay(2);
        
        assert!(delay1.as_millis() >= 1000);
        assert!(delay2.as_millis() >= 2000);
        assert!(delay3.as_millis() >= 4000);
    }
    
    #[test]
    fn test_should_retry() {
        let config = RetryConfig::default();
        
        assert!(config.should_retry(0, "timeout error"));
        assert!(config.should_retry(0, "rate_limit"));
        assert!(!config.should_retry(0, "invalid_api_key"));
        assert!(!config.should_retry(100, "timeout"));
    }
}
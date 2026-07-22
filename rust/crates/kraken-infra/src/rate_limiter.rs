use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AdaptiveTokenBucket {
    pub name: String,
    pub base_capacity: f64,
    pub max_capacity: f64,
    pub min_capacity: f64,
    pub refill_rate: f64,
    pub confidence_bonus: f64,
    pub error_malus: f64,
    tokens: f64,
    last_refill: Instant,
    pub current_capacity: f64,
    pub request_count: u64,
    pub error_count: u64,
    pub last_adjustment: Instant,
    pub adjustment_interval: Duration,
}

impl AdaptiveTokenBucket {
    #[must_use]
    pub fn new(
        name: &str,
        base_capacity: f64,
        refill_rate: f64,
        max_capacity: f64,
        min_capacity: f64,
    ) -> Self {
        Self {
            name: name.to_string(),
            base_capacity,
            max_capacity,
            min_capacity,
            refill_rate,
            confidence_bonus: 0.0,
            error_malus: 0.0,
            tokens: base_capacity,
            last_refill: Instant::now(),
            current_capacity: base_capacity,
            request_count: 0,
            error_count: 0,
            last_adjustment: Instant::now(),
            adjustment_interval: Duration::from_secs(30),
        }
    }

    pub fn allow(&mut self, cost: f64) -> bool {
        self.refill();

        if self.tokens >= cost {
            self.tokens -= cost;
            self.request_count += 1;
            true
        } else {
            false
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn try_consume(&mut self, cost: f64) -> Result<(), ()> {
        self.refill();
        if self.tokens >= cost {
            self.tokens -= cost;
            self.request_count += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn record_error(&mut self) {
        self.error_count += 1;
    }

    pub fn record_success(&mut self) {
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn adjust(&mut self) {
        if self.last_adjustment.elapsed() < self.adjustment_interval {
            return;
        }

        let total = self.request_count.max(1);
        let error_rate = self.error_count as f64 / total as f64;

        if error_rate < 0.05 {
            self.confidence_bonus = (self.confidence_bonus + self.base_capacity * 0.1).min(self.base_capacity * 0.5);
            self.error_malus = 0.0;
        } else if error_rate > 0.2 {
            self.error_malus = (self.error_malus + self.base_capacity * 0.2).min(self.base_capacity * 0.8);
            self.confidence_bonus = 0.0;
        } else {
            let adjustment = self.base_capacity * 0.05;
            self.confidence_bonus = (self.confidence_bonus - adjustment).max(0.0);
            self.error_malus = (self.error_malus - adjustment * 0.5).max(0.0);
        }

        let raw_capacity = self.base_capacity + self.confidence_bonus - self.error_malus;
        self.current_capacity = raw_capacity.clamp(self.min_capacity, self.max_capacity);

        if self.tokens > self.current_capacity {
            self.tokens = self.current_capacity;
        }

        self.request_count = 0;
        self.error_count = 0;
        self.last_adjustment = Instant::now();
    }

    #[must_use]
    pub fn remaining(&self) -> f64 {
        self.tokens
    }

    pub fn reset(&mut self) {
        self.tokens = self.current_capacity;
        self.last_refill = Instant::now();
        self.request_count = 0;
        self.error_count = 0;
        self.confidence_bonus = 0.0;
        self.error_malus = 0.0;
        self.current_capacity = self.base_capacity;
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let new_tokens = elapsed * self.refill_rate;
            self.tokens = (self.tokens + new_tokens).min(self.current_capacity);
            self.last_refill = Instant::now();
        }
    }

    #[must_use]
    pub fn utilization(&self) -> f64 {
        self.tokens / self.current_capacity.max(1.0)
    }

    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.tokens < 1.0
    }
}

pub struct TokenBucketRegistry {
    buckets: HashMap<String, AdaptiveTokenBucket>,
    default_base_capacity: f64,
    default_refill_rate: f64,
    default_max_capacity: f64,
    default_min_capacity: f64,
    global_bucket: Option<AdaptiveTokenBucket>,
}

impl TokenBucketRegistry {
    #[must_use]
    pub fn new(
        default_base_capacity: f64,
        default_refill_rate: f64,
        default_max_capacity: f64,
        default_min_capacity: f64,
    ) -> Self {
        Self {
            buckets: HashMap::new(),
            default_base_capacity,
            default_refill_rate,
            default_max_capacity,
            default_min_capacity,
            global_bucket: None,
        }
    }

    pub fn register(&mut self, name: &str) {
        self.buckets.insert(
            name.to_string(),
            AdaptiveTokenBucket::new(
                name,
                self.default_base_capacity,
                self.default_refill_rate,
                self.default_max_capacity,
                self.default_min_capacity,
            ),
        );
    }

    pub fn register_with_params(
        &mut self,
        name: &str,
        base_capacity: f64,
        refill_rate: f64,
        max_capacity: f64,
        min_capacity: f64,
    ) {
        self.buckets.insert(
            name.to_string(),
            AdaptiveTokenBucket::new(name, base_capacity, refill_rate, max_capacity, min_capacity),
        );
    }

    pub fn set_global_bucket(&mut self, bucket: AdaptiveTokenBucket) {
        self.global_bucket = Some(bucket);
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut AdaptiveTokenBucket> {
        self.buckets.get_mut(name)
    }

    pub fn allow(&mut self, name: &str, cost: f64) -> bool {
        let local_ok = self
            .buckets
            .get_mut(name)
            .is_none_or(|b| b.allow(cost));

        if !local_ok {
            return false;
        }

        if let Some(ref mut global) = self.global_bucket {
            global.allow(cost)
        } else {
            true
        }
    }

    pub fn record_error(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.record_error();
        }
        if let Some(ref mut global) = self.global_bucket {
            global.record_error();
        }
    }

    pub fn record_success(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.record_success();
        }
        if let Some(ref mut global) = self.global_bucket {
            global.record_success();
        }
    }

    pub fn adjust_all(&mut self) {
        for bucket in self.buckets.values_mut() {
            bucket.adjust();
        }
        if let Some(ref mut global) = self.global_bucket {
            global.adjust();
        }
    }

    #[must_use]
    pub fn remaining(&self, name: &str) -> Option<f64> {
        self.buckets.get(name).map(AdaptiveTokenBucket::remaining)
    }

    #[must_use]
    pub fn is_exhausted(&self, name: &str) -> bool {
        self.buckets.get(name).is_some_and(AdaptiveTokenBucket::is_exhausted)
    }

    pub fn reset(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.reset();
        }
    }

    #[must_use]
    pub fn bucket_names(&self) -> Vec<String> {
        self.buckets.keys().cloned().collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &AdaptiveTokenBucket)> {
        self.buckets.iter()
    }
}

static GLOBAL_RATE_LIMITER: OnceLock<Mutex<TokenBucketRegistry>> = OnceLock::new();

pub fn global_rate_limiter() -> &'static Mutex<TokenBucketRegistry> {
    GLOBAL_RATE_LIMITER.get_or_init(|| {
        let mut registry = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
        registry.register("anthropic");
        registry.register("deepseek");
        registry.register("bigpickle");
        registry.register("ollama");
        registry.register("bash");
        registry.register("read");
        registry.register("write");
        registry.register("search");
        registry.register("mcp");
        registry.set_global_bucket(AdaptiveTokenBucket::new(
            "global",
            200.0,
            3.0,
            400.0,
            50.0,
        ));
        Mutex::new(registry)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_bucket_initial_state() {
        let bucket = AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
        assert_eq!(bucket.name, "test");
        assert_eq!(bucket.base_capacity, 100.0);
        assert_eq!(bucket.tokens, 100.0);
        assert!(bucket.utilization() > 0.99);
    }

    #[test]
    fn test_adaptive_bucket_allow_success() {
        let mut bucket = AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
        assert!(bucket.allow(50.0));
        assert_eq!(bucket.remaining(), 50.0);
    }

    #[test]
    fn test_adaptive_bucket_allow_failure() {
        let mut bucket = AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
        assert!(!bucket.allow(150.0));
    }

    #[test]
    fn test_adaptive_bucket_refill() {
        let mut bucket = AdaptiveTokenBucket::new("test", 100.0, 50.0, 200.0, 10.0);
        assert!(bucket.allow(100.0));
        assert_eq!(bucket.remaining(), 0.0);
        std::thread::sleep(Duration::from_millis(100));
        bucket.refill();
        assert!(bucket.remaining() > 0.0);
    }

    #[test]
    fn test_adaptive_bucket_adjust_confidence() {
        let mut bucket = AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
        bucket.last_adjustment = Instant::now() - Duration::from_secs(31);
        bucket.request_count = 100;
        bucket.error_count = 2;
        bucket.adjust();
        assert!(bucket.confidence_bonus > 0.0);
        assert!(bucket.current_capacity > 100.0);
    }

    #[test]
    fn test_adaptive_bucket_adjust_malus() {
        let mut bucket = AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
        bucket.last_adjustment = Instant::now() - Duration::from_secs(31);
        bucket.request_count = 100;
        bucket.error_count = 30;
        bucket.adjust();
        assert!(bucket.error_malus > 0.0);
        assert!(bucket.current_capacity < 100.0);
    }

    #[test]
    fn test_adaptive_bucket_adjust_not_ready() {
        let mut bucket = AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
        bucket.request_count = 100;
        bucket.error_count = 50;
        bucket.adjust();
        assert!((bucket.current_capacity - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_adaptive_bucket_clamp_capacity() {
        let mut bucket = AdaptiveTokenBucket::new("test", 100.0, 1.0, 110.0, 90.0);
        bucket.last_adjustment = Instant::now() - Duration::from_secs(31);
        bucket.request_count = 100;
        bucket.error_count = 0;
        bucket.adjust();
        assert!(bucket.current_capacity <= 110.0);

        bucket.last_adjustment = Instant::now() - Duration::from_secs(31);
        bucket.request_count = 100;
        bucket.error_count = 100;
        bucket.adjust();
        assert!(bucket.current_capacity >= 90.0);
    }

    #[test]
    fn test_adaptive_bucket_exhausted() {
        let mut bucket = AdaptiveTokenBucket::new("test", 1.0, 0.01, 1.0, 1.0);
        assert!(bucket.allow(1.0));
        assert!(bucket.is_exhausted());
    }

    #[test]
    fn test_adaptive_bucket_try_consume() {
        let mut bucket = AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
        assert!(bucket.try_consume(50.0).is_ok());
        assert!(bucket.try_consume(60.0).is_err());
    }

    #[test]
    fn test_adaptive_bucket_reset() {
        let mut bucket = AdaptiveTokenBucket::new("test", 100.0, 1.0, 200.0, 10.0);
        bucket.allow(50.0);
        bucket.record_error();
        bucket.reset();
        assert!((bucket.remaining() - 100.0).abs() < 0.001);
        assert_eq!(bucket.request_count, 0);
        assert_eq!(bucket.error_count, 0);
    }

    #[test]
    fn test_token_bucket_registry() {
        let mut registry = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
        registry.register("p1");
        assert!(registry.allow("p1", 10.0));
        assert_eq!(registry.remaining("p1"), Some(50.0));
    }

    #[test]
    fn test_token_bucket_registry_unknown_key() {
        let mut registry = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
        assert!(registry.allow("unknown", 10.0));
    }

    #[test]
    fn test_token_bucket_registry_global() {
        let mut registry = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
        registry.register("p1");
        registry.set_global_bucket(AdaptiveTokenBucket::new("g", 5.0, 0.1, 10.0, 1.0));
        assert!(registry.allow("p1", 4.0));
        assert!(!registry.allow("p1", 4.0));
    }

    #[test]
    fn test_token_bucket_registry_error_success() {
        let mut registry = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
        registry.register("p1");
        registry.allow("p1", 10.0);
        registry.record_error("p1");
        registry.record_success("p1");
        let bucket = registry.get_mut("p1").unwrap();
        assert_eq!(bucket.error_count, 1);
        assert_eq!(bucket.request_count, 1);
    }

    #[test]
    fn test_token_bucket_registry_adjust_all() {
        let mut registry = TokenBucketRegistry::new(100.0, 1.0, 200.0, 10.0);
        registry.register("p1");
        let bucket = registry.get_mut("p1").unwrap();
        bucket.last_adjustment = Instant::now() - Duration::from_secs(31);
        drop(bucket);
        registry.adjust_all();
        let bucket = registry.get_mut("p1").unwrap();
        assert!(bucket.current_capacity > 100.0);
    }

    #[test]
    fn test_token_bucket_registry_bucket_names() {
        let mut registry = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
        registry.register("p1");
        registry.register("p2");
        let names = registry.bucket_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"p1".to_string()));
    }

    #[test]
    fn test_token_bucket_registry_reset() {
        let mut registry = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
        registry.register("p1");
        registry.allow("p1", 30.0);
        registry.reset("p1");
        assert_eq!(registry.remaining("p1"), Some(60.0));
    }

    #[test]
    fn test_global_rate_limiter_initialized() {
        let limiter = global_rate_limiter();
        let mut guard = limiter.lock().unwrap();
        assert!(guard.get_mut("anthropic").is_some());
        assert!(guard.get_mut("bash").is_some());
    }

    #[test]
    fn test_register_with_params() {
        let mut registry = TokenBucketRegistry::new(60.0, 1.0, 120.0, 10.0);
        registry.register_with_params("custom", 200.0, 5.0, 500.0, 20.0);
        let bucket = registry.get_mut("custom").unwrap();
        assert_eq!(bucket.base_capacity, 200.0);
        assert_eq!(bucket.refill_rate, 5.0);
    }

    #[test]
    fn test_is_exhausted() {
        let mut registry = TokenBucketRegistry::new(1.0, 0.01, 1.0, 1.0);
        registry.register("p1");
        registry.allow("p1", 1.0);
        assert!(registry.is_exhausted("p1"));
    }
}

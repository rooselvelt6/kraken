use serde::{Deserialize, Serialize};

const FEATURE_COUNT: usize = 66;

/// A trained logistic regression model with 3 classes.
/// Weights are pre-trained offline and loaded at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainedModel {
    pub name: String,
    pub version: String,
    pub benign_weights: Vec<f64>,
    pub suspicious_weights: Vec<f64>,
    pub malicious_weights: Vec<f64>,
    pub benign_bias: f64,
    pub suspicious_bias: f64,
    pub malicious_bias: f64,
}

impl TrainedModel {
    pub fn new(
        name: &str,
        version: &str,
        benign_weights: Vec<f64>,
        suspicious_weights: Vec<f64>,
        malicious_weights: Vec<f64>,
        benign_bias: f64,
        suspicious_bias: f64,
        malicious_bias: f64,
    ) -> Self {
        assert_eq!(benign_weights.len(), FEATURE_COUNT);
        assert_eq!(suspicious_weights.len(), FEATURE_COUNT);
        assert_eq!(malicious_weights.len(), FEATURE_COUNT);
        Self {
            name: name.to_string(),
            version: version.to_string(),
            benign_weights,
            suspicious_weights,
            malicious_weights,
            benign_bias,
            suspicious_bias,
            malicious_bias,
        }
    }

    pub fn feature_count(&self) -> usize {
        FEATURE_COUNT
    }

    /// Default small model with hand-tuned weights based on expert knowledge.
    /// In production, these weights would be learned from labeled data.
    pub fn default_small() -> Self {
        // Positive weights = feature indicates malicious
        // Negative weights = feature indicates benign
        // Zero = no signal
        let mut benign = vec![0.0; FEATURE_COUNT];
        let mut suspicious = vec![0.0; FEATURE_COUNT];
        let mut malicious = vec![0.0; FEATURE_COUNT];

        // Indices (must match CommandFeatures::as_feature_vec order):
        // 0-4: length/entropy features
        // 5-12: shell syntax
        // 13-22: dangerous patterns
        // 23-27: encoding anomalies
        // 28-35: path analysis
        // 36-41: network indicators
        // 42-47: process manipulation
        // 48-52: privilege escalation
        // 53-56: persistence
        // 57-59: compression
        // 60-62: compilation
        // 63: special_char_ratio (not used as single)

        // Benign indicators
        // Longer commands with pipes are often normal development
        benign[0] = 0.01;  // char_len — very weak signal, mostly noise
        benign[5] = 0.15;  // has_pipe (common in dev)
        benign[63] = -0.3; // special_char_ratio — more special chars = less benign

        // Malicious pattern weights
        // Dangerous patterns (13-22)
        malicious[13] = 3.0;  // has_rm_rf
        malicious[14] = 2.0;  // has_dd
        malicious[15] = 2.0;  // has_mkfs
        malicious[16] = 2.0;  // has_chmod_recursive
        malicious[17] = 1.5;  // has_chown
        malicious[18] = 2.0;  // has_wget_curl
        malicious[19] = 3.5;  // has_bash_network (reverse shell)
        malicious[20] = 2.5;  // has_eval
        malicious[21] = 3.0;  // has_wget_to_pipe
        malicious[22] = 3.0;  // has_curl_to_pipe

        // Encoding anomalies (23-27)
        malicious[23] = 2.5;  // has_base64 (common in obfuscated payloads)
        malicious[24] = 1.5;  // has_hex_encoding
        malicious[26] = 1.5;  // has_url_encoding
        malicious[27] = 2.0;  // has_unicode_escape

        // Path analysis (28-35)
        malicious[28] = 1.0;  // has_system_path
        malicious[29] = 1.5;  // has_proc_path
        malicious[30] = 1.0;  // has_dev_path
        malicious[31] = 2.5;  // has_ssh_path
        malicious[32] = 1.5;  // has_git_path

        // Network indicators (36-41)
        malicious[36] = 1.0;  // has_ip_address
        malicious[40] = 0.5;  // has_localhost
        malicious[41] = 2.5;  // has_network_conn (nc, netcat, socat)

        // Process manipulation (42-47)
        malicious[42] = 1.0;  // has_kill
        malicious[46] = 3.5;  // has_fork_bomb
        malicious[47] = 2.0;  // has_ptrace

        // Privilege escalation (48-52)
        malicious[48] = 1.5;  // has_sudo
        malicious[49] = 1.0;  // has_su
        malicious[50] = 2.0;  // has_setuid
        malicious[51] = 1.5;  // has_capability
        malicious[52] = 2.5;  // has_pkexec

        // Persistence (53-56)
        malicious[53] = 2.0;  // has_cron
        malicious[54] = 1.5;  // has_systemd
        malicious[55] = 1.5;  // has_rc_local
        malicious[56] = 2.5;  // has_ssh_authorized

        // Suspicious (mid-level) weights — milder versions
        suspicious[18] = 0.8;  // has_wget_curl
        suspicious[28] = 0.3;  // has_system_path
        suspicious[48] = 0.5;  // has_sudo
        suspicious[1] = 0.2;   // word_count

        // Biases
        let benign_bias = 0.0;     // Neutral default — indicators drive classification
        let suspicious_bias = -1.0;
        let malicious_bias = -1.5;

        Self::new(
            "kraken-default-v1",
            "1.0.0",
            benign,
            suspicious,
            malicious,
            benign_bias,
            suspicious_bias,
            malicious_bias,
        )
    }
}

/// Model storage for saving/loading trained models.
pub struct ModelStorage;

impl ModelStorage {
    /// Save model to JSON file.
    pub fn save_to_file(model: &TrainedModel, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(model)
            .map_err(|e| format!("serialize model: {e}"))?;
        std::fs::write(path, json)
            .map_err(|e| format!("write model file: {e}"))
    }

    /// Load model from JSON file.
    pub fn load_from_file(path: &str) -> Result<TrainedModel, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("read model file: {e}"))?;
        serde_json::from_str(&json)
            .map_err(|e| format!("deserialize model: {e}"))
    }

    /// Load model from embedded bytes.
    pub fn load_from_bytes(bytes: &[u8]) -> Result<TrainedModel, String> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("deserialize model from bytes: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_model_has_correct_dimensions() {
        let model = TrainedModel::default_small();
        assert_eq!(model.feature_count(), 66);
        assert_eq!(model.benign_weights.len(), 66);
        assert_eq!(model.suspicious_weights.len(), 66);
        assert_eq!(model.malicious_weights.len(), 66);
    }

    #[test]
    fn test_default_model_has_malicious_weights() {
        let model = TrainedModel::default_small();
        let has_malicious_weight = model.malicious_weights.iter().any(|&w| w > 1.0);
        assert!(has_malicious_weight);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let model = TrainedModel::default_small();
        let path = std::env::temp_dir().join("test_model.json");
        let path_str = path.to_string_lossy().to_string();

        ModelStorage::save_to_file(&model, &path_str).unwrap();
        let loaded = ModelStorage::load_from_file(&path_str).unwrap();

        assert_eq!(loaded.name, model.name);
        assert_eq!(loaded.version, model.version);
        assert_eq!(loaded.benign_weights, model.benign_weights);
        assert_eq!(loaded.malicious_weights, model.malicious_weights);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_from_bytes() {
        let model = TrainedModel::default_small();
        let json = serde_json::to_vec(&model).unwrap();
        let loaded = ModelStorage::load_from_bytes(&json).unwrap();
        assert_eq!(loaded.name, model.name);
    }

    #[test]
    fn test_model_new_panics_on_wrong_dimensions() {
        let result = std::panic::catch_unwind(|| {
            TrainedModel::new("test", "1.0", vec![0.0; 10], vec![0.0; 66], vec![0.0; 66], 0.0, 0.0, 0.0);
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_model_new_valid() {
        let model = TrainedModel::new(
            "test",
            "1.0",
            vec![0.0; 66],
            vec![0.0; 66],
            vec![0.0; 66],
            0.0, 0.0, 0.0,
        );
        assert_eq!(model.name, "test");
    }
}

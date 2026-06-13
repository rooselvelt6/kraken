use crate::model::TrainedModel;

/// Online learner that adjusts model weights based on user feedback.
///
/// Uses a simple weight update rule:
///   w_new = w_old + lr * (feedback - prediction) * feature_value
///
/// where feedback = 1 for "this was malicious", 0 for "this was benign".
#[derive(Debug, Clone)]
pub struct OnlineLearner {
    /// Learning rate for weight updates.
    pub learning_rate: f64,
    /// L2 regularization strength.
    pub regularization: f64,
    /// Number of updates performed.
    pub update_count: u64,
    /// Recent loss values for monitoring.
    pub recent_losses: Vec<f64>,
    max_loss_history: usize,
}

impl OnlineLearner {
    pub fn new(learning_rate: f64, regularization: f64) -> Self {
        Self {
            learning_rate,
            regularization,
            update_count: 0,
            recent_losses: Vec::with_capacity(100),
            max_loss_history: 100,
        }
    }
}

impl Default for OnlineLearner {
    fn default() -> Self {
        Self::new(0.01, 0.001)
    }
}

impl OnlineLearner {
    /// Update model weights based on user feedback.
    ///
    /// `features`: feature vector for the command
    /// `label`: 1.0 if malicious/suspicious, 0.0 if benign
    /// `prediction`: the model's predicted probability (0-1)
    /// `model`: the model to update (mutated in place)
    pub fn update(
        &mut self,
        features: &[f64],
        label: f64,
        prediction: f64,
        model: &mut TrainedModel,
    ) -> f64 {
        let error = label - prediction;
        let loss = error * error; // MSE

        self.update_count += 1;
        self.recent_losses.push(loss);
        if self.recent_losses.len() > self.max_loss_history {
            self.recent_losses.remove(0);
        }

        // Update malicious weights (for malicious feedback)
        let lr = self.learning_rate;
        let reg = self.regularization;

        if label > 0.5 {
            // Malicious: increase malicious weights, decrease benign
            for (i, fv) in features.iter().enumerate() {
                if i < model.malicious_weights.len() {
                    let update = lr * error * fv - reg * model.malicious_weights[i];
                    model.malicious_weights[i] += update;
                }
                if i < model.benign_weights.len() {
                    let update = -lr * error * fv - reg * model.benign_weights[i];
                    model.benign_weights[i] += update;
                }
            }
            model.malicious_bias += lr * error;
            model.benign_bias -= lr * error;
        } else {
            // Benign: increase benign weights, decrease malicious
            for (i, fv) in features.iter().enumerate() {
                if i < model.benign_weights.len() {
                    let update = lr * error.abs() * fv - reg * model.benign_weights[i];
                    model.benign_weights[i] += update;
                }
                if i < model.malicious_weights.len() {
                    let update = -lr * error.abs() * fv - reg * model.malicious_weights[i];
                    model.malicious_weights[i] += update;
                }
            }
            model.benign_bias += lr * error.abs();
            model.malicious_bias -= lr * error.abs();
        }

        loss
    }

    /// Update from a classification result and user approval.
    ///
    /// `approved`: true if the user approved the command (it was benign)
    /// `malicious`: true if the classifier flagged it as malicious
    pub fn update_from_feedback(
        &mut self,
        features: &[f64],
        approved: bool,
        was_malicious_prediction: bool,
        model: &mut TrainedModel,
    ) -> f64 {
        // If user approved a command we flagged as malicious → error
        // If user rejected a command we flagged as benign → error
        let label = if approved { 0.0 } else { 1.0 };
        let prediction = if was_malicious_prediction { 1.0 } else { 0.0 };
        self.update(features, label, prediction, model)
    }

    /// Get average recent loss.
    pub fn average_loss(&self) -> f64 {
        if self.recent_losses.is_empty() {
            return 0.0;
        }
        self.recent_losses.iter().sum::<f64>() / self.recent_losses.len() as f64
    }

    /// Get learning rate.
    pub fn learning_rate(&self) -> f64 {
        self.learning_rate
    }

    /// Adjust learning rate (e.g., decay over time).
    pub fn set_learning_rate(&mut self, rate: f64) {
        self.learning_rate = rate;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_online_learner_default() {
        let learner = OnlineLearner::default();
        assert!((learner.learning_rate - 0.01).abs() < 0.001);
        assert!((learner.regularization - 0.001).abs() < 0.0001);
        assert_eq!(learner.update_count, 0);
    }

    #[test]
    fn test_update_malicious_feedback() {
        let mut learner = OnlineLearner::default();
        let mut model = TrainedModel::default_small();
        let original_mal_weight = model.malicious_weights[13]; // has_rm_rf

        let mut features = vec![0.0; 66];
        features[13] = 1.0; // has_rm_rf feature active
        let loss = learner.update(&features, 1.0, 0.0, &mut model);

        assert!(loss > 0.0);
        assert_eq!(learner.update_count, 1);
        // Malicious weights should have increased (feature active, error > 0)
        assert!(
            model.malicious_weights[13] > original_mal_weight,
            "expected {} > {}", model.malicious_weights[13], original_mal_weight
        );
    }

    #[test]
    fn test_update_benign_feedback() {
        let mut learner = OnlineLearner::default();
        let mut model = TrainedModel::default_small();
        let original_benign_weight = model.benign_weights[0];

        let mut features = vec![0.0; 66];
        features[0] = 1.0;
        let loss = learner.update(&features, 0.0, 0.3, &mut model);

        assert!(loss > 0.0);
        assert_eq!(learner.update_count, 1);
    }

    #[test]
    fn test_update_from_feedback() {
        let mut learner = OnlineLearner::default();
        let mut model = TrainedModel::default_small();
        let features = vec![0.0; 66];

        // User approved a command we flagged as malicious
        let loss = learner.update_from_feedback(&features, true, true, &mut model);
        assert!(loss > 0.0);

        // User rejected a command we flagged as benign
        let loss = learner.update_from_feedback(&features, false, false, &mut model);
        assert!(loss > 0.0);

        assert_eq!(learner.update_count, 2);
    }

    #[test]
    fn test_average_loss() {
        let mut learner = OnlineLearner::default();
        let mut model = TrainedModel::default_small();

        assert!((learner.average_loss() - 0.0).abs() < 0.001);

        for _ in 0..5 {
            learner.update(&vec![0.0; 66], 1.0, 0.0, &mut model);
        }
        assert!(learner.average_loss() > 0.0);
    }

    #[test]
    fn test_learning_rate_adjustment() {
        let mut learner = OnlineLearner::default();
        assert!((learner.learning_rate() - 0.01).abs() < 0.001);
        learner.set_learning_rate(0.001);
        assert!((learner.learning_rate() - 0.001).abs() < 0.0001);
    }

    #[test]
    fn test_update_does_not_panic_with_empty_features() {
        let mut learner = OnlineLearner::default();
        let mut model = TrainedModel::default_small();
        let features = vec![0.0; 66];
        learner.update(&features, 1.0, 0.5, &mut model);
        // Should not panic — features are just zeros
    }

    #[test]
    fn test_regularization_prevents_divergence() {
        let mut learner = OnlineLearner::new(0.5, 0.1); // High LR, high reg
        let mut model = TrainedModel::default_small();
        let features = vec![1.0; 66];

        // Many updates should not cause weights to explode
        for _ in 0..100 {
            learner.update(&features, 1.0, 0.0, &mut model);
        }

        // Weights should not be NaN or infinite
        for &w in &model.malicious_weights {
            assert!(w.is_finite());
        }
    }
}

from .feature_extractor import FeatureExtractor, FEATURE_NAMES
import joblib
import os
import logging

logger = logging.getLogger(__name__)


class MalwareClassifier:
    """
    Industry-grade malware classifier using an ensemble of
    GradientBoosting + RandomForest with 19 PE features.
    """
    
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.model = None
        self.model_version = 'unknown'
        self.expected_features = len(FEATURE_NAMES)
        
        # Load the model package dynamically
        model_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'ml_models', 'malware_classifier.pkl'
        )
        
        try:
            package = joblib.load(model_path)
            
            # Handle both old (raw model) and new (packaged) formats
            if isinstance(package, dict) and 'model' in package:
                self.model = package['model']
                self.model_version = package.get('version', '2.0.0')
                saved_features = package.get('num_features', 0)
                
                # Validate feature count matches
                if saved_features != self.expected_features:
                    logger.warning(
                        f"Model expects {saved_features} features but extractor provides "
                        f"{self.expected_features}. Using heuristic fallback."
                    )
                    self.model = None
                else:
                    logger.info(
                        f"Loaded Malware Classifier v{self.model_version} "
                        f"(CV F1: {package.get('cv_f1', 'N/A'):.4f})"
                    )
            else:
                # Legacy model format — check feature count compatibility
                self.model = package
                self.model_version = '1.0.0-legacy'
                logger.warning("Loaded legacy model format. Consider retraining with train_model.py")
                
                # Legacy models expect 3 features, we now have 19 — can't use directly
                try:
                    test_pred = self.model.predict([[0.0] * self.expected_features])
                except Exception:
                    logger.warning("Legacy model incompatible with 19 features. Using heuristic fallback.")
                    self.model = None
                    
        except FileNotFoundError:
            logger.warning(f"ML model not found at {model_path}. Using heuristic fallback.")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self.model = None

    def predict(self, static_analysis_results):
        """
        Predict whether a file is malware based on static analysis results.
        Returns: {'is_malware': bool, 'confidence': float, 'model_version': str}
        """
        features = self.extractor.extract(static_analysis_results)
        
        if not self.model:
            return self._heuristic_fallback(features, static_analysis_results)
        
        try:
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            # Probability array: [prob_clean, prob_malware]
            confidence = probabilities[1] if prediction == 1 else probabilities[0]
            
            return {
                'is_malware': bool(prediction == 1),
                'confidence': float(round(confidence, 4)),
                'model_version': self.model_version,
                'method': 'ensemble_ml',
            }
        except Exception as e:
            logger.error(f"ML Prediction error: {e}")
            return self._heuristic_fallback(features, static_analysis_results)

    def _heuristic_fallback(self, features, static_results):
        """
        Multi-signal heuristic fallback when the trained model is unavailable.
        Uses the 19 extracted features for a rule-based assessment.
        """
        f = features[0]  # First (and only) sample
        
        # Feature indices mapping
        entropy = f[0]
        num_suspicious_sections = f[2]
        num_suspicious_imports = f[5]
        has_debug_info = f[6]
        has_tls_callbacks = f[7]
        timestamp_anomaly = f[10]
        section_name_anomaly_count = f[11]
        is_signed = f[16]
        ransom_string_count = f[17]
        
        # Weighted scoring
        score = 0.0
        
        # High entropy (packed/encrypted) — strong signal
        if entropy > 7.2:
            score += 0.25
        elif entropy > 6.8:
            score += 0.15
        
        # Ransomware strings — very strong signal
        if ransom_string_count >= 3:
            score += 0.30
        elif ransom_string_count >= 1:
            score += 0.15
        
        # Suspicious sections
        if num_suspicious_sections >= 3:
            score += 0.15
        elif num_suspicious_sections >= 1:
            score += 0.08
        
        # Suspicious imports
        if num_suspicious_imports >= 5:
            score += 0.15
        elif num_suspicious_imports >= 3:
            score += 0.08
        
        # No debug info — weak signal but adds up
        if not has_debug_info:
            score += 0.05
        
        # TLS callbacks (anti-debugging)
        if has_tls_callbacks:
            score += 0.08
        
        # Timestamp anomaly
        if timestamp_anomaly:
            score += 0.05
        
        # Non-standard section names
        if section_name_anomaly_count >= 3:
            score += 0.08
        
        # Not signed — weak signal
        if not is_signed:
            score += 0.05
        
        is_malware = score >= 0.40
        confidence = min(score + 0.30, 0.95) if is_malware else max(0.60, 1.0 - score)
        
        return {
            'is_malware': is_malware,
            'confidence': float(round(confidence, 4)),
            'model_version': 'heuristic_v2',
            'method': 'heuristic_fallback',
        }

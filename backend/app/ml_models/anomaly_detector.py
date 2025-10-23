"""
Anomaly Detection Models for AISF
- GMM Anomaly Detector for behavioral analysis
- Autoencoder for zero-day threat detection
"""

import numpy as np
import pandas as pd
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import tensorflow as tf
from tensorflow.keras import layers, Model
import joblib
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Base class for anomaly detection"""
    
    def __init__(self):
        self.is_trained = False
        self.scaler = StandardScaler()
    
    def detect_anomaly(self, data: np.ndarray) -> Dict:
        """Detect anomalies in data"""
        raise NotImplementedError
    
    def train(self, data: np.ndarray) -> Dict:
        """Train the anomaly detector"""
        raise NotImplementedError

class GMMAnomalyDetector(AnomalyDetector):
    """
    Gaussian Mixture Model for behavioral anomaly detection
    Implements real-time GMM-based anomaly detection as per research
    """
    
    def __init__(self, n_components: int = 3, model_path: str = "models/gmm_anomaly.pkl"):
        super().__init__()
        self.n_components = n_components
        self.model_path = model_path
        self.gmm = None
        self.threshold = None
        
        # Behavioral features for user analysis
        self.behavioral_features = [
            'login_hour', 'login_day', 'session_duration', 'failed_attempts',
            'ip_address_changes', 'device_changes', 'location_changes',
            'resource_access_pattern', 'command_execution_frequency',
            'data_transfer_volume', 'network_connections', 'file_access_count'
        ]
    
    def calculate_tps_score(self, user_data: Dict, time_factor: float = 1.0) -> float:
        """
        Calculate Threat Probability Score using research formula:
        TPS(u,t) = Σ w_i · R_i(u,t) · α_i(t)
        """
        risk_factors = {
            'login_hour': 0.15,      # Unusual login times
            'failed_attempts': 0.25,  # Failed authentication
            'ip_changes': 0.20,       # IP address changes
            'device_changes': 0.15,   # Device changes
            'location_changes': 0.15, # Geographic location changes
            'resource_access': 0.10   # Unusual resource access
        }
        
        tps_score = 0.0
        
        # Calculate risk for each factor
        for factor, weight in risk_factors.items():
            risk_value = self._calculate_risk_factor(user_data, factor)
            tps_score += weight * risk_value * time_factor
        
        return min(tps_score, 1.0)
    
    def _calculate_risk_factor(self, user_data: Dict, factor: str) -> float:
        """Calculate individual risk factor value"""
        if factor == 'login_hour':
            hour = user_data.get('login_hour', 12)
            # Higher risk for off-hours (22:00-06:00)
            if 22 <= hour or hour <= 6:
                return 0.8
            elif 7 <= hour <= 9 or 17 <= hour <= 19:
                return 0.2
            else:
                return 0.5
        
        elif factor == 'failed_attempts':
            attempts = user_data.get('failed_attempts', 0)
            return min(attempts / 5.0, 1.0)
        
        elif factor == 'ip_changes':
            changes = user_data.get('ip_changes', 0)
            return min(changes / 3.0, 1.0)
        
        elif factor == 'device_changes':
            changes = user_data.get('device_changes', 0)
            return min(changes / 2.0, 1.0)
        
        elif factor == 'location_changes':
            changes = user_data.get('location_changes', 0)
            return min(changes / 2.0, 1.0)
        
        elif factor == 'resource_access':
            unusual_access = user_data.get('unusual_resource_access', 0)
            return min(unusual_access / 10.0, 1.0)
        
        return 0.0
    
    def train(self, data: np.ndarray) -> Dict:
        """
        Train GMM model for behavioral anomaly detection
        """
        logger.info("Training GMM anomaly detector...")
        
        # Scale the data
        data_scaled = self.scaler.fit_transform(data)
        
        # Initialize and train GMM
        self.gmm = GaussianMixture(
            n_components=self.n_components,
            covariance_type='full',
            random_state=42,
            n_init=10
        )
        
        self.gmm.fit(data_scaled)
        
        # Calculate threshold based on log likelihood
        log_likelihoods = self.gmm.score_samples(data_scaled)
        self.threshold = np.percentile(log_likelihoods, 5)  # 5% threshold
        
        # Calculate silhouette score for model quality
        labels = self.gmm.predict(data_scaled)
        silhouette = silhouette_score(data_scaled, labels)
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.gmm, self.model_path)
        joblib.dump(self.scaler, self.model_path.replace('.pkl', '_scaler.pkl'))
        joblib.dump(self.threshold, self.model_path.replace('.pkl', '_threshold.pkl'))
        
        self.is_trained = True
        
        results = {
            'silhouette_score': silhouette,
            'n_components': self.n_components,
            'threshold': self.threshold,
            'mean_log_likelihood': np.mean(log_likelihoods)
        }
        
        logger.info(f"GMM trained successfully. Silhouette score: {silhouette:.4f}")
        
        return results
    
    def detect_anomaly(self, data: np.ndarray) -> Dict:
        """
        Detect behavioral anomalies using GMM
        """
        if not self.is_trained:
            self.load_model()
        
        if self.gmm is None:
            raise ValueError("Model not trained or loaded")
        
        # Scale the data
        data_scaled = self.scaler.transform(data.reshape(1, -1))
        
        # Calculate log likelihood
        log_likelihood = self.gmm.score_samples(data_scaled)[0]
        
        # Determine if anomaly
        is_anomaly = log_likelihood < self.threshold
        
        # Calculate anomaly score (0-1)
        anomaly_score = max(0, (self.threshold - log_likelihood) / abs(self.threshold))
        
        return {
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'log_likelihood': float(log_likelihood),
            'threshold': float(self.threshold),
            'timestamp': datetime.now().isoformat()
        }
    
    def load_model(self):
        """Load trained GMM model"""
        try:
            self.gmm = joblib.load(self.model_path)
            self.scaler = joblib.load(self.model_path.replace('.pkl', '_scaler.pkl'))
            self.threshold = joblib.load(self.model_path.replace('.pkl', '_threshold.pkl'))
            self.is_trained = True
            logger.info("GMM model loaded successfully")
        except FileNotFoundError:
            logger.warning("No trained GMM model found")
            self.gmm = None
    
    def generate_behavioral_data(self, n_samples: int = 1000) -> np.ndarray:
        """
        Generate sample behavioral data for training
        """
        np.random.seed(42)
        
        data = {
            'login_hour': np.random.randint(0, 24, n_samples),
            'login_day': np.random.randint(0, 7, n_samples),
            'session_duration': np.random.exponential(3600, n_samples),  # seconds
            'failed_attempts': np.random.poisson(0.5, n_samples),
            'ip_address_changes': np.random.poisson(0.2, n_samples),
            'device_changes': np.random.poisson(0.1, n_samples),
            'location_changes': np.random.poisson(0.1, n_samples),
            'resource_access_pattern': np.random.normal(50, 20, n_samples),
            'command_execution_frequency': np.random.poisson(10, n_samples),
            'data_transfer_volume': np.random.exponential(1000, n_samples),  # MB
            'network_connections': np.random.poisson(5, n_samples),
            'file_access_count': np.random.poisson(20, n_samples)
        }
        
        return np.array([list(data.values())]).T.reshape(n_samples, -1)

class AutoencoderAnomalyDetector(AnomalyDetector):
    """
    Autoencoder for zero-day threat detection
    Implements autoencoder-based anomaly detection as per research
    """
    
    def __init__(self, input_dim: int = 41, encoding_dim: int = 16, model_path: str = "models/autoencoder"):
        super().__init__()
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.model_path = model_path
        self.autoencoder = None
        self.threshold = None
        
        # Network traffic features for zero-day detection
        self.traffic_features = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
            'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
            'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
            'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
            'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate'
        ]
    
    def build_autoencoder(self):
        """Build the autoencoder architecture"""
        # Encoder
        input_layer = layers.Input(shape=(self.input_dim,))
        encoded = layers.Dense(self.encoding_dim * 2, activation='relu')(input_layer)
        encoded = layers.Dropout(0.2)(encoded)
        encoded = layers.Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = layers.Dense(self.encoding_dim * 2, activation='relu')(encoded)
        decoded = layers.Dropout(0.2)(decoded)
        decoded = layers.Dense(self.input_dim, activation='sigmoid')(decoded)
        
        # Create autoencoder model
        self.autoencoder = Model(input_layer, decoded)
        
        # Compile model
        self.autoencoder.compile(
            optimizer='adam',
            loss='mse',
            metrics=['mae']
        )
        
        return self.autoencoder
    
    def train(self, data: np.ndarray, epochs: int = 50, batch_size: int = 32) -> Dict:
        """
        Train autoencoder for zero-day detection
        """
        logger.info("Training autoencoder for zero-day detection...")
        
        # Scale the data
        data_scaled = self.scaler.fit_transform(data)
        
        # Build and train autoencoder
        self.build_autoencoder()
        
        history = self.autoencoder.fit(
            data_scaled, data_scaled,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,
            verbose=1
        )
        
        # Calculate reconstruction error threshold
        reconstructed = self.autoencoder.predict(data_scaled)
        mse_scores = np.mean(np.square(data_scaled - reconstructed), axis=1)
        self.threshold = np.percentile(mse_scores, 95)  # 95th percentile threshold
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        self.autoencoder.save(self.model_path)
        joblib.dump(self.scaler, f"{self.model_path}_scaler.pkl")
        joblib.dump(self.threshold, f"{self.model_path}_threshold.pkl")
        
        self.is_trained = True
        
        results = {
            'final_loss': history.history['loss'][-1],
            'final_val_loss': history.history['val_loss'][-1],
            'threshold': self.threshold,
            'mean_mse': np.mean(mse_scores)
        }
        
        logger.info(f"Autoencoder trained successfully. Final loss: {results['final_loss']:.6f}")
        
        return results
    
    def detect_anomaly(self, data: np.ndarray) -> Dict:
        """
        Detect zero-day threats using autoencoder
        """
        if not self.is_trained:
            self.load_model()
        
        if self.autoencoder is None:
            raise ValueError("Model not trained or loaded")
        
        # Scale the data
        data_scaled = self.scaler.transform(data.reshape(1, -1))
        
        # Reconstruct the input
        reconstructed = self.autoencoder.predict(data_scaled)
        
        # Calculate reconstruction error
        mse = np.mean(np.square(data_scaled - reconstructed))
        
        # Determine if anomaly (zero-day threat)
        is_anomaly = mse > self.threshold
        
        # Calculate anomaly score (0-1)
        anomaly_score = min(1.0, mse / self.threshold)
        
        return {
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'reconstruction_error': float(mse),
            'threshold': float(self.threshold),
            'is_zero_day': bool(is_anomaly),
            'timestamp': datetime.now().isoformat()
        }
    
    def load_model(self):
        """Load trained autoencoder model"""
        try:
            self.autoencoder = tf.keras.models.load_model(self.model_path)
            self.scaler = joblib.load(f"{self.model_path}_scaler.pkl")
            self.threshold = joblib.load(f"{self.model_path}_threshold.pkl")
            self.is_trained = True
            logger.info("Autoencoder model loaded successfully")
        except FileNotFoundError:
            logger.warning("No trained autoencoder model found")
            self.autoencoder = None
    
    def generate_traffic_data(self, n_samples: int = 1000) -> np.ndarray:
        """
        Generate sample network traffic data for training
        """
        np.random.seed(42)
        
        data = {}
        for feature in self.traffic_features:
            if 'bytes' in feature:
                data[feature] = np.random.exponential(1000, n_samples)
            elif 'rate' in feature:
                data[feature] = np.random.beta(1, 10, n_samples)
            elif 'count' in feature:
                data[feature] = np.random.poisson(5, n_samples)
            elif feature in ['duration', 'land', 'urgent', 'hot', 'logged_in', 'is_host_login', 'is_guest_login']:
                data[feature] = np.random.choice([0, 1], n_samples)
            else:
                data[feature] = np.random.randint(0, 100, n_samples)
        
        return np.array([list(data.values())]).T.reshape(n_samples, -1) 
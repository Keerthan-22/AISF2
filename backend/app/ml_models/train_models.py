"""
ML Model Training Scripts for AISF
Trains and saves models for threat classification, anomaly detection, and response optimization.
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.mixture import GaussianMixture
from sklearn.decomposition import PCA
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import warnings
warnings.filterwarnings('ignore')


class ModelTrainer:
    """Base class for model training."""
    
    def __init__(self):
        self.models_dir = "backend/app/ml_models/saved_models"
        os.makedirs(self.models_dir, exist_ok=True)
    
    def save_model(self, model, filename: str):
        """Save trained model to disk."""
        filepath = os.path.join(self.models_dir, filename)
        joblib.dump(model, filepath)
        print(f"Model saved to: {filepath}")
    
    def load_model(self, filename: str):
        """Load trained model from disk."""
        filepath = os.path.join(self.models_dir, filename)
        if os.path.exists(filepath):
            return joblib.load(filepath)
        return None


class ThreatClassifierTrainer(ModelTrainer):
    """Trains threat classification models."""
    
    def __init__(self):
        super().__init__()
        self.feature_names = [
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
    
    def generate_mock_data(self, n_samples: int = 10000) -> tuple:
        """Generate mock network traffic data for training."""
        print("Generating mock network traffic data...")
        
        # Generate features
        data = {}
        
        # Numerical features
        data['duration'] = np.random.exponential(100, n_samples)
        data['src_bytes'] = np.random.lognormal(5, 2, n_samples)
        data['dst_bytes'] = np.random.lognormal(5, 2, n_samples)
        data['land'] = np.random.choice([0, 1], n_samples, p=[0.99, 0.01])
        data['wrong_fragment'] = np.random.poisson(0.1, n_samples)
        data['urgent'] = np.random.poisson(0.05, n_samples)
        data['hot'] = np.random.poisson(0.1, n_samples)
        data['num_failed_logins'] = np.random.poisson(0.2, n_samples)
        data['logged_in'] = np.random.choice([0, 1], n_samples, p=[0.3, 0.7])
        data['num_compromised'] = np.random.poisson(0.1, n_samples)
        data['root_shell'] = np.random.choice([0, 1], n_samples, p=[0.95, 0.05])
        data['su_attempted'] = np.random.choice([0, 1], n_samples, p=[0.9, 0.1])
        data['num_root'] = np.random.poisson(0.1, n_samples)
        data['num_file_creations'] = np.random.poisson(0.5, n_samples)
        data['num_shells'] = np.random.poisson(0.1, n_samples)
        data['num_access_files'] = np.random.poisson(0.3, n_samples)
        data['num_outbound_cmds'] = np.random.poisson(0.05, n_samples)
        data['is_host_login'] = np.random.choice([0, 1], n_samples, p=[0.8, 0.2])
        data['is_guest_login'] = np.random.choice([0, 1], n_samples, p=[0.9, 0.1])
        data['count'] = np.random.poisson(2, n_samples)
        data['srv_count'] = np.random.poisson(2, n_samples)
        data['serror_rate'] = np.random.beta(1, 10, n_samples)
        data['srv_serror_rate'] = np.random.beta(1, 10, n_samples)
        data['rerror_rate'] = np.random.beta(1, 10, n_samples)
        data['srv_rerror_rate'] = np.random.beta(1, 10, n_samples)
        data['same_srv_rate'] = np.random.beta(5, 5, n_samples)
        data['diff_srv_rate'] = np.random.beta(5, 5, n_samples)
        data['srv_diff_host_rate'] = np.random.beta(1, 10, n_samples)
        data['dst_host_count'] = np.random.poisson(5, n_samples)
        data['dst_host_srv_count'] = np.random.poisson(3, n_samples)
        data['dst_host_same_srv_rate'] = np.random.beta(5, 5, n_samples)
        data['dst_host_diff_srv_rate'] = np.random.beta(5, 5, n_samples)
        data['dst_host_same_src_port_rate'] = np.random.beta(5, 5, n_samples)
        data['dst_host_srv_diff_host_rate'] = np.random.beta(1, 10, n_samples)
        data['dst_host_serror_rate'] = np.random.beta(1, 10, n_samples)
        data['dst_host_srv_serror_rate'] = np.random.beta(1, 10, n_samples)
        data['dst_host_rerror_rate'] = np.random.beta(1, 10, n_samples)
        data['dst_host_srv_rerror_rate'] = np.random.beta(1, 10, n_samples)
        
        # Categorical features
        data['protocol_type'] = np.random.choice(['tcp', 'udp', 'icmp'], n_samples, p=[0.7, 0.2, 0.1])
        data['service'] = np.random.choice(['http', 'ftp', 'smtp', 'ssh', 'telnet'], n_samples)
        data['flag'] = np.random.choice(['SF', 'S0', 'REJ', 'RSTO'], n_samples, p=[0.8, 0.1, 0.05, 0.05])
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Generate labels based on patterns
        labels = self._generate_labels(df)
        
        return df, labels
    
    def _generate_labels(self, df: pd.DataFrame) -> np.ndarray:
        """Generate threat labels based on feature patterns."""
        labels = []
        
        for _, row in df.iterrows():
            # Normal traffic patterns
            if (row['duration'] < 100 and 
                row['src_bytes'] < 1000 and 
                row['dst_bytes'] < 1000 and
                row['num_failed_logins'] == 0 and
                row['root_shell'] == 0):
                labels.append('normal')
            
            # DoS attack patterns
            elif (row['duration'] < 10 and 
                  row['src_bytes'] < 100 and 
                  row['dst_bytes'] == 0 and
                  row['count'] > 10):
                labels.append('dos')
            
            # Probe attack patterns
            elif (row['duration'] > 100 and 
                  row['src_bytes'] < 100 and 
                  row['dst_bytes'] < 100 and
                  row['serror_rate'] > 0.5):
                labels.append('probe')
            
            # R2L attack patterns
            elif (row['duration'] > 1000 and 
                  row['src_bytes'] > 1000 and 
                  row['dst_bytes'] < 100 and
                  row['num_failed_logins'] > 0):
                labels.append('r2l')
            
            # U2R attack patterns
            elif (row['duration'] > 1000 and 
                  row['src_bytes'] > 1000 and 
                  row['dst_bytes'] > 1000 and
                  row['root_shell'] == 1):
                labels.append('u2r')
            
            else:
                labels.append('normal')
        
        return np.array(labels)
    
    def train_random_forest(self, X: pd.DataFrame, y: np.ndarray) -> RandomForestClassifier:
        """Train Random Forest classifier."""
        print("Training Random Forest classifier...")
        
        # Prepare features
        X_numeric = X.select_dtypes(include=[np.number])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_numeric, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        rf_model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = rf_model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Random Forest Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        # Save model and scaler
        self.save_model(rf_model, "random_forest_model.pkl")
        self.save_model(scaler, "scaler.pkl")
        
        return rf_model
    
    def train_lstm_model(self, X: pd.DataFrame, y: np.ndarray):
        """Train LSTM model for sequential threat detection."""
        print("Training LSTM model...")
        
        # Prepare sequential data
        X_numeric = X.select_dtypes(include=[np.number])
        
        # Encode labels
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        
        # Create sequences (mock implementation)
        sequence_length = 10
        X_sequences = []
        y_sequences = []
        
        for i in range(len(X_numeric) - sequence_length):
            X_sequences.append(X_numeric.iloc[i:i+sequence_length].values)
            y_sequences.append(y_encoded[i+sequence_length])
        
        X_sequences = np.array(X_sequences)
        y_sequences = np.array(y_sequences)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_sequences, y_sequences, test_size=0.2, random_state=42
        )
        
        # Build LSTM model
        model = keras.Sequential([
            layers.LSTM(64, input_shape=(sequence_length, X_sequences.shape[2]), return_sequences=True),
            layers.Dropout(0.2),
            layers.LSTM(32),
            layers.Dropout(0.2),
            layers.Dense(len(np.unique(y_encoded)), activation='softmax')
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        # Train model
        history = model.fit(
            X_train, y_train,
            epochs=10,
            batch_size=32,
            validation_data=(X_test, y_test),
            verbose=1
        )
        
        # Save model
        model.save(os.path.join(self.models_dir, "lstm_model.h5"))
        self.save_model(label_encoder, "label_encoder.pkl")
        
        print(f"LSTM model saved. Final accuracy: {history.history['accuracy'][-1]:.4f}")
        
        return model


class AnomalyDetectorTrainer(ModelTrainer):
    """Trains anomaly detection models."""
    
    def train_gmm_anomaly_detector(self, X: pd.DataFrame) -> GaussianMixture:
        """Train Gaussian Mixture Model for anomaly detection."""
        print("Training GMM anomaly detector...")
        
        # Prepare features
        X_numeric = X.select_dtypes(include=[np.number])
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_numeric)
        
        # Train GMM
        gmm = GaussianMixture(
            n_components=3,
            random_state=42,
            covariance_type='full'
        )
        
        gmm.fit(X_scaled)
        
        # Calculate anomaly scores
        log_probs = gmm.score_samples(X_scaled)
        anomaly_scores = -log_probs
        
        # Set threshold (95th percentile)
        threshold = np.percentile(anomaly_scores, 95)
        
        print(f"GMM trained. Anomaly threshold: {threshold:.4f}")
        
        # Save model
        self.save_model(gmm, "gmm_anomaly_detector.pkl")
        self.save_model(scaler, "gmm_scaler.pkl")
        
        return gmm
    
    def train_autoencoder(self, X: pd.DataFrame):
        """Train autoencoder for anomaly detection."""
        print("Training autoencoder...")
        
        # Prepare features
        X_numeric = X.select_dtypes(include=[np.number])
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_numeric)
        
        # Build autoencoder
        input_dim = X_scaled.shape[1]
        encoding_dim = input_dim // 2
        
        # Encoder
        input_layer = layers.Input(shape=(input_dim,))
        encoded = layers.Dense(encoding_dim, activation='relu')(input_layer)
        encoded = layers.Dense(encoding_dim // 2, activation='relu')(encoded)
        
        # Decoder
        decoded = layers.Dense(encoding_dim, activation='relu')(encoded)
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
        
        # Autoencoder model
        autoencoder = keras.Model(input_layer, decoded)
        
        # Compile model
        autoencoder.compile(optimizer='adam', loss='mse')
        
        # Train model
        history = autoencoder.fit(
            X_scaled, X_scaled,
            epochs=20,
            batch_size=32,
            validation_split=0.2,
            verbose=1
        )
        
        # Save model
        autoencoder.save(os.path.join(self.models_dir, "autoencoder_model.h5"))
        self.save_model(scaler, "autoencoder_scaler.pkl")
        
        print(f"Autoencoder trained. Final loss: {history.history['loss'][-1]:.4f}")
        
        return autoencoder


class ResponseOptimizerTrainer(ModelTrainer):
    """Trains response optimization models."""
    
    def generate_response_training_data(self, n_samples: int = 5000) -> tuple:
        """Generate training data for response optimization."""
        print("Generating response optimization training data...")
        
        # Generate incident states
        states = []
        actions = []
        rewards = []
        
        for _ in range(n_samples):
            # Generate random incident state
            state = np.random.rand(10)  # 10-dimensional state
            
            # Generate random action
            action = np.random.randint(0, 8)  # 8 possible actions
            
            # Generate reward based on state-action combination
            reward = self._calculate_reward(state, action)
            
            states.append(state)
            actions.append(action)
            rewards.append(reward)
        
        return np.array(states), np.array(actions), np.array(rewards)
    
    def _calculate_reward(self, state: np.ndarray, action: int) -> float:
        """Calculate reward for state-action pair."""
        # Mock reward function
        # In real implementation, this would be based on actual incident outcomes
        
        # Base reward
        reward = 0.0
        
        # Reward based on threat severity
        threat_severity = state[0]
        if threat_severity > 0.7:  # High severity
            reward += 10.0
        elif threat_severity > 0.4:  # Medium severity
            reward += 5.0
        else:  # Low severity
            reward += 1.0
        
        # Reward based on action appropriateness
        action_effectiveness = [0.9, 0.8, 0.95, 0.85, 0.6, 0.7, 0.9, 0.8]
        reward += action_effectiveness[action] * 5.0
        
        # Penalty for false positives
        false_positive_risk = [0.3, 0.2, 0.4, 0.25, 0.1, 0.05, 0.1, 0.15]
        reward -= false_positive_risk[action] * 2.0
        
        return reward
    
    def train_ppo_model(self, states: np.ndarray, actions: np.ndarray, rewards: np.ndarray):
        """Train PPO model for response optimization."""
        print("Training PPO model...")
        
        # Simplified PPO implementation
        # In real implementation, this would use a proper PPO library
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            states, actions, test_size=0.2, random_state=42
        )
        
        # Train a simple policy network
        model = keras.Sequential([
            layers.Dense(64, activation='relu', input_shape=(10,)),
            layers.Dropout(0.2),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(8, activation='softmax')  # 8 actions
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        # Train model
        history = model.fit(
            X_train, y_train,
            epochs=20,
            batch_size=32,
            validation_data=(X_test, y_test),
            verbose=1
        )
        
        # Save model
        model.save(os.path.join(self.models_dir, "ppo_response_model.h5"))
        
        print(f"PPO model trained. Final accuracy: {history.history['accuracy'][-1]:.4f}")
        
        return model


def main():
    """Main training function."""
    print("Starting AISF ML Model Training...")
    
    # Initialize trainers
    threat_trainer = ThreatClassifierTrainer()
    anomaly_trainer = AnomalyDetectorTrainer()
    response_trainer = ResponseOptimizerTrainer()
    
    # Generate training data
    print("\n=== Generating Training Data ===")
    threat_data, threat_labels = threat_trainer.generate_mock_data(10000)
    
    # Train threat classification models
    print("\n=== Training Threat Classification Models ===")
    rf_model = threat_trainer.train_random_forest(threat_data, threat_labels)
    lstm_model = threat_trainer.train_lstm_model(threat_data, threat_labels)
    
    # Train anomaly detection models
    print("\n=== Training Anomaly Detection Models ===")
    gmm_model = anomaly_trainer.train_gmm_anomaly_detector(threat_data)
    autoencoder_model = anomaly_trainer.train_autoencoder(threat_data)
    
    # Train response optimization models
    print("\n=== Training Response Optimization Models ===")
    states, actions, rewards = response_trainer.generate_response_training_data(5000)
    ppo_model = response_trainer.train_ppo_model(states, actions, rewards)
    
    print("\n=== Training Complete ===")
    print("All models have been trained and saved successfully!")
    print(f"Models saved in: {threat_trainer.models_dir}")


if __name__ == "__main__":
    main() 
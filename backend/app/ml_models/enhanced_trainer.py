"""
Enhanced ML Model Trainer for AISF Security Framework
Trains advanced AI models using real security datasets
"""

import pandas as pd
import numpy as np
import joblib
import os
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.feature_selection import SelectKBest, f_classif
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Conv1D, MaxPooling1D, Flatten
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedMLTrainer:
    """Enhanced ML model trainer for security threat detection."""
    
    def __init__(self):
        self.models_dir = "backend/app/ml_models/saved_models"
        self.data_dir = "backend/app/ml_models/datasets"
        self.scalers = {}
        self.label_encoders = {}
        self.models = {}
        
        # Ensure directories exist
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Feature names for network intrusion detection
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
        
        # Threat categories
        self.threat_categories = ['normal', 'dos', 'probe', 'r2l', 'u2r']
        
    def generate_synthetic_dataset(self, size: int = 10000) -> pd.DataFrame:
        """Generate synthetic security dataset based on real patterns."""
        logger.info(f"Generating synthetic dataset with {size} samples...")
        
        data = []
        
        # Generate normal traffic (70% of data)
        normal_count = int(size * 0.7)
        for _ in range(normal_count):
            sample = self._generate_normal_traffic()
            sample['attack_type'] = 'normal'
            data.append(sample)
        
        # Generate attack traffic (30% of data)
        attack_count = size - normal_count
        attack_types = ['dos', 'probe', 'r2l', 'u2r']
        
        for attack_type in attack_types:
            count = attack_count // len(attack_types)
            for _ in range(count):
                sample = self._generate_attack_traffic(attack_type)
                sample['attack_type'] = attack_type
                data.append(sample)
        
        df = pd.DataFrame(data)
        logger.info(f"Generated dataset with shape: {df.shape}")
        logger.info(f"Attack type distribution:\n{df['attack_type'].value_counts()}")
        
        return df
    
    def _generate_normal_traffic(self) -> Dict:
        """Generate normal network traffic patterns."""
        return {
            'duration': np.random.randint(1, 300),
            'protocol_type': np.random.choice(['tcp', 'udp', 'icmp']),
            'service': np.random.choice(['http', 'https', 'ftp', 'ssh', 'smtp', 'dns']),
            'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR']),
            'src_bytes': np.random.randint(0, 1000),
            'dst_bytes': np.random.randint(0, 1000),
            'land': np.random.choice([0, 1]),
            'wrong_fragment': np.random.randint(0, 3),
            'urgent': np.random.randint(0, 3),
            'hot': np.random.randint(0, 5),
            'num_failed_logins': np.random.randint(0, 2),
            'logged_in': np.random.choice([0, 1]),
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': np.random.randint(0, 2),
            'num_shells': 0,
            'num_access_files': np.random.randint(0, 2),
            'num_outbound_cmds': 0,
            'is_host_login': np.random.choice([0, 1]),
            'is_guest_login': np.random.choice([0, 1]),
            'count': np.random.randint(1, 50),
            'srv_count': np.random.randint(0, 10),
            'serror_rate': np.random.uniform(0, 0.1),
            'srv_serror_rate': np.random.uniform(0, 0.1),
            'rerror_rate': np.random.uniform(0, 0.1),
            'srv_rerror_rate': np.random.uniform(0, 0.1),
            'same_srv_rate': np.random.uniform(0.8, 1.0),
            'diff_srv_rate': np.random.uniform(0, 0.2),
            'srv_diff_host_rate': np.random.uniform(0, 0.2),
            'dst_host_count': np.random.randint(0, 50),
            'dst_host_srv_count': np.random.randint(0, 50),
            'dst_host_same_srv_rate': np.random.uniform(0.8, 1.0),
            'dst_host_diff_srv_rate': np.random.uniform(0, 0.2),
            'dst_host_same_src_port_rate': np.random.uniform(0.8, 1.0),
            'dst_host_srv_diff_host_rate': np.random.uniform(0, 0.2),
            'dst_host_serror_rate': np.random.uniform(0, 0.1),
            'dst_host_srv_serror_rate': np.random.uniform(0, 0.1),
            'dst_host_rerror_rate': np.random.uniform(0, 0.1),
            'dst_host_srv_rerror_rate': np.random.uniform(0, 0.1)
        }
    
    def _generate_attack_traffic(self, attack_type: str) -> Dict:
        """Generate attack traffic patterns based on attack type."""
        base = self._generate_normal_traffic()
        
        if attack_type == 'dos':
            # DoS attack characteristics
            base['duration'] = np.random.randint(0, 10)
            base['src_bytes'] = np.random.randint(0, 100)
            base['dst_bytes'] = 0
            base['count'] = np.random.randint(100, 1000)
            base['serror_rate'] = np.random.uniform(0.8, 1.0)
            base['srv_serror_rate'] = np.random.uniform(0.8, 1.0)
            
        elif attack_type == 'probe':
            # Probe attack characteristics
            base['duration'] = np.random.randint(0, 5)
            base['src_bytes'] = np.random.randint(0, 100)
            base['dst_bytes'] = np.random.randint(0, 100)
            base['count'] = np.random.randint(1, 20)
            base['srv_count'] = np.random.randint(5, 20)
            
        elif attack_type == 'r2l':
            # R2L attack characteristics
            base['duration'] = np.random.randint(0, 10)
            base['src_bytes'] = np.random.randint(0, 100)
            base['dst_bytes'] = np.random.randint(0, 100)
            base['num_failed_logins'] = np.random.randint(3, 10)
            base['logged_in'] = 0
            base['num_compromised'] = np.random.randint(1, 5)
            
        elif attack_type == 'u2r':
            # U2R attack characteristics
            base['duration'] = np.random.randint(0, 10)
            base['src_bytes'] = np.random.randint(0, 100)
            base['dst_bytes'] = np.random.randint(0, 100)
            base['root_shell'] = 1
            base['su_attempted'] = 1
            base['num_root'] = np.random.randint(1, 3)
            base['num_file_creations'] = np.random.randint(3, 10)
            base['num_shells'] = np.random.randint(1, 3)
            
        return base
    
    def preprocess_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Preprocess the dataset for ML training."""
        logger.info("Preprocessing data...")
        
        # Handle categorical variables
        categorical_features = ['protocol_type', 'service', 'flag']
        
        for feature in categorical_features:
            if feature in df.columns:
                le = LabelEncoder()
                df[feature] = le.fit_transform(df[feature].astype(str))
                self.label_encoders[feature] = le
        
        # Prepare features and target
        feature_cols = [col for col in df.columns if col != 'attack_type']
        X = df[feature_cols].values
        y = df['attack_type'].values
        
        # Encode target variable
        target_encoder = LabelEncoder()
        y = target_encoder.fit_transform(y)
        self.label_encoders['attack_type'] = target_encoder
        
        # Scale features
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
        self.scalers['main'] = scaler
        
        logger.info(f"Preprocessed data shape: X={X.shape}, y={y.shape}")
        return X, y
    
    def train_random_forest(self, X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
        """Train Random Forest model."""
        logger.info("Training Random Forest model...")
        
        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        # Train the model
        rf_model.fit(X, y)
        
        # Evaluate
        y_pred = rf_model.predict(X)
        accuracy = accuracy_score(y, y_pred)
        logger.info(f"Random Forest accuracy: {accuracy:.4f}")
        
        self.models['random_forest'] = rf_model
        return rf_model
    
    def train_gradient_boosting(self, X: np.ndarray, y: np.ndarray) -> GradientBoostingClassifier:
        """Train Gradient Boosting model."""
        logger.info("Training Gradient Boosting model...")
        
        gb_model = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=8,
            random_state=42
        )
        
        # Train the model
        gb_model.fit(X, y)
        
        # Evaluate
        y_pred = gb_model.predict(X)
        accuracy = accuracy_score(y, y_pred)
        logger.info(f"Gradient Boosting accuracy: {accuracy:.4f}")
        
        self.models['gradient_boosting'] = gb_model
        return gb_model
    
    def train_neural_network(self, X: np.ndarray, y: np.ndarray) -> MLPClassifier:
        """Train Neural Network model."""
        logger.info("Training Neural Network model...")
        
        nn_model = MLPClassifier(
            hidden_layer_sizes=(100, 50, 25),
            activation='relu',
            solver='adam',
            alpha=0.001,
            learning_rate='adaptive',
            max_iter=500,
            random_state=42
        )
        
        # Train the model
        nn_model.fit(X, y)
        
        # Evaluate
        y_pred = nn_model.predict(X)
        accuracy = accuracy_score(y, y_pred)
        logger.info(f"Neural Network accuracy: {accuracy:.4f}")
        
        self.models['neural_network'] = nn_model
        return nn_model
    
    def train_lstm_model(self, X: np.ndarray, y: np.ndarray, sequence_length: int = 10) -> tf.keras.Model:
        """Train LSTM model for sequence-based threat detection."""
        logger.info("Training LSTM model...")
        
        # Reshape data for LSTM (samples, timesteps, features)
        X_reshaped = self._reshape_for_lstm(X, sequence_length)
        y_reshaped = y[sequence_length-1:]  # Adjust target to match sequence length
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_reshaped, y_reshaped, test_size=0.2, random_state=42
        )
        
        # Build LSTM model
        model = Sequential([
            LSTM(128, return_sequences=True, input_shape=(sequence_length, X.shape[1])),
            Dropout(0.3),
            LSTM(64, return_sequences=False),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(len(np.unique(y)), activation='softmax')
        ])
        
        # Compile model
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        # Callbacks
        callbacks = [
            EarlyStopping(patience=10, restore_best_weights=True),
            ModelCheckpoint(
                os.path.join(self.models_dir, 'lstm_model.h5'),
                save_best_only=True
            )
        ]
        
        # Train model
        history = model.fit(
            X_train, y_train,
            validation_data=(X_test, y_test),
            epochs=50,
            batch_size=32,
            callbacks=callbacks,
            verbose=1
        )
        
        # Evaluate
        test_loss, test_accuracy = model.evaluate(X_test, y_test, verbose=0)
        logger.info(f"LSTM test accuracy: {test_accuracy:.4f}")
        
        self.models['lstm'] = model
        return model
    
    def _reshape_for_lstm(self, X: np.ndarray, sequence_length: int) -> np.ndarray:
        """Reshape data for LSTM input."""
        sequences = []
        for i in range(len(X) - sequence_length + 1):
            sequences.append(X[i:i + sequence_length])
        return np.array(sequences)
    
    def train_autoencoder(self, X: np.ndarray) -> tf.keras.Model:
        """Train Autoencoder for anomaly detection."""
        logger.info("Training Autoencoder for anomaly detection...")
        
        # Split data
        X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
        
        # Build autoencoder
        input_dim = X.shape[1]
        encoding_dim = int(input_dim * 0.3)
        
        # Encoder
        input_layer = tf.keras.layers.Input(shape=(input_dim,))
        encoded = Dense(encoding_dim * 2, activation='relu')(input_layer)
        encoded = Dense(encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = Dense(encoding_dim * 2, activation='relu')(encoded)
        decoded = Dense(input_dim, activation='sigmoid')(decoded)
        
        # Autoencoder model
        autoencoder = tf.keras.Model(input_layer, decoded)
        
        # Compile
        autoencoder.compile(optimizer='adam', loss='mse')
        
        # Train
        history = autoencoder.fit(
            X_train, X_train,
            epochs=50,
            batch_size=32,
            validation_data=(X_test, X_test),
            verbose=1
        )
        
        # Evaluate
        test_loss = autoencoder.evaluate(X_test, X_test, verbose=0)
        logger.info(f"Autoencoder test loss: {test_loss:.4f}")
        
        self.models['autoencoder'] = autoencoder
        return autoencoder
    
    def save_models(self):
        """Save all trained models and preprocessors."""
        logger.info("Saving models and preprocessors...")
        
        # Save scikit-learn models
        for name, model in self.models.items():
            if hasattr(model, 'predict'):  # Scikit-learn models
                model_path = os.path.join(self.models_dir, f'{name}_model.pkl')
                joblib.dump(model, model_path)
                logger.info(f"Saved {name} model to {model_path}")
        
        # Save TensorFlow models
        for name, model in self.models.items():
            if hasattr(model, 'save'):  # TensorFlow models
                model_path = os.path.join(self.models_dir, f'{name}_model')
                model.save(model_path)
                logger.info(f"Saved {name} model to {model_path}")
        
        # Save preprocessors
        preprocessor_path = os.path.join(self.models_dir, 'preprocessors.pkl')
        joblib.dump({
            'scalers': self.scalers,
            'label_encoders': self.label_encoders
        }, preprocessor_path)
        logger.info(f"Saved preprocessors to {preprocessor_path}")
    
    def load_models(self):
        """Load saved models and preprocessors."""
        logger.info("Loading saved models and preprocessors...")
        
        # Load preprocessors
        preprocessor_path = os.path.join(self.models_dir, 'preprocessors.pkl')
        if os.path.exists(preprocessor_path):
            preprocessors = joblib.load(preprocessor_path)
            self.scalers = preprocessors['scalers']
            self.label_encoders = preprocessors['label_encoders']
            logger.info("Loaded preprocessors")
        
        # Load scikit-learn models
        model_files = {
            'random_forest': 'random_forest_model.pkl',
            'gradient_boosting': 'gradient_boosting_model.pkl',
            'neural_network': 'neural_network_model.pkl'
        }
        
        for name, filename in model_files.items():
            model_path = os.path.join(self.models_dir, filename)
            if os.path.exists(model_path):
                self.models[name] = joblib.load(model_path)
                logger.info(f"Loaded {name} model")
        
        # Load TensorFlow models
        tf_model_files = ['lstm_model', 'autoencoder_model']
        for name in tf_model_files:
            model_path = os.path.join(self.models_dir, name)
            if os.path.exists(model_path):
                self.models[name.replace('_model', '')] = tf.keras.models.load_model(model_path)
                logger.info(f"Loaded {name} model")
    
    def train_all_models(self, dataset_size: int = 10000):
        """Train all ML models."""
        logger.info("Starting comprehensive model training...")
        
        # Generate dataset
        df = self.generate_synthetic_dataset(dataset_size)
        
        # Preprocess data
        X, y = self.preprocess_data(df)
        
        # Train models
        self.train_random_forest(X, y)
        self.train_gradient_boosting(X, y)
        self.train_neural_network(X, y)
        self.train_lstm_model(X, y)
        self.train_autoencoder(X)
        
        # Save models
        self.save_models()
        
        logger.info("All models trained and saved successfully!")

# Global instance
ml_trainer = EnhancedMLTrainer() 
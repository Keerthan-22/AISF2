"""
Sequential Analyzer - LSTM Implementation
Implements LSTM networks for sequential threat pattern analysis
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras import layers, Model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import joblib
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)

class SequentialAnalyzer:
    """
    LSTM-based sequential threat pattern analyzer
    Implements LSTM networks for sequential threat pattern analysis as per research
    """
    
    def __init__(self, sequence_length: int = 50, model_path: str = "models/lstm_analyzer"):
        self.sequence_length = sequence_length
        self.model_path = model_path
        self.lstm_model = None
        self.scaler = None
        self.is_trained = False
        
        # Threat pattern features
        self.pattern_features = [
            'timestamp', 'src_ip', 'dst_ip', 'protocol', 'port',
            'packet_size', 'packet_count', 'connection_duration',
            'bytes_sent', 'bytes_received', 'flags', 'window_size',
            'ttl', 'tos', 'id', 'fragment_offset', 'checksum'
        ]
        
        # Threat pattern types
        self.pattern_types = {
            'normal': 'Normal traffic pattern',
            'scanning': 'Port scanning pattern',
            'flooding': 'DDoS flooding pattern',
            'lateral_movement': 'Lateral movement pattern',
            'data_exfiltration': 'Data exfiltration pattern',
            'command_control': 'C&C communication pattern'
        }
    
    def build_lstm_model(self, input_shape: Tuple[int, int], num_classes: int):
        """Build LSTM model for sequential pattern analysis"""
        
        # Input layer
        input_layer = layers.Input(shape=input_shape)
        
        # LSTM layers
        lstm1 = layers.LSTM(128, return_sequences=True, dropout=0.2)(input_layer)
        lstm2 = layers.LSTM(64, return_sequences=False, dropout=0.2)(lstm1)
        
        # Dense layers
        dense1 = layers.Dense(32, activation='relu')(lstm2)
        dropout = layers.Dropout(0.3)(dense1)
        output = layers.Dense(num_classes, activation='softmax')(dropout)
        
        # Create model
        self.lstm_model = Model(input_layer, output)
        
        # Compile model
        self.lstm_model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return self.lstm_model
    
    def create_sequences(self, data: np.ndarray, labels: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Create sequences for LSTM training"""
        sequences = []
        sequence_labels = []
        
        for i in range(len(data) - self.sequence_length):
            sequence = data[i:i + self.sequence_length]
            label = labels[i + self.sequence_length]
            sequences.append(sequence)
            sequence_labels.append(label)
        
        return np.array(sequences), np.array(sequence_labels)
    
    def train(self, data: np.ndarray, labels: np.ndarray, epochs: int = 100, batch_size: int = 32) -> Dict:
        """
        Train LSTM model for sequential threat pattern analysis
        """
        logger.info("Training LSTM sequential analyzer...")
        
        # Scale the data
        from sklearn.preprocessing import StandardScaler
        self.scaler = StandardScaler()
        data_scaled = self.scaler.fit_transform(data)
        
        # Create sequences
        X_sequences, y_sequences = self.create_sequences(data_scaled, labels)
        
        # Split data
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(
            X_sequences, y_sequences, test_size=0.2, random_state=42
        )
        
        # Build model
        num_classes = len(np.unique(labels))
        self.build_lstm_model((self.sequence_length, data.shape[1]), num_classes)
        
        # Train model
        history = self.lstm_model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_data=(X_test, y_test),
            verbose=1
        )
        
        # Evaluate model
        test_loss, test_accuracy = self.lstm_model.evaluate(X_test, y_test, verbose=0)
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        self.lstm_model.save(self.model_path + '.keras')
        joblib.dump(self.scaler, f"{self.model_path}_scaler.pkl")
        
        self.is_trained = True
        
        results = {
            'test_accuracy': test_accuracy,
            'test_loss': test_loss,
            'final_accuracy': history.history['accuracy'][-1],
            'final_val_accuracy': history.history['val_accuracy'][-1]
        }
        
        logger.info(f"LSTM trained successfully. Test accuracy: {test_accuracy:.4f}")
        
        return results
    
    def predict_pattern(self, sequence: np.ndarray) -> Dict:
        """
        Predict threat pattern from sequence
        """
        if not self.is_trained:
            self.load_model()
        
        if self.lstm_model is None:
            raise ValueError("Model not trained or loaded")
        
        # Ensure sequence length
        if len(sequence) != self.sequence_length:
            raise ValueError(f"Expected sequence length {self.sequence_length}, got {len(sequence)}")
        
        # Scale the sequence
        sequence_scaled = self.scaler.transform(sequence)
        sequence_reshaped = sequence_scaled.reshape(1, self.sequence_length, -1)
        
        # Predict
        prediction_proba = self.lstm_model.predict(sequence_reshaped)[0]
        prediction = np.argmax(prediction_proba)
        
        # Get pattern type
        pattern_type = list(self.pattern_types.keys())[prediction]
        pattern_description = self.pattern_types[pattern_type]
        
        return {
            'prediction': int(prediction),
            'pattern_type': pattern_type,
            'pattern_description': pattern_description,
            'confidence': float(np.max(prediction_proba)),
            'probabilities': dict(zip(self.pattern_types.keys(), prediction_proba)),
            'timestamp': datetime.now().isoformat()
        }
    
    def detect_lateral_movement(self, network_data: List[Dict]) -> Dict:
        """
        Detect lateral movement patterns in network data
        """
        if len(network_data) < self.sequence_length:
            return {'detected': False, 'confidence': 0.0}
        
        # Convert to sequence
        sequence = []
        for data_point in network_data[-self.sequence_length:]:
            features = [
                data_point.get('timestamp', 0),
                data_point.get('src_ip_hash', 0),
                data_point.get('dst_ip_hash', 0),
                data_point.get('protocol', 0),
                data_point.get('port', 0),
                data_point.get('packet_size', 0),
                data_point.get('packet_count', 0),
                data_point.get('connection_duration', 0),
                data_point.get('bytes_sent', 0),
                data_point.get('bytes_received', 0),
                data_point.get('flags', 0),
                data_point.get('window_size', 0),
                data_point.get('ttl', 0),
                data_point.get('tos', 0),
                data_point.get('id', 0),
                data_point.get('fragment_offset', 0),
                data_point.get('checksum', 0)
            ]
            sequence.append(features)
        
        sequence_array = np.array(sequence)
        
        # Predict pattern
        prediction = self.predict_pattern(sequence_array)
        
        # Check for lateral movement
        is_lateral_movement = prediction['pattern_type'] == 'lateral_movement'
        
        return {
            'detected': is_lateral_movement,
            'confidence': prediction['confidence'],
            'pattern_type': prediction['pattern_type'],
            'pattern_description': prediction['pattern_description'],
            'timestamp': datetime.now().isoformat()
        }
    
    def load_model(self):
        """Load trained LSTM model"""
        try:
            self.lstm_model = tf.keras.models.load_model(self.model_path + '.keras')
            self.scaler = joblib.load(f"{self.model_path}_scaler.pkl")
            self.is_trained = True
            logger.info("LSTM model loaded successfully")
        except FileNotFoundError:
            logger.warning("No trained LSTM model found")
            self.lstm_model = None
    
    def generate_sequential_data(self, n_samples: int = 10000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate sample sequential network data for training
        """
        np.random.seed(42)
        
        # Generate time series data
        timestamps = np.arange(n_samples)
        
        # Generate different patterns
        data = []
        labels = []
        
        # Normal traffic pattern
        normal_samples = int(n_samples * 0.6)
        for i in range(normal_samples):
            features = [
                timestamps[i],
                np.random.randint(1, 1000),  # src_ip_hash
                np.random.randint(1, 1000),  # dst_ip_hash
                np.random.choice([1, 6, 17]),  # protocol (TCP, UDP, ICMP)
                np.random.randint(1, 65536),  # port
                np.random.exponential(1000),  # packet_size
                np.random.poisson(10),  # packet_count
                np.random.exponential(60),  # connection_duration
                np.random.exponential(5000),  # bytes_sent
                np.random.exponential(5000),  # bytes_received
                np.random.randint(0, 256),  # flags
                np.random.randint(1000, 65535),  # window_size
                np.random.randint(32, 255),  # ttl
                np.random.randint(0, 255),  # tos
                np.random.randint(0, 65535),  # id
                np.random.randint(0, 8192),  # fragment_offset
                np.random.randint(0, 65535)  # checksum
            ]
            data.append(features)
            labels.append(0)  # normal
        
        # Scanning pattern
        scan_samples = int(n_samples * 0.15)
        for i in range(scan_samples):
            features = [
                timestamps[normal_samples + i],
                np.random.randint(1, 100),  # src_ip_hash
                np.random.randint(1, 1000),  # dst_ip_hash
                6,  # TCP
                np.random.randint(1, 1024),  # port
                np.random.exponential(500),  # packet_size
                np.random.poisson(1),  # packet_count
                np.random.exponential(10),  # connection_duration
                np.random.exponential(100),  # bytes_sent
                np.random.exponential(100),  # bytes_received
                2,  # SYN flag
                np.random.randint(1000, 65535),  # window_size
                np.random.randint(32, 255),  # ttl
                np.random.randint(0, 255),  # tos
                np.random.randint(0, 65535),  # id
                np.random.randint(0, 8192),  # fragment_offset
                np.random.randint(0, 65535)  # checksum
            ]
            data.append(features)
            labels.append(1)  # scanning
        
        # Flooding pattern
        flood_samples = int(n_samples * 0.15)
        for i in range(flood_samples):
            features = [
                timestamps[normal_samples + scan_samples + i],
                np.random.randint(1, 100),  # src_ip_hash
                np.random.randint(1, 10),  # dst_ip_hash
                np.random.choice([6, 17]),  # TCP/UDP
                np.random.randint(80, 443),  # port
                np.random.exponential(1500),  # packet_size
                np.random.poisson(100),  # packet_count
                np.random.exponential(1),  # connection_duration
                np.random.exponential(10000),  # bytes_sent
                np.random.exponential(100),  # bytes_received
                np.random.randint(0, 256),  # flags
                np.random.randint(1000, 65535),  # window_size
                np.random.randint(32, 255),  # ttl
                np.random.randint(0, 255),  # tos
                np.random.randint(0, 65535),  # id
                np.random.randint(0, 8192),  # fragment_offset
                np.random.randint(0, 65535)  # checksum
            ]
            data.append(features)
            labels.append(2)  # flooding
        
        # Lateral movement pattern
        lateral_samples = int(n_samples * 0.05)
        for i in range(lateral_samples):
            features = [
                timestamps[normal_samples + scan_samples + flood_samples + i],
                np.random.randint(1, 50),  # src_ip_hash
                np.random.randint(1, 50),  # dst_ip_hash
                6,  # TCP
                np.random.randint(22, 23),  # SSH/Telnet
                np.random.exponential(1000),  # packet_size
                np.random.poisson(50),  # packet_count
                np.random.exponential(3600),  # connection_duration
                np.random.exponential(10000),  # bytes_sent
                np.random.exponential(10000),  # bytes_received
                np.random.randint(0, 256),  # flags
                np.random.randint(1000, 65535),  # window_size
                np.random.randint(32, 255),  # ttl
                np.random.randint(0, 255),  # tos
                np.random.randint(0, 65535),  # id
                np.random.randint(0, 8192),  # fragment_offset
                np.random.randint(0, 65535)  # checksum
            ]
            data.append(features)
            labels.append(3)  # lateral_movement
        
        # Data exfiltration pattern
        exfil_samples = int(n_samples * 0.03)
        for i in range(exfil_samples):
            features = [
                timestamps[normal_samples + scan_samples + flood_samples + lateral_samples + i],
                np.random.randint(1, 10),  # src_ip_hash
                np.random.randint(1000, 2000),  # dst_ip_hash
                6,  # TCP
                np.random.randint(80, 443),  # port
                np.random.exponential(2000),  # packet_size
                np.random.poisson(200),  # packet_count
                np.random.exponential(300),  # connection_duration
                np.random.exponential(50000),  # bytes_sent
                np.random.exponential(1000),  # bytes_received
                np.random.randint(0, 256),  # flags
                np.random.randint(1000, 65535),  # window_size
                np.random.randint(32, 255),  # ttl
                np.random.randint(0, 255),  # tos
                np.random.randint(0, 65535),  # id
                np.random.randint(0, 8192),  # fragment_offset
                np.random.randint(0, 65535)  # checksum
            ]
            data.append(features)
            labels.append(4)  # data_exfiltration
        
        # C&C communication pattern
        cnc_samples = int(n_samples * 0.02)
        for i in range(cnc_samples):
            features = [
                timestamps[normal_samples + scan_samples + flood_samples + lateral_samples + exfil_samples + i],
                np.random.randint(1, 10),  # src_ip_hash
                np.random.randint(2000, 3000),  # dst_ip_hash
                6,  # TCP
                np.random.randint(443, 444),  # port
                np.random.exponential(500),  # packet_size
                np.random.poisson(10),  # packet_count
                np.random.exponential(60),  # connection_duration
                np.random.exponential(1000),  # bytes_sent
                np.random.exponential(1000),  # bytes_received
                np.random.randint(0, 256),  # flags
                np.random.randint(1000, 65535),  # window_size
                np.random.randint(32, 255),  # ttl
                np.random.randint(0, 255),  # tos
                np.random.randint(0, 65535),  # id
                np.random.randint(0, 8192),  # fragment_offset
                np.random.randint(0, 65535)  # checksum
            ]
            data.append(features)
            labels.append(5)  # command_control
        
        return np.array(data), np.array(labels) 
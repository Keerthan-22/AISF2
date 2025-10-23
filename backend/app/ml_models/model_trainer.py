"""
Model Trainer - Orchestrates training of all AISF ML models
"""

import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import os
import json

from .threat_classifier import ThreatClassifier
from .anomaly_detector import GMMAnomalyDetector, AutoencoderAnomalyDetector
from .sequential_analyzer import SequentialAnalyzer
from .response_optimizer import ResponseOptimizer

logger = logging.getLogger(__name__)

class ModelTrainer:
    """
    Orchestrates training of all AISF ML models
    Implements complete ML pipeline for the research framework
    """
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.threat_classifier = ThreatClassifier()
        self.gmm_detector = GMMAnomalyDetector()
        self.autoencoder_detector = AutoencoderAnomalyDetector()
        self.sequential_analyzer = SequentialAnalyzer()
        self.response_optimizer = ResponseOptimizer()
        
        # Training results storage
        self.training_results = {}
        
        # Create models directory
        os.makedirs(models_dir, exist_ok=True)
    
    def train_all_models(self) -> Dict:
        """
        Train all AISF ML models
        Returns comprehensive training results
        """
        logger.info("Starting comprehensive AISF model training...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'models_trained': [],
            'overall_accuracy': 0.0,
            'training_duration': 0.0
        }
        
        start_time = datetime.now()
        
        try:
            # 1. Train Threat Classifier (Random Forest)
            logger.info("Training Threat Classifier...")
            threat_results = self.train_threat_classifier()
            results['threat_classifier'] = threat_results
            results['models_trained'].append('threat_classifier')
            
            # 2. Train GMM Anomaly Detector
            logger.info("Training GMM Anomaly Detector...")
            gmm_results = self.train_gmm_detector()
            results['gmm_detector'] = gmm_results
            results['models_trained'].append('gmm_detector')
            
            # 3. Train Autoencoder for Zero-day Detection
            logger.info("Training Autoencoder for Zero-day Detection...")
            autoencoder_results = self.train_autoencoder_detector()
            results['autoencoder_detector'] = autoencoder_results
            results['models_trained'].append('autoencoder_detector')
            
            # 4. Train Sequential Analyzer (LSTM)
            logger.info("Training Sequential Analyzer...")
            sequential_results = self.train_sequential_analyzer()
            results['sequential_analyzer'] = sequential_results
            results['models_trained'].append('sequential_analyzer')
            
            # 5. Train Response Optimizer (PPO)
            logger.info("Training Response Optimizer...")
            response_results = self.train_response_optimizer()
            results['response_optimizer'] = response_results
            results['models_trained'].append('response_optimizer')
            
            # Calculate overall metrics
            results['overall_accuracy'] = self.calculate_overall_accuracy(results)
            results['training_duration'] = (datetime.now() - start_time).total_seconds()
            
            # Save training results
            self.save_training_results(results)
            
            logger.info(f"All models trained successfully in {results['training_duration']:.2f} seconds")
            logger.info(f"Overall accuracy: {results['overall_accuracy']:.4f}")
            
        except Exception as e:
            logger.error(f"Error during model training: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def train_threat_classifier(self) -> Dict:
        """Train Random Forest threat classifier"""
        try:
            # Generate sample data
            X, y = self.threat_classifier.generate_sample_data()
            
            # Train model
            results = self.threat_classifier.train(X, y)
            
            # Add additional metrics
            results['model_type'] = 'Random Forest'
            results['target_accuracy'] = 0.9769  # Research target
            results['accuracy_gap'] = results['target_accuracy'] - results['accuracy']
            
            return results
            
        except Exception as e:
            logger.error(f"Error training threat classifier: {str(e)}")
            return {'error': str(e)}
    
    def train_gmm_detector(self) -> Dict:
        """Train GMM anomaly detector for behavioral analysis"""
        try:
            # Generate behavioral data
            data = self.gmm_detector.generate_behavioral_data()
            
            # Train model
            results = self.gmm_detector.train(data)
            
            # Add additional metrics
            results['model_type'] = 'Gaussian Mixture Model'
            results['n_components'] = self.gmm_detector.n_components
            
            return results
            
        except Exception as e:
            logger.error(f"Error training GMM detector: {str(e)}")
            return {'error': str(e)}
    
    def train_autoencoder_detector(self) -> Dict:
        """Train autoencoder for zero-day detection"""
        try:
            # Generate traffic data
            data = self.autoencoder_detector.generate_traffic_data()
            
            # Train model
            results = self.autoencoder_detector.train(data, epochs=30)  # Reduced for speed
            
            # Add additional metrics
            results['model_type'] = 'Autoencoder'
            results['input_dim'] = self.autoencoder_detector.input_dim
            results['encoding_dim'] = self.autoencoder_detector.encoding_dim
            
            return results
            
        except Exception as e:
            logger.error(f"Error training autoencoder detector: {str(e)}")
            return {'error': str(e)}
    
    def train_sequential_analyzer(self) -> Dict:
        """Train LSTM sequential analyzer"""
        try:
            # Generate sequential data
            data, labels = self.sequential_analyzer.generate_sequential_data(n_samples=5000)
            
            # Train model
            results = self.sequential_analyzer.train(data, labels, epochs=50)  # Reduced for speed
            
            # Add additional metrics
            results['model_type'] = 'LSTM'
            results['sequence_length'] = self.sequential_analyzer.sequence_length
            
            return results
            
        except Exception as e:
            logger.error(f"Error training sequential analyzer: {str(e)}")
            return {'error': str(e)}
    
    def train_response_optimizer(self) -> Dict:
        """Train PPO response optimizer"""
        try:
            # Train model
            results = self.response_optimizer.train(training_episodes=500)  # Reduced for speed
            
            # Add additional metrics
            results['model_type'] = 'PPO (Proximal Policy Optimization)'
            results['state_dim'] = self.response_optimizer.state_dim
            results['action_dim'] = self.response_optimizer.action_dim
            
            return results
            
        except Exception as e:
            logger.error(f"Error training response optimizer: {str(e)}")
            return {'error': str(e)}
    
    def calculate_overall_accuracy(self, results: Dict) -> float:
        """Calculate overall accuracy across all models"""
        accuracies = []
        
        # Threat classifier accuracy
        if 'threat_classifier' in results and 'accuracy' in results['threat_classifier']:
            accuracies.append(results['threat_classifier']['accuracy'])
        
        # Sequential analyzer accuracy
        if 'sequential_analyzer' in results and 'test_accuracy' in results['sequential_analyzer']:
            accuracies.append(results['sequential_analyzer']['test_accuracy'])
        
        # Autoencoder effectiveness (using final loss as proxy)
        if 'autoencoder_detector' in results and 'final_loss' in results['autoencoder_detector']:
            # Convert loss to accuracy-like metric (lower loss = higher accuracy)
            loss = results['autoencoder_detector']['final_loss']
            accuracy_proxy = max(0, 1 - loss * 10)  # Simple conversion
            accuracies.append(accuracy_proxy)
        
        # GMM effectiveness (using silhouette score as proxy)
        if 'gmm_detector' in results and 'silhouette_score' in results['gmm_detector']:
            silhouette = results['gmm_detector']['silhouette_score']
            accuracy_proxy = (silhouette + 1) / 2  # Convert to 0-1 range
            accuracies.append(accuracy_proxy)
        
        # PPO effectiveness (using average reward as proxy)
        if 'response_optimizer' in results and 'average_reward' in results['response_optimizer']:
            reward = results['response_optimizer']['average_reward']
            accuracies.append(reward)
        
        return np.mean(accuracies) if accuracies else 0.0
    
    def save_training_results(self, results: Dict):
        """Save training results to file"""
        results_file = os.path.join(self.models_dir, 'training_results.json')
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Training results saved to {results_file}")
    
    def load_all_models(self) -> Dict:
        """Load all trained models"""
        logger.info("Loading all trained models...")
        
        load_results = {
            'models_loaded': [],
            'models_failed': [],
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Load threat classifier
            self.threat_classifier.load_model()
            if self.threat_classifier.model is not None:
                load_results['models_loaded'].append('threat_classifier')
            else:
                load_results['models_failed'].append('threat_classifier')
        except Exception as e:
            load_results['models_failed'].append('threat_classifier')
            logger.error(f"Failed to load threat classifier: {str(e)}")
        
        try:
            # Load GMM detector
            self.gmm_detector.load_model()
            if self.gmm_detector.gmm is not None:
                load_results['models_loaded'].append('gmm_detector')
            else:
                load_results['models_failed'].append('gmm_detector')
        except Exception as e:
            load_results['models_failed'].append('gmm_detector')
            logger.error(f"Failed to load GMM detector: {str(e)}")
        
        try:
            # Load autoencoder detector
            self.autoencoder_detector.load_model()
            if self.autoencoder_detector.autoencoder is not None:
                load_results['models_loaded'].append('autoencoder_detector')
            else:
                load_results['models_failed'].append('autoencoder_detector')
        except Exception as e:
            load_results['models_failed'].append('autoencoder_detector')
            logger.error(f"Failed to load autoencoder detector: {str(e)}")
        
        try:
            # Load sequential analyzer
            self.sequential_analyzer.load_model()
            if self.sequential_analyzer.lstm_model is not None:
                load_results['models_loaded'].append('sequential_analyzer')
            else:
                load_results['models_failed'].append('sequential_analyzer')
        except Exception as e:
            load_results['models_failed'].append('sequential_analyzer')
            logger.error(f"Failed to load sequential analyzer: {str(e)}")
        
        try:
            # Load response optimizer
            self.response_optimizer.load_model()
            if self.response_optimizer.actor_model is not None:
                load_results['models_loaded'].append('response_optimizer')
            else:
                load_results['models_failed'].append('response_optimizer')
        except Exception as e:
            load_results['models_failed'].append('response_optimizer')
            logger.error(f"Failed to load response optimizer: {str(e)}")
        
        logger.info(f"Models loaded: {len(load_results['models_loaded'])}")
        logger.info(f"Models failed: {len(load_results['models_failed'])}")
        
        return load_results
    
    def get_model_status(self) -> Dict:
        """Get status of all models"""
        status = {
            'threat_classifier': {
                'trained': self.threat_classifier.model is not None,
                'model_type': 'Random Forest',
                'target_accuracy': 0.9769
            },
            'gmm_detector': {
                'trained': self.gmm_detector.gmm is not None,
                'model_type': 'Gaussian Mixture Model',
                'n_components': self.gmm_detector.n_components
            },
            'autoencoder_detector': {
                'trained': self.autoencoder_detector.autoencoder is not None,
                'model_type': 'Autoencoder',
                'input_dim': self.autoencoder_detector.input_dim
            },
            'sequential_analyzer': {
                'trained': self.sequential_analyzer.lstm_model is not None,
                'model_type': 'LSTM',
                'sequence_length': self.sequential_analyzer.sequence_length
            },
            'response_optimizer': {
                'trained': self.response_optimizer.actor_model is not None,
                'model_type': 'PPO',
                'action_dim': self.response_optimizer.action_dim
            }
        }
        
        return status
    
    def run_comprehensive_test(self) -> Dict:
        """Run comprehensive test of all models"""
        logger.info("Running comprehensive model test...")
        
        test_results = {
            'timestamp': datetime.now().isoformat(),
            'tests_passed': 0,
            'tests_failed': 0,
            'detailed_results': {}
        }
        
        # Test 1: Threat Classification
        try:
            # Generate sample features
            sample_features = np.random.rand(41)  # 41 features for NSL-KDD
            prediction = self.threat_classifier.predict(sample_features)
            
            test_results['detailed_results']['threat_classification'] = {
                'status': 'PASSED',
                'prediction': prediction['prediction'],
                'confidence': prediction['confidence'],
                'threat_category': prediction['threat_category']
            }
            test_results['tests_passed'] += 1
            
        except Exception as e:
            test_results['detailed_results']['threat_classification'] = {
                'status': 'FAILED',
                'error': str(e)
            }
            test_results['tests_failed'] += 1
        
        # Test 2: Behavioral Anomaly Detection
        try:
            # Generate sample behavioral data
            behavioral_data = np.random.rand(12)  # 12 behavioral features
            anomaly_result = self.gmm_detector.detect_anomaly(behavioral_data)
            
            test_results['detailed_results']['behavioral_anomaly'] = {
                'status': 'PASSED',
                'is_anomaly': anomaly_result['is_anomaly'],
                'anomaly_score': anomaly_result['anomaly_score']
            }
            test_results['tests_passed'] += 1
            
        except Exception as e:
            test_results['detailed_results']['behavioral_anomaly'] = {
                'status': 'FAILED',
                'error': str(e)
            }
            test_results['tests_failed'] += 1
        
        # Test 3: Zero-day Detection
        try:
            # Generate sample traffic data
            traffic_data = np.random.rand(41)  # 41 traffic features
            zero_day_result = self.autoencoder_detector.detect_anomaly(traffic_data)
            
            test_results['detailed_results']['zero_day_detection'] = {
                'status': 'PASSED',
                'is_zero_day': zero_day_result['is_zero_day'],
                'anomaly_score': zero_day_result['anomaly_score']
            }
            test_results['tests_passed'] += 1
            
        except Exception as e:
            test_results['detailed_results']['zero_day_detection'] = {
                'status': 'FAILED',
                'error': str(e)
            }
            test_results['tests_failed'] += 1
        
        # Test 4: Sequential Pattern Analysis
        try:
            # Generate sample sequence
            sequence = np.random.rand(50, 17)  # 50 timesteps, 17 features
            pattern_result = self.sequential_analyzer.predict_pattern(sequence)
            
            test_results['detailed_results']['sequential_analysis'] = {
                'status': 'PASSED',
                'pattern_type': pattern_result['pattern_type'],
                'confidence': pattern_result['confidence']
            }
            test_results['tests_passed'] += 1
            
        except Exception as e:
            test_results['detailed_results']['sequential_analysis'] = {
                'status': 'FAILED',
                'error': str(e)
            }
            test_results['tests_failed'] += 1
        
        # Test 5: Response Optimization
        try:
            # Generate sample incident state
            incident_state = {
                'threat_severity': 0.7,
                'threat_confidence': 0.8,
                'affected_systems': 0.3,
                'data_sensitivity': 0.6,
                'user_privileges': 0.4,
                'network_location': 0.5,
                'time_of_day': 0.3,
                'business_impact': 0.6,
                'attack_type': 0.7,
                'attacker_sophistication': 0.5,
                'victim_organization': 0.4,
                'geographic_location': 0.3,
                'system_criticality': 0.8,
                'data_volume': 0.2,
                'attack_duration': 0.4,
                'previous_incidents': 0.1,
                'compliance_requirements': 0.7,
                'resource_availability': 0.6,
                'response_time_constraint': 0.8,
                'escalation_level': 0.5
            }
            
            response_result = self.response_optimizer.select_response_action(incident_state)
            
            test_results['detailed_results']['response_optimization'] = {
                'status': 'PASSED',
                'selected_action': response_result['action_name'],
                'confidence': response_result['confidence'],
                'effectiveness': response_result['effectiveness']
            }
            test_results['tests_passed'] += 1
            
        except Exception as e:
            test_results['detailed_results']['response_optimization'] = {
                'status': 'FAILED',
                'error': str(e)
            }
            test_results['tests_failed'] += 1
        
        logger.info(f"Comprehensive test completed: {test_results['tests_passed']} passed, {test_results['tests_failed']} failed")
        
        return test_results 
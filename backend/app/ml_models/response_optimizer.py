"""
Response Optimizer - PPO Implementation
Implements PPO (Proximal Policy Optimization) for response action selection
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras import layers, Model
import joblib
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import os
import random

logger = logging.getLogger(__name__)

class ResponseOptimizer:
    """
    PPO-based response action optimizer
    Implements AI-powered response action selection using reinforcement learning
    """
    
    def __init__(self, state_dim: int = 20, action_dim: int = 8, model_path: str = "models/ppo_optimizer"):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.model_path = model_path
        self.actor_model = None
        self.critic_model = None
        self.is_trained = False
        
        # Response actions
        self.response_actions = {
            0: 'isolate_host',
            1: 'block_ip',
            2: 'revoke_access',
            3: 'quarantine_file',
            4: 'reset_password',
            5: 'disable_account',
            6: 'update_firewall',
            7: 'no_action'
        }
        
        # Action descriptions
        self.action_descriptions = {
            'isolate_host': 'Isolate compromised host from network',
            'block_ip': 'Block malicious IP address',
            'revoke_access': 'Revoke user access privileges',
            'quarantine_file': 'Quarantine suspicious file',
            'reset_password': 'Force password reset',
            'disable_account': 'Temporarily disable user account',
            'update_firewall': 'Update firewall rules',
            'no_action': 'No immediate action required'
        }
        
        # State features for incident response
        self.state_features = [
            'threat_severity', 'threat_confidence', 'affected_systems',
            'data_sensitivity', 'user_privileges', 'network_location',
            'time_of_day', 'business_impact', 'attack_type',
            'attacker_sophistication', 'victim_organization', 'geographic_location',
            'system_criticality', 'data_volume', 'attack_duration',
            'previous_incidents', 'compliance_requirements', 'resource_availability',
            'response_time_constraint', 'escalation_level'
        ]
    
    def build_actor_model(self):
        """Build actor network for PPO"""
        input_layer = layers.Input(shape=(self.state_dim,))
        
        # Hidden layers
        dense1 = layers.Dense(128, activation='relu')(input_layer)
        dropout1 = layers.Dropout(0.3)(dense1)
        dense2 = layers.Dense(64, activation='relu')(dropout1)
        dropout2 = layers.Dropout(0.3)(dense2)
        dense3 = layers.Dense(32, activation='relu')(dropout2)
        
        # Output layer (action probabilities)
        output = layers.Dense(self.action_dim, activation='softmax')(dense3)
        
        self.actor_model = Model(input_layer, output)
        return self.actor_model
    
    def build_critic_model(self):
        """Build critic network for PPO"""
        input_layer = layers.Input(shape=(self.state_dim,))
        
        # Hidden layers
        dense1 = layers.Dense(128, activation='relu')(input_layer)
        dropout1 = layers.Dropout(0.3)(dense1)
        dense2 = layers.Dense(64, activation='relu')(dropout1)
        dropout2 = layers.Dropout(0.3)(dense2)
        dense3 = layers.Dense(32, activation='relu')(dropout2)
        
        # Output layer (state value)
        output = layers.Dense(1, activation='linear')(dense3)
        
        self.critic_model = Model(input_layer, output)
        return self.critic_model
    
    def calculate_response_effectiveness(self, action: str, incident_state: Dict) -> float:
        """
        Calculate response effectiveness score (0-1)
        Higher score = better response
        """
        effectiveness = 0.0
        
        # Base effectiveness by action type
        action_effectiveness = {
            'isolate_host': 0.9,
            'block_ip': 0.8,
            'revoke_access': 0.85,
            'quarantine_file': 0.75,
            'reset_password': 0.7,
            'disable_account': 0.8,
            'update_firewall': 0.85,
            'no_action': 0.1
        }
        
        effectiveness += action_effectiveness.get(action, 0.5)
        
        # Adjust based on incident characteristics
        threat_severity = incident_state.get('threat_severity', 0.5)
        threat_confidence = incident_state.get('threat_confidence', 0.5)
        
        # Higher severity/confidence should lead to stronger responses
        if threat_severity > 0.7 and action in ['isolate_host', 'block_ip', 'revoke_access']:
            effectiveness += 0.1
        elif threat_severity < 0.3 and action == 'no_action':
            effectiveness += 0.2
        
        # Consider business impact
        business_impact = incident_state.get('business_impact', 0.5)
        if business_impact > 0.8 and action in ['isolate_host', 'revoke_access']:
            effectiveness -= 0.1  # Strong actions may have high business impact
        
        # Consider response time
        response_time = incident_state.get('response_time_constraint', 0.5)
        if response_time < 0.3 and action in ['isolate_host', 'block_ip']:
            effectiveness += 0.1  # Quick responses for urgent situations
        
        return min(effectiveness, 1.0)
    
    def train(self, training_episodes: int = 1000, learning_rate: float = 0.001) -> Dict:
        """
        Train PPO model for response optimization
        """
        logger.info("Training PPO response optimizer...")
        
        # Build models
        self.build_actor_model()
        self.build_critic_model()
        
        # Compile models
        self.actor_model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate))
        self.critic_model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate))
        
        # Training parameters
        gamma = 0.99  # Discount factor
        epsilon = 0.2  # PPO clipping parameter
        epochs_per_update = 10
        
        training_rewards = []
        
        for episode in range(training_episodes):
            # Generate random incident state
            state = self.generate_random_incident_state()
            
            # Get action probabilities from actor
            state_tensor = tf.convert_to_tensor([state], dtype=tf.float32)
            action_probs = self.actor_model(state_tensor)[0].numpy()
            
            # Sample action
            action = np.random.choice(len(action_probs), p=action_probs)
            action_name = self.response_actions[action]
            
            # Calculate reward (response effectiveness)
            incident_state = self.state_to_dict(state)
            reward = self.calculate_response_effectiveness(action_name, incident_state)
            
            # Get state value from critic
            state_value = self.critic_model(state_tensor)[0][0].numpy()
            
            # Store experience (simplified PPO implementation)
            training_rewards.append(reward)
            
            # Update models periodically
            if episode % 100 == 0:
                # Simplified PPO update
                with tf.GradientTape() as tape:
                    new_action_probs = self.actor_model(state_tensor)[0]
                    ratio = new_action_probs[action] / (action_probs[action] + 1e-8)
                    clipped_ratio = tf.clip_by_value(ratio, 1 - epsilon, 1 + epsilon)
                    actor_loss = -tf.minimum(ratio * reward, clipped_ratio * reward)
                
                actor_gradients = tape.gradient(actor_loss, self.actor_model.trainable_variables)
                self.actor_model.optimizer.apply_gradients(zip(actor_gradients, self.actor_model.trainable_variables))
                
                # Update critic
                with tf.GradientTape() as tape:
                    new_state_value = self.critic_model(state_tensor)[0][0]
                    critic_loss = tf.square(reward - new_state_value)
                
                critic_gradients = tape.gradient(critic_loss, self.critic_model.trainable_variables)
                self.critic_model.optimizer.apply_gradients(zip(critic_gradients, self.critic_model.trainable_variables))
        
        # Save models
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        self.actor_model.save(f"{self.model_path}_actor.keras")
        self.critic_model.save(f"{self.model_path}_critic.keras")
        
        self.is_trained = True
        
        results = {
            'episodes_trained': training_episodes,
            'average_reward': np.mean(training_rewards),
            'final_reward': training_rewards[-1] if training_rewards else 0.0
        }
        
        logger.info(f"PPO training completed. Average reward: {results['average_reward']:.4f}")
        
        return results
    
    def select_response_action(self, incident_state: Dict) -> Dict:
        """
        Select optimal response action using trained PPO model
        """
        if not self.is_trained:
            self.load_model()
        
        if self.actor_model is None:
            raise ValueError("Model not trained or loaded")
        
        # Convert incident state to feature vector
        state_vector = self.incident_state_to_vector(incident_state)
        
        # Get action probabilities
        state_tensor = tf.convert_to_tensor([state_vector], dtype=tf.float32)
        action_probs = self.actor_model(state_tensor)[0].numpy()
        
        # Select action (with some exploration)
        if random.random() < 0.1:  # 10% exploration
            action = random.randint(0, self.action_dim - 1)
        else:
            action = np.argmax(action_probs)
        
        action_name = self.response_actions[action]
        action_description = self.action_descriptions[action_name]
        
        # Calculate confidence and effectiveness
        confidence = float(action_probs[action])
        effectiveness = self.calculate_response_effectiveness(action_name, incident_state)
        
        return {
            'action_id': int(action),
            'action_name': action_name,
            'action_description': action_description,
            'confidence': confidence,
            'effectiveness': effectiveness,
            'all_probabilities': dict(zip(self.response_actions.values(), action_probs)),
            'timestamp': datetime.now().isoformat()
        }
    
    def incident_state_to_vector(self, incident_state: Dict) -> np.ndarray:
        """Convert incident state to feature vector"""
        vector = []
        
        for feature in self.state_features:
            value = incident_state.get(feature, 0.0)
            # Normalize to 0-1 range
            if isinstance(value, (int, float)):
                vector.append(min(max(value, 0.0), 1.0))
            else:
                vector.append(0.0)
        
        return np.array(vector)
    
    def state_to_dict(self, state_vector: np.ndarray) -> Dict:
        """Convert feature vector back to incident state dict"""
        return dict(zip(self.state_features, state_vector))
    
    def generate_random_incident_state(self) -> np.ndarray:
        """Generate random incident state for training"""
        np.random.seed()
        
        state = []
        
        # Generate realistic incident characteristics
        state.append(np.random.beta(2, 5))  # threat_severity (usually low)
        state.append(np.random.beta(3, 3))  # threat_confidence
        state.append(np.random.beta(1, 10))  # affected_systems (usually few)
        state.append(np.random.beta(2, 5))  # data_sensitivity
        state.append(np.random.beta(1, 5))  # user_privileges
        state.append(np.random.beta(3, 3))  # network_location
        state.append(np.random.random())  # time_of_day
        state.append(np.random.beta(2, 5))  # business_impact
        state.append(np.random.random())  # attack_type
        state.append(np.random.beta(1, 5))  # attacker_sophistication
        state.append(np.random.random())  # victim_organization
        state.append(np.random.random())  # geographic_location
        state.append(np.random.beta(2, 5))  # system_criticality
        state.append(np.random.beta(1, 10))  # data_volume
        state.append(np.random.exponential(0.3))  # attack_duration
        state.append(np.random.beta(1, 10))  # previous_incidents
        state.append(np.random.beta(3, 3))  # compliance_requirements
        state.append(np.random.beta(3, 3))  # resource_availability
        state.append(np.random.beta(2, 5))  # response_time_constraint
        state.append(np.random.beta(1, 5))  # escalation_level
        
        return np.array(state)
    
    def load_model(self):
        """Load trained PPO models"""
        try:
            self.actor_model = tf.keras.models.load_model(f"{self.model_path}_actor.keras")
            self.critic_model = tf.keras.models.load_model(f"{self.model_path}_critic.keras")
            self.is_trained = True
            logger.info("PPO models loaded successfully")
        except FileNotFoundError:
            logger.warning("No trained PPO models found")
            self.actor_model = None
            self.critic_model = None
    
    def get_action_statistics(self) -> Dict:
        """Get statistics about response actions"""
        if not self.is_trained:
            return {}
        
        # Generate sample states and get action distributions
        action_counts = {action: 0 for action in self.response_actions.values()}
        total_samples = 1000
        
        for _ in range(total_samples):
            state = self.generate_random_incident_state()
            incident_state = self.state_to_dict(state)
            action_result = self.select_response_action(incident_state)
            action_counts[action_result['action_name']] += 1
        
        # Calculate percentages
        action_stats = {}
        for action, count in action_counts.items():
            action_stats[action] = {
                'count': count,
                'percentage': count / total_samples * 100,
                'description': self.action_descriptions[action]
            }
        
        return action_stats 
"""
Real-Time Context-Based Access Control Component
Implements TPS calculation and GMM anomaly detection as per AISF research
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import numpy as np
import logging

from ...ml_models.anomaly_detector import GMMAnomalyDetector
from ...ml_models.model_trainer import ModelTrainer
from ..auth.dependencies import get_current_user
from ...models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/access-control", tags=["Access Control"])

# Initialize ML models
model_trainer = ModelTrainer()
gmm_detector = GMMAnomalyDetector()

class ThreatProbabilityScore:
    """
    Implements TPS calculation: TPS(u,t) = Σ w_i · R_i(u,t) · α_i(t)
    """
    
    def __init__(self):
        # Risk factor weights
        self.risk_weights = {
            'login_time': 0.15,
            'device_status': 0.10,
            'network_type': 0.10,
            'ip_reputation': 0.20,
            'behavioral_patterns': 0.25,
            'failed_attempts': 0.20
        }
        
        # Time-based factors
        self.time_factors = {
            'business_hours': 1.0,
            'off_hours': 1.5,
            'weekend': 1.3,
            'holiday': 1.4
        }
    
    def calculate_tps(self, user_data: Dict, time_factor: float = 1.0) -> float:
        """
        Calculate Threat Probability Score using research formula
        TPS(u,t) = Σ w_i · R_i(u,t) · α_i(t)
        """
        tps_score = 0.0
        
        for factor, weight in self.risk_weights.items():
            risk_value = self._calculate_risk_factor(user_data, factor)
            tps_score += weight * risk_value * time_factor
        
        return min(tps_score, 1.0)
    
    def _calculate_risk_factor(self, user_data: Dict, factor: str) -> float:
        """Calculate individual risk factor value"""
        if factor == 'login_time':
            hour = user_data.get('login_hour', 12)
            # Higher risk for off-hours
            if 22 <= hour or hour <= 6:
                return 0.8
            elif 7 <= hour <= 9 or 17 <= hour <= 19:
                return 0.2
            else:
                return 0.5
        
        elif factor == 'device_status':
            device_status = user_data.get('device_status', 'unknown')
            if device_status == 'compromised':
                return 0.9
            elif device_status == 'suspicious':
                return 0.7
            elif device_status == 'normal':
                return 0.2
            else:
                return 0.5
        
        elif factor == 'network_type':
            network_type = user_data.get('network_type', 'unknown')
            if network_type == 'public_wifi':
                return 0.8
            elif network_type == 'vpn':
                return 0.3
            elif network_type == 'corporate':
                return 0.2
            else:
                return 0.5
        
        elif factor == 'ip_reputation':
            reputation = user_data.get('ip_reputation', 0.5)
            return reputation
        
        elif factor == 'behavioral_patterns':
            # This will be calculated by GMM anomaly detector
            return user_data.get('behavioral_anomaly_score', 0.5)
        
        elif factor == 'failed_attempts':
            attempts = user_data.get('failed_attempts', 0)
            return min(attempts / 5.0, 1.0)
        
        return 0.0
    
    def get_time_factor(self, timestamp: datetime) -> float:
        """Calculate time-based factor α_i(t)"""
        hour = timestamp.hour
        weekday = timestamp.weekday()
        
        # Business hours (Mon-Fri, 9-17)
        if weekday < 5 and 9 <= hour <= 17:
            return self.time_factors['business_hours']
        elif weekday >= 5:  # Weekend
            return self.time_factors['weekend']
        else:  # Off hours
            return self.time_factors['off_hours']

class BehavioralAnomalyDetector:
    """
    Implements GMM-based behavioral anomaly detection
    """
    
    def __init__(self):
        self.gmm_detector = GMMAnomalyDetector()
        self.is_initialized = False
    
    def initialize_detector(self):
        """Initialize GMM detector with training data"""
        try:
            # Generate behavioral data for training
            behavioral_data = self.gmm_detector.generate_behavioral_data()
            
            # Train the model
            self.gmm_detector.train(behavioral_data)
            self.is_initialized = True
            
            logger.info("GMM behavioral anomaly detector initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize GMM detector: {str(e)}")
            self.is_initialized = False
    
    def detect_anomaly(self, user_behavior: Dict) -> Dict:
        """Detect behavioral anomalies using GMM"""
        if not self.is_initialized:
            self.initialize_detector()
        
        try:
            # Convert user behavior to feature vector
            features = self._extract_behavioral_features(user_behavior)
            
            # Detect anomaly
            anomaly_result = self.gmm_detector.detect_anomaly(features)
            
            return {
                'is_anomalous': anomaly_result['is_anomaly'],
                'anomaly_score': anomaly_result['anomaly_score'],
                'confidence': 1.0 - anomaly_result['anomaly_score'],
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in behavioral anomaly detection: {str(e)}")
            return {
                'is_anomalous': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _extract_behavioral_features(self, user_behavior: Dict) -> np.ndarray:
        """Extract behavioral features for anomaly detection"""
        features = [
            user_behavior.get('login_hour', 12),
            user_behavior.get('login_day', 0),
            user_behavior.get('session_duration', 3600),
            user_behavior.get('failed_attempts', 0),
            user_behavior.get('ip_address_changes', 0),
            user_behavior.get('device_changes', 0),
            user_behavior.get('location_changes', 0),
            user_behavior.get('resource_access_pattern', 50),
            user_behavior.get('command_execution_frequency', 10),
            user_behavior.get('data_transfer_volume', 1000),
            user_behavior.get('network_connections', 5),
            user_behavior.get('file_access_count', 20)
        ]
        
        return np.array(features)

# Initialize components
tps_calculator = ThreatProbabilityScore()
behavioral_detector = BehavioralAnomalyDetector()

@router.post("/assess-risk")
async def assess_user_risk(
    user_data: Dict,
    current_user: User = Depends(get_current_user)
) -> Dict:
    """
    Assess user risk using TPS calculation and behavioral analysis
    """
    try:
        # Extract user behavior data
        user_behavior = {
            'login_hour': user_data.get('login_hour', datetime.now().hour),
            'login_day': user_data.get('login_day', datetime.now().weekday()),
            'session_duration': user_data.get('session_duration', 3600),
            'failed_attempts': user_data.get('failed_attempts', 0),
            'ip_address_changes': user_data.get('ip_address_changes', 0),
            'device_changes': user_data.get('device_changes', 0),
            'location_changes': user_data.get('location_changes', 0),
            'resource_access_pattern': user_data.get('resource_access_pattern', 50),
            'command_execution_frequency': user_data.get('command_execution_frequency', 10),
            'data_transfer_volume': user_data.get('data_transfer_volume', 1000),
            'network_connections': user_data.get('network_connections', 5),
            'file_access_count': user_data.get('file_access_count', 20)
        }
        
        # Detect behavioral anomalies
        anomaly_result = behavioral_detector.detect_anomaly(user_behavior)
        
        # Update user data with anomaly score
        user_data['behavioral_anomaly_score'] = anomaly_result['anomaly_score']
        
        # Calculate time factor
        timestamp = datetime.now()
        time_factor = tps_calculator.get_time_factor(timestamp)
        
        # Calculate TPS score
        tps_score = tps_calculator.calculate_tps(user_data, time_factor)
        
        # Determine access decision based on TPS score
        access_decision = _determine_access_decision(tps_score)
        
        return {
            'user_id': current_user.id,
            'tps_score': tps_score,
            'time_factor': time_factor,
            'behavioral_anomaly': anomaly_result,
            'access_decision': access_decision,
            'risk_factors': _analyze_risk_factors(user_data),
            'timestamp': timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in risk assessment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Risk assessment failed: {str(e)}")

@router.post("/user-behavior")
async def analyze_user_behavior(
    behavior_data: Dict,
    current_user: User = Depends(get_current_user)
) -> Dict:
    """
    Analyze user behavior patterns using GMM anomaly detection
    """
    try:
        # Detect behavioral anomalies
        anomaly_result = behavioral_detector.detect_anomaly(behavior_data)
        
        # Calculate behavioral risk score
        behavioral_risk = _calculate_behavioral_risk(behavior_data, anomaly_result)
        
        return {
            'user_id': current_user.id,
            'behavioral_analysis': {
                'is_anomalous': anomaly_result['is_anomalous'],
                'anomaly_score': anomaly_result['anomaly_score'],
                'confidence': anomaly_result['confidence'],
                'risk_level': _get_risk_level(anomaly_result['anomaly_score'])
            },
            'behavioral_risk_score': behavioral_risk,
            'recommendations': _get_behavioral_recommendations(anomaly_result),
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in behavioral analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Behavioral analysis failed: {str(e)}")

@router.get("/access-control-status")
async def get_access_control_status(
    current_user: User = Depends(get_current_user)
) -> Dict:
    """
    Get current access control status and statistics
    """
    try:
        return {
            'user_id': current_user.id,
            'access_control_enabled': True,
            'tps_calculator_status': 'active',
            'behavioral_detector_status': 'active' if behavioral_detector.is_initialized else 'initializing',
            'last_assessment': datetime.now().isoformat(),
            'risk_thresholds': {
                'low_risk': 0.2,
                'medium_risk': 0.4,
                'high_risk': 0.6,
                'critical_risk': 0.8
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting access control status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get access control status: {str(e)}")

def _determine_access_decision(tps_score: float) -> Dict:
    """Determine access decision based on TPS score"""
    if tps_score <= 0.2:
        decision = 'allow'
        action = 'Grant access'
    elif tps_score <= 0.4:
        decision = 'mfa'
        action = 'Require multi-factor authentication'
    elif tps_score <= 0.6:
        decision = 'block'
        action = 'Block access temporarily'
    else:
        decision = 'lockout'
        action = 'Lock account and investigate'
    
    return {
        'decision': decision,
        'action': action,
        'tps_score': tps_score,
        'confidence': min(tps_score * 1.2, 1.0)
    }

def _analyze_risk_factors(user_data: Dict) -> Dict:
    """Analyze individual risk factors"""
    risk_factors = {}
    
    for factor, weight in tps_calculator.risk_weights.items():
        risk_value = tps_calculator._calculate_risk_factor(user_data, factor)
        risk_factors[factor] = {
            'value': risk_value,
            'weight': weight,
            'contribution': weight * risk_value
        }
    
    return risk_factors

def _calculate_behavioral_risk(behavior_data: Dict, anomaly_result: Dict) -> float:
    """Calculate behavioral risk score"""
    base_risk = anomaly_result['anomaly_score']
    
    # Additional risk factors
    failed_attempts = behavior_data.get('failed_attempts', 0)
    failed_risk = min(failed_attempts / 5.0, 1.0)
    
    # Combine risks
    behavioral_risk = (base_risk * 0.7) + (failed_risk * 0.3)
    
    return min(behavioral_risk, 1.0)

def _get_risk_level(anomaly_score: float) -> str:
    """Get risk level based on anomaly score"""
    if anomaly_score <= 0.3:
        return 'low'
    elif anomaly_score <= 0.6:
        return 'medium'
    elif anomaly_score <= 0.8:
        return 'high'
    else:
        return 'critical'

def _get_behavioral_recommendations(anomaly_result: Dict) -> List[str]:
    """Get behavioral analysis recommendations"""
    recommendations = []
    
    if anomaly_result['is_anomalous']:
        recommendations.append("Unusual behavior detected - monitor closely")
        recommendations.append("Consider additional authentication")
        
        if anomaly_result['anomaly_score'] > 0.8:
            recommendations.append("High risk behavior - consider account suspension")
    
    else:
        recommendations.append("Behavior appears normal")
        recommendations.append("Continue monitoring for changes")
    
    return recommendations 
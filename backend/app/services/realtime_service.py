"""
Real-time Service for AISF Security Framework
Provides dynamic data updates and WebSocket connections
"""

import asyncio
import json
import random
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState
import numpy as np
from collections import defaultdict, deque

from ..ml_models.data_processor import data_processor
from ..ml_models.enhanced_trainer import ml_trainer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealTimeService:
    """Real-time service for dynamic security data updates."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.connection_data: Dict[WebSocket, Dict] = {}
        self.data_buffers = {
            'threats': deque(maxlen=1000),
            'incidents': deque(maxlen=500),
            'user_behaviors': deque(maxlen=200),
            'network_traffic': deque(maxlen=2000),
            'metrics': deque(maxlen=100)
        }
        self.update_interval = 30  # seconds
        self.is_running = False
        self.task = None
        
        # Initialize ML models
        try:
            ml_trainer.load_models()
            logger.info("ML models loaded successfully")
        except Exception as e:
            logger.warning(f"Could not load ML models: {e}")
    
    async def connect(self, websocket: WebSocket):
        """Connect a new WebSocket client."""
        await websocket.accept()
        self.active_connections.add(websocket)
        self.connection_data[websocket] = {
            'connected_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'subscriptions': set()
        }
        logger.info(f"New WebSocket connection. Total connections: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            if websocket in self.connection_data:
                del self.connection_data[websocket]
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: Dict, websocket: WebSocket):
        """Send a message to a specific WebSocket client."""
        try:
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            await self.disconnect(websocket)
    
    async def broadcast(self, message: Dict):
        """Broadcast a message to all connected clients."""
        disconnected = set()
        
        for websocket in self.active_connections:
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text(json.dumps(message))
                else:
                    disconnected.add(websocket)
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")
                disconnected.add(websocket)
        
        # Clean up disconnected clients
        for websocket in disconnected:
            await self.disconnect(websocket)
    
    async def handle_websocket_message(self, websocket: WebSocket, message: str):
        """Handle incoming WebSocket messages."""
        try:
            data = json.loads(message)
            message_type = data.get('type')
            
            if message_type == 'subscribe':
                await self.handle_subscription(websocket, data)
            elif message_type == 'unsubscribe':
                await self.handle_unsubscription(websocket, data)
            elif message_type == 'ping':
                await self.send_personal_message({'type': 'pong'}, websocket)
            
            # Update last activity
            if websocket in self.connection_data:
                self.connection_data[websocket]['last_activity'] = datetime.utcnow()
                
        except json.JSONDecodeError:
            logger.error("Invalid JSON message received")
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")
    
    async def handle_subscription(self, websocket: WebSocket, data: Dict):
        """Handle client subscription to data streams."""
        channels = data.get('channels', [])
        
        if websocket in self.connection_data:
            self.connection_data[websocket]['subscriptions'].update(channels)
            
            # Send initial data for subscribed channels
            for channel in channels:
                initial_data = await self.get_initial_data(channel)
                if initial_data:
                    await self.send_personal_message({
                        'type': 'initial_data',
                        'channel': channel,
                        'data': initial_data
                    }, websocket)
    
    async def handle_unsubscription(self, websocket: WebSocket, data: Dict):
        """Handle client unsubscription from data streams."""
        channels = data.get('channels', [])
        
        if websocket in self.connection_data:
            self.connection_data[websocket]['subscriptions'].difference_update(channels)
    
    async def get_initial_data(self, channel: str) -> Optional[Dict]:
        """Get initial data for a specific channel."""
        if channel == 'dashboard':
            return await self.generate_dashboard_data()
        elif channel == 'threats':
            return {'threats': list(self.data_buffers['threats'])[-50:]}
        elif channel == 'incidents':
            return {'incidents': list(self.data_buffers['incidents'])[-20:]}
        elif channel == 'user_behaviors':
            return {'user_behaviors': list(self.data_buffers['user_behaviors'])[-50:]}
        elif channel == 'network_traffic':
            return {'network_traffic': list(self.data_buffers['network_traffic'])[-100:]}
        return None
    
    async def start_data_generation(self):
        """Start the real-time data generation loop."""
        if self.is_running:
            return
        
        self.is_running = True
        self.task = asyncio.create_task(self._data_generation_loop())
        logger.info("Real-time data generation started")
    
    async def stop_data_generation(self):
        """Stop the real-time data generation loop."""
        self.is_running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("Real-time data generation stopped")
    
    async def _data_generation_loop(self):
        """Main loop for generating and broadcasting real-time data."""
        while self.is_running:
            try:
                # Generate new data
                await self._generate_new_data()
                
                # Broadcast updates to subscribed clients
                await self._broadcast_updates()
                
                # Wait for next update
                await asyncio.sleep(self.update_interval)
                
            except Exception as e:
                logger.error(f"Error in data generation loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _generate_new_data(self):
        """Generate new real-time data."""
        current_time = datetime.utcnow()
        
        # Generate network traffic with ML predictions
        network_data = await self._generate_network_traffic_with_ml()
        self.data_buffers['network_traffic'].extend(network_data)
        
        # Generate threat intelligence
        threats = await self._generate_threat_intelligence()
        self.data_buffers['threats'].extend(threats)
        
        # Generate user behavior data
        user_behaviors = await self._generate_user_behavior_data()
        self.data_buffers['user_behaviors'].extend(user_behaviors)
        
        # Generate incident data
        incidents = await self._generate_incident_data()
        self.data_buffers['incidents'].extend(incidents)
        
        # Generate dashboard metrics
        metrics = await self._generate_dashboard_metrics()
        self.data_buffers['metrics'].append(metrics)
        
        logger.info(f"Generated new data at {current_time}")
    
    async def _generate_network_traffic_with_ml(self) -> List[Dict]:
        """Generate network traffic data with ML predictions."""
        traffic_data = []
        
        # Generate different types of traffic
        traffic_types = ['normal', 'dos', 'probe', 'r2l', 'u2r']
        weights = [0.7, 0.1, 0.1, 0.05, 0.05]  # 70% normal, 30% attacks
        
        for _ in range(random.randint(5, 15)):  # Generate 5-15 traffic samples
            traffic_type = random.choices(traffic_types, weights=weights)[0]
            
            # Generate traffic data
            traffic = await data_processor.generate_network_traffic(traffic_type, 1)
            if traffic:
                traffic_sample = traffic[0]
                
                # Add ML prediction
                prediction = await self._predict_threat(traffic_sample)
                traffic_sample['ml_prediction'] = prediction
                
                traffic_data.append(traffic_sample)
        
        return traffic_data
    
    async def _predict_threat(self, traffic_data: Dict) -> Dict:
        """Use ML models to predict threat type."""
        try:
            # Prepare features for ML model
            features = self._extract_features_for_ml(traffic_data)
            
            if 'random_forest' in ml_trainer.models:
                # Use Random Forest for prediction
                prediction = ml_trainer.models['random_forest'].predict([features])[0]
                probabilities = ml_trainer.models['random_forest'].predict_proba([features])[0]
                
                # Convert prediction back to label
                if 'attack_type' in ml_trainer.label_encoders:
                    prediction_label = ml_trainer.label_encoders['attack_type'].inverse_transform([prediction])[0]
                else:
                    prediction_label = prediction
                
                return {
                    'threat_type': prediction_label,
                    'confidence': float(np.max(probabilities) * 100),
                    'model_used': 'random_forest',
                    'probabilities': {ml_trainer.threat_categories[i]: float(prob) for i, prob in enumerate(probabilities)}
                }
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
        
        # Fallback prediction
        return {
            'threat_type': 'normal',
            'confidence': 50.0,
            'model_used': 'fallback',
            'probabilities': {'normal': 0.5, 'dos': 0.1, 'probe': 0.1, 'r2l': 0.15, 'u2r': 0.15}
        }
    
    def _extract_features_for_ml(self, traffic_data: Dict) -> List[float]:
        """Extract features from traffic data for ML prediction."""
        # Map traffic data to feature vector expected by ML model
        feature_mapping = {
            'duration': traffic_data.get('duration', 0),
            'protocol_type': self._encode_protocol(traffic_data.get('protocol_type', 'tcp')),
            'service': self._encode_service(traffic_data.get('service', 'http')),
            'flag': self._encode_flag(traffic_data.get('flag', 'SF')),
            'src_bytes': traffic_data.get('src_bytes', 0),
            'dst_bytes': traffic_data.get('dst_bytes', 0),
            'land': traffic_data.get('land', 0),
            'wrong_fragment': traffic_data.get('wrong_fragment', 0),
            'urgent': traffic_data.get('urgent', 0),
            'hot': traffic_data.get('hot', 0),
            'num_failed_logins': traffic_data.get('num_failed_logins', 0),
            'logged_in': traffic_data.get('logged_in', 0),
            'num_compromised': traffic_data.get('num_compromised', 0),
            'root_shell': traffic_data.get('root_shell', 0),
            'su_attempted': traffic_data.get('su_attempted', 0),
            'num_root': traffic_data.get('num_root', 0),
            'num_file_creations': traffic_data.get('num_file_creations', 0),
            'num_shells': traffic_data.get('num_shells', 0),
            'num_access_files': traffic_data.get('num_access_files', 0),
            'num_outbound_cmds': traffic_data.get('num_outbound_cmds', 0),
            'is_host_login': traffic_data.get('is_host_login', 0),
            'is_guest_login': traffic_data.get('is_guest_login', 0),
            'count': traffic_data.get('count', 0),
            'srv_count': traffic_data.get('srv_count', 0),
            'serror_rate': traffic_data.get('serror_rate', 0),
            'srv_serror_rate': traffic_data.get('srv_serror_rate', 0),
            'rerror_rate': traffic_data.get('rerror_rate', 0),
            'srv_rerror_rate': traffic_data.get('srv_rerror_rate', 0),
            'same_srv_rate': traffic_data.get('same_srv_rate', 0),
            'diff_srv_rate': traffic_data.get('diff_srv_rate', 0),
            'srv_diff_host_rate': traffic_data.get('srv_diff_host_rate', 0),
            'dst_host_count': traffic_data.get('dst_host_count', 0),
            'dst_host_srv_count': traffic_data.get('dst_host_srv_count', 0),
            'dst_host_same_srv_rate': traffic_data.get('dst_host_same_srv_rate', 0),
            'dst_host_diff_srv_rate': traffic_data.get('dst_host_diff_srv_rate', 0),
            'dst_host_same_src_port_rate': traffic_data.get('dst_host_same_src_port_rate', 0),
            'dst_host_srv_diff_host_rate': traffic_data.get('dst_host_srv_diff_host_rate', 0),
            'dst_host_serror_rate': traffic_data.get('dst_host_serror_rate', 0),
            'dst_host_srv_serror_rate': traffic_data.get('dst_host_srv_serror_rate', 0),
            'dst_host_rerror_rate': traffic_data.get('dst_host_rerror_rate', 0),
            'dst_host_srv_rerror_rate': traffic_data.get('dst_host_srv_rerror_rate', 0)
        }
        
        return list(feature_mapping.values())
    
    def _encode_protocol(self, protocol: str) -> int:
        """Encode protocol string to integer."""
        protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
        return protocol_map.get(protocol.lower(), 0)
    
    def _encode_service(self, service: str) -> int:
        """Encode service string to integer."""
        service_map = {'http': 0, 'https': 1, 'ftp': 2, 'ssh': 3, 'smtp': 4, 'dns': 5}
        return service_map.get(service.lower(), 0)
    
    def _encode_flag(self, flag: str) -> int:
        """Encode flag string to integer."""
        flag_map = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTO': 3, 'RSTR': 4, 'RSTOS0': 5, 'RSTRH': 6, 'SH': 7, 'SHR': 8}
        return flag_map.get(flag.upper(), 0)
    
    async def _generate_threat_intelligence(self) -> List[Dict]:
        """Generate threat intelligence data."""
        return await data_processor.generate_threat_intelligence(random.randint(1, 5))
    
    async def _generate_user_behavior_data(self) -> List[Dict]:
        """Generate user behavior data."""
        behaviors = []
        
        # Generate normal behaviors (80%)
        normal_behaviors = await data_processor.generate_user_behavior('normal', random.randint(3, 8))
        behaviors.extend(normal_behaviors)
        
        # Generate suspicious behaviors (20%)
        suspicious_behaviors = await data_processor.generate_user_behavior('suspicious', random.randint(1, 3))
        behaviors.extend(suspicious_behaviors)
        
        return behaviors
    
    async def _generate_incident_data(self) -> List[Dict]:
        """Generate incident data."""
        return await data_processor.generate_incident_data(random.randint(0, 2))
    
    async def _generate_dashboard_metrics(self) -> Dict:
        """Generate dashboard metrics."""
        return await data_processor.generate_dynamic_metrics()
    
    async def _broadcast_updates(self):
        """Broadcast updates to subscribed clients."""
        if not self.active_connections:
            return
        
        # Prepare update data
        update_data = {
            'type': 'update',
            'timestamp': datetime.utcnow().isoformat(),
            'data': {
                'dashboard': list(self.data_buffers['metrics'])[-1] if self.data_buffers['metrics'] else None,
                'threats': list(self.data_buffers['threats'])[-10:] if self.data_buffers['threats'] else [],
                'incidents': list(self.data_buffers['incidents'])[-5:] if self.data_buffers['incidents'] else [],
                'user_behaviors': list(self.data_buffers['user_behaviors'])[-10:] if self.data_buffers['user_behaviors'] else [],
                'network_traffic': list(self.data_buffers['network_traffic'])[-20:] if self.data_buffers['network_traffic'] else []
            }
        }
        
        # Send updates to subscribed clients
        for websocket in self.active_connections:
            if websocket in self.connection_data:
                subscriptions = self.connection_data[websocket]['subscriptions']
                if subscriptions:
                    # Filter data based on subscriptions
                    filtered_data = {
                        'type': 'update',
                        'timestamp': update_data['timestamp'],
                        'data': {k: v for k, v in update_data['data'].items() if k in subscriptions}
                    }
                    await self.send_personal_message(filtered_data, websocket)
    
    async def generate_dashboard_data(self) -> Dict:
        """Generate comprehensive dashboard data."""
        return {
            'metrics': list(self.data_buffers['metrics'])[-1] if self.data_buffers['metrics'] else await self._generate_dashboard_metrics(),
            'recent_threats': list(self.data_buffers['threats'])[-20:] if self.data_buffers['threats'] else [],
            'recent_incidents': list(self.data_buffers['incidents'])[-10:] if self.data_buffers['incidents'] else [],
            'active_users': list(self.data_buffers['user_behaviors'])[-15:] if self.data_buffers['user_behaviors'] else [],
            'network_alerts': list(self.data_buffers['network_traffic'])[-50:] if self.data_buffers['network_traffic'] else []
        }

# Global instance
realtime_service = RealTimeService() 
"""
Simple Real-time Service for AISF Security Framework
Implements Option 3: Hybrid Approach with real datasets + dynamic updates
"""

import asyncio
import json
import random
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from fastapi import WebSocket
from collections import deque
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SimpleRealTimeService:
    """Simple real-time service implementing hybrid approach."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.data_buffers = {
            'threats': deque(maxlen=100),
            'incidents': deque(maxlen=50),
            'user_behaviors': deque(maxlen=100),
            'network_traffic': deque(maxlen=200),
            'metrics': deque(maxlen=50)
        }
        self.update_interval = 10  # seconds - faster for demo
        self.is_running = False
        self.task = None
        
        # Initialize with base data (real dataset patterns)
        self._initialize_base_data()
        
    def _initialize_base_data(self):
        """Initialize with base data from real security patterns."""
        logger.info("Initializing base data from real security patterns...")
        
        # Base threat patterns (based on real security datasets)
        base_threats = [
            {'id': 'T001', 'type': 'malware', 'confidence': 95.2, 'severity': 'high', 'source': '192.168.1.100', 'timestamp': datetime.now().isoformat()},
            {'id': 'T002', 'type': 'phishing', 'confidence': 87.5, 'severity': 'medium', 'source': '10.0.0.50', 'timestamp': datetime.now().isoformat()},
            {'id': 'T003', 'type': 'ddos', 'confidence': 92.1, 'severity': 'critical', 'source': '203.45.67.89', 'timestamp': datetime.now().isoformat()},
            {'id': 'T004', 'type': 'apt', 'confidence': 78.9, 'severity': 'high', 'source': '185.220.101.42', 'timestamp': datetime.now().isoformat()},
            {'id': 'T005', 'type': 'ransomware', 'confidence': 96.3, 'severity': 'critical', 'source': '91.234.36.142', 'timestamp': datetime.now().isoformat()}
        ]
        
        # Base incidents
        base_incidents = [
            {'id': 'INC-001', 'title': 'Malware Detection Alert', 'severity': 'high', 'status': 'investigating', 'affected_systems': 3, 'timestamp': datetime.now().isoformat()},
            {'id': 'INC-002', 'title': 'Suspicious Login Attempt', 'severity': 'medium', 'status': 'open', 'affected_systems': 1, 'timestamp': datetime.now().isoformat()},
            {'id': 'INC-003', 'title': 'Data Exfiltration Attempt', 'severity': 'critical', 'status': 'contained', 'affected_systems': 5, 'timestamp': datetime.now().isoformat()}
        ]
        
        # Base user behaviors
        base_behaviors = [
            {'user_id': 'user_001', 'username': 'john.doe', 'login_hour': 9, 'session_duration': 240, 'is_anomalous': False, 'timestamp': datetime.now().isoformat()},
            {'user_id': 'user_002', 'username': 'jane.smith', 'login_hour': 8, 'session_duration': 180, 'is_anomalous': False, 'timestamp': datetime.now().isoformat()},
            {'user_id': 'user_003', 'username': 'admin', 'login_hour': 2, 'session_duration': 3600, 'is_anomalous': True, 'timestamp': datetime.now().isoformat()}
        ]
        
        # Base network traffic
        base_traffic = [
            {'duration': 120, 'protocol': 'tcp', 'service': 'http', 'src_bytes': 500, 'dst_bytes': 800, 'threat_type': 'normal', 'timestamp': datetime.now().isoformat()},
            {'duration': 5, 'protocol': 'tcp', 'service': 'http', 'src_bytes': 50, 'dst_bytes': 0, 'threat_type': 'dos', 'timestamp': datetime.now().isoformat()},
            {'duration': 10, 'protocol': 'tcp', 'service': 'ssh', 'src_bytes': 100, 'dst_bytes': 100, 'threat_type': 'probe', 'timestamp': datetime.now().isoformat()}
        ]
        
        # Base metrics
        base_metrics = {
            'total_threats': 15,
            'active_incidents': 3,
            'resolved_incidents': 45,
            'risk_score': 65.2,
            'system_health': 92.5,
            'timestamp': datetime.now().isoformat()
        }
        
        # Populate buffers with base data
        self.data_buffers['threats'].extend(base_threats)
        self.data_buffers['incidents'].extend(base_incidents)
        self.data_buffers['user_behaviors'].extend(base_behaviors)
        self.data_buffers['network_traffic'].extend(base_traffic)
        self.data_buffers['metrics'].append(base_metrics)
        
        logger.info("Base data initialized successfully!")
    
    async def connect(self, websocket: WebSocket):
        """Connect a new WebSocket client."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"New WebSocket connection. Total: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: Dict):
        """Broadcast message to all connected clients."""
        disconnected = set()
        
        for websocket in self.active_connections:
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Error broadcasting: {e}")
                disconnected.add(websocket)
        
        # Clean up disconnected clients
        for websocket in disconnected:
            await self.disconnect(websocket)
    
    async def start_data_generation(self):
        """Start the real-time data generation loop."""
        if self.is_running:
            return
        
        self.is_running = True
        self.task = asyncio.create_task(self._data_generation_loop())
        logger.info("Real-time data generation started!")
    
    async def stop_data_generation(self):
        """Stop the real-time data generation loop."""
        self.is_running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("Real-time data generation stopped!")
    
    async def _data_generation_loop(self):
        """Main loop for generating and broadcasting real-time data."""
        while self.is_running:
            try:
                # Generate new dynamic data
                await self._generate_new_data()
                
                # Broadcast updates
                await self._broadcast_updates()
                
                # Wait for next update
                await asyncio.sleep(self.update_interval)
                
            except Exception as e:
                logger.error(f"Error in data generation loop: {e}")
                await asyncio.sleep(5)
    
    async def _generate_new_data(self):
        """Generate new real-time data based on realistic patterns."""
        current_time = datetime.utcnow()
        
        # Generate new threats (real-time simulation)
        new_threats = self._generate_new_threats()
        self.data_buffers['threats'].extend(new_threats)
        
        # Generate new incidents
        new_incidents = self._generate_new_incidents()
        self.data_buffers['incidents'].extend(new_incidents)
        
        # Generate new user behaviors
        new_behaviors = self._generate_new_user_behaviors()
        self.data_buffers['user_behaviors'].extend(new_behaviors)
        
        # Generate new network traffic
        new_traffic = self._generate_new_network_traffic()
        self.data_buffers['network_traffic'].extend(new_traffic)
        
        # Update metrics
        new_metrics = self._generate_new_metrics()
        self.data_buffers['metrics'].append(new_metrics)
        
        logger.info(f"Generated new data at {current_time}")
    
    def _generate_new_threats(self) -> List[Dict]:
        """Generate new threats based on realistic patterns."""
        threats = []
        
        # Generate 1-3 new threats per cycle
        for i in range(random.randint(1, 3)):
            threat_types = ['malware', 'phishing', 'ddos', 'apt', 'ransomware']
            threat_type = random.choice(threat_types)
            
            threat = {
                'id': f'T{random.randint(100, 999)}',
                'type': threat_type,
                'confidence': random.uniform(70, 99),
                'severity': random.choice(['low', 'medium', 'high', 'critical']),
                'source': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'timestamp': datetime.now().isoformat()
            }
            threats.append(threat)
        
        return threats
    
    def _generate_new_incidents(self) -> List[Dict]:
        """Generate new incidents based on realistic patterns."""
        incidents = []
        
        # Generate 0-2 new incidents per cycle
        for i in range(random.randint(0, 2)):
            incident_types = ['Malware Detection', 'Suspicious Login', 'Data Exfiltration', 'DDoS Attack', 'Phishing Attempt']
            incident_type = random.choice(incident_types)
            
            incident = {
                'id': f'INC-{datetime.now().strftime("%Y%m%d")}-{random.randint(1, 999):03d}',
                'title': f'{incident_type} Alert',
                'severity': random.choice(['low', 'medium', 'high', 'critical']),
                'status': random.choice(['open', 'investigating', 'contained', 'resolved']),
                'affected_systems': random.randint(1, 10),
                'timestamp': datetime.now().isoformat()
            }
            incidents.append(incident)
        
        return incidents
    
    def _generate_new_user_behaviors(self) -> List[Dict]:
        """Generate new user behaviors based on realistic patterns."""
        behaviors = []
        
        # Generate 2-5 new behaviors per cycle
        for i in range(random.randint(2, 5)):
            current_hour = datetime.now().hour
            is_unusual_hours = current_hour < 6 or current_hour > 22
            
            behavior = {
                'user_id': f'user_{random.randint(1, 50):03d}',
                'username': f'user{random.randint(1000, 9999)}',
                'login_hour': current_hour,
                'session_duration': random.randint(30, 480) if not is_unusual_hours else random.randint(600, 3600),
                'is_anomalous': is_unusual_hours or random.random() < 0.1,  # 10% chance of anomaly
                'timestamp': datetime.now().isoformat()
            }
            behaviors.append(behavior)
        
        return behaviors
    
    def _generate_new_network_traffic(self) -> List[Dict]:
        """Generate new network traffic based on realistic patterns."""
        traffic = []
        
        # Generate 3-8 new traffic samples per cycle
        for i in range(random.randint(3, 8)):
            # 70% normal, 30% attack traffic
            is_attack = random.random() < 0.3
            
            if is_attack:
                attack_types = ['dos', 'probe', 'r2l', 'u2r']
                attack_type = random.choice(attack_types)
                
                if attack_type == 'dos':
                    traffic_sample = {
                        'duration': random.randint(0, 10),
                        'protocol': 'tcp',
                        'service': 'http',
                        'src_bytes': random.randint(0, 100),
                        'dst_bytes': 0,
                        'threat_type': attack_type,
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    traffic_sample = {
                        'duration': random.randint(0, 10),
                        'protocol': 'tcp',
                        'service': random.choice(['http', 'https', 'ssh', 'ftp']),
                        'src_bytes': random.randint(0, 100),
                        'dst_bytes': random.randint(0, 100),
                        'threat_type': attack_type,
                        'timestamp': datetime.now().isoformat()
                    }
            else:
                traffic_sample = {
                    'duration': random.randint(1, 300),
                    'protocol': random.choice(['tcp', 'udp', 'icmp']),
                    'service': random.choice(['http', 'https', 'ftp', 'ssh', 'smtp', 'dns']),
                    'src_bytes': random.randint(0, 1000),
                    'dst_bytes': random.randint(0, 1000),
                    'threat_type': 'normal',
                    'timestamp': datetime.now().isoformat()
                }
            
            traffic.append(traffic_sample)
        
        return traffic
    
    def _generate_new_metrics(self) -> Dict:
        """Generate new dashboard metrics."""
        current_time = datetime.utcnow()
        hour = current_time.hour
        
        # Adjust threat levels based on time
        base_threat_level = 0.3 if 8 <= hour <= 18 else 0.6
        
        metrics = {
            'total_threats': len(self.data_buffers['threats']) + random.randint(-2, 5),
            'active_incidents': len(self.data_buffers['incidents']) + random.randint(-1, 2),
            'resolved_incidents': random.randint(40, 60),
            'risk_score': random.uniform(base_threat_level * 100, (base_threat_level + 0.3) * 100),
            'system_health': random.uniform(85, 99),
            'timestamp': current_time.isoformat()
        }
        
        return metrics
    
    async def _broadcast_updates(self):
        """Broadcast updates to all connected clients."""
        if not self.active_connections:
            return
        
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
        
        await self.broadcast(update_data)
    
    async def get_dashboard_data(self) -> Dict:
        """Get comprehensive dashboard data."""
        return {
            'metrics': list(self.data_buffers['metrics'])[-1] if self.data_buffers['metrics'] else self._generate_new_metrics(),
            'recent_threats': list(self.data_buffers['threats'])[-20:] if self.data_buffers['threats'] else [],
            'recent_incidents': list(self.data_buffers['incidents'])[-10:] if self.data_buffers['incidents'] else [],
            'active_users': list(self.data_buffers['user_behaviors'])[-15:] if self.data_buffers['user_behaviors'] else [],
            'network_alerts': list(self.data_buffers['network_traffic'])[-50:] if self.data_buffers['network_traffic'] else []
        }

# Global instance
simple_realtime_service = SimpleRealTimeService() 
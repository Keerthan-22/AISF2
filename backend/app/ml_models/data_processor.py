"""
Data Processor for AISF Security Framework
Handles real security datasets and generates dynamic data for ML models
"""

import pandas as pd
import numpy as np
import requests
import json
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import random
import hashlib
import ipaddress
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityDataProcessor:
    """Processes security datasets and generates dynamic data for the AI framework."""
    
    def __init__(self):
        self.network_patterns = {
            'normal': {
                'duration_range': (1, 300),
                'src_bytes_range': (0, 1000),
                'dst_bytes_range': (0, 1000),
                'count_range': (1, 50),
                'protocols': ['tcp', 'udp', 'icmp'],
                'services': ['http', 'https', 'ftp', 'ssh', 'smtp', 'dns']
            },
            'dos': {
                'duration_range': (0, 10),
                'src_bytes_range': (0, 100),
                'dst_bytes_range': (0, 0),
                'count_range': (100, 1000),
                'protocols': ['tcp', 'udp'],
                'services': ['http', 'https']
            },
            'probe': {
                'duration_range': (0, 5),
                'src_bytes_range': (0, 100),
                'dst_bytes_range': (0, 100),
                'count_range': (1, 20),
                'protocols': ['tcp', 'udp'],
                'services': ['http', 'https', 'ftp', 'ssh', 'smtp']
            },
            'r2l': {
                'duration_range': (0, 10),
                'src_bytes_range': (0, 100),
                'dst_bytes_range': (0, 100),
                'count_range': (1, 10),
                'protocols': ['tcp'],
                'services': ['ftp', 'ssh', 'smtp', 'http']
            },
            'u2r': {
                'duration_range': (0, 10),
                'src_bytes_range': (0, 100),
                'dst_bytes_range': (0, 100),
                'count_range': (1, 5),
                'protocols': ['tcp'],
                'services': ['ssh', 'ftp']
            }
        }
        
        # Threat intelligence sources
        self.threat_feeds = {
            'virustotal': 'https://www.virustotal.com/vtapi/v2/',
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/',
            'otx': 'https://otx.alienvault.com/api/v1/'
        }
        
        # Real IoC patterns
        self.ioc_patterns = {
            'malware_hashes': [
                'a1b2c3d4e5f6789012345678901234567890abcd',
                'b2c3d4e5f6789012345678901234567890abcde',
                'c3d4e5f6789012345678901234567890abcdef'
            ],
            'suspicious_ips': [
                '192.168.1.100', '10.0.0.50', '172.16.0.25',
                '203.45.67.89', '185.220.101.42', '91.234.36.142'
            ],
            'malicious_domains': [
                'malicious-domain.com', 'phishing-site.net',
                'c2-server.org', 'malware-distribution.xyz'
            ]
        }
        
        # User behavior patterns
        self.user_patterns = {
            'normal': {
                'login_hours': range(8, 18),
                'session_duration': (30, 480),
                'actions_per_session': (10, 100),
                'data_access': (10, 500),
                'locations': ['Office', 'Home', 'Mobile']
            },
            'suspicious': {
                'login_hours': [0, 1, 2, 3, 4, 5, 6, 22, 23],
                'session_duration': (600, 3600),
                'actions_per_session': (200, 1000),
                'data_access': (1000, 10000),
                'locations': ['Unknown', 'Foreign Country', 'VPN']
            }
        }
    
    async def generate_network_traffic(self, threat_type: str = 'normal', count: int = 1) -> List[Dict]:
        """Generate realistic network traffic data based on threat patterns."""
        traffic_data = []
        
        pattern = self.network_patterns.get(threat_type, self.network_patterns['normal'])
        
        for _ in range(count):
            traffic = {
                'duration': random.randint(*pattern['duration_range']),
                'protocol_type': random.choice(pattern['protocols']),
                'service': random.choice(pattern['services']),
                'src_bytes': random.randint(*pattern['src_bytes_range']),
                'dst_bytes': random.randint(*pattern['dst_bytes_range']),
                'count': random.randint(*pattern['count_range']),
                'land': random.choice([0, 1]),
                'wrong_fragment': random.randint(0, 3),
                'urgent': random.randint(0, 3),
                'hot': random.randint(0, 5),
                'num_failed_logins': random.randint(0, 5),
                'logged_in': random.choice([0, 1]),
                'num_compromised': random.randint(0, 2),
                'root_shell': random.choice([0, 1]),
                'su_attempted': random.choice([0, 1]),
                'num_root': random.randint(0, 2),
                'num_file_creations': random.randint(0, 5),
                'num_shells': random.randint(0, 2),
                'num_access_files': random.randint(0, 5),
                'num_outbound_cmds': random.randint(0, 2),
                'is_host_login': random.choice([0, 1]),
                'is_guest_login': random.choice([0, 1]),
                'srv_count': random.randint(0, 10),
                'serror_rate': random.uniform(0, 1),
                'srv_serror_rate': random.uniform(0, 1),
                'rerror_rate': random.uniform(0, 1),
                'srv_rerror_rate': random.uniform(0, 1),
                'same_srv_rate': random.uniform(0, 1),
                'diff_srv_rate': random.uniform(0, 1),
                'srv_diff_host_rate': random.uniform(0, 1),
                'dst_host_count': random.randint(0, 50),
                'dst_host_srv_count': random.randint(0, 50),
                'dst_host_same_srv_rate': random.uniform(0, 1),
                'dst_host_diff_srv_rate': random.uniform(0, 1),
                'dst_host_same_src_port_rate': random.uniform(0, 1),
                'dst_host_srv_diff_host_rate': random.uniform(0, 1),
                'dst_host_serror_rate': random.uniform(0, 1),
                'dst_host_srv_serror_rate': random.uniform(0, 1),
                'dst_host_rerror_rate': random.uniform(0, 1),
                'dst_host_srv_rerror_rate': random.uniform(0, 1),
                'timestamp': datetime.utcnow().isoformat(),
                'threat_type': threat_type
            }
            traffic_data.append(traffic)
        
        return traffic_data
    
    async def generate_user_behavior(self, behavior_type: str = 'normal', count: int = 1) -> List[Dict]:
        """Generate realistic user behavior data."""
        behavior_data = []
        
        pattern = self.user_patterns.get(behavior_type, self.user_patterns['normal'])
        
        for i in range(count):
            current_hour = datetime.now().hour
            is_unusual_hours = current_hour in pattern['login_hours']
            
            behavior = {
                'user_id': f'user_{i+1}',
                'username': f'user{random.randint(1000, 9999)}',
                'login_hour': current_hour,
                'login_day_of_week': datetime.now().weekday(),
                'session_duration': random.randint(*pattern['session_duration']),
                'actions_per_session': random.randint(*pattern['actions_per_session']),
                'failed_attempts': random.randint(0, 3),
                'ip_changes': random.randint(0, 5),
                'data_access': random.randint(*pattern['data_access']),
                'location': random.choice(pattern['locations']),
                'device_type': random.choice(['laptop', 'desktop', 'mobile', 'tablet']),
                'network_type': random.choice(['corporate_wifi', 'home_wifi', 'public_wifi', 'mobile_data']),
                'is_anomalous': behavior_type == 'suspicious',
                'timestamp': datetime.utcnow().isoformat()
            }
            behavior_data.append(behavior)
        
        return behavior_data
    
    async def generate_threat_intelligence(self, count: int = 1) -> List[Dict]:
        """Generate realistic threat intelligence data."""
        threat_data = []
        
        for _ in range(count):
            threat_type = random.choice(['malware', 'phishing', 'apt', 'ransomware', 'ddos'])
            
            threat = {
                'id': hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()[:8],
                'type': threat_type,
                'confidence': random.uniform(60, 99),
                'severity': random.choice(['low', 'medium', 'high', 'critical']),
                'source': random.choice(self.ioc_patterns['suspicious_ips']),
                'ioc_type': random.choice(['ip', 'domain', 'hash', 'url']),
                'ioc_value': random.choice(self.ioc_patterns['malware_hashes']),
                'first_seen': (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat(),
                'last_seen': datetime.utcnow().isoformat(),
                'sources': random.sample(['VirusTotal', 'AbuseIPDB', 'AlienVault', 'ThreatFox'], random.randint(1, 4)),
                'tags': [threat_type, 'active', 'monitored'],
                'description': f'{threat_type.upper()} threat detected from {random.choice(self.ioc_patterns["suspicious_ips"])}',
                'timestamp': datetime.utcnow().isoformat()
            }
            threat_data.append(threat)
        
        return threat_data
    
    async def generate_incident_data(self, count: int = 1) -> List[Dict]:
        """Generate realistic incident data."""
        incident_data = []
        
        incident_types = [
            'malware_detection', 'phishing_attempt', 'unauthorized_access',
            'data_exfiltration', 'ddos_attack', 'insider_threat'
        ]
        
        for i in range(count):
            incident_type = random.choice(incident_types)
            
            incident = {
                'id': f'INC-{datetime.now().strftime("%Y%m%d")}-{i+1:03d}',
                'title': f'{incident_type.replace("_", " ").title()} Incident',
                'description': f'Detected {incident_type} activity affecting {random.randint(1, 10)} systems',
                'severity': random.choice(['low', 'medium', 'high', 'critical']),
                'status': random.choice(['open', 'investigating', 'contained', 'resolved']),
                'threat_type': incident_type,
                'affected_systems': random.randint(1, 20),
                'affected_users': random.randint(1, 100),
                'detected_at': (datetime.utcnow() - timedelta(hours=random.randint(1, 24))).isoformat(),
                'updated_at': datetime.utcnow().isoformat(),
                'assigned_to': f'analyst_{random.randint(1, 5)}',
                'priority': random.randint(1, 5),
                'tags': [incident_type, 'active', 'investigation'],
                'threat_data': {
                    'confidence': random.uniform(70, 95),
                    'type': incident_type,
                    'source': random.choice(self.ioc_patterns['suspicious_ips'])
                }
            }
            incident_data.append(incident)
        
        return incident_data
    
    async def get_real_threat_intelligence(self, ioc: str, ioc_type: str) -> Dict:
        """Get real threat intelligence from external APIs (mock implementation)."""
        # In production, this would call real threat intelligence APIs
        # For now, we'll simulate realistic responses
        
        mock_responses = {
            'ip': {
                'reputation_score': random.uniform(0, 100),
                'abuse_confidence': random.uniform(0, 100),
                'country': random.choice(['US', 'CN', 'RU', 'DE', 'UK']),
                'isp': random.choice(['Comcast', 'Verizon', 'AT&T', 'Unknown']),
                'threat_types': random.sample(['malware', 'phishing', 'botnet'], random.randint(0, 3)),
                'last_seen': datetime.utcnow().isoformat()
            },
            'domain': {
                'reputation_score': random.uniform(0, 100),
                'malware_families': random.sample(['Emotet', 'TrickBot', 'Dridex'], random.randint(0, 2)),
                'phishing_score': random.uniform(0, 100),
                'registration_date': (datetime.utcnow() - timedelta(days=random.randint(1, 365))).isoformat(),
                'threat_types': random.sample(['phishing', 'malware', 'c2'], random.randint(0, 3))
            },
            'hash': {
                'detection_rate': random.uniform(0, 100),
                'malware_families': random.sample(['Trojan', 'Ransomware', 'Spyware'], random.randint(0, 2)),
                'file_type': random.choice(['exe', 'dll', 'pdf', 'doc']),
                'file_size': random.randint(1000, 10000000),
                'threat_score': random.uniform(0, 100)
            }
        }
        
        return mock_responses.get(ioc_type, {})
    
    async def generate_dynamic_metrics(self) -> Dict:
        """Generate dynamic security metrics for dashboard."""
        current_time = datetime.utcnow()
        
        # Generate time-based patterns
        hour = current_time.hour
        is_business_hours = 8 <= hour <= 18
        
        # Adjust threat levels based on time
        base_threat_level = 0.3 if is_business_hours else 0.6
        
        metrics = {
            'total_threats': random.randint(50, 200),
            'active_incidents': random.randint(5, 25),
            'resolved_incidents': random.randint(100, 500),
            'risk_score': random.uniform(base_threat_level * 100, (base_threat_level + 0.3) * 100),
            'system_health': random.uniform(85, 99),
            'threat_trends': {
                'malware': random.randint(10, 50),
                'phishing': random.randint(5, 30),
                'ddos': random.randint(1, 10),
                'apt': random.randint(1, 5)
            },
            'user_sessions': random.randint(100, 1000),
            'network_alerts': random.randint(20, 100),
            'timestamp': current_time.isoformat()
        }
        
        return metrics

# Global instance
data_processor = SecurityDataProcessor() 
"""
Demo Data Generator for AISF
Generates realistic demo data for testing and demonstration.
"""

import json
import random
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any
import asyncio

from ..core.database import redis


class DemoDataGenerator:
    """Generates demo data for AISF components."""
    
    def __init__(self):
        self.user_ids = list(range(1, 21))  # 20 users
        self.ip_addresses = [
            '192.168.1.100', '192.168.1.101', '192.168.1.102',
            '10.0.0.50', '10.0.0.51', '10.0.0.52',
            '172.16.0.10', '172.16.0.11', '172.16.0.12',
            '185.220.101.45', '185.220.101.46',  # Suspicious IPs
            '8.8.8.8', '1.1.1.1'  # Public IPs
        ]
        
        self.device_types = ['desktop', 'laptop', 'mobile', 'tablet', 'unknown']
        self.network_types = ['corporate_wifi', 'home_wifi', 'public_wifi', 'mobile_data', 'vpn']
        self.threat_types = ['normal', 'dos', 'probe', 'r2l', 'u2r', 'malware', 'phishing']
        self.severity_levels = ['low', 'medium', 'high', 'critical']
    
    async def generate_access_control_data(self, num_records: int = 100) -> List[Dict]:
        """Generate demo data for access control component."""
        print(f"Generating {num_records} access control records...")
        
        records = []
        for i in range(num_records):
            user_id = random.choice(self.user_ids)
            timestamp = datetime.utcnow() - timedelta(
                hours=random.randint(0, 24),
                minutes=random.randint(0, 60)
            )
            
            # Generate risk factors
            risk_factors = {
                'login_time': random.uniform(0, 100),
                'device_status': random.uniform(0, 100),
                'network_type': random.uniform(0, 100),
                'ip_reputation': random.uniform(0, 100),
                'behavioral_pattern': random.uniform(0, 100),
                'failed_attempts': random.uniform(0, 100)
            }
            
            # Calculate TPS score
            tps_score = sum(risk_factors.values()) / len(risk_factors)
            
            # Determine action based on TPS
            if tps_score <= 20:
                action = 'allow'
            elif tps_score <= 40:
                action = 'mfa'
            elif tps_score <= 60:
                action = 'block'
            else:
                action = 'lockout'
            
            record = {
                'id': i + 1,
                'user_id': user_id,
                'tps_score': round(tps_score, 2),
                'factors': json.dumps(risk_factors),
                'action_taken': action,
                'timestamp': timestamp.isoformat(),
                'ip_address': random.choice(self.ip_addresses),
                'device_info': {
                    'type': random.choice(self.device_types),
                    'is_known_device': random.choice([True, False]),
                    'has_security_software': random.choice([True, False])
                },
                'network_type': random.choice(self.network_types)
            }
            
            records.append(record)
        
        return records
    
    async def generate_threat_prediction_data(self, num_records: int = 50) -> List[Dict]:
        """Generate demo data for threat prediction component."""
        print(f"Generating {num_records} threat prediction records...")
        
        records = []
        for i in range(num_records):
            threat_type = random.choice(self.threat_types)
            confidence = random.uniform(50, 99)
            
            # Generate network data
            network_data = {
                'duration': random.uniform(0, 1000),
                'src_bytes': random.uniform(0, 10000),
                'dst_bytes': random.uniform(0, 10000),
                'count': random.randint(1, 100),
                'srv_count': random.randint(1, 50),
                'serror_rate': random.uniform(0, 1),
                'srv_serror_rate': random.uniform(0, 1),
                'rerror_rate': random.uniform(0, 1),
                'srv_rerror_rate': random.uniform(0, 1),
                'same_srv_rate': random.uniform(0, 1),
                'diff_srv_rate': random.uniform(0, 1),
                'srv_diff_host_rate': random.uniform(0, 1),
                'dst_host_count': random.randint(1, 100),
                'dst_host_srv_count': random.randint(1, 50),
                'dst_host_same_srv_rate': random.uniform(0, 1),
                'dst_host_diff_srv_rate': random.uniform(0, 1),
                'dst_host_same_src_port_rate': random.uniform(0, 1),
                'dst_host_srv_diff_host_rate': random.uniform(0, 1),
                'dst_host_serror_rate': random.uniform(0, 1),
                'dst_host_srv_serror_rate': random.uniform(0, 1),
                'dst_host_rerror_rate': random.uniform(0, 1),
                'dst_host_srv_rerror_rate': random.uniform(0, 1)
            }
            
            record = {
                'id': i + 1,
                'type': threat_type,
                'confidence': round(confidence, 2),
                'source': 'ml_prediction',
                'status': 'detected',
                'detected_at': (datetime.utcnow() - timedelta(minutes=random.randint(0, 60))).isoformat(),
                'network_data': network_data,
                'zero_day_detection': {
                    'is_zero_day': random.choice([True, False]),
                    'anomaly_score': random.uniform(0, 1),
                    'confidence': random.uniform(50, 99)
                }
            }
            
            records.append(record)
        
        return records
    
    async def generate_threat_hunting_data(self, num_records: int = 30) -> List[Dict]:
        """Generate demo data for threat hunting component."""
        print(f"Generating {num_records} threat hunting records...")
        
        records = []
        for i in range(num_records):
            query_type = random.choice(['apt_detection', 'malware_detection', 'insider_threat'])
            
            # Generate hunting results
            hunting_results = []
            for j in range(random.randint(1, 5)):
                finding = {
                    'type': f'finding_{j+1}',
                    'severity': random.choice(['low', 'medium', 'high', 'critical']),
                    'description': f'Suspicious activity detected in {query_type}',
                    'timestamp': (datetime.utcnow() - timedelta(minutes=random.randint(0, 30))).isoformat(),
                    'details': {
                        'source_ip': random.choice(self.ip_addresses),
                        'destination_ip': random.choice(self.ip_addresses),
                        'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
                        'port': random.randint(1, 65535)
                    }
                }
                hunting_results.append(finding)
            
            # Generate IoC data
            ioc_data = f"""
            Suspicious IP: {random.choice(self.ip_addresses)}
            Malicious domain: {random.choice(['malware.example.com', 'phishing.site.com', 'botnet.net'])}
            File hash: {self._generate_random_hash()}
            URL: https://{random.choice(['suspicious.com', 'malware.net', 'phishing.org'])}/payload
            Email: {random.choice(['attacker@evil.com', 'malware@bad.net', 'phish@fake.org'])}
            """
            
            record = {
                'id': i + 1,
                'query_type': query_type,
                'data_source': 'network',
                'hunting_results': hunting_results,
                'hunting_score': random.uniform(0, 100),
                'total_findings': len(hunting_results),
                'ioc_data': ioc_data,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            records.append(record)
        
        return records
    
    async def generate_incident_response_data(self, num_records: int = 20) -> List[Dict]:
        """Generate demo data for incident response component."""
        print(f"Generating {num_records} incident response records...")
        
        records = []
        for i in range(num_records):
            severity = random.choice(self.severity_levels)
            threat_type = random.choice(self.threat_types)
            
            # Generate response actions
            available_actions = ['isolate', 'block', 'revoke', 'quarantine', 'monitor', 'alert', 'backup', 'patch']
            selected_actions = random.sample(available_actions, random.randint(1, 4))
            
            response_actions = []
            for action in selected_actions:
                response_actions.append({
                    'action': action,
                    'description': f'Execute {action} action',
                    'severity': random.choice(['low', 'medium', 'high']),
                    'execution_time': random.randint(5, 60),
                    'effectiveness': random.uniform(0.6, 0.95),
                    'probability': random.uniform(0.1, 1.0)
                })
            
            record = {
                'id': i + 1,
                'severity': severity,
                'threat_type': threat_type,
                'affected_systems': random.randint(1, 10),
                'user_impact': random.choice(['low', 'medium', 'high', 'critical']),
                'business_critical': random.choice([True, False]),
                'detection_time': (datetime.utcnow() - timedelta(minutes=random.randint(0, 120))).isoformat(),
                'response_actions': response_actions,
                'response_confidence': random.uniform(50, 99),
                'expected_effectiveness': random.uniform(0.7, 0.95),
                'estimated_execution_time': sum(action['execution_time'] for action in response_actions),
                'status': random.choice(['responding', 'investigating', 'resolved']),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            records.append(record)
        
        return records
    
    async def generate_user_behavior_data(self, num_records: int = 200) -> List[Dict]:
        """Generate demo data for user behavior analysis."""
        print(f"Generating {num_records} user behavior records...")
        
        records = []
        for i in range(num_records):
            user_id = random.choice(self.user_ids)
            
            # Generate behavior patterns
            behavior_data = {
                'login_hour': random.randint(0, 23),
                'login_day_of_week': random.randint(0, 6),
                'session_duration': random.randint(5, 480),  # minutes
                'actions_per_session': random.randint(10, 200),
                'failed_attempts': random.randint(0, 5),
                'ip_changes': random.randint(0, 3),
                'unusual_files_accessed': random.randint(0, 10),
                'privilege_events': random.randint(0, 5),
                'data_transfer_size': random.randint(0, 1000000),  # bytes
                'after_hours_activity': random.choice([True, False])
            }
            
            record = {
                'id': i + 1,
                'user_id': user_id,
                'behavior_data': behavior_data,
                'timestamp': (datetime.utcnow() - timedelta(hours=random.randint(0, 24))).isoformat(),
                'risk_score': random.uniform(0, 100),
                'anomaly_detected': random.choice([True, False])
            }
            
            records.append(record)
        
        return records
    
    def _generate_random_hash(self) -> str:
        """Generate a random hash for demo purposes."""
        return ''.join(random.choices('0123456789abcdef', k=32))
    
    async def populate_redis_cache(self):
        """Populate Redis cache with demo data."""
        print("Populating Redis cache with demo data...")
        
        # Cache some IP reputation data
        for ip in self.ip_addresses:
            if ip.startswith('185.220.'):
                await redis.setex(f"ip_risk:{ip}", 3600, str(random.uniform(70, 95)))
            elif ip.startswith(('192.168.', '10.', '172.')):
                await redis.setex(f"ip_risk:{ip}", 3600, str(random.uniform(10, 30)))
            else:
                await redis.setex(f"ip_risk:{ip}", 3600, str(random.uniform(30, 60)))
        
        # Cache some failed login attempts
        for user_id in self.user_ids:
            if random.random() < 0.3:  # 30% chance of failed attempts
                failed_count = random.randint(1, 5)
                await redis.setex(f"failed_attempts:{user_id}", 3600, str(failed_count))
        
        print("Redis cache populated successfully!")
    
    async def generate_all_demo_data(self) -> Dict[str, List[Dict]]:
        """Generate all types of demo data."""
        print("Generating comprehensive demo data for AISF...")
        
        all_data = {
            'access_control': await self.generate_access_control_data(100),
            'threat_prediction': await self.generate_threat_prediction_data(50),
            'threat_hunting': await self.generate_threat_hunting_data(30),
            'incident_response': await self.generate_incident_response_data(20),
            'user_behavior': await self.generate_user_behavior_data(200)
        }
        
        # Populate Redis cache
        await self.populate_redis_cache()
        
        print("Demo data generation complete!")
        print(f"Generated {sum(len(data) for data in all_data.values())} total records")
        
        return all_data
    
    def save_demo_data_to_file(self, data: Dict[str, List[Dict]], filename: str = "demo_data.json"):
        """Save demo data to JSON file."""
        filepath = f"backend/app/utils/{filename}"
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"Demo data saved to: {filepath}")


async def main():
    """Main function to generate demo data."""
    generator = DemoDataGenerator()
    
    # Generate all demo data
    demo_data = await generator.generate_all_demo_data()
    
    # Save to file
    generator.save_demo_data_to_file(demo_data)
    
    # Print summary
    print("\n=== Demo Data Summary ===")
    for category, records in demo_data.items():
        print(f"{category.replace('_', ' ').title()}: {len(records)} records")
    
    print("\nDemo data generation completed successfully!")


if __name__ == "__main__":
    asyncio.run(main()) 
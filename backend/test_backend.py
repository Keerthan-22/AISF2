"""
Simple Backend Test Script
Tests the basic functionality of the AISF backend components.
"""

import asyncio
import json
import sys
import os

# Add the app directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.core.database import get_db, redis
from app.api.components.access_control import access_control_manager
from app.api.components.threat_prediction import threat_prediction_manager
from app.api.components.threat_hunting import threat_hunting_manager
from app.api.components.incident_response import incident_response_manager


async def test_access_control():
    """Test access control component."""
    print("\n=== Testing Access Control Component ===")
    
    try:
        # Test risk assessment
        context = {
            'login_time': '2024-01-15T14:30:00Z',
            'device_info': {
                'type': 'laptop',
                'is_known_device': True,
                'has_security_software': True
            },
            'network_type': 'corporate_wifi',
            'ip_address': '192.168.1.100'
        }
        
        # Mock database session
        async for db in get_db():
            result = await access_control_manager.assess_user_access(1, context, db)
            break
        
        print(f"✓ Risk assessment completed")
        print(f"  TPS Score: {result['tps_score']:.2f}")
        print(f"  Access Decision: {result['access_decision']}")
        print(f"  Is Anomalous: {result['is_anomalous']}")
        
        return True
        
    except Exception as e:
        print(f"✗ Access control test failed: {e}")
        return False


async def test_threat_prediction():
    """Test threat prediction component."""
    print("\n=== Testing Threat Prediction Component ===")
    
    try:
        # Test threat prediction
        network_data = {
            'duration': 100,
            'src_bytes': 1000,
            'dst_bytes': 0,
            'count': 50,
            'srv_count': 25,
            'serror_rate': 0.1,
            'srv_serror_rate': 0.1,
            'rerror_rate': 0.05,
            'srv_rerror_rate': 0.05,
            'same_srv_rate': 0.8,
            'diff_srv_rate': 0.2,
            'srv_diff_host_rate': 0.1,
            'dst_host_count': 10,
            'dst_host_srv_count': 5,
            'dst_host_same_srv_rate': 0.8,
            'dst_host_diff_srv_rate': 0.2,
            'dst_host_same_src_port_rate': 0.9,
            'dst_host_srv_diff_host_rate': 0.1,
            'dst_host_serror_rate': 0.1,
            'dst_host_srv_serror_rate': 0.1,
            'dst_host_rerror_rate': 0.05,
            'dst_host_srv_rerror_rate': 0.05
        }
        
        # Mock database session
        async for db in get_db():
            result = await threat_prediction_manager.predict_and_analyze_threat(network_data, db)
            break
        
        print(f"✓ Threat prediction completed")
        print(f"  Threat ID: {result['threat_id']}")
        print(f"  Overall Confidence: {result['overall_confidence']:.2f}")
        print(f"  Prediction: {result['prediction']['threat_type']}")
        
        return True
        
    except Exception as e:
        print(f"✗ Threat prediction test failed: {e}")
        return False


async def test_threat_hunting():
    """Test threat hunting component."""
    print("\n=== Testing Threat Hunting Component ===")
    
    try:
        # Test threat hunting
        hunting_data = {
            'data_source': 'network',
            'query_type': 'apt_detection',
            'filters': {'time_range': 'last_24_hours'},
            'ioc_data': """
            Suspicious IP: 185.220.101.45
            Malicious domain: malware.example.com
            File hash: d41d8cd98f00b204e9800998ecf8427e
            URL: https://suspicious.com/payload
            Email: attacker@evil.com
            """,
            'user_activity': {
                'login_times': ['2024-01-15T14:30:00Z'],
                'privilege_events': [],
                'data_access': {'unusual_files': 2}
            }
        }
        
        # Mock database session
        async for db in get_db():
            result = await threat_hunting_manager.comprehensive_threat_hunt(hunting_data, db)
            break
        
        print(f"✓ Threat hunting completed")
        print(f"  Overall Threat Score: {result['overall_threat_score']:.2f}")
        print(f"  Total Findings: {result['hunting_results'].get('automated_hunting', {}).get('total_findings', 0)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Threat hunting test failed: {e}")
        return False


async def test_incident_response():
    """Test incident response component."""
    print("\n=== Testing Incident Response Component ===")
    
    try:
        # Test incident response
        incident_data = {
            'severity': 'high',
            'threat_type': 'malware',
            'affected_systems': 5,
            'user_impact': 'high',
            'business_critical': True,
            'detection_time': '2024-01-15T14:30:00Z'
        }
        
        threat_data = {
            'confidence': 85.5,
            'type': 'malware',
            'source': 'ml_prediction'
        }
        
        # Mock database session
        async for db in get_db():
            result = await incident_response_manager.handle_incident(incident_data, threat_data, db)
            break
        
        print(f"✓ Incident response completed")
        print(f"  Incident ID: {result['incident_id']}")
        print(f"  Overall Status: {result['overall_status']}")
        print(f"  Actions Selected: {len(result['response_selection']['selected_actions'])}")
        
        return True
        
    except Exception as e:
        print(f"✗ Incident response test failed: {e}")
        return False


async def test_redis_connection():
    """Test Redis connection."""
    print("\n=== Testing Redis Connection ===")
    
    try:
        # Test Redis connection
        await redis.ping()
        print("✓ Redis connection successful")
        
        # Test basic operations
        await redis.set("test_key", "test_value")
        value = await redis.get("test_key")
        await redis.delete("test_key")
        
        if value == "test_value":
            print("✓ Redis operations successful")
            return True
        else:
            print("✗ Redis operations failed")
            return False
            
    except Exception as e:
        print(f"✗ Redis connection failed: {e}")
        return False


async def main():
    """Run all tests."""
    print("AISF Backend Component Tests")
    print("=" * 50)
    
    results = []
    
    # Test Redis connection first
    redis_result = await test_redis_connection()
    results.append(("Redis Connection", redis_result))
    
    # Test each component
    results.append(("Access Control", await test_access_control()))
    results.append(("Threat Prediction", await test_threat_prediction()))
    results.append(("Threat Hunting", await test_threat_hunting()))
    results.append(("Incident Response", await test_incident_response()))
    
    # Print summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name:<20} {status}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Backend is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 
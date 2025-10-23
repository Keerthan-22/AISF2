"""
Test Performance Monitor
Demonstrates real-time performance logging and XAI explanations for AISF research.
"""

import asyncio
import logging
import numpy as np
from datetime import datetime
import json

from performance_monitor import performance_monitor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def test_detection_performance():
    """Test detection performance logging."""
    logger.info("🔍 Testing detection performance logging...")
    
    # Simulate multiple detection events
    for i in range(50):
        # Generate mock features
        features = np.random.randn(1, 78)  # CICIDS-2017 features
        
        # Simulate prediction
        prediction = np.random.choice(['normal', 'dos', 'probe', 'r2l', 'u2r'])
        confidence = np.random.uniform(0.7, 0.99)
        
        # Log detection event
        event_id = await performance_monitor.log_detection_event(
            model_name='threat_classifier',
            dataset_name='cicids2017',
            features=features,
            prediction=prediction,
            true_label=np.random.choice(['normal', 'dos', 'probe', 'r2l', 'u2r']),
            confidence=confidence
        )
        
        if event_id:
            logger.info(f"   Detection {i+1}: {event_id}")
        
        # Small delay between detections
        await asyncio.sleep(0.01)
    
    logger.info("✅ Detection performance testing completed")

async def test_response_performance():
    """Test response performance logging."""
    logger.info("🚨 Testing response performance logging...")
    
    # Simulate different response scenarios
    scenarios = [
        {
            'incident_id': 'INC-001',
            'response_type': 'automated',
            'actions': ['block_ip', 'update_firewall'],
            'severity': 'low'
        },
        {
            'incident_id': 'INC-002',
            'response_type': 'manual',
            'actions': ['investigate', 'isolate_host', 'notify_admin'],
            'severity': 'medium'
        },
        {
            'incident_id': 'INC-003',
            'response_type': 'escalated',
            'actions': ['emergency_response', 'activate_incident_team', 'coordinate_with_external'],
            'severity': 'critical'
        }
    ]
    
    for i, scenario in enumerate(scenarios):
        event_id = await performance_monitor.log_response_event(
            incident_id=scenario['incident_id'],
            response_type=scenario['response_type'],
            actions=scenario['actions'],
            severity=scenario['severity']
        )
        
        if event_id:
            logger.info(f"   Response {i+1}: {event_id} - {scenario['severity']} severity")
        
        await asyncio.sleep(0.02)
    
    logger.info("✅ Response performance testing completed")

async def test_training_performance():
    """Test training performance logging."""
    logger.info("🎯 Testing training performance logging...")
    
    # Simulate model training events
    models = ['threat_classifier', 'anomaly_detector', 'zero_day_detector']
    datasets = ['cicids2017', 'nsl_kdd', 'unsw_nb15']
    
    for i in range(10):
        model_name = np.random.choice(models)
        dataset_name = np.random.choice(datasets)
        
        # Mock training metrics
        training_metrics = {
            'accuracy': np.random.uniform(0.95, 0.99),
            'precision': np.random.uniform(0.94, 0.98),
            'recall': np.random.uniform(0.93, 0.97),
            'f1_score': np.random.uniform(0.94, 0.98),
            'loss': np.random.uniform(0.01, 0.05)
        }
        
        event_id = await performance_monitor.log_training_event(
            model_name=model_name,
            dataset_name=dataset_name,
            training_metrics=training_metrics
        )
        
        if event_id:
            logger.info(f"   Training {i+1}: {event_id} - {model_name} on {dataset_name}")
        
        await asyncio.sleep(0.05)
    
    logger.info("✅ Training performance testing completed")

async def test_validation_performance():
    """Test validation performance logging."""
    logger.info("✅ Testing validation performance logging...")
    
    # Simulate validation events
    for i in range(15):
        model_name = np.random.choice(['threat_classifier', 'anomaly_detector'])
        dataset_name = np.random.choice(['cicids2017', 'nsl_kdd'])
        
        # Mock validation metrics
        validation_metrics = {
            'test_accuracy': np.random.uniform(0.96, 0.99),
            'test_precision': np.random.uniform(0.95, 0.98),
            'test_recall': np.random.uniform(0.94, 0.97),
            'test_f1_score': np.random.uniform(0.95, 0.98),
            'zero_day_detection_rate': np.random.uniform(0.97, 0.99)
        }
        
        event_id = await performance_monitor.log_validation_event(
            model_name=model_name,
            dataset_name=dataset_name,
            validation_metrics=validation_metrics
        )
        
        if event_id:
            logger.info(f"   Validation {i+1}: {event_id} - {model_name} on {dataset_name}")
        
        await asyncio.sleep(0.03)
    
    logger.info("✅ Validation performance testing completed")

async def generate_performance_report():
    """Generate comprehensive performance report."""
    logger.info("📊 Generating performance report...")
    
    # Get performance summary
    summary = await performance_monitor.get_performance_summary()
    
    # Display key metrics
    logger.info("📋 Performance Summary:")
    
    if summary.get('detection_performance'):
        det_perf = summary['detection_performance']
        logger.info(f"   Detection Performance:")
        logger.info(f"     Mean MTTD: {det_perf['mean_mttd_ms']:.2f}ms")
        logger.info(f"     Total Detections: {det_perf['total_detections']}")
        logger.info(f"     Meets Requirement: {det_perf['meets_requirement']}")
    
    if summary.get('response_performance'):
        resp_perf = summary['response_performance']
        logger.info(f"   Response Performance:")
        logger.info(f"     Mean MTTR: {resp_perf['mean_mttr_ms']:.2f}ms")
        logger.info(f"     Total Responses: {resp_perf['total_responses']}")
        logger.info(f"     Meets Requirement: {resp_perf['meets_requirement']}")
    
    if summary.get('research_compliance'):
        compliance = summary['research_compliance']
        logger.info(f"   Research Compliance:")
        logger.info(f"     MTTD Compliance: {compliance['mttd_compliance']}")
        logger.info(f"     MTTR Compliance: {compliance['mttr_compliance']}")
        logger.info(f"     XAI Available: {compliance['xai_available']}")
        logger.info(f"     XAI Explanations: {compliance['total_xai_explanations']}")
    
    # Save detailed report
    report_file = await performance_monitor.save_performance_report()
    if report_file:
        logger.info(f"📄 Detailed report saved: {report_file}")
    
    return summary

async def main():
    """Main test function."""
    logger.info("🚀 Starting AISF Performance Monitor Testing...")
    
    try:
        # Test all performance monitoring components
        await test_detection_performance()
        await test_response_performance()
        await test_training_performance()
        await test_validation_performance()
        
        # Generate comprehensive report
        summary = await generate_performance_report()
        
        # Check overall compliance
        compliance = summary.get('research_compliance', {})
        mttd_compliant = compliance.get('mttd_compliance', False)
        mttr_compliant = compliance.get('mttr_compliance', False)
        xai_available = compliance.get('xai_available', False)
        
        logger.info("🎯 Research Compliance Summary:")
        logger.info(f"   MTTD < 10s: {'✅ PASS' if mttd_compliant else '❌ FAIL'}")
        logger.info(f"   MTTR < 60s: {'✅ PASS' if mttr_compliant else '❌ FAIL'}")
        logger.info(f"   XAI Available: {'✅ PASS' if xai_available else '❌ FAIL'}")
        
        overall_success = mttd_compliant and mttr_compliant and xai_available
        logger.info(f"   Overall: {'🎉 SUCCESS' if overall_success else '⚠️ NEEDS IMPROVEMENT'}")
        
        return overall_success
        
    except Exception as e:
        logger.error(f"❌ Error during performance testing: {str(e)}")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1) 
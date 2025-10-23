"""
Master Test Suite for AISF Security Platform
Comprehensive validation of all system components and functionalities.
"""

import asyncio
import logging
import json
import time
from pathlib import Path
from datetime import datetime

# Import all test modules
from dataset_integration import dataset_integration
from performance_monitor import performance_monitor
from scientific_artifacts import artifacts_generator
from live_telemetry import telemetry_system

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MasterTestSuite:
    """Comprehensive test suite for AISF Security Platform."""
    
    def __init__(self):
        self.test_results = {}
        self.start_time = datetime.now()
    
    async def run_dataset_integration_test(self):
        """Test dataset integration functionality."""
        logger.info("🔍 Testing Dataset Integration...")
        
        try:
            # Test benchmark datasets
            benchmark_results = await dataset_integration.generate_benchmark_datasets()
            benchmark_success = all(benchmark_results.values())
            
            # Test synthetic data
            synthetic_data = await dataset_integration.generate_synthetic_data()
            synthetic_success = len(synthetic_data.get('normal_sessions', [])) > 0
            
            # Test validation
            validation_results = await dataset_integration.validate_dataset_integration()
            validation_success = validation_results.get('overall_status') == 'PASS'
            
            self.test_results['dataset_integration'] = {
                'benchmark_datasets': benchmark_success,
                'synthetic_data': synthetic_success,
                'validation': validation_success,
                'overall': benchmark_success and synthetic_success and validation_success
            }
            
            logger.info(f"   ✅ Dataset Integration: {'PASS' if self.test_results['dataset_integration']['overall'] else 'FAIL'}")
            return self.test_results['dataset_integration']['overall']
            
        except Exception as e:
            logger.error(f"   ❌ Dataset Integration Error: {str(e)}")
            self.test_results['dataset_integration'] = {'overall': False}
            return False
    
    async def run_performance_monitoring_test(self):
        """Test performance monitoring functionality."""
        logger.info("🔍 Testing Performance Monitoring...")
        
        try:
            # Test detection performance
            import numpy as np
            for i in range(10):
                await performance_monitor.log_detection_event(
                    model_name='test_model',
                    dataset_name='test_dataset',
                    features=np.array([[1.0, 2.0, 3.0]]),
                    prediction='normal',
                    true_label='normal',
                    confidence=0.95
                )
            
            # Test response performance
            for i in range(5):
                await performance_monitor.log_response_event(
                    incident_id=f'TEST-{i+1}',
                    response_type='automated',
                    actions=['block_ip', 'update_firewall'],
                    severity='medium'
                )
            
            # Test training performance
            await performance_monitor.log_training_event(
                model_name='test_model',
                dataset_name='test_dataset',
                training_metrics={'accuracy': 0.95, 'precision': 0.94}
            )
            
            # Test validation performance
            await performance_monitor.log_validation_event(
                model_name='test_model',
                dataset_name='test_dataset',
                validation_metrics={'test_accuracy': 0.96, 'test_precision': 0.95}
            )
            
            # Get performance summary
            summary = await performance_monitor.get_performance_summary()
            performance_success = summary is not None and len(summary) > 0
            
            self.test_results['performance_monitoring'] = {
                'detection_logging': True,
                'response_logging': True,
                'training_logging': True,
                'validation_logging': True,
                'summary_generation': performance_success,
                'overall': performance_success
            }
            
            logger.info(f"   ✅ Performance Monitoring: {'PASS' if performance_success else 'FAIL'}")
            return performance_success
            
        except Exception as e:
            logger.error(f"   ❌ Performance Monitoring Error: {str(e)}")
            self.test_results['performance_monitoring'] = {'overall': False}
            return False
    
    async def run_scientific_artifacts_test(self):
        """Test scientific artifacts generation."""
        logger.info("🔍 Testing Scientific Artifacts...")
        
        try:
            # Generate all artifacts
            results = await artifacts_generator.generate_all_artifacts()
            
            if results:
                summary = results.get('summary', {})
                notebooks_count = summary.get('total_notebooks', 0)
                artifacts_count = summary.get('total_artifacts', 0)
                
                artifacts_success = notebooks_count >= 5 and artifacts_count >= 3
                
                self.test_results['scientific_artifacts'] = {
                    'notebooks_generated': notebooks_count >= 5,
                    'artifacts_created': artifacts_count >= 3,
                    'manifest_created': True,
                    'overall': artifacts_success
                }
                
                logger.info(f"   ✅ Scientific Artifacts: {'PASS' if artifacts_success else 'FAIL'}")
                return artifacts_success
            else:
                logger.error("   ❌ Scientific artifacts generation failed")
                self.test_results['scientific_artifacts'] = {'overall': False}
                return False
                
        except Exception as e:
            logger.error(f"   ❌ Scientific Artifacts Error: {str(e)}")
            self.test_results['scientific_artifacts'] = {'overall': False}
            return False
    
    async def run_live_telemetry_test(self):
        """Test live telemetry system."""
        logger.info("🔍 Testing Live Telemetry System...")
        
        try:
            # Generate live telemetry for 1 minute (for testing)
            telemetry_data = await telemetry_system.generate_live_telemetry(duration_minutes=1)
            
            if telemetry_data:
                metrics = telemetry_data.get('metrics', {})
                total_events = metrics.get('total_events', 0)
                total_responses = metrics.get('total_responses', 0)
                success_rate = metrics.get('success_rate', 0)
                
                telemetry_success = (
                    total_events > 0 and 
                    total_responses > 0 and 
                    success_rate >= 0.9
                )
                
                self.test_results['live_telemetry'] = {
                    'events_generated': total_events > 0,
                    'responses_generated': total_responses > 0,
                    'success_rate_acceptable': success_rate >= 0.9,
                    'overall': telemetry_success
                }
                
                logger.info(f"   ✅ Live Telemetry: {'PASS' if telemetry_success else 'FAIL'}")
                return telemetry_success
            else:
                logger.error("   ❌ Live telemetry generation failed")
                self.test_results['live_telemetry'] = {'overall': False}
                return False
                
        except Exception as e:
            logger.error(f"   ❌ Live Telemetry Error: {str(e)}")
            self.test_results['live_telemetry'] = {'overall': False}
            return False
    
    async def run_system_validation_test(self):
        """Test system validation."""
        logger.info("🔍 Testing System Validation...")
        
        try:
            # Validate system performance
            validation_results = await telemetry_system.validate_system_performance()
            
            if validation_results:
                metrics = validation_results.get('metrics', {})
                mttd_compliance = validation_results.get('mttd_compliance', False)
                mttr_compliance = validation_results.get('mttr_compliance', False)
                success_rate_compliance = validation_results.get('success_rate_compliance', False)
                
                system_success = mttd_compliance and mttr_compliance and success_rate_compliance
                
                self.test_results['system_validation'] = {
                    'mttd_compliance': mttd_compliance,
                    'mttr_compliance': mttr_compliance,
                    'success_rate_compliance': success_rate_compliance,
                    'overall': system_success
                }
                
                logger.info(f"   ✅ System Validation: {'PASS' if system_success else 'FAIL'}")
                return system_success
            else:
                logger.error("   ❌ System validation failed")
                self.test_results['system_validation'] = {'overall': False}
                return False
                
        except Exception as e:
            logger.error(f"   ❌ System Validation Error: {str(e)}")
            self.test_results['system_validation'] = {'overall': False}
            return False
    
    async def run_file_system_test(self):
        """Test file system and generated files."""
        logger.info("🔍 Testing File System...")
        
        try:
            required_directories = [
                'datasets',
                'performance_logs',
                'scientific_artifacts',
                'live_telemetry'
            ]
            
            required_files = [
                'datasets/integration_results.json',
                'performance_logs/performance_events.jsonl',
                'scientific_artifacts/results/research_manifest.json',
                'live_telemetry/telemetry_summary.json'
            ]
            
            # Check directories
            directories_exist = all(Path(d).exists() for d in required_directories)
            
            # Check files
            files_exist = all(Path(f).exists() for f in required_files)
            
            file_system_success = directories_exist and files_exist
            
            self.test_results['file_system'] = {
                'directories_exist': directories_exist,
                'files_exist': files_exist,
                'overall': file_system_success
            }
            
            logger.info(f"   ✅ File System: {'PASS' if file_system_success else 'FAIL'}")
            return file_system_success
            
        except Exception as e:
            logger.error(f"   ❌ File System Error: {str(e)}")
            self.test_results['file_system'] = {'overall': False}
            return False
    
    async def run_comprehensive_test(self):
        """Run comprehensive test of all components."""
        logger.info("🚀 Starting AISF Security Platform Comprehensive Test...")
        
        test_functions = [
            ('Dataset Integration', self.run_dataset_integration_test),
            ('Performance Monitoring', self.run_performance_monitoring_test),
            ('Scientific Artifacts', self.run_scientific_artifacts_test),
            ('Live Telemetry', self.run_live_telemetry_test),
            ('System Validation', self.run_system_validation_test),
            ('File System', self.run_file_system_test)
        ]
        
        all_tests_passed = True
        
        for test_name, test_func in test_functions:
            logger.info(f"\n📋 Running {test_name} Test...")
            try:
                result = await test_func()
                if not result:
                    all_tests_passed = False
                await asyncio.sleep(1)  # Small delay between tests
            except Exception as e:
                logger.error(f"❌ {test_name} test failed: {str(e)}")
                all_tests_passed = False
        
        # Generate final report
        await self.generate_final_report(all_tests_passed)
        
        return all_tests_passed
    
    async def generate_final_report(self, overall_success: bool):
        """Generate comprehensive test report."""
        logger.info("\n" + "="*60)
        logger.info("🏆 AISF SECURITY PLATFORM - COMPREHENSIVE TEST REPORT")
        logger.info("="*60)
        
        # Calculate test duration
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        # Display individual test results
        logger.info("\n📊 Test Results:")
        for test_name, results in self.test_results.items():
            status = "✅ PASS" if results.get('overall', False) else "❌ FAIL"
            logger.info(f"   {test_name.replace('_', ' ').title()}: {status}")
        
        # Overall status
        overall_status = "🎉 ALL TESTS PASSED" if overall_success else "⚠️ SOME TESTS FAILED"
        logger.info(f"\n🎯 Overall Status: {overall_status}")
        logger.info(f"⏱️  Test Duration: {duration.total_seconds():.2f} seconds")
        
        # Research compliance check
        logger.info("\n📋 Research Compliance Check:")
        compliance_items = [
            "Dataset Integration",
            "Performance Monitoring", 
            "Scientific Artifacts",
            "Live Telemetry",
            "System Validation",
            "File System"
        ]
        
        for item in compliance_items:
            key = item.lower().replace(' ', '_')
            status = "✅ PASS" if self.test_results.get(key, {}).get('overall', False) else "❌ FAIL"
            logger.info(f"   {item}: {status}")
        
        # Final recommendation
        if overall_success:
            logger.info("\n🎉 RECOMMENDATION: System is ready for production and research publication!")
        else:
            logger.info("\n⚠️ RECOMMENDATION: System needs attention before production deployment.")
        
        logger.info("="*60)
        
        # Save detailed report
        report_data = {
            'test_timestamp': self.start_time.isoformat(),
            'test_duration_seconds': duration.total_seconds(),
            'overall_success': bool(overall_success),
            'test_results': self.test_results,
            'recommendation': 'ready_for_production' if overall_success else 'needs_attention'
        }
        
        report_file = Path("comprehensive_test_report.json")
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"📄 Detailed report saved: {report_file}")

async def main():
    """Main test function."""
    test_suite = MasterTestSuite()
    success = await test_suite.run_comprehensive_test()
    return success

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1) 
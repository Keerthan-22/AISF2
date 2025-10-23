"""
Dataset Integration Runner
Executes dataset integration for AISF research validation.
"""

import asyncio
import logging
from pathlib import Path
import json

from dataset_integration import dataset_integration

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def main():
    """Main function to run dataset integration."""
    logger.info("🚀 Starting AISF Dataset Integration...")
    
    try:
        # 1. Generate benchmark datasets
        logger.info("📊 Generating benchmark datasets...")
        benchmark_results = await dataset_integration.generate_benchmark_datasets()
        
        # Log results
        for dataset_name, success in benchmark_results.items():
            status = "✅ SUCCESS" if success else "❌ FAILED"
            logger.info(f"   {dataset_name}: {status}")
        
        # 2. Generate synthetic data
        logger.info("🔧 Generating synthetic data...")
        synthetic_data = await dataset_integration.generate_synthetic_data()
        
        logger.info(f"   Normal sessions: {len(synthetic_data['normal_sessions'])}")
        logger.info(f"   Anomalous sessions: {len(synthetic_data['anomalous_sessions'])}")
        
        # 3. Validate integration
        logger.info("🔍 Validating dataset integration...")
        validation_results = await dataset_integration.validate_dataset_integration()
        
        # Display validation results
        logger.info("📋 Validation Results:")
        
        # Benchmark datasets
        logger.info("   Benchmark Datasets:")
        for dataset_name, result in validation_results['benchmark_datasets'].items():
            if result['exists']:
                logger.info(f"     {dataset_name}: ✅ {result['file_count']}/{result['expected_files']} files")
            else:
                logger.info(f"     {dataset_name}: ❌ Not found")
        
        # Synthetic data
        logger.info("   Synthetic Data:")
        for data_type, result in validation_results['synthetic_data'].items():
            status = "✅" if result['exists'] else "❌"
            logger.info(f"     {data_type}: {status}")
        
        # Overall status
        overall_status = validation_results['overall_status']
        logger.info(f"   Overall Status: {overall_status}")
        
        # 4. Save results summary
        results_summary = {
            'timestamp': str(Path.cwd()),
            'benchmark_results': benchmark_results,
            'synthetic_data_counts': {
                'normal_sessions': len(synthetic_data['normal_sessions']),
                'anomalous_sessions': len(synthetic_data['anomalous_sessions'])
            },
            'validation_results': validation_results
        }
        
        # Save to file
        results_file = Path("datasets/integration_results.json")
        results_file.parent.mkdir(exist_ok=True)
        
        with open(results_file, 'w') as f:
            json.dump(results_summary, f, indent=2, default=str)
        
        logger.info(f"💾 Results saved to {results_file}")
        
        # 5. Final status
        if overall_status == 'PASS':
            logger.info("🎉 Dataset integration completed successfully!")
        else:
            logger.warning("⚠️ Dataset integration completed with issues. Check logs above.")
        
        return overall_status == 'PASS'
        
    except Exception as e:
        logger.error(f"❌ Error during dataset integration: {str(e)}")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1) 
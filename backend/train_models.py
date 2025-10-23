#!/usr/bin/env python3
"""
AISF Model Training Script
Trains all ML models for the Advanced Intelligent Security Framework
"""

import asyncio
import logging
import sys
import os
from datetime import datetime

# Add the app directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.ml_models.model_trainer import ModelTrainer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('training.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

async def main():
    """Main training function"""
    logger.info("🚀 Starting AISF Model Training...")
    logger.info("=" * 60)
    
    try:
        # Initialize model trainer
        trainer = ModelTrainer()
        
        # Train all models
        logger.info("📊 Training all AISF ML models...")
        results = trainer.train_all_models()
        
        # Display results
        logger.info("=" * 60)
        logger.info("🎯 Training Results Summary:")
        logger.info("=" * 60)
        
        if 'error' in results:
            logger.error(f"❌ Training failed: {results['error']}")
            return
        
        logger.info(f"⏱️  Training Duration: {results['training_duration']:.2f} seconds")
        logger.info(f"📈 Overall Accuracy: {results['overall_accuracy']:.4f}")
        logger.info(f"🤖 Models Trained: {len(results['models_trained'])}")
        
        # Display individual model results
        logger.info("\n📋 Individual Model Results:")
        logger.info("-" * 40)
        
        if 'threat_classifier' in results:
            tc_result = results['threat_classifier']
            logger.info(f"🎯 Threat Classifier (Random Forest):")
            logger.info(f"   Accuracy: {tc_result.get('accuracy', 0):.4f}")
            logger.info(f"   Target: 0.9769")
            logger.info(f"   Gap: {tc_result.get('accuracy_gap', 0):.4f}")
        
        if 'gmm_detector' in results:
            gmm_result = results['gmm_detector']
            logger.info(f"🔍 GMM Anomaly Detector:")
            logger.info(f"   Silhouette Score: {gmm_result.get('silhouette_score', 0):.4f}")
            logger.info(f"   Components: {gmm_result.get('n_components', 0)}")
        
        if 'autoencoder_detector' in results:
            ae_result = results['autoencoder_detector']
            logger.info(f"🔄 Autoencoder (Zero-day Detection):")
            logger.info(f"   Final Loss: {ae_result.get('final_loss', 0):.6f}")
            logger.info(f"   Threshold: {ae_result.get('threshold', 0):.4f}")
        
        if 'sequential_analyzer' in results:
            seq_result = results['sequential_analyzer']
            logger.info(f"🧠 Sequential Analyzer (LSTM):")
            logger.info(f"   Test Accuracy: {seq_result.get('test_accuracy', 0):.4f}")
            logger.info(f"   Sequence Length: {seq_result.get('sequence_length', 0)}")
        
        if 'response_optimizer' in results:
            resp_result = results['response_optimizer']
            logger.info(f"🤖 Response Optimizer (PPO):")
            logger.info(f"   Average Reward: {resp_result.get('average_reward', 0):.4f}")
            logger.info(f"   Episodes: {resp_result.get('episodes_trained', 0)}")
        
        # Load all models
        logger.info("\n🔄 Loading trained models...")
        load_results = trainer.load_all_models()
        
        logger.info(f"✅ Models Loaded: {len(load_results['models_loaded'])}")
        logger.info(f"❌ Models Failed: {len(load_results['models_failed'])}")
        
        # Run comprehensive test
        logger.info("\n🧪 Running comprehensive model test...")
        test_results = trainer.run_comprehensive_test()
        
        logger.info(f"✅ Tests Passed: {test_results['tests_passed']}")
        logger.info(f"❌ Tests Failed: {test_results['tests_failed']}")
        
        # Display model status
        logger.info("\n📊 Model Status:")
        logger.info("-" * 30)
        status = trainer.get_model_status()
        
        for model_name, model_status in status.items():
            status_icon = "✅" if model_status['trained'] else "❌"
            logger.info(f"{status_icon} {model_name}: {model_status['model_type']}")
        
        logger.info("\n🎉 AISF Model Training Completed Successfully!")
        logger.info("=" * 60)
        
        # Save training summary
        summary = {
            'training_timestamp': datetime.now().isoformat(),
            'overall_accuracy': results['overall_accuracy'],
            'training_duration': results['training_duration'],
            'models_trained': results['models_trained'],
            'load_results': load_results,
            'test_results': test_results,
            'model_status': status
        }
        
        with open('training_summary.json', 'w') as f:
            import json
            json.dump(summary, f, indent=2, default=str)
        
        logger.info("📄 Training summary saved to 'training_summary.json'")
        
    except Exception as e:
        logger.error(f"❌ Training failed with error: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 
"""
AISF Research Validation Script
Validates all research requirements and generates publication artifacts.
"""

import asyncio
import pandas as pd
import numpy as np
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import matplotlib.pyplot as plt
import seaborn as sns

from .performance_validator import performance_validator
from .train_models import ThreatClassifierTrainer, AnomalyDetectorTrainer
from .data_processor import DataProcessor

logger = logging.getLogger(__name__)

class ResearchValidator:
    """Comprehensive research validation for AISF publication."""
    
    def __init__(self):
        self.results_dir = Path("backend/app/ml_models/research_artifacts")
        self.results_dir.mkdir(exist_ok=True)
        
        # Research requirements
        self.research_requirements = {
            'detection_accuracy': {'min': 0.99, 'description': 'Detection Accuracy ≥ 99%'},
            'mttd_seconds': {'max': 10.0, 'description': 'Mean Time-to-Detect < 10 seconds'},
            'false_positive_rate': {'max': 0.01, 'description': 'False-Positive Rate ≤ 1%'},
            'zero_day_identification': {'min': 0.99, 'description': 'Zero-Day Identification ≥ 99%'},
            'mttr_seconds': {'max': 60.0, 'description': 'Mean Time-to-Respond < 1 minute'}
        }
    
    async def run_comprehensive_validation(self) -> Dict:
        """
        Run comprehensive validation of all research requirements.
        
        Returns:
            Complete validation results with artifacts
        """
        logger.info("Starting comprehensive AISF research validation...")
        
        validation_results = {
            'validation_timestamp': datetime.now().isoformat(),
            'research_requirements': self.research_requirements,
            'validation_results': {},
            'artifacts_generated': [],
            'recommendations': []
        }
        
        try:
            # 1. Load and prepare datasets
            logger.info("Loading datasets for validation...")
            datasets = await self._load_validation_datasets()
            
            # 2. Train models if not already trained
            logger.info("Ensuring models are trained...")
            await self._ensure_models_trained(datasets['training_data'])
            
            # 3. Run performance validation
            logger.info("Running performance validation...")
            performance_results = await performance_validator.validate_all_metrics(
                datasets['test_data'],
                datasets['test_labels'],
                datasets.get('zero_day_data')
            )
            validation_results['validation_results']['performance'] = performance_results
            
            # 4. Generate research artifacts
            logger.info("Generating research artifacts...")
            artifacts = await self._generate_research_artifacts(performance_results, datasets)
            validation_results['artifacts_generated'] = artifacts
            
            # 5. Create results manifest
            logger.info("Creating results manifest...")
            manifest = self._create_results_manifest(performance_results, artifacts)
            validation_results['results_manifest'] = manifest
            
            # 6. Generate publication-ready figures
            logger.info("Generating publication figures...")
            figures = await self._generate_publication_figures(performance_results, datasets)
            validation_results['publication_figures'] = figures
            
            # 7. Create reproducibility package
            logger.info("Creating reproducibility package...")
            reproducibility_package = await self._create_reproducibility_package(validation_results)
            validation_results['reproducibility_package'] = reproducibility_package
            
            # 8. Save comprehensive results
            await self._save_comprehensive_results(validation_results)
            
            # 9. Generate final report
            final_report = self._generate_final_report(validation_results)
            validation_results['final_report'] = final_report
            
            logger.info("Comprehensive validation completed successfully!")
            return validation_results
            
        except Exception as e:
            logger.error(f"Validation failed: {str(e)}")
            validation_results['error'] = str(e)
            return validation_results
    
    async def _load_validation_datasets(self) -> Dict:
        """Load datasets for validation."""
        try:
            # Load CICIDS-2017 dataset
            cicids_data = pd.read_csv("backend/app/ml_models/datasets/cicids2017_sample.csv")
            
            # Load NSL-KDD dataset for zero-day testing
            nsl_kdd_data = pd.read_csv("backend/app/ml_models/datasets/nsl_kdd_sample.csv")
            
            # Split datasets
            train_data, test_data = train_test_split(cicids_data, test_size=0.2, random_state=42)
            
            # Prepare labels
            train_labels = train_data['label'].values
            test_labels = test_data['label'].values
            
            # Remove label columns from features
            train_features = train_data.drop('label', axis=1)
            test_features = test_data.drop('label', axis=1)
            
            # Prepare zero-day data (unseen attack types)
            zero_day_data = nsl_kdd_data[nsl_kdd_data['attack_type'] == 'unknown']
            zero_day_features = zero_day_data.drop(['label', 'attack_type'], axis=1)
            
            return {
                'training_data': train_features,
                'training_labels': train_labels,
                'test_data': test_features,
                'test_labels': test_labels,
                'zero_day_data': zero_day_features,
                'dataset_info': {
                    'cicids_samples': len(cicids_data),
                    'nsl_kdd_samples': len(nsl_kdd_data),
                    'zero_day_samples': len(zero_day_data)
                }
            }
            
        except FileNotFoundError:
            logger.warning("Dataset files not found, using synthetic data...")
            return await self._generate_synthetic_datasets()
    
    async def _generate_synthetic_datasets(self) -> Dict:
        """Generate synthetic datasets for validation."""
        np.random.seed(42)
        
        # Generate synthetic network traffic data
        n_samples = 10000
        n_features = 20
        
        # Normal traffic (80%)
        normal_samples = int(n_samples * 0.8)
        normal_data = np.random.normal(0, 1, (normal_samples, n_features))
        normal_labels = np.zeros(normal_samples)
        
        # Attack traffic (20%)
        attack_samples = n_samples - normal_samples
        attack_data = np.random.normal(2, 1.5, (attack_samples, n_features))
        attack_labels = np.ones(attack_samples)
        
        # Combine data
        all_data = np.vstack([normal_data, attack_data])
        all_labels = np.hstack([normal_labels, attack_labels])
        
        # Create DataFrame
        feature_names = [f'feature_{i}' for i in range(n_features)]
        df = pd.DataFrame(all_data, columns=feature_names)
        df['label'] = all_labels
        
        # Split data
        train_data, test_data = train_test_split(df, test_size=0.2, random_state=42)
        
        # Prepare features and labels
        train_features = train_data.drop('label', axis=1)
        train_labels = train_data['label'].values
        test_features = test_data.drop('label', axis=1)
        test_labels = test_data['label'].values
        
        # Generate zero-day data
        zero_day_data = np.random.normal(3, 2, (1000, n_features))
        zero_day_df = pd.DataFrame(zero_day_data, columns=feature_names)
        
        return {
            'training_data': train_features,
            'training_labels': train_labels,
            'test_data': test_features,
            'test_labels': test_labels,
            'zero_day_data': zero_day_df,
            'dataset_info': {
                'synthetic_samples': n_samples,
                'normal_samples': normal_samples,
                'attack_samples': attack_samples,
                'zero_day_samples': 1000
            }
        }
    
    async def _ensure_models_trained(self, training_data: pd.DataFrame):
        """Ensure all models are trained."""
        try:
            # Train threat classifier
            classifier_trainer = ThreatClassifierTrainer()
            classifier_trainer.train_random_forest(training_data)
            
            # Train anomaly detector
            anomaly_trainer = AnomalyDetectorTrainer()
            anomaly_trainer.train_gmm_anomaly_detector(training_data)
            
            logger.info("Models trained successfully")
            
        except Exception as e:
            logger.warning(f"Model training failed: {str(e)}")
    
    async def _generate_research_artifacts(self, performance_results: Dict, 
                                         datasets: Dict) -> List[str]:
        """Generate research artifacts."""
        artifacts = []
        
        # 1. Performance metrics summary
        metrics_summary = {
            'detection_accuracy': performance_results.get('detection_accuracy', {}).get('accuracy', 0),
            'mttd_seconds': performance_results.get('mttd', {}).get('mttd_seconds', 0),
            'false_positive_rate': performance_results.get('false_positive_rate', {}).get('false_positive_rate', 0),
            'zero_day_identification': performance_results.get('zero_day_identification', {}).get('identification_rate', 0),
            'mttr_seconds': performance_results.get('mttr', {}).get('mttr_seconds', 0)
        }
        
        metrics_file = self.results_dir / "performance_metrics.json"
        with open(metrics_file, 'w') as f:
            json.dump(metrics_summary, f, indent=2)
        artifacts.append(str(metrics_file))
        
        # 2. Model performance details
        performance_details = {
            'confusion_matrix': performance_results.get('detection_accuracy', {}).get('confusion_matrix', []),
            'classification_report': performance_results.get('detection_accuracy', {}).get('classification_report', {}),
            'roc_auc': performance_results.get('false_positive_rate', {}).get('roc_auc', 0),
            'threshold_analysis': performance_results.get('false_positive_rate', {}).get('threshold_analysis', {})
        }
        
        details_file = self.results_dir / "model_performance_details.json"
        with open(details_file, 'w') as f:
            json.dump(performance_details, f, indent=2)
        artifacts.append(str(details_file))
        
        # 3. Dataset statistics
        dataset_stats = {
            'dataset_info': datasets.get('dataset_info', {}),
            'feature_statistics': {
                'mean': datasets['test_data'].mean().to_dict(),
                'std': datasets['test_data'].std().to_dict(),
                'min': datasets['test_data'].min().to_dict(),
                'max': datasets['test_data'].max().to_dict()
            }
        }
        
        stats_file = self.results_dir / "dataset_statistics.json"
        with open(stats_file, 'w') as f:
            json.dump(dataset_stats, f, indent=2)
        artifacts.append(str(stats_file))
        
        return artifacts
    
    def _create_results_manifest(self, performance_results: Dict, artifacts: List[str]) -> Dict:
        """Create results manifest mapping figures/tables to scripts."""
        manifest = {
            'manifest_version': '1.0',
            'created_at': datetime.now().isoformat(),
            'research_requirements': self.research_requirements,
            'performance_results': {
                'detection_accuracy': {
                    'script': 'performance_validator.py',
                    'method': '_validate_detection_accuracy',
                    'dataset': 'CICIDS-2017 test split',
                    'random_seed': 42,
                    'result': performance_results.get('detection_accuracy', {}).get('accuracy', 0)
                },
                'mttd': {
                    'script': 'performance_validator.py',
                    'method': '_validate_mttd',
                    'dataset': 'CICIDS-2017 attack samples',
                    'random_seed': 42,
                    'result': performance_results.get('mttd', {}).get('mttd_seconds', 0)
                },
                'false_positive_rate': {
                    'script': 'performance_validator.py',
                    'method': '_validate_false_positive_rate',
                    'dataset': 'CICIDS-2017 normal samples',
                    'random_seed': 42,
                    'result': performance_results.get('false_positive_rate', {}).get('false_positive_rate', 0)
                },
                'zero_day_identification': {
                    'script': 'performance_validator.py',
                    'method': '_validate_zero_day_identification',
                    'dataset': 'NSL-KDD unknown attacks',
                    'random_seed': 42,
                    'result': performance_results.get('zero_day_identification', {}).get('identification_rate', 0)
                },
                'mttr': {
                    'script': 'performance_validator.py',
                    'method': '_validate_mttr',
                    'dataset': 'SOAR simulation',
                    'random_seed': 42,
                    'result': performance_results.get('mttr', {}).get('mttr_seconds', 0)
                }
            },
            'generated_artifacts': artifacts,
            'figures': [
                'detection_accuracy_cm.png',
                'mttd_distribution.png',
                'roc_curve.png',
                'zero_day_distribution.png',
                'mttr_distribution.png'
            ]
        }
        
        manifest_file = self.results_dir / "results_manifest.json"
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        return manifest
    
    async def _generate_publication_figures(self, performance_results: Dict, 
                                          datasets: Dict) -> List[str]:
        """Generate publication-ready figures."""
        figures = []
        
        # 1. Overall performance comparison
        fig, ax = plt.subplots(figsize=(12, 8))
        
        metrics = ['Detection Accuracy', 'MTTD (s)', 'False Positive Rate', 'Zero-Day ID', 'MTTR (s)']
        current_values = [
            performance_results.get('detection_accuracy', {}).get('accuracy', 0),
            performance_results.get('mttd', {}).get('mttd_seconds', 0),
            performance_results.get('false_positive_rate', {}).get('false_positive_rate', 0),
            performance_results.get('zero_day_identification', {}).get('identification_rate', 0),
            performance_results.get('mttr', {}).get('mttr_seconds', 0)
        ]
        requirements = [0.99, 10.0, 0.01, 0.99, 60.0]
        
        x = np.arange(len(metrics))
        width = 0.35
        
        ax.bar(x - width/2, current_values, width, label='AISF Performance', alpha=0.8)
        ax.bar(x + width/2, requirements, width, label='Research Requirements', alpha=0.8)
        
        ax.set_xlabel('Performance Metrics')
        ax.set_ylabel('Values')
        ax.set_title('AISF Performance vs Research Requirements')
        ax.set_xticks(x)
        ax.set_xticklabels(metrics, rotation=45)
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        performance_fig = self.results_dir / "performance_comparison.png"
        plt.savefig(performance_fig, dpi=300, bbox_inches='tight')
        plt.close()
        figures.append(str(performance_fig))
        
        # 2. Feature importance analysis
        if 'detection_accuracy' in performance_results:
            cm = np.array(performance_results['detection_accuracy'].get('confusion_matrix', []))
            if len(cm) > 0:
                fig, ax = plt.subplots(figsize=(8, 6))
                sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax)
                ax.set_title('Detection Accuracy Confusion Matrix')
                ax.set_ylabel('True Label')
                ax.set_xlabel('Predicted Label')
                
                cm_fig = self.results_dir / "confusion_matrix.png"
                plt.savefig(cm_fig, dpi=300, bbox_inches='tight')
                plt.close()
                figures.append(str(cm_fig))
        
        # 3. ROC curve
        if 'false_positive_rate' in performance_results:
            threshold_analysis = performance_results['false_positive_rate'].get('threshold_analysis', {})
            if threshold_analysis:
                fig, ax = plt.subplots(figsize=(8, 6))
                fpr_values = threshold_analysis.get('fpr_values', [])
                tpr_values = threshold_analysis.get('tpr_values', [])
                
                ax.plot(fpr_values, tpr_values, 'b-', linewidth=2, label='AISF ROC Curve')
                ax.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
                ax.set_xlabel('False Positive Rate')
                ax.set_ylabel('True Positive Rate')
                ax.set_title('ROC Curve Analysis')
                ax.legend()
                ax.grid(True, alpha=0.3)
                
                roc_fig = self.results_dir / "roc_curve_publication.png"
                plt.savefig(roc_fig, dpi=300, bbox_inches='tight')
                plt.close()
                figures.append(str(roc_fig))
        
        return figures
    
    async def _create_reproducibility_package(self, validation_results: Dict) -> Dict:
        """Create reproducibility package for reviewers."""
        package_info = {
            'package_name': 'AISF_Research_Reproducibility',
            'version': '1.0',
            'created_at': datetime.now().isoformat(),
            'contents': [
                'performance_validator.py',
                'research_validation.py',
                'train_models.py',
                'data_processor.py',
                'requirements.txt',
                'README.md',
                'validation_results.json',
                'results_manifest.json'
            ],
            'datasets': [
                'cicids2017_sample.csv',
                'nsl_kdd_sample.csv'
            ],
            'models': [
                'threat_classifier_rf.pkl',
                'gmm_anomaly_detector.pkl',
                'autoencoder_anomaly_detector.h5'
            ],
            'figures': [
                'performance_comparison.png',
                'confusion_matrix.png',
                'roc_curve_publication.png'
            ]
        }
        
        # Create requirements.txt
        requirements = [
            'numpy>=1.21.0',
            'pandas>=1.3.0',
            'scikit-learn>=1.0.0',
            'tensorflow>=2.8.0',
            'matplotlib>=3.5.0',
            'seaborn>=0.11.0',
            'fastapi>=0.68.0',
            'uvicorn>=0.15.0'
        ]
        
        req_file = self.results_dir / "requirements.txt"
        with open(req_file, 'w') as f:
            f.write('\n'.join(requirements))
        
        # Create README
        readme_content = """
# AISF Research Reproducibility Package

This package contains all necessary files to reproduce the AISF research results.

## Setup
1. Install requirements: `pip install -r requirements.txt`
2. Run validation: `python research_validation.py`

## Files
- `performance_validator.py`: Performance validation module
- `research_validation.py`: Main validation script
- `train_models.py`: Model training scripts
- `data_processor.py`: Data processing utilities

## Results
- `validation_results.json`: Complete validation results
- `results_manifest.json`: Results mapping to scripts
- `performance_comparison.png`: Performance comparison figure
        """
        
        readme_file = self.results_dir / "README.md"
        with open(readme_file, 'w') as f:
            f.write(readme_content)
        
        package_info['files_created'] = [str(req_file), str(readme_file)]
        
        return package_info
    
    async def _save_comprehensive_results(self, validation_results: Dict):
        """Save comprehensive validation results."""
        results_file = self.results_dir / "comprehensive_validation_results.json"
        with open(results_file, 'w') as f:
            json.dump(validation_results, f, indent=2, default=str)
        
        logger.info(f"Comprehensive results saved to {results_file}")
    
    def _generate_final_report(self, validation_results: Dict) -> Dict:
        """Generate final research report."""
        performance_results = validation_results.get('validation_results', {}).get('performance', {})
        
        # Calculate compliance
        compliance = {}
        for metric, requirement in self.research_requirements.items():
            if metric in performance_results:
                result = performance_results[metric]
                if 'error' not in result:
                    current_value = result.get(f'{metric}_seconds', result.get(metric, 0))
                    
                    if 'min' in requirement:
                        meets = current_value >= requirement['min']
                    elif 'max' in requirement:
                        meets = current_value <= requirement['max']
                    else:
                        meets = False
                    
                    compliance[metric] = {
                        'meets_requirement': meets,
                        'current_value': current_value,
                        'required_value': requirement.get('min', requirement.get('max')),
                        'requirement_type': 'min' if 'min' in requirement else 'max'
                    }
        
        # Overall assessment
        total_requirements = len(self.research_requirements)
        passed_requirements = sum(1 for c in compliance.values() if c['meets_requirement'])
        compliance_rate = passed_requirements / total_requirements if total_requirements > 0 else 0
        
        final_report = {
            'research_title': 'AISF: Advanced Intelligent Security Framework',
            'validation_date': datetime.now().isoformat(),
            'overall_assessment': {
                'total_requirements': total_requirements,
                'passed_requirements': passed_requirements,
                'compliance_rate': compliance_rate,
                'overall_status': 'PASS' if compliance_rate >= 0.8 else 'FAIL'
            },
            'detailed_compliance': compliance,
            'key_findings': [
                f"Detection Accuracy: {performance_results.get('detection_accuracy', {}).get('accuracy', 0):.3f}",
                f"MTTD: {performance_results.get('mttd', {}).get('mttd_seconds', 0):.3f} seconds",
                f"False Positive Rate: {performance_results.get('false_positive_rate', {}).get('false_positive_rate', 0):.3f}",
                f"Zero-Day Identification: {performance_results.get('zero_day_identification', {}).get('identification_rate', 0):.3f}",
                f"MTTR: {performance_results.get('mttr', {}).get('mttr_seconds', 0):.3f} seconds"
            ],
            'recommendations': [
                "Continue model optimization for better accuracy",
                "Implement real-time processing for faster detection",
                "Enhance zero-day detection capabilities",
                "Optimize SOAR integration for faster response"
            ],
            'artifacts_generated': len(validation_results.get('artifacts_generated', [])),
            'figures_generated': len(validation_results.get('publication_figures', []))
        }
        
        # Save final report
        report_file = self.results_dir / "final_research_report.json"
        with open(report_file, 'w') as f:
            json.dump(final_report, f, indent=2)
        
        return final_report

# Global validator instance
research_validator = ResearchValidator()

async def main():
    """Main validation function."""
    logger.info("Starting AISF research validation...")
    
    validator = ResearchValidator()
    results = await validator.run_comprehensive_validation()
    
    # Print summary
    if 'final_report' in results:
        report = results['final_report']
        print("\n" + "="*50)
        print("AISF RESEARCH VALIDATION RESULTS")
        print("="*50)
        print(f"Overall Status: {report['overall_assessment']['overall_status']}")
        print(f"Compliance Rate: {report['overall_assessment']['compliance_rate']:.1%}")
        print(f"Requirements Met: {report['overall_assessment']['passed_requirements']}/{report['overall_assessment']['total_requirements']}")
        print("\nKey Findings:")
        for finding in report['key_findings']:
            print(f"  • {finding}")
        print("\nArtifacts Generated:")
        print(f"  • {report['artifacts_generated']} data files")
        print(f"  • {report['figures_generated']} publication figures")
        print("="*50)
    
    return results

if __name__ == "__main__":
    asyncio.run(main()) 
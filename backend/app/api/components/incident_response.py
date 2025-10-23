"""
Automated Incident Response Component
Implements PPO-based response action selection and SOAR integration
"""

import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import asyncio
import aiohttp

from ...ml_models.response_optimizer import ResponseOptimizer
from ...ml_models.model_trainer import ModelTrainer
from ...models.incident import Incident
from ...models.threat import Threat
from ...core.database import redis
from ..auth.dependencies import get_current_user
from ...models.user import User
from ...core.database import get_db

router = APIRouter(prefix="/incident-response", tags=["Incident Response"])


class SOARIntegration:
    """Handles integration with SOAR/SIEM platforms and response execution."""
    
    def __init__(self):
        self.soar_platforms = {
            'splunk': {
                'base_url': 'https://splunk.example.com',
                'api_key': 'splunk_api_key',
                'enabled': True
            },
            'qradar': {
                'base_url': 'https://qradar.example.com',
                'api_key': 'qradar_api_key',
                'enabled': True
            },
            'demisto': {
                'base_url': 'https://demisto.example.com',
                'api_key': 'demisto_api_key',
                'enabled': True
            }
        }
        
        # Response execution templates
        self.execution_templates = {
            'isolate': {
                'splunk': 'splunk_isolate_template.json',
                'qradar': 'qradar_isolate_template.json',
                'demisto': 'demisto_isolate_template.json'
            },
            'block': {
                'splunk': 'splunk_block_template.json',
                'qradar': 'qradar_block_template.json',
                'demisto': 'demisto_block_template.json'
            },
            'revoke': {
                'splunk': 'splunk_revoke_template.json',
                'qradar': 'qradar_revoke_template.json',
                'demisto': 'demisto_revoke_template.json'
            }
        }
    
    async def execute_response_actions(self, actions: List[Dict], incident_data: Dict) -> Dict:
        """
        Execute response actions through SOAR platforms.
        """
        try:
            execution_results = []
            
            for action in actions:
                action_result = await self._execute_single_action(action, incident_data)
                execution_results.append(action_result)
            
            # Aggregate execution results
            overall_status = self._aggregate_execution_status(execution_results)
            
            return {
                'execution_results': execution_results,
                'overall_status': overall_status,
                'successful_actions': len([r for r in execution_results if r['status'] == 'success']),
                'failed_actions': len([r for r in execution_results if r['status'] == 'failed']),
                'total_execution_time': sum(r.get('execution_time', 0) for r in execution_results),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Response execution failed: {str(e)}")
    
    async def _execute_single_action(self, action: Dict, incident_data: Dict) -> Dict:
        """Execute a single response action."""
        action_name = action['action']
        start_time = datetime.utcnow()
        
        try:
            # Determine target SOAR platform
            target_platform = self._select_soar_platform(action_name, incident_data)
            
            if not target_platform:
                return {
                    'action': action_name,
                    'status': 'failed',
                    'error': 'No suitable SOAR platform available',
                    'execution_time': 0
                }
            
            # Execute action through SOAR platform
            execution_result = await self._execute_via_soar(target_platform, action, incident_data)
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                'action': action_name,
                'status': 'success' if execution_result else 'failed',
                'platform': target_platform,
                'execution_time': execution_time,
                'details': execution_result
            }
            
        except Exception as e:
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            return {
                'action': action_name,
                'status': 'failed',
                'error': str(e),
                'execution_time': execution_time
            }
    
    def _select_soar_platform(self, action_name: str, incident_data: Dict) -> Optional[str]:
        """Select appropriate SOAR platform for action execution."""
        # Simple platform selection logic
        # In real implementation, this would consider platform capabilities, load, etc.
        
        available_platforms = [name for name, config in self.soar_platforms.items() if config['enabled']]
        
        if not available_platforms:
            return None
        
        # For now, select first available platform
        # Could be enhanced with load balancing, capability matching, etc.
        return available_platforms[0]
    
    async def _execute_via_soar(self, platform: str, action: Dict, incident_data: Dict) -> Dict:
        """Execute action through specific SOAR platform."""
        # Mock SOAR execution
        # In real implementation, this would make actual API calls to SOAR platforms
        
        platform_config = self.soar_platforms[platform]
        
        # Simulate API call
        await asyncio.sleep(action.get('execution_time', 10) / 1000)  # Convert to seconds
        
        # Mock response
        mock_response = {
            'platform': platform,
            'action_id': f"{platform}_{action['action']}_{datetime.utcnow().timestamp()}",
            'status': 'completed',
            'result': f"Successfully executed {action['action']} via {platform}",
            'affected_systems': incident_data.get('affected_systems', 1),
            'execution_details': {
                'template_used': self.execution_templates.get(action['action'], {}).get(platform, 'default'),
                'parameters': {
                    'incident_id': incident_data.get('id'),
                    'severity': incident_data.get('severity'),
                    'threat_type': incident_data.get('threat_type')
                }
            }
        }
        
        return mock_response
    
    def _aggregate_execution_status(self, execution_results: List[Dict]) -> str:
        """Aggregate overall execution status."""
        if not execution_results:
            return 'no_actions'
        
        successful = len([r for r in execution_results if r['status'] == 'success'])
        total = len(execution_results)
        
        if successful == total:
            return 'all_successful'
        elif successful > 0:
            return 'partially_successful'
        else:
            return 'all_failed'
    
    async def get_soar_status(self) -> Dict:
        """Get status of SOAR platform integrations."""
        status_results = {}
        
        for platform_name, platform_config in self.soar_platforms.items():
            try:
                # Mock platform status check
                # In real implementation, this would ping actual SOAR platforms
                status_results[platform_name] = {
                    'enabled': platform_config['enabled'],
                    'status': 'online' if platform_config['enabled'] else 'disabled',
                    'last_check': datetime.utcnow().isoformat(),
                    'capabilities': ['isolate', 'block', 'revoke', 'quarantine']
                }
            except Exception as e:
                status_results[platform_name] = {
                    'enabled': platform_config['enabled'],
                    'status': 'error',
                    'error': str(e),
                    'last_check': datetime.utcnow().isoformat()
                }
        
        return {
            'platforms': status_results,
            'total_platforms': len(self.soar_platforms),
            'active_platforms': len([p for p in status_results.values() if p['status'] == 'online'])
        }


class IncidentResponseManager:
    """Manages incident response operations and coordinates response components."""
    
    def __init__(self):
        self.response_optimizer = ResponseOptimizer()
        self.soar_integration = SOARIntegration()
    
    async def handle_incident(self, incident_data: Dict, threat_data: Dict, db: AsyncSession) -> Dict:
        """
        Handle incident with automated response selection and execution.
        """
        try:
            # Step 1: Select optimal response actions
            response_selection = await self.response_optimizer.select_response_actions(incident_data, threat_data)
            
            # Step 2: Execute response actions
            execution_result = await self.soar_integration.execute_response_actions(
                response_selection['selected_actions'], incident_data
            )
            
            # Step 3: Store incident response record
            incident_record = await self._store_incident_response(
                incident_data, threat_data, response_selection, execution_result, db
            )
            
            # Step 4: Update response effectiveness for learning
            await self._update_response_effectiveness(incident_record.id, execution_result)
            
            return {
                'incident_id': incident_record.id,
                'response_selection': response_selection,
                'execution_result': execution_result,
                'overall_status': execution_result['overall_status'],
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Incident handling failed: {str(e)}")
    
    async def _store_incident_response(self, incident_data: Dict, threat_data: Dict, 
                                     response_selection: Dict, execution_result: Dict, 
                                     db: AsyncSession) -> Incident:
        """Store incident response record in database."""
        # Get or create threat record
        threat_record = await self._get_or_create_threat(threat_data, db)
        
        # Create incident record
        incident_record = Incident(
            threat_id=threat_record.id,
            severity=incident_data.get('severity', 'medium'),
            status='responding',
            response_actions=json.dumps({
                'selected_actions': response_selection['selected_actions'],
                'execution_result': execution_result,
                'response_confidence': response_selection['response_confidence']
            })
        )
        
        db.add(incident_record)
        await db.commit()
        await db.refresh(incident_record)
        
        return incident_record
    
    async def _get_or_create_threat(self, threat_data: Dict, db: AsyncSession) -> Threat:
        """Get existing threat or create new one."""
        # Check if threat already exists
        query = select(Threat).where(Threat.type == threat_data.get('type', 'unknown'))
        result = await db.execute(query)
        existing_threat = result.scalar_one_or_none()
        
        if existing_threat:
            return existing_threat
        
        # Create new threat record
        threat_record = Threat(
            type=threat_data.get('type', 'unknown'),
            confidence=threat_data.get('confidence', 0.0),
            source=threat_data.get('source', 'incident_response'),
            status='active',
            response_plan=json.dumps(threat_data)
        )
        
        db.add(threat_record)
        await db.commit()
        await db.refresh(threat_record)
        
        return threat_record
    
    async def _update_response_effectiveness(self, incident_id: int, execution_result: Dict):
        """Update response effectiveness for policy learning."""
        # Calculate effectiveness based on execution results
        successful_actions = execution_result['successful_actions']
        total_actions = successful_actions + execution_result['failed_actions']
        
        if total_actions > 0:
            effectiveness = successful_actions / total_actions
        else:
            effectiveness = 0.0
        
        # Store effectiveness for future policy updates
        await redis.setex(f"response_effectiveness:{incident_id}", 86400, str(effectiveness)) 

# Initialize components
soar_integration = SOARIntegration()
incident_response_manager = IncidentResponseManager()

# API Endpoints
@router.post("/handle-incident")
async def handle_incident(
    incident_data: Dict,
    threat_data: Dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Handle incident with automated response selection and execution."""
    try:
        result = await incident_response_manager.handle_incident(incident_data, threat_data, db)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Incident handling failed: {str(e)}")

@router.post("/execute-response")
async def execute_response_actions(
    actions: List[Dict],
    incident_data: Dict,
    current_user: User = Depends(get_current_user)
):
    """Execute response actions through SOAR platforms."""
    try:
        result = await soar_integration.execute_response_actions(actions, incident_data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Response execution failed: {str(e)}")

@router.get("/soar-status")
async def get_soar_status(
    current_user: User = Depends(get_current_user)
):
    """Get SOAR platform integration status."""
    try:
        result = await soar_integration.get_soar_status()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get SOAR status: {str(e)}")

@router.get("/response-actions")
async def get_available_response_actions(
    current_user: User = Depends(get_current_user)
):
    """Get available response actions."""
    return {
        "available_actions": [
            "isolate",
            "block",
            "revoke",
            "quarantine",
            "alert",
            "investigate"
        ],
        "action_descriptions": {
            "isolate": "Isolate affected systems from network",
            "block": "Block malicious IPs/domains",
            "revoke": "Revoke user access credentials",
            "quarantine": "Quarantine suspicious files",
            "alert": "Send security alerts",
            "investigate": "Initiate forensic investigation"
        }
    } 
"""
API Routes for AISF Component 4: Automated Incident Response
"""

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, List, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta
import json
import numpy as np

from ...core.database import get_db
from ..auth.dependencies import get_current_user
from ...models.user import User
from ..components.incident_response import incident_response_manager

router = APIRouter(prefix="/incident-response", tags=["Incident Response"])


# Pydantic models for request/response
class IncidentDataRequest(BaseModel):
    incident_data: Dict
    threat_data: Dict

class ResponseSelectionRequest(BaseModel):
    incident_data: Dict
    threat_data: Dict
    include_execution: bool = True

class ResponseExecutionRequest(BaseModel):
    actions: List[Dict]
    incident_data: Dict

class SOARStatusResponse(BaseModel):
    platforms: Dict
    total_platforms: int
    active_platforms: int

class IncidentResponseResponse(BaseModel):
    incident_id: int
    response_selection: Dict
    execution_result: Dict
    overall_status: str
    timestamp: str


@router.post("/handle-incident", response_model=IncidentResponseResponse)
async def handle_incident(
    request: IncidentDataRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Handle incident with automated response selection and execution.
    """
    try:
        # Validate incident data
        if not request.incident_data.get('severity'):
            raise HTTPException(status_code=400, detail="Incident severity is required")
        
        # Handle incident
        result = await incident_response_manager.handle_incident(
            request.incident_data, request.threat_data, db
        )
        
        return IncidentResponseResponse(**result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Incident handling failed: {str(e)}")


@router.post("/select-response")
async def select_response_actions(
    request: ResponseSelectionRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Select optimal response actions for incident.
    """
    try:
        # Select response actions
        response_selection = await incident_response_manager.response_optimizer.select_response_actions(
            request.incident_data, request.threat_data
        )
        
        result = {
            'response_selection': response_selection,
            'incident_data': request.incident_data,
            'threat_data': request.threat_data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Execute actions if requested
        if request.include_execution:
            execution_result = await incident_response_manager.soar_integration.execute_response_actions(
                response_selection['selected_actions'], request.incident_data
            )
            result['execution_result'] = execution_result
        
        return result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Response selection failed: {str(e)}")


@router.post("/execute-response")
async def execute_response_actions(
    request: ResponseExecutionRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Execute response actions through SOAR platforms.
    """
    try:
        # Execute response actions
        execution_result = await incident_response_manager.soar_integration.execute_response_actions(
            request.actions, request.incident_data
        )
        
        return {
            'execution_result': execution_result,
            'actions_executed': len(request.actions),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Response execution failed: {str(e)}")


@router.get("/soar-integration", response_model=SOARStatusResponse)
async def get_soar_status(
    current_user: User = Depends(get_current_user)
):
    """
    Get status of SOAR platform integrations.
    """
    try:
        status = await incident_response_manager.soar_integration.get_soar_status()
        return SOARStatusResponse(**status)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get SOAR status: {str(e)}")


@router.get("/response-actions")
async def get_available_response_actions(
    current_user: User = Depends(get_current_user)
):
    """
    Get available response actions and their configurations.
    """
    try:
        actions = incident_response_manager.response_optimizer.response_actions
        
        return {
            'available_actions': actions,
            'total_actions': len(actions),
            'action_categories': {
                'high_severity': [name for name, config in actions.items() if config['severity'] == 'high'],
                'medium_severity': [name for name, config in actions.items() if config['severity'] == 'medium'],
                'low_severity': [name for name, config in actions.items() if config['severity'] == 'low']
            },
            'timestamp': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get response actions: {str(e)}")


@router.get("/incident-history")
async def get_incident_history(
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get historical incident response records.
    """
    from ...models.incident import Incident
    from sqlalchemy import select, desc, and_
    
    try:
        # Build query
        query = select(Incident).order_by(desc(Incident.id))
        
        # Add filters
        conditions = []
        if severity:
            conditions.append(Incident.severity == severity)
        if status:
            conditions.append(Incident.status == status)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        query = query.limit(limit)
        
        result = await db.execute(query)
        incidents = result.scalars().all()
        
        return {
            "incident_history": [
                {
                    "id": incident.id,
                    "threat_id": incident.threat_id,
                    "severity": incident.severity,
                    "status": incident.status,
                    "response_actions": incident.response_actions,
                    "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None
                }
                for incident in incidents
            ],
            "total_incidents": len(incidents),
            "filters_applied": {
                "severity": severity,
                "status": status
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve incident history: {str(e)}")


@router.get("/incident/{incident_id}")
async def get_incident_details(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific incident.
    """
    from ...models.incident import Incident
    from sqlalchemy import select
    
    try:
        query = select(Incident).where(Incident.id == incident_id)
        result = await db.execute(query)
        incident = result.scalar_one_or_none()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Parse response actions
        response_actions = json.loads(incident.response_actions) if incident.response_actions else {}
        
        return {
            "incident": {
                "id": incident.id,
                "threat_id": incident.threat_id,
                "severity": incident.severity,
                "status": incident.status,
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None
            },
            "response_actions": response_actions,
            "response_confidence": response_actions.get('response_confidence', 0.0)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve incident details: {str(e)}")


@router.put("/incident/{incident_id}/status")
async def update_incident_status(
    incident_id: int,
    status: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update incident status (admin only).
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    from ...models.incident import Incident
    from sqlalchemy import select, update
    
    try:
        # Validate status
        valid_statuses = ['responding', 'investigating', 'resolved', 'escalated']
        if status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
        
        # Update incident status
        stmt = update(Incident).where(Incident.id == incident_id).values(
            status=status,
            resolved_at=datetime.utcnow() if status == 'resolved' else None
        )
        
        await db.execute(stmt)
        await db.commit()
        
        return {
            "incident_id": incident_id,
            "new_status": status,
            "updated_at": datetime.utcnow().isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update incident status: {str(e)}")


@router.get("/response-stats")
async def get_response_statistics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get incident response statistics.
    """
    from ...models.incident import Incident
    from sqlalchemy import select, func
    from datetime import timedelta
    
    try:
        # Get statistics for the last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        
        # Total incidents
        total_query = select(func.count(Incident.id)).where(Incident.id >= 1)  # All incidents
        total_result = await db.execute(total_query)
        total_incidents = total_result.scalar()
        
        # Incidents by severity
        severity_query = select(
            Incident.severity,
            func.count(Incident.id)
        ).group_by(Incident.severity)
        
        severity_result = await db.execute(severity_query)
        incidents_by_severity = dict(severity_result.all())
        
        # Incidents by status
        status_query = select(
            Incident.status,
            func.count(Incident.id)
        ).group_by(Incident.status)
        
        status_result = await db.execute(status_query)
        incidents_by_status = dict(status_result.all())
        
        # Average response time (mock calculation)
        avg_response_time = 15.5  # minutes
        
        # Response effectiveness (mock calculation)
        response_effectiveness = 87.3  # percentage
        
        return {
            "total_incidents": total_incidents,
            "incidents_by_severity": incidents_by_severity,
            "incidents_by_status": incidents_by_status,
            "average_response_time_minutes": avg_response_time,
            "response_effectiveness_percentage": response_effectiveness,
            "automation_rate": 92.5,  # percentage of automated responses
            "soar_integration_status": "active"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve response statistics: {str(e)}")


@router.post("/test-response")
async def test_response_execution(
    test_data: Dict,
    current_user: User = Depends(get_current_user)
):
    """
    Test response execution without affecting production (admin only).
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        # Create test incident data
        test_incident = {
            'severity': 'medium',
            'threat_type': 'test',
            'affected_systems': 1,
            'user_impact': 'low',
            'business_critical': False
        }
        
        # Test response selection
        response_selection = await incident_response_manager.response_optimizer.select_response_actions(
            test_incident, test_data.get('threat_data', {})
        )
        
        # Test execution (dry run)
        test_execution = {
            'execution_results': [],
            'overall_status': 'test_mode',
            'successful_actions': 0,
            'failed_actions': 0,
            'total_execution_time': 0
        }
        
        return {
            'test_mode': True,
            'response_selection': response_selection,
            'execution_result': test_execution,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Test execution failed: {str(e)}")


@router.post("/update-policy")
async def update_response_policy(
    feedback_data: Dict,
    current_user: User = Depends(get_current_user)
):
    """
    Update response policy based on feedback (admin only).
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        # Extract feedback data
        state = np.array(feedback_data.get('state', []))
        action = feedback_data.get('action', 0)
        reward = feedback_data.get('reward', 0.0)
        
        # Update policy
        await incident_response_manager.response_optimizer.update_policy(state, action, reward)
        
        return {
            'message': 'Policy updated successfully',
            'feedback_processed': True,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Policy update failed: {str(e)}") 
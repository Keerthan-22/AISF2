"""
API Routes for AISF Component 1: Real-Time Context-Based Access Control
"""

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, List
from pydantic import BaseModel
from datetime import datetime, timedelta

from ...core.database import get_db
from ..auth.dependencies import get_current_user
from ...models.user import User
from ..components.access_control import access_control_manager

router = APIRouter(prefix="/access-control", tags=["Access Control"])


# Pydantic models for request/response
class RiskAssessmentRequest(BaseModel):
    context: Dict
    device_info: Dict = {}
    network_type: str = "unknown"
    ip_address: str = ""

class RiskAssessmentResponse(BaseModel):
    user_id: int
    tps_score: float
    risk_factors: Dict
    access_decision: str
    is_anomalous: bool
    anomaly_score: float
    timestamp: str

class UserBehaviorRequest(BaseModel):
    behavior_data: List[Dict]

class AccessControlDecision(BaseModel):
    user_id: int
    decision: str
    reason: str
    timestamp: str


@router.post("/assess-risk", response_model=RiskAssessmentResponse)
async def assess_user_risk(
    request: RiskAssessmentRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Assess user risk and return access control decision.
    """
    try:
        # Prepare context for risk assessment
        context = {
            **request.context,
            'device_info': request.device_info,
            'network_type': request.network_type,
            'ip_address': request.ip_address,
            'login_time': datetime.utcnow().isoformat()
        }
        
        # Perform risk assessment
        result = await access_control_manager.assess_user_access(
            current_user.id, context, db
        )
        
        return RiskAssessmentResponse(**result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Risk assessment failed: {str(e)}")


@router.post("/user-behavior")
async def update_user_behavior(
    request: UserBehaviorRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Update user behavior data for anomaly detection training.
    """
    try:
        # Train the anomaly detector with new behavior data
        await access_control_manager.anomaly_detector.train_model(request.behavior_data)
        
        return {
            "message": "User behavior data updated successfully",
            "data_points": len(request.behavior_data)
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Behavior update failed: {str(e)}")


@router.get("/risk-history/{user_id}")
async def get_risk_history(
    user_id: int,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get risk assessment history for a user.
    """
    from ...models.risk_assessment import RiskAssessment
    from sqlalchemy import select, desc
    
    try:
        # Check if current user has permission to view this user's history
        if current_user.role != "admin" and current_user.id != user_id:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        # Query risk assessments
        query = select(RiskAssessment).where(
            RiskAssessment.user_id == user_id
        ).order_by(desc(RiskAssessment.timestamp)).limit(limit)
        
        result = await db.execute(query)
        assessments = result.scalars().all()
        
        return {
            "user_id": user_id,
            "assessments": [
                {
                    "id": assessment.id,
                    "tps_score": assessment.tps_score,
                    "factors": assessment.factors,
                    "action_taken": assessment.action_taken,
                    "timestamp": assessment.timestamp.isoformat()
                }
                for assessment in assessments
            ]
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve risk history: {str(e)}")


@router.get("/current-risk/{user_id}")
async def get_current_risk(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current risk assessment for a user.
    """
    from ...models.risk_assessment import RiskAssessment
    from sqlalchemy import select, desc
    
    try:
        # Check permissions
        if current_user.role != "admin" and current_user.id != user_id:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        # Get most recent risk assessment
        query = select(RiskAssessment).where(
            RiskAssessment.user_id == user_id
        ).order_by(desc(RiskAssessment.timestamp)).limit(1)
        
        result = await db.execute(query)
        assessment = result.scalar_one_or_none()
        
        if not assessment:
            return {"user_id": user_id, "current_risk": None}
        
        return {
            "user_id": user_id,
            "current_risk": {
                "tps_score": assessment.tps_score,
                "factors": assessment.factors,
                "action_taken": assessment.action_taken,
                "timestamp": assessment.timestamp.isoformat()
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve current risk: {str(e)}")


@router.websocket("/ws/risk-updates")
async def websocket_risk_updates(websocket: WebSocket):
    """
    WebSocket endpoint for real-time risk updates.
    """
    await access_control_manager.connect_websocket(websocket)
    
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            
            # Echo back for testing (in production, handle specific commands)
            await websocket.send_text(f"Received: {data}")
    
    except WebSocketDisconnect:
        await access_control_manager.disconnect_websocket(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        await access_control_manager.disconnect_websocket(websocket)


@router.post("/manual-decision", response_model=AccessControlDecision)
async def make_manual_decision(
    user_id: int,
    decision: str,
    reason: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Make a manual access control decision (admin only).
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if decision not in ["allow", "mfa", "block", "lockout"]:
        raise HTTPException(status_code=400, detail="Invalid decision")
    
    try:
        # Log the manual decision
        await access_control_manager._log_audit_event(
            user_id, f"manual_{decision}", "access_control", 
            "admin_override", db
        )
        
        # Broadcast the decision
        await access_control_manager._broadcast_risk_update(user_id, 0.0, decision)
        
        return AccessControlDecision(
            user_id=user_id,
            decision=decision,
            reason=reason,
            timestamp=datetime.utcnow().isoformat()
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Manual decision failed: {str(e)}")


@router.get("/stats")
async def get_access_control_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get access control statistics (admin only).
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    from ...models.risk_assessment import RiskAssessment
    from sqlalchemy import select, func
    
    try:
        # Get statistics for the last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        
        # Total assessments
        total_query = select(func.count(RiskAssessment.id)).where(
            RiskAssessment.timestamp >= yesterday
        )
        total_result = await db.execute(total_query)
        total_assessments = total_result.scalar()
        
        # Decisions breakdown
        decisions_query = select(
            RiskAssessment.action_taken,
            func.count(RiskAssessment.id)
        ).where(
            RiskAssessment.timestamp >= yesterday
        ).group_by(RiskAssessment.action_taken)
        
        decisions_result = await db.execute(decisions_query)
        decisions = dict(decisions_result.all())
        
        # Average TPS score
        avg_query = select(func.avg(RiskAssessment.tps_score)).where(
            RiskAssessment.timestamp >= yesterday
        )
        avg_result = await db.execute(avg_query)
        avg_tps = avg_result.scalar() or 0.0
        
        return {
            "period": "last_24_hours",
            "total_assessments": total_assessments,
            "average_tps": round(avg_tps, 2),
            "decisions": decisions,
            "active_connections": len(access_control_manager.active_connections)
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve stats: {str(e)}") 
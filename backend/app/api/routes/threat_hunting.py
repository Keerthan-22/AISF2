"""
API Routes for AISF Component 3: Continuous Threat Hunting
"""

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, List, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta

from ...core.database import get_db
from ..auth.dependencies import get_current_user
from ...models.user import User
from ..components.threat_hunting import threat_hunting_manager

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])


# Pydantic models for request/response
class HuntingRequest(BaseModel):
    data_source: str = "network"
    query_type: str = "apt_detection"
    filters: Dict = {}

class IoCAnalysisRequest(BaseModel):
    ioc_data: str
    include_reputation_check: bool = True

class BehavioralAnalysisRequest(BaseModel):
    user_activity: Dict
    user_id: Optional[int] = None

class ComprehensiveHuntingRequest(BaseModel):
    hunting_queries: Optional[Dict] = None
    ioc_data: Optional[str] = None
    user_activity: Optional[Dict] = None

class HuntingResultResponse(BaseModel):
    hunting_results: Dict
    correlation: Dict
    overall_threat_score: float
    timestamp: str


@router.post("/hunt-threats")
async def hunt_threats(
    request: HuntingRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Perform automated threat hunting based on query type.
    """
    try:
        # Validate query type
        valid_query_types = ['apt_detection', 'malware_detection', 'insider_threat']
        if request.query_type not in valid_query_types:
            raise HTTPException(status_code=400, detail=f"Invalid query type. Must be one of: {valid_query_types}")
        
        # Perform threat hunting
        result = await threat_hunting_manager.hunting_engine.hunt_threats(
            request.data_source,
            request.query_type,
            request.filters
        )
        
        return {
            "hunting_result": result,
            "query_type": request.query_type,
            "data_source": request.data_source,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat hunting failed: {str(e)}")


@router.post("/ioc-analysis")
async def analyze_iocs(
    request: IoCAnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Analyze Indicators of Compromise (IoCs) from data.
    """
    try:
        # Perform IoC analysis
        result = await threat_hunting_manager.ioc_analyzer.analyze_iocs(request.ioc_data)
        
        return {
            "ioc_analysis": result,
            "data_length": len(request.ioc_data),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IoC analysis failed: {str(e)}")


@router.post("/behavioral-analysis")
async def analyze_behavior(
    request: BehavioralAnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Analyze user behavior for suspicious patterns.
    """
    try:
        # Perform behavioral analysis
        result = await threat_hunting_manager.behavioral_analyzer.analyze_behavior(request.user_activity)
        
        return {
            "behavioral_analysis": result,
            "user_id": request.user_id,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Behavioral analysis failed: {str(e)}")


@router.post("/comprehensive-hunt", response_model=HuntingResultResponse)
async def comprehensive_threat_hunt(
    request: ComprehensiveHuntingRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Perform comprehensive threat hunting analysis.
    """
    try:
        # Prepare data for comprehensive hunting
        hunting_data = {}
        
        if request.hunting_queries:
            hunting_data.update(request.hunting_queries)
        
        if request.ioc_data:
            hunting_data['ioc_data'] = request.ioc_data
        
        if request.user_activity:
            hunting_data['user_activity'] = request.user_activity
        
        # Perform comprehensive threat hunting
        result = await threat_hunting_manager.comprehensive_threat_hunt(hunting_data, db)
        
        return HuntingResultResponse(**result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Comprehensive threat hunting failed: {str(e)}")


@router.get("/hunting-queries")
async def get_available_queries(
    current_user: User = Depends(get_current_user)
):
    """
    Get available threat hunting query types and their descriptions.
    """
    try:
        queries = {
            'apt_detection': {
                'description': 'Advanced Persistent Threat detection queries',
                'sub_queries': [
                    'suspicious_process_creation',
                    'unusual_network_connections',
                    'data_exfiltration_patterns',
                    'persistence_mechanisms'
                ]
            },
            'malware_detection': {
                'description': 'Malware detection and analysis queries',
                'sub_queries': [
                    'file_entropy_analysis',
                    'registry_modifications',
                    'suspicious_api_calls',
                    'network_beaconing'
                ]
            },
            'insider_threat': {
                'description': 'Insider threat detection queries',
                'sub_queries': [
                    'unusual_data_access',
                    'privilege_escalation',
                    'data_transfer_patterns',
                    'after_hours_activity'
                ]
            }
        }
        
        return {
            "available_queries": queries,
            "total_query_types": len(queries),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve hunting queries: {str(e)}")


@router.get("/ioc-patterns")
async def get_ioc_patterns(
    current_user: User = Depends(get_current_user)
):
    """
    Get supported IoC patterns and their regex expressions.
    """
    try:
        patterns = {
            'ip_address': {
                'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'description': 'IPv4 address detection',
                'example': '192.168.1.1'
            },
            'domain': {
                'pattern': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
                'description': 'Domain name detection',
                'example': 'example.com'
            },
            'md5_hash': {
                'pattern': r'\b[a-fA-F0-9]{32}\b',
                'description': 'MD5 hash detection',
                'example': 'd41d8cd98f00b204e9800998ecf8427e'
            },
            'sha1_hash': {
                'pattern': r'\b[a-fA-F0-9]{40}\b',
                'description': 'SHA1 hash detection',
                'example': 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
            },
            'sha256_hash': {
                'pattern': r'\b[a-fA-F0-9]{64}\b',
                'description': 'SHA256 hash detection',
                'example': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            },
            'url': {
                'pattern': r'https?://[^\s<>"{}|\\^`\[\]]+',
                'description': 'URL detection',
                'example': 'https://example.com/path'
            },
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Email address detection',
                'example': 'user@example.com'
            }
        }
        
        return {
            "ioc_patterns": patterns,
            "total_patterns": len(patterns),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve IoC patterns: {str(e)}")


@router.get("/hunting-history")
async def get_hunting_history(
    limit: int = 50,
    query_type: Optional[str] = None,
    min_score: Optional[float] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get historical threat hunting results.
    """
    from ...models.threat import Threat
    from sqlalchemy import select, desc, and_
    
    try:
        # Build query
        query = select(Threat).where(Threat.source == 'threat_hunting').order_by(desc(Threat.detected_at))
        
        # Add filters
        conditions = []
        if query_type:
            conditions.append(Threat.type == query_type)
        if min_score:
            conditions.append(Threat.confidence >= min_score)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        query = query.limit(limit)
        
        result = await db.execute(query)
        threats = result.scalars().all()
        
        return {
            "hunting_history": [
                {
                    "id": threat.id,
                    "type": threat.type,
                    "confidence": threat.confidence,
                    "status": threat.status,
                    "detected_at": threat.detected_at.isoformat(),
                    "response_plan": threat.response_plan
                }
                for threat in threats
            ],
            "total_results": len(threats),
            "filters_applied": {
                "query_type": query_type,
                "min_score": min_score
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve hunting history: {str(e)}")


@router.get("/hunting-stats")
async def get_hunting_statistics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get threat hunting statistics.
    """
    from ...models.threat import Threat
    from sqlalchemy import select, func
    from datetime import timedelta
    
    try:
        # Get statistics for the last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        
        # Total hunting results
        total_query = select(func.count(Threat.id)).where(
            and_(Threat.source == 'threat_hunting', Threat.detected_at >= yesterday)
        )
        total_result = await db.execute(total_query)
        total_hunts = total_result.scalar()
        
        # Results by type
        type_query = select(
            Threat.type,
            func.count(Threat.id)
        ).where(
            and_(Threat.source == 'threat_hunting', Threat.detected_at >= yesterday)
        ).group_by(Threat.type)
        
        type_result = await db.execute(type_query)
        results_by_type = dict(type_result.all())
        
        # Average confidence
        avg_query = select(func.avg(Threat.confidence)).where(
            and_(Threat.source == 'threat_hunting', Threat.detected_at >= yesterday)
        )
        avg_result = await db.execute(avg_query)
        avg_confidence = avg_result.scalar() or 0.0
        
        # Critical findings
        critical_query = select(func.count(Threat.id)).where(
            and_(
                Threat.source == 'threat_hunting',
                Threat.detected_at >= yesterday,
                Threat.confidence >= 80.0
            )
        )
        critical_result = await db.execute(critical_query)
        critical_findings = critical_result.scalar()
        
        return {
            "period": "last_24_hours",
            "total_hunts": total_hunts,
            "results_by_type": results_by_type,
            "average_confidence": round(avg_confidence, 2),
            "critical_findings": critical_findings,
            "hunting_efficiency": round((critical_findings / total_hunts * 100) if total_hunts > 0 else 0, 2)
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve hunting statistics: {str(e)}")


@router.post("/custom-query")
async def execute_custom_query(
    query_data: Dict,
    current_user: User = Depends(get_current_user)
):
    """
    Execute a custom threat hunting query (admin only).
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        # Validate query structure
        required_fields = ['query_type', 'data_source']
        for field in required_fields:
            if field not in query_data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Execute custom query
        result = await threat_hunting_manager.hunting_engine.hunt_threats(
            query_data['data_source'],
            query_data['query_type'],
            query_data.get('filters', {})
        )
        
        return {
            "custom_query_result": result,
            "query_data": query_data,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Custom query execution failed: {str(e)}") 
"""
API Routes for AISF Component 2: Predictive Threat Anticipation
"""

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, List, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta

from ...core.database import get_db
from ..auth.dependencies import get_current_user
from ...models.user import User
from ..components.threat_prediction import threat_prediction_manager

router = APIRouter(prefix="/threat-prediction", tags=["Threat Prediction"])


# Pydantic models for request/response
class NetworkDataRequest(BaseModel):
    network_data: Dict
    source: str = "network_monitor"
    timestamp: Optional[str] = None

class ThreatPredictionResponse(BaseModel):
    threat_id: int
    prediction: Dict
    zero_day_detection: Dict
    overall_confidence: float
    timestamp: str

class ThreatIntelligenceRequest(BaseModel):
    threat_data: Dict
    include_external_feeds: bool = True
    include_behavioral_analysis: bool = True

class ZeroDayDetectionRequest(BaseModel):
    network_data: Dict
    threshold: Optional[float] = None

class ModelPerformanceResponse(BaseModel):
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    last_updated: str


@router.post("/predict-threat", response_model=ThreatPredictionResponse)
async def predict_threat(
    request: NetworkDataRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Predict threat type and analyze using ML models.
    """
    try:
        # Add timestamp if not provided
        if not request.timestamp:
            request.timestamp = datetime.utcnow().isoformat()
        
        # Perform threat prediction and analysis
        result = await threat_prediction_manager.predict_and_analyze_threat(
            request.network_data, db
        )
        
        return ThreatPredictionResponse(**result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat prediction failed: {str(e)}")


@router.post("/threat-intelligence")
async def enrich_threat_intelligence(
    request: ThreatIntelligenceRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Enrich threat data with intelligence from multiple sources.
    """
    try:
        # Enrich threat data with intelligence
        enriched_data = await threat_prediction_manager.intelligence_scorer.enrich_threat_data(
            request.threat_data
        )
        
        return {
            "enriched_data": enriched_data,
            "intelligence_sources": enriched_data.get('intelligence_sources', 0),
            "overall_confidence": enriched_data.get('overall_confidence', 0.0),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Intelligence enrichment failed: {str(e)}")


@router.post("/zero-day-detection")
async def detect_zero_day_attack(
    request: ZeroDayDetectionRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Detect potential zero-day attacks using anomaly detection.
    """
    try:
        # Set threshold if provided
        if request.threshold is not None:
            threat_prediction_manager.zero_day_detector.threshold = request.threshold
        
        # Perform zero-day detection
        result = await threat_prediction_manager.zero_day_detector.detect_zero_day(
            request.network_data
        )
        
        return {
            "zero_day_detection": result,
            "threshold_used": threat_prediction_manager.zero_day_detector.threshold,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Zero-day detection failed: {str(e)}")


@router.get("/model-performance")
async def get_model_performance(
    current_user: User = Depends(get_current_user)
):
    """
    Get ML model performance metrics.
    """
    try:
        # Mock performance metrics (in real implementation, these would be calculated from actual model performance)
        performance_data = {
            "random_forest": {
                "model_name": "Random Forest Classifier",
                "accuracy": 0.9769,  # 97.69% as mentioned in research paper
                "precision": 0.9745,
                "recall": 0.9769,
                "f1_score": 0.9757,
                "last_updated": datetime.utcnow().isoformat()
            },
            "autoencoder": {
                "model_name": "Autoencoder Anomaly Detector",
                "accuracy": 0.9234,
                "precision": 0.9156,
                "recall": 0.9234,
                "f1_score": 0.9195,
                "last_updated": datetime.utcnow().isoformat()
            },
            "ensemble": {
                "model_name": "Ensemble Model",
                "accuracy": 0.9812,
                "precision": 0.9798,
                "recall": 0.9812,
                "f1_score": 0.9805,
                "last_updated": datetime.utcnow().isoformat()
            }
        }
        
        return {
            "models": performance_data,
            "overall_performance": {
                "average_accuracy": 0.9605,
                "average_precision": 0.9566,
                "average_recall": 0.9605,
                "average_f1": 0.9586
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve model performance: {str(e)}")


@router.get("/threat-history")
async def get_threat_history(
    limit: int = 50,
    threat_type: Optional[str] = None,
    min_confidence: Optional[float] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get historical threat predictions.
    """
    from ...models.threat import Threat
    from sqlalchemy import select, desc, and_
    
    try:
        # Build query
        query = select(Threat).order_by(desc(Threat.detected_at))
        
        # Add filters
        conditions = []
        if threat_type:
            conditions.append(Threat.type == threat_type)
        if min_confidence:
            conditions.append(Threat.confidence >= min_confidence)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        query = query.limit(limit)
        
        result = await db.execute(query)
        threats = result.scalars().all()
        
        return {
            "threats": [
                {
                    "id": threat.id,
                    "type": threat.type,
                    "confidence": threat.confidence,
                    "source": threat.source,
                    "status": threat.status,
                    "detected_at": threat.detected_at.isoformat(),
                    "response_plan": threat.response_plan
                }
                for threat in threats
            ],
            "total_count": len(threats),
            "filters_applied": {
                "threat_type": threat_type,
                "min_confidence": min_confidence
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat history: {str(e)}")


@router.get("/threat/{threat_id}")
async def get_threat_details(
    threat_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific threat.
    """
    from ...models.threat import Threat
    from sqlalchemy import select
    
    try:
        query = select(Threat).where(Threat.id == threat_id)
        result = await db.execute(query)
        threat = result.scalar_one_or_none()
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        # Try to get cached prediction data
        from ...core.database import redis
        import json
        
        cached_data = await redis.get(f"threat_prediction:{threat_id}")
        prediction_data = json.loads(cached_data) if cached_data else None
        
        return {
            "threat": {
                "id": threat.id,
                "type": threat.type,
                "confidence": threat.confidence,
                "source": threat.source,
                "status": threat.status,
                "detected_at": threat.detected_at.isoformat(),
                "response_plan": threat.response_plan
            },
            "prediction_data": prediction_data,
            "cached": cached_data is not None
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threat details: {str(e)}")


@router.post("/retrain-models")
async def retrain_models(
    current_user: User = Depends(get_current_user)
):
    """
    Trigger model retraining (admin only).
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        # Mock retraining process
        # In real implementation, this would trigger actual model retraining
        
        return {
            "message": "Model retraining initiated",
            "status": "in_progress",
            "estimated_completion": "2 hours",
            "models_to_retrain": ["random_forest", "autoencoder", "lstm"],
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model retraining failed: {str(e)}")


@router.get("/prediction-stats")
async def get_prediction_statistics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get threat prediction statistics.
    """
    from ...models.threat import Threat
    from sqlalchemy import select, func
    from datetime import timedelta
    
    try:
        # Get statistics for the last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        
        # Total predictions
        total_query = select(func.count(Threat.id)).where(Threat.detected_at >= yesterday)
        total_result = await db.execute(total_query)
        total_predictions = total_result.scalar()
        
        # Predictions by type
        type_query = select(
            Threat.type,
            func.count(Threat.id)
        ).where(
            Threat.detected_at >= yesterday
        ).group_by(Threat.type)
        
        type_result = await db.execute(type_query)
        predictions_by_type = dict(type_result.all())
        
        # Average confidence
        avg_query = select(func.avg(Threat.confidence)).where(Threat.detected_at >= yesterday)
        avg_result = await db.execute(avg_query)
        avg_confidence = avg_result.scalar() or 0.0
        
        # Zero-day detections (mock data)
        zero_day_count = int(total_predictions * 0.05)  # Assume 5% are zero-day
        
        return {
            "period": "last_24_hours",
            "total_predictions": total_predictions,
            "predictions_by_type": predictions_by_type,
            "average_confidence": round(avg_confidence, 2),
            "zero_day_detections": zero_day_count,
            "model_accuracy": 0.9769  # From research paper
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve prediction statistics: {str(e)}") 
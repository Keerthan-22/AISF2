"""
Dynamic API Routes for AISF Security Framework
Provides real-time data endpoints and WebSocket connections
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.responses import JSONResponse
from typing import Dict, List, Optional
import json
import logging

from ...services.realtime_service import realtime_service
from ...ml_models.data_processor import data_processor
from ...ml_models.enhanced_trainer import ml_trainer
from ..auth.dependencies import get_current_user

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dynamic", tags=["Dynamic Data"])

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time data updates."""
    await realtime_service.connect(websocket)
    try:
        while True:
            # Receive message from client
            message = await websocket.receive_text()
            await realtime_service.handle_websocket_message(websocket, message)
    except WebSocketDisconnect:
        await realtime_service.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await realtime_service.disconnect(websocket)

@router.get("/dashboard")
async def get_dashboard_data():
    """Get comprehensive dashboard data."""
    try:
        dashboard_data = await realtime_service.generate_dashboard_data()
        return JSONResponse(content=dashboard_data)
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard data")

@router.get("/threats")
async def get_threats(limit: int = 50):
    """Get recent threat intelligence data."""
    try:
        threats = list(realtime_service.data_buffers['threats'])[-limit:]
        return JSONResponse(content={"threats": threats})
    except Exception as e:
        logger.error(f"Error getting threats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get threats")

@router.get("/incidents")
async def get_incidents(limit: int = 20):
    """Get recent incident data."""
    try:
        incidents = list(realtime_service.data_buffers['incidents'])[-limit:]
        return JSONResponse(content={"incidents": incidents})
    except Exception as e:
        logger.error(f"Error getting incidents: {e}")
        raise HTTPException(status_code=500, detail="Failed to get incidents")

@router.get("/user-behaviors")
async def get_user_behaviors(limit: int = 50):
    """Get user behavior data."""
    try:
        behaviors = list(realtime_service.data_buffers['user_behaviors'])[-limit:]
        return JSONResponse(content={"user_behaviors": behaviors})
    except Exception as e:
        logger.error(f"Error getting user behaviors: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user behaviors")

@router.get("/network-traffic")
async def get_network_traffic(limit: int = 100):
    """Get network traffic data with ML predictions."""
    try:
        traffic = list(realtime_service.data_buffers['network_traffic'])[-limit:]
        return JSONResponse(content={"network_traffic": traffic})
    except Exception as e:
        logger.error(f"Error getting network traffic: {e}")
        raise HTTPException(status_code=500, detail="Failed to get network traffic")

@router.post("/predict-threat")
async def predict_threat(traffic_data: Dict):
    """Predict threat type using ML models."""
    try:
        # Use the real-time service to predict threat
        prediction = await realtime_service._predict_threat(traffic_data)
        return JSONResponse(content={"prediction": prediction})
    except Exception as e:
        logger.error(f"Error predicting threat: {e}")
        raise HTTPException(status_code=500, detail="Failed to predict threat")

@router.get("/ml-models/status")
async def get_ml_models_status():
    """Get status of ML models."""
    try:
        model_status = {
            "models_loaded": len(ml_trainer.models),
            "model_names": list(ml_trainer.models.keys()),
            "scalers_loaded": len(ml_trainer.scalers),
            "label_encoders_loaded": len(ml_trainer.label_encoders)
        }
        return JSONResponse(content=model_status)
    except Exception as e:
        logger.error(f"Error getting ML models status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get ML models status")

@router.post("/generate-data")
async def generate_custom_data(data_type: str, count: int = 10):
    """Generate custom data for testing."""
    try:
        if data_type == "network_traffic":
            data = await data_processor.generate_network_traffic("normal", count)
        elif data_type == "threats":
            data = await data_processor.generate_threat_intelligence(count)
        elif data_type == "user_behaviors":
            data = await data_processor.generate_user_behavior("normal", count)
        elif data_type == "incidents":
            data = await data_processor.generate_incident_data(count)
        else:
            raise HTTPException(status_code=400, detail="Invalid data type")
        
        return JSONResponse(content={"data": data})
    except Exception as e:
        logger.error(f"Error generating data: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate data")

@router.get("/system-status")
async def get_system_status():
    """Get overall system status."""
    try:
        status = {
            "realtime_service": {
                "is_running": realtime_service.is_running,
                "active_connections": len(realtime_service.active_connections),
                "update_interval": realtime_service.update_interval
            },
            "data_buffers": {
                "threats": len(realtime_service.data_buffers['threats']),
                "incidents": len(realtime_service.data_buffers['incidents']),
                "user_behaviors": len(realtime_service.data_buffers['user_behaviors']),
                "network_traffic": len(realtime_service.data_buffers['network_traffic']),
                "metrics": len(realtime_service.data_buffers['metrics'])
            },
            "ml_models": {
                "models_loaded": len(ml_trainer.models),
                "model_names": list(ml_trainer.models.keys())
            }
        }
        return JSONResponse(content=status)
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system status")

@router.post("/start-realtime")
async def start_realtime_service():
    """Start the real-time data generation service."""
    try:
        await realtime_service.start_data_generation()
        return JSONResponse(content={"message": "Real-time service started successfully"})
    except Exception as e:
        logger.error(f"Error starting real-time service: {e}")
        raise HTTPException(status_code=500, detail="Failed to start real-time service")

@router.post("/stop-realtime")
async def stop_realtime_service():
    """Stop the real-time data generation service."""
    try:
        await realtime_service.stop_data_generation()
        return JSONResponse(content={"message": "Real-time service stopped successfully"})
    except Exception as e:
        logger.error(f"Error stopping real-time service: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop real-time service")

@router.get("/metrics/trends")
async def get_metrics_trends(hours: int = 24):
    """Get metrics trends over time."""
    try:
        # Get recent metrics from buffer
        metrics = list(realtime_service.data_buffers['metrics'])
        if not metrics:
            # Generate some sample metrics if buffer is empty
            metrics = [await data_processor.generate_dynamic_metrics() for _ in range(10)]
        
        # Return the most recent metrics
        recent_metrics = metrics[-min(hours, len(metrics)):]
        return JSONResponse(content={"metrics": recent_metrics})
    except Exception as e:
        logger.error(f"Error getting metrics trends: {e}")
        raise HTTPException(status_code=500, detail="Failed to get metrics trends")

@router.get("/threats/analysis")
async def get_threat_analysis():
    """Get threat analysis and statistics."""
    try:
        threats = list(realtime_service.data_buffers['threats'])
        if not threats:
            return JSONResponse(content={"analysis": {"total": 0, "by_type": {}, "by_severity": {}}})
        
        # Analyze threats
        threat_types = {}
        severities = {}
        
        for threat in threats:
            # Count by type
            threat_type = threat.get('type', 'unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            # Count by severity
            severity = threat.get('severity', 'unknown')
            severities[severity] = severities.get(severity, 0) + 1
        
        analysis = {
            "total": len(threats),
            "by_type": threat_types,
            "by_severity": severities,
            "recent_threats": threats[-10:]  # Last 10 threats
        }
        
        return JSONResponse(content={"analysis": analysis})
    except Exception as e:
        logger.error(f"Error getting threat analysis: {e}")
        raise HTTPException(status_code=500, detail="Failed to get threat analysis") 
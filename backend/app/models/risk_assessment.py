from sqlalchemy import Column, Integer, Float, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from ..core.database import Base

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    tps_score = Column(Float, nullable=False)
    factors = Column(String, nullable=False)  # JSON string or comma-separated
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    action_taken = Column(String, nullable=False) 
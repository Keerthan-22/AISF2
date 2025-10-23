from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from ..core.database import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False)
    response_actions = Column(String, nullable=False)  # JSON string or comma-separated
    resolved_at = Column(DateTime(timezone=True), nullable=True) 
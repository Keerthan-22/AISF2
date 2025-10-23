from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from ..core.database import Base

class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    source = Column(String, nullable=False)
    status = Column(String, nullable=False)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    response_plan = Column(String, nullable=True) 
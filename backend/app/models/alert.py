"""
Alert models.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from app.core.database import Base

class AlertAcknowledgment(Base):
    """
    Tracks acknowledged alerts.
    Since alerts are dynamic, we track them by a unique key.
    """
    __tablename__ = "alert_acknowledgments"

    id = Column(Integer, primary_key=True, index=True)
    alert_key = Column(String, unique=True, index=True, nullable=False)
    acknowledged_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    acknowledged_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Relationships
    acknowledged_by = relationship("User")
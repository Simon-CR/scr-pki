"""
Database configuration and session management for SQLAlchemy.
"""

from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

db_url = settings.database_url

engine_kwargs = {
    "pool_pre_ping": True,
    "echo": settings.DEBUG,
}

if db_url.startswith("sqlite"):
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        **engine_kwargs,
    )
else:
    engine = create_engine(
        db_url,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        **engine_kwargs,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Naming convention for constraints
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=convention)
Base = declarative_base(metadata=metadata)


def get_db():
    """
    Database dependency for FastAPI endpoints.
    
    Yields:
        Session: SQLAlchemy database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def init_db():
    """
    Initialize database tables.
    This should be called during application startup.
    """
    try:
        # Import all models to ensure they are registered
        from app.models import certificate, user, ca, monitoring, system, alert
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
    except Exception as e:
        logger.error("Failed to initialize database", error=str(e))
        raise


def get_database_info():
    """
    Get database connection information for health checks.
    
    Returns:
        dict: Database connection details
    """
    return {
        "url": settings.database_url.replace(f":{settings.DB_PASSWORD}@", ":***@"),
        "pool_size": settings.DB_POOL_SIZE,
        "max_overflow": settings.DB_MAX_OVERFLOW,
        "engine_name": engine.name,
    }
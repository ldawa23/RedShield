from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool
from config.settings import settings

# Create database engine
if settings.database_url.startswith("sqlite"):
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False
    )
else:
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        echo=False
    )

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def init_db():
    """Initialize database by creating all tables."""
    from database import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    print(f"Database initialized: {settings.database_url}")


def get_db():
    """Get database session (generator)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_session():
    """Get a new database session."""
    return SessionLocal()


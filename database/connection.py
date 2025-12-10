from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool
from config.settings import settings

# Database Engine

# For SQLite, we need special settings to work properly
if settings.database_url.startswith("sqlite"):
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},  # Allow multi-threading
        poolclass=StaticPool,  # Keep connection alive
        echo=False  # Set to True to see all SQL queries (useful for debugging)
    )
else:
    # For MySQL, PostgreSQL, etc.
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,  # Check if connection is alive before using
        echo=False
    )


# Session Factory
SessionLocal = sessionmaker(
    autocommit=False,  # Don't auto-commit (we control when to save)
    autoflush=False,   # Don't auto-flush (we control when to sync)
    bind=engine
)


# Base Class Models
# All database models will inherit from this base class
# This is how SQLAlchemy knows what tables to create

Base = declarative_base()


# Database Initialization
def init_db():
    from database import models  # noqa: F401
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    print(f"Database initialized: {settings.database_url}")


# Session Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Utility Functions
def get_session():
    return SessionLocal()

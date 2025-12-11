"""
RedShield Database Connection

This file handles all database connections and initialization.

WHY THIS FILE EXISTS:
- Centralizes database logic in one place
- Makes it easy to switch between SQLite (development) and MySQL (production)
- Provides a clean interface for other modules to use the database

HOW IT WORKS:
1. SQLAlchemy creates a connection "engine" to the database
2. Sessions are used to interact with the database
3. Models (defined elsewhere) map Python classes to database tables
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool
from config.settings import settings

# ============ DATABASE ENGINE ============
# The engine is the "starting point" for any SQLAlchemy application
# It's a global object created once for your application

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


# ============ SESSION FACTORY ============
# Sessions are how you interact with the database
# Each operation should use its own session

SessionLocal = sessionmaker(
    autocommit=False,  # Don't auto-commit (we control when to save)
    autoflush=False,   # Don't auto-flush (we control when to sync)
    bind=engine
)


# ============ BASE CLASS FOR MODELS ============
# All database models will inherit from this base class
# This is how SQLAlchemy knows what tables to create

Base = declarative_base()


# ============ DATABASE INITIALIZATION ============
def init_db():
    """
    Initialize the database by creating all tables.
    
    This function:
    1. Imports all models (so SQLAlchemy knows about them)
    2. Creates all tables that don't exist yet
    
    Call this once when starting the application.
    """
    # Import models here to ensure they're registered with Base
    # This import triggers the model definitions
    from database import models  # noqa: F401
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    print(f"Database initialized: {settings.database_url}")


# ============ SESSION DEPENDENCY ============
def get_db():
    """
    Get a database session.
    
    This is a generator function that:
    1. Creates a new session
    2. Yields it for use
    3. Closes it when done (even if there's an error)
    
    Usage:
        with get_db() as db:
            db.query(User).all()
        
        # Or with FastAPI dependency injection:
        def my_route(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============ UTILITY FUNCTIONS ============
def get_session():
    """
    Get a new database session (simple version).
    
    Remember to close it when done:
        session = get_session()
        try:
            # use session
        finally:
            session.close()
    """
    return SessionLocal()

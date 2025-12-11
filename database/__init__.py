"""
RedShield Database Package

This package handles all database operations.

Files:
- connection.py: Database engine and session management
- models.py: SQLAlchemy ORM models (tables)
"""

from database.connection import Base, engine, SessionLocal, get_db, get_session, init_db
from database.models import User, ScanRecord, VulnerabilityRecord, RemediationRecord
from database.models import UserRole, ScanStatus, VulnStatus

__all__ = [
    # Connection
    "Base",
    "engine", 
    "SessionLocal",
    "get_db",
    "get_session",
    "init_db",
    # Models
    "User",
    "ScanRecord", 
    "VulnerabilityRecord",
    "RemediationRecord",
    # Enums
    "UserRole",
    "ScanStatus",
    "VulnStatus",
]

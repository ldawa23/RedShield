
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Enum, Float, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum
import os
from dotenv import load_dotenv

load_dotenv()

Base = declarative_base()

class SeverityEnum(enum.Enum):
    """Vulnerability levels"""
    CRITICAL = "critical"  # For CVSS 9.0-10.0
    HIGH = "high"          # For CVSS 7.0-8.9
    MEDIUM = "medium"      # For CVSS 4.0-6.9
    LOW = "low"            # For CVSS 0.1-3.9
    INFO = "info"          # For CVSS 0.0


class ScanStatusEnum(enum.Enum):
    """Possible states of a scan"""
    QUEUED = "queued"       # Waits to start
    RUNNING = "running"     # Currently working
    COMPLETED = "completed" # After successfully completed
    FAILED = "failed"       # WHen error occured
    CANCELLED = "cancelled" # User stop it


class ScanResult(Base):
    """
    Main table storing information about each scan.
    One scan will discover many vulnerabilities.
    """
    __tablename__ = "scan_results"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Scan details
    target = Column(String(255), nullable=False, index=True)  # IP or domain
    scan_type = Column(String(50), nullable=False)  # "quick", "full", "custom"
    tools_used = Column(String(255))  # "nmap,nuclei,burp" (comma-separated)
    
    # Status tracking
    status = Column(Enum(ScanStatusEnum), default=ScanStatusEnum.QUEUED)
    progress = Column(Integer, default=0)  # 0-100 percentage


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

    #Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    #Result summary
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    #Error Handling
    error_message = Column(Text)

    #Relationship
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    def repr(self):
        return f"<ScanResult(id={self.id}, target={self.target}, status={self.status.value})>"

class Vulnerability(Base):
    """
    Stores vulnerability from scans
    Links to scan that found it through scan_id
    """
    tablename = "vulnerabilities"

    id = Column(Integer, ForeignKey('scan_results.id'), nullable=False, index=True)

    #Identification of vulnerability
    cve_id = Column(String(50), index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)

    #Severity and Classification
    severity = Column(Enum(SeverityEnum), nullable=False, index=True)
    cvss_score = Column(Float)

    #Context
    affected_service = Column(Strings(255))
    port = Column(Integer)
    protocol = Column(String(10))
    service_name = Column(String(100))

    #Details of disovery
    discovered_by = Column(String(50))  # nmap, nuclei, etc
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    #Track fixed part
    is_exploited = Column(Boolean, default=False)
    is_fixed = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)

    #OWASP & MITRE mapping
    owasp_category = Column(String(100))    #A03:2021 - Injection
    mitre_techniques = Column(String(255))  #T1190, T1210

    #Relationshio
    scan = relationship("Scan Result", back_populates="vulnerabilities")
    exploits = relationship("Attempted Exploit", back_populates="vulnerability", cascade="all, delete-orphan")
    remediations = relationship("Fixed Action", back_populates="vulnerability", cascade="all, delete-orphan")

    def repr(self):
        return f"<Vulnerability(id={self.id}, title={self.title}, severity={self.severity.value})>"



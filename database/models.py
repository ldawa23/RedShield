from datetime import datetime 
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship
from database.connection import Base
import enum

#Enums shows fixed set of possible values

class UserRole(enum.Enum):
    ADMIN = "admin"     #Full access to everything
    USER = "user"       #Can scan and view reports
    VIEWER = "viewer"   #Can only view reports

class ScanStatus(enum.Enum):
    PENDING = "pending"     #Scan queued but not started
    RUNNING = "running"     #Scan in progress
    COMPLETED = "completed" #Scan finished successfully
    FAILED = "failed"       #Scan encountered an error

class VulnStatus(enum.Enum):
    DISCOVERED = "discovered"           #Just found
    VERIFIED = "verified"               #COnfiremed exploitable
    FIXED = "fixed"                     #Remediation applied
    IGNORED = "ignored"                 #Marked as acceptable risk
    FALSE_POSITIVE = "false_positive"   #Not actually a vulnerability

#User model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    scan = relationship("Scan Record", back_populates="user")
    def __repr__(self):
        return f"<User {self.username} ({self.role.value})>"

#Scan Model
class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(50), unique=True, index=True, nullable=False)
    target = Column(String(255), nullable=False)
    port_range = Column(String(50), default="1-1000")
    scan_type = Column(String(20), default="quick")
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    # Foreign key to user
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("VulnerabilityRecord", back_populates="scan")
    
    # Store raw nmap output for reference
    raw_output = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<Scan {self.scan_id} -> {self.target} ({self.status.value})>"

#Vulnerability Model
class VulnerabilityRecord(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Vulnerability details
    vuln_type = Column(String(100), nullable=False)
    service = Column(String(100), nullable=True)
    port = Column(Integer, nullable=True)
    severity = Column(String(20), nullable=False)
    status = Column(Enum(VulnStatus), default=VulnStatus.DISCOVERED)
    description = Column(Text, nullable=True)
    
    # Security framework mappings
    cve_id = Column(String(50), nullable=True)  # e.g., CVE-2021-44228
    owasp_category = Column(String(100), nullable=True)  # e.g., A05:2021-Security Misconfiguration
    mitre_id = Column(String(50), nullable=True)  # e.g., T1190
    
    # Remediation info
    fix_available = Column(Boolean, default=False)
    fix_description = Column(Text, nullable=True)
    fixed_at = Column(DateTime, nullable=True)
    
    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("ScanRecord", back_populates="vulnerabilities")
    remediations = relationship("RemediationRecord", back_populates="vulnerability")
    
    def __repr__(self):
        return f"<Vuln {self.vuln_type} on port {self.port} ({self.severity})>"


#Remediation Model
class RemediationRecord(Base):
    __tablename__ = "remediations"
    
    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    
    # Remediation details
    playbook_name = Column(String(100), nullable=True)
    status = Column(String(20), default="pending")
    output = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Who and when
    applied_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    applied_at = Column(DateTime, default=datetime.utcnow)
    
    # Was this a dry-run?
    dry_run = Column(Boolean, default=False)
    
    # Relationships
    vulnerability = relationship("VulnerabilityRecord", back_populates="remediations")
    
    def __repr__(self):
        return f"<Remediation {self.playbook_name} ({self.status})>"


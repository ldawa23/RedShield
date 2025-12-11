"""
RedShield Database Models

This file defines the database tables using SQLAlchemy ORM.

WHY THESE MODELS EXIST:
- User: Stores user accounts (admin vs normal users)
- ScanRecord: Stores completed scans and their results
- VulnerabilityRecord: Stores discovered vulnerabilities
- RemediationRecord: Stores what fixes were applied

HOW IT WORKS:
- Each class = one database table
- Each attribute with Column() = one column in that table
- Relationships link tables together (like foreign keys)
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship
from database.connection import Base
import enum


# ============ ENUMS ============
# Enums define a fixed set of possible values

class UserRole(enum.Enum):
    """User roles for access control."""
    ADMIN = "admin"      # Full access to everything
    USER = "user"        # Can scan and view reports
    VIEWER = "viewer"    # Can only view reports


class ScanStatus(enum.Enum):
    """Possible states of a scan."""
    PENDING = "pending"        # Scan queued but not started
    RUNNING = "running"        # Scan in progress
    COMPLETED = "completed"    # Scan finished successfully
    FAILED = "failed"          # Scan encountered an error


class VulnStatus(enum.Enum):
    """Possible states of a vulnerability."""
    DISCOVERED = "discovered"  # Just found
    VERIFIED = "verified"      # Confirmed exploitable
    FIXED = "fixed"            # Remediation applied
    IGNORED = "ignored"        # Marked as acceptable risk
    FALSE_POSITIVE = "false_positive"  # Not actually a vulnerability


# ============ USER MODEL ============
class User(Base):
    """
    User accounts for the system.
    
    Fields:
    - id: Unique identifier (auto-generated)
    - username: Login name (must be unique)
    - email: User's email (must be unique)
    - hashed_password: Encrypted password (never store plain text!)
    - role: admin, user, or viewer
    - is_active: Can this user login?
    - created_at: When the account was created
    - last_login: Last successful login time
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    scans = relationship("ScanRecord", back_populates="user")
    
    def __repr__(self):
        return f"<User {self.username} ({self.role.value})>"


# ============ SCAN MODEL ============
class ScanRecord(Base):
    """
    Records of scans performed.
    
    Fields:
    - id: Unique identifier (auto-generated)
    - scan_id: Human-readable scan ID (e.g., "scan-abc123")
    - target: What was scanned (IP or hostname)
    - port_range: Which ports were scanned
    - scan_type: quick, full, or deep
    - status: Current state of the scan
    - started_at: When scan began
    - completed_at: When scan finished
    - user_id: Who initiated the scan
    """
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


# ============ VULNERABILITY MODEL ============
class VulnerabilityRecord(Base):
    """
    Vulnerabilities discovered during scans.
    
    Fields:
    - id: Unique identifier
    - scan_id: Which scan found this
    - vuln_type: Category (e.g., EXPOSED_DATABASE_PORT)
    - service: What service is affected (e.g., MongoDB)
    - port: Port number
    - severity: Critical, High, Medium, Low
    - status: discovered, verified, fixed, etc.
    - description: Human-readable explanation
    - cve_id: CVE identifier if known
    - owasp_category: OWASP Top 10 mapping
    - mitre_id: MITRE ATT&CK mapping
    """
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


# ============ REMEDIATION MODEL ============
class RemediationRecord(Base):
    """
    Records of remediation attempts.
    
    Fields:
    - id: Unique identifier
    - vulnerability_id: Which vulnerability was fixed
    - playbook_name: Which Ansible playbook was used
    - status: success, failed, pending
    - output: Ansible output/logs
    - applied_by: Who applied the fix
    - applied_at: When the fix was applied
    """
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

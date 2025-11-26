
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Enum, Float, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum
import os
from dotenv import load_dotenv

load_dotenv()

Base = declarative_base()

class SeverityEnum(enum.Enum):
    """Vulnerability levels"""
    CRITICAL = "C"  # For CVSS 9.0-10.0
    HIGH = "H"          # For CVSS 7.0-8.9
    MEDIUM = "M"      # For CVSS 4.0-6.9
    LOW = "L"            # For CVSS 0.1-3.9
    INFO = "I"          # For CVSS 0.0


class ScanStatusEnum(enum.Enum):
    """Possible states of a scan"""
    QUEUED = "queued"       # Waits to start
    RUNNING = "running"     # Currently working
    COMPLETED = "completed" # After successfully completed
    FAILED = "failed"       # WHen error occured
    CANCELLED = "cancelled" # User stop it


class ScanResult(Base):
    """
    Main table storing information about each scan and one scan will be enough to discover many vulnerabilities.
    """
    __tablename__ = "scan_results"
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Scan details
    target = Column(String(200), nullable=False, index=True)  # IP or domain
    scan_type = Column(String(50), nullable=False)  # "quick", "full", "custom"
    tools_used = Column(String(200))  # "nmap,nuclei,burp" (comma-separated)
    
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
    Stores vulnerability from scans and aligning links to scan that found it through scan_id
    """
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)

    scan_id = Column(Integer, ForeignKey('scan_results.id'), nullable=False, index=True)
    
    #Identification of vulnerability
    cve_id = Column(String(50), index=True)
    title = Column(String(220), nullable=False)
    description = Column(Text)

    #Severity and Classification
    severity = Column(Enum(SeverityEnum), nullable=False, index=True)
    cvss_score = Column(Float)

    #Context
    affected_service = Column(String(200))
    port = Column(Integer)
    protocol = Column(String(8))
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
    mitre_techniques = Column(String(200))  #T1190, T1210

    #Relationship
    scan = relationship("Scan Result", back_populates="vulnerabilities")
    exploits = relationship("Attempted Exploit", back_populates="vulnerability", cascade="all, delete-orphan")
    remediations = relationship("Fixed Action", back_populates="vulnerability", cascade="all, delete-orphan")

    def repr(self):
        return f"<Vulnerability(id={self.id}, title={self.title}, severity={self.severity.value})>"

class ExploitAttempt(Base):
    """
    Records attemptss to exploit vulnerabilities (POC validation) with saftey method first: only runs authorized and safe exploits
    """
    __tablename__ = "exploit_attempts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'), nullable=False)

    #details of exploitation
    exploit_name = Column(String(200))
    exploit_module = Column(String(200))    #Path of metasploit module
    payload_used = Column(Text)

    #results
    success = Column(Boolean, default=False)
    evidence = Column(Text)                 # Proof of exploitation
    impact = Column(Text)                   # What access was gained

    #safety
    safe_mode = Column(Boolean, default=True)   #Always True in production
    authorized = Column(Boolean, default=False) #Must be explicitly authorized

    #time
    attempted_at = Column(DateTime, default=datetime.utcnow)
    duration_seconds = Column(Integer)

    #Relationship
    vulnerability = relationship("Vulnerability", back_populates="exploits")

    def repr(self):
        return f"<ExploitAttempt(id={self.id}, success={self.success})>"

class fixAction(Base):
    """
    Tracks the fixing actions applied to vulnerabilities and links it with Ansible playbooks and tracks fix verfication
    """
    __tablename__ = "remediation_actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'), nullable=False)

    #Fix details
    playbook_name = Column(String(200)) #Ansible playbook name
    playbook_path = Column(String(500))
    fix_method = Column(String(50))     #AUtomatic, manual, suggested

    #Execution
    applied_at = Column(DateTime, default=datetime.utcnow)
    applied_by = Column(String(75))    #Username or system

    #Output
    success = Column(Boolean, default=False)
    output = Column(Text)               #Ansible output
    error_message = Column(Text)

    #Verification
    verified = Column(Boolean, default=False)
    verification_scan_id = Column(Integer, ForeignKey('scan_results.id'))

    #Rollback capability
    snapshot_Created = Column(Boolean, default=False)
    snapshot_id = Column(String(220))
    rolled_back = Column(Boolean, default=False)

    #Relationship
    vulnerability = relationship("Vulnerability", back_populates="remediations")

    def repr(Self):
        return f"<fixAction(id={self.id}, playbook={self.playbook_name}, success={self.sucess})>"

class Report(Base):
    """
    Stores reports and their metadata with generating reports for individual scans or aggregate multiple scans
    """
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)

    #Report identification
    title = Column(String(220), nullable=False)      
    report_type = Column(String(50))        #executive, technical, compilance
    format = Column(String(20))             #pdf, html, json

    #Scope
    scan_ids = Column(String(220))          #1,2,3 - comma-seperated scan IDs
    target_summary = Column(String(500))

    #Content
    file_path = Column(String(500))         #Where report file is saved
    file_Size = Column(Integer)             #In bytes

    #Metadata
    generated_at = Column(DateTime, default=datetime.utcnow)
    generated_by = Column(String(100))
    
    # Summary statistics
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    fixed_count = Column(Integer, default=0)
    
    def __repr__(self):
        return f"<Report(id={self.id}, title={self.title}, format={self.format})>"


# Database connection setup
DATABASE_URL = os.getenv('DATABASE_URL', 'mysql+pymysql://root:password@localhost:3306/redshield_db')

# Create engine - this connects to the database
engine = create_engine(
    DATABASE_URL,
    echo=True,  # Set to False in production (prints SQL queries to console for learning)
    pool_pre_ping=True,  # Checks connection before using
    pool_recycle=3600  # Recycle connections every hour
)

# SessionLocal creates database sessions for transactions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """
    Initialize database by creating all tables.
    Call this once when setting up the project.
    """
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully!")


def get_db():
    """
    Dependency function to get database session.
    Used in FastAPI endpoints to inject database access.
    
    Usage in FastAPI:
        @app.get("/scans")
        def list_scans(db: Session = Depends(get_db)):
            scans = db.query(ScanResult).all()
            return scans
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    # When run directly, create database tables
    print("Creating database tables...")
    init_db()


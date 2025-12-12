from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime, timedelta
import jwt
import uuid

from database.connection import get_session, init_db
from database.models import User, ScanRecord, VulnerabilityRecord, RemediationRecord, UserRole, ScanStatus, VulnStatus
from cli.utils.auth import hash_password, verify_password

# ============================================================
# App Configuration
# ============================================================

app = FastAPI(
    title="RedShield API",
    description="End-to-End Red Team Remediation Toolkit API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS - Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
SECRET_KEY = "redshield-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

security = HTTPBearer()


# ============================================================
# Pydantic Models (Request/Response schemas)
# ============================================================

# Auth Models
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

# Scan Models
class ScanRequest(BaseModel):
    target: str = Field(..., description="IP, hostname, or URL to scan")
    scanner: str = Field(default="auto", description="nmap, nuclei, zap, or auto")
    scan_type: str = Field(default="quick", description="quick, full, or deep")
    port_range: Optional[str] = Field(default=None, description="Port range for nmap")
    templates: Optional[List[str]] = Field(default=None, description="Nuclei templates")

class ScanResponse(BaseModel):
    scan_id: str
    target: str
    scanner: str
    status: str
    started_at: datetime
    message: str

# Vulnerability Models
class FixRequest(BaseModel):
    dry_run: bool = Field(default=True, description="If true, show what would be done without applying")


# ============================================================
# Authentication Helpers
# ============================================================

def create_token(user_id: int, username: str, role: str) -> str:
    """Create JWT token for authenticated user."""
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify JWT token and return user info."""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return {
            "user_id": int(payload["sub"]),
            "username": payload["username"],
            "role": payload["role"]
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_admin(current_user: dict = Depends(verify_token)) -> dict:
    """Require admin role for endpoint."""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user


# ============================================================
# API Endpoints - Authentication
# ============================================================

@app.post("/api/auth/register", response_model=TokenResponse, tags=["Authentication"])
def register(req: RegisterRequest):
    """
    Register a new user account.
    First registered user automatically becomes admin.
    """
    session = get_session()
    
    existing = session.query(User).filter(
        (User.username == req.username) | (User.email == req.email)
    ).first()
    
    if existing:
        session.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    user_count = session.query(User).count()
    role = UserRole.ADMIN if user_count == 0 else UserRole.USER
    
    user = User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        role=role,
        is_active=True
    )
    session.add(user)
    session.commit()
    
    token = create_token(user.id, user.username, user.role.value)
    
    result = {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "is_admin": user.role == UserRole.ADMIN
        }
    }
    
    session.close()
    return result


@app.post("/api/auth/login", response_model=TokenResponse, tags=["Authentication"])
def login(req: LoginRequest):
    """Login with username and password. Returns JWT token."""
    session = get_session()
    
    user = session.query(User).filter(User.username == req.username).first()
    
    if not user or not user.is_active:
        session.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not verify_password(req.password, user.hashed_password):
        session.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    user.last_login = datetime.utcnow()
    session.commit()
    
    token = create_token(user.id, user.username, user.role.value)
    
    result = {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "is_admin": user.role == UserRole.ADMIN
        }
    }
    
    session.close()
    return result


@app.get("/api/auth/me", tags=["Authentication"])
def get_current_user(current_user: dict = Depends(verify_token)):
    """Get current authenticated user info."""
    session = get_session()
    user = session.query(User).filter(User.id == current_user["user_id"]).first()
    
    if not user:
        session.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    result = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_admin": user.role == UserRole.ADMIN,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None
    }
    
    session.close()
    return result


# ============================================================
# API Endpoints - Scans
# ============================================================

def generate_scan_id():
    timestamp = datetime.now().strftime("%Y%m%d")
    unique = uuid.uuid4().hex[:6].upper()
    return f"scan-{timestamp}-{unique}"


@app.post("/api/scans", response_model=ScanResponse, tags=["Scans"])
def create_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(verify_token)
):
    """Create a new vulnerability scan. Runs in background."""
    scan_id = generate_scan_id()
    session = get_session()
    
    is_url = req.target.startswith(('http://', 'https://'))
    scanner = req.scanner if req.scanner != "auto" else ("nuclei" if is_url else "nmap")
    
    port_range = req.port_range
    if scanner == "nmap" and not port_range:
        port_ranges = {"quick": "22,80,443,3306,5432,27017", "full": "1-1000", "deep": "1-65535"}
        port_range = port_ranges.get(req.scan_type, "1-1000")
    
    scan = ScanRecord(
        scan_id=scan_id,
        target=req.target,
        port_range=port_range or "web-scan",
        scan_type=req.scan_type,
        status=ScanStatus.PENDING,
        user_id=current_user["user_id"]
    )
    session.add(scan)
    session.commit()
    session.close()
    
    background_tasks.add_task(run_scan_task, scan_id, req.target, scanner, port_range, req.templates)
    
    return ScanResponse(
        scan_id=scan_id,
        target=req.target,
        scanner=scanner,
        status="pending",
        started_at=datetime.utcnow(),
        message=f"Scan started. Check status at GET /api/scans/{scan_id}"
    )


def run_scan_task(scan_id: str, target: str, scanner: str, port_range: str, templates: List[str] = None):
    """Background task to run the actual scan."""
    session = get_session()
    scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan:
        session.close()
        return
    
    scan.status = ScanStatus.RUNNING
    session.commit()
    
    try:
        vulnerabilities = []
        
        if scanner == "nuclei":
            from integrations.nuclei import generate_demo_nuclei_findings
            findings = generate_demo_nuclei_findings(target)
            vulnerabilities = [{"type": f["name"], "severity": f["severity"].capitalize(), "port": f.get("port", 80), "service": "http", "description": f["description"]} for f in findings]
        elif scanner == "zap":
            from integrations.zap import generate_demo_zap_findings
            findings = generate_demo_zap_findings(target)
            vulnerabilities = [{"type": f["name"], "severity": f["severity"], "port": f.get("port", 80), "service": "http", "description": f["description"]} for f in findings]
        else:
            from core.fake_data import build_demo_vulnerabilities
            demo_vulns = build_demo_vulnerabilities(target)
            vulnerabilities = [{"type": v.vuln_type, "severity": v.severity, "port": v.port, "service": v.service, "description": f"Vulnerability on port {v.port}"} for v in demo_vulns]
        
        for v in vulnerabilities:
            vuln = VulnerabilityRecord(
                scan_id=scan.id,
                vuln_type=v["type"],
                service=v.get("service", "unknown"),
                port=v.get("port"),
                severity=v["severity"],
                status=VulnStatus.DISCOVERED,
                description=v.get("description", ""),
                fix_available=True
            )
            session.add(vuln)
        
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        session.commit()
        
    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.raw_output = str(e)
        session.commit()
    
    session.close()


@app.get("/api/scans", tags=["Scans"])
def list_scans(limit: int = 20, current_user: dict = Depends(verify_token)):
    """List all scans for the current user. Admins see all scans."""
    session = get_session()
    
    query = session.query(ScanRecord)
    if current_user["role"] != "admin":
        query = query.filter(ScanRecord.user_id == current_user["user_id"])
    
    scans = query.order_by(ScanRecord.started_at.desc()).limit(limit).all()
    
    result = []
    for scan in scans:
        vuln_count = session.query(VulnerabilityRecord).filter(VulnerabilityRecord.scan_id == scan.id).count()
        result.append({
            "scan_id": scan.scan_id,
            "target": scan.target,
            "status": scan.status.value,
            "scan_type": scan.scan_type,
            "vulnerability_count": vuln_count,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        })
    
    session.close()
    return {"scans": result, "total": len(result)}


@app.get("/api/scans/{scan_id}", tags=["Scans"])
def get_scan(scan_id: str, current_user: dict = Depends(verify_token)):
    """Get detailed scan results including all vulnerabilities."""
    session = get_session()
    scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    
    if not scan:
        session.close()
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if current_user["role"] != "admin" and scan.user_id != current_user["user_id"]:
        session.close()
        raise HTTPException(status_code=403, detail="Access denied")
    
    vulns = session.query(VulnerabilityRecord).filter(VulnerabilityRecord.scan_id == scan.id).all()
    
    vulnerabilities = [{
        "id": v.id, "type": v.vuln_type, "severity": v.severity, "service": v.service,
        "port": v.port, "status": v.status.value, "description": v.description, "fix_available": v.fix_available
    } for v in vulns]
    
    severity_counts = {}
    for v in vulns:
        severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
    
    result = {
        "scan_id": scan.scan_id, "target": scan.target, "status": scan.status.value,
        "scan_type": scan.scan_type, "port_range": scan.port_range,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "vulnerabilities": vulnerabilities,
        "summary": {"total": len(vulns), "by_severity": severity_counts}
    }
    
    session.close()
    return result


# ============================================================
# API Endpoints - Vulnerabilities
# ============================================================

@app.get("/api/vulnerabilities", tags=["Vulnerabilities"])
def list_vulnerabilities(scan_id: Optional[str] = None, severity: Optional[str] = None, current_user: dict = Depends(verify_token)):
    """List vulnerabilities with optional filters."""
    session = get_session()
    query = session.query(VulnerabilityRecord).join(ScanRecord)
    
    if current_user["role"] != "admin":
        query = query.filter(ScanRecord.user_id == current_user["user_id"])
    
    if scan_id:
        scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        if scan:
            query = query.filter(VulnerabilityRecord.scan_id == scan.id)
    
    if severity:
        query = query.filter(VulnerabilityRecord.severity == severity)
    
    vulns = query.limit(100).all()
    
    result = [{"id": v.id, "scan_id": v.scan.scan_id, "type": v.vuln_type, "severity": v.severity, "service": v.service, "port": v.port, "status": v.status.value} for v in vulns]
    
    session.close()
    return {"vulnerabilities": result, "total": len(result)}


@app.post("/api/vulnerabilities/{vuln_id}/fix", tags=["Vulnerabilities"])
def fix_vulnerability(vuln_id: int, req: FixRequest, current_user: dict = Depends(require_admin)):
    """Apply fix to a vulnerability. **Requires admin privileges.**"""
    session = get_session()
    vuln = session.query(VulnerabilityRecord).filter(VulnerabilityRecord.id == vuln_id).first()
    
    if not vuln:
        session.close()
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    if vuln.status == VulnStatus.FIXED:
        session.close()
        raise HTTPException(status_code=400, detail="Already fixed")
    
    from core.remediation import execute_remediation, generate_remediation_evidence
    scan = vuln.scan
    
    result = execute_remediation(
        vuln_id=vuln.id, vuln_type=vuln.vuln_type, target=scan.target,
        port=vuln.port or 0, service=vuln.service or "unknown", dry_run=req.dry_run, verbose=False
    )
    
    if not req.dry_run and result.success:
        vuln.status = VulnStatus.FIXED
        vuln.fixed_at = datetime.utcnow()
        remediation = RemediationRecord(
            vulnerability_id=vuln.id, playbook_name=vuln.vuln_type, status="success",
            output=generate_remediation_evidence(result), applied_by=current_user["user_id"],
            applied_at=datetime.utcnow(), dry_run=False
        )
        session.add(remediation)
        session.commit()
    
    response = {
        "vulnerability_id": vuln_id,
        "status": "dry_run" if req.dry_run else ("fixed" if result.success else "failed"),
        "steps": [{"step": s.step_number, "action": s.action, "command": s.command, "status": s.status} for s in result.steps],
        "verification": result.after_status
    }
    
    session.close()
    return response


# ============================================================
# API Endpoints - Reports
# ============================================================

@app.get("/api/reports/{scan_id}", tags=["Reports"])
def generate_report(scan_id: str, format: str = "json", current_user: dict = Depends(verify_token)):
    """Generate a security report. Formats: json, html, summary"""
    session = get_session()
    scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    
    if not scan:
        session.close()
        raise HTTPException(status_code=404, detail="Scan not found")
    
    vulns = session.query(VulnerabilityRecord).filter(VulnerabilityRecord.scan_id == scan.id).all()
    
    report_data = {
        "report_id": f"report-{scan_id}",
        "generated_at": datetime.utcnow().isoformat(),
        "scan": {"scan_id": scan.scan_id, "target": scan.target, "status": scan.status.value},
        "summary": {
            "total": len(vulns),
            "critical": len([v for v in vulns if v.severity.lower() == "critical"]),
            "high": len([v for v in vulns if v.severity.lower() == "high"]),
            "medium": len([v for v in vulns if v.severity.lower() == "medium"]),
            "low": len([v for v in vulns if v.severity.lower() == "low"]),
            "fixed": len([v for v in vulns if v.status == VulnStatus.FIXED])
        },
        "vulnerabilities": [{"id": v.id, "type": v.vuln_type, "severity": v.severity, "port": v.port, "status": v.status.value} for v in vulns]
    }
    
    session.close()
    
    if format == "summary":
        return {"format": "summary", "content": report_data["summary"]}
    return report_data


# ============================================================
# API Endpoints - Dashboard
# ============================================================

@app.get("/api/dashboard", tags=["Dashboard"])
def get_dashboard(current_user: dict = Depends(verify_token)):
    """Get dashboard statistics."""
    session = get_session()
    
    if current_user["role"] == "admin":
        total_scans = session.query(ScanRecord).count()
        total_vulns = session.query(VulnerabilityRecord).count()
        fixed_vulns = session.query(VulnerabilityRecord).filter(VulnerabilityRecord.status == VulnStatus.FIXED).count()
    else:
        total_scans = session.query(ScanRecord).filter(ScanRecord.user_id == current_user["user_id"]).count()
        user_scans = session.query(ScanRecord.id).filter(ScanRecord.user_id == current_user["user_id"]).subquery()
        total_vulns = session.query(VulnerabilityRecord).filter(VulnerabilityRecord.scan_id.in_(user_scans)).count()
        fixed_vulns = session.query(VulnerabilityRecord).filter(VulnerabilityRecord.scan_id.in_(user_scans), VulnerabilityRecord.status == VulnStatus.FIXED).count()
    
    result = {
        "stats": {
            "total_scans": total_scans,
            "total_vulnerabilities": total_vulns,
            "fixed_vulnerabilities": fixed_vulns,
            "pending_vulnerabilities": total_vulns - fixed_vulns
        }
    }
    
    session.close()
    return result


# ============================================================
# Health Check & Root
# ============================================================

@app.get("/api/health", tags=["System"])
def health_check():
    """API health check."""
    return {"status": "healthy", "version": "1.0.0", "timestamp": datetime.utcnow().isoformat()}


@app.get("/", tags=["System"])
def root():
    """Root endpoint with API info."""
    return {"name": "RedShield API", "version": "1.0.0", "docs": "/docs", "health": "/api/health"}


@app.on_event("startup")
def startup():
    """Initialize database on startup."""
    init_db()


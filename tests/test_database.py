import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.database import SessionLocal, ScanResult, Vulnerability, SeverityEnum, ScanStatusEnum
from datetime import datetime

def test_create_scan():
    """Test creating a new scan record"""
    db = SessionLocal()
    
    try:
        # Create new scan
        scan = ScanResult(
            target="testphp.vulnweb.com",
            scan_type="quick",
            tools_used="nmap,nuclei",
            status=ScanStatusEnum.RUNNING,
            progress=50
        )
        
        # Add to database
        db.add(scan)
        db.commit()  # Save changes
        db.refresh(scan)  # Get the ID that was auto-generated
        
        print(f"Created scan with ID: {scan.id}")
        print(f"Target: {scan.target}")
        print(f"Status: {scan.status.value}")
        
        return scan.id
        
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()

def test_create_vulnerability(scan_id):
    """Test creating a vulnerability linked to a scan"""
    db = SessionLocal()
    
    try:
        # Create vulnerability
        vuln = Vulnerability(
            scan_id=scan_id,
            cve_id="CVE-2024-1234",
            title="SQL Injection in login.php",
            description="User input not sanitized in login form",
            severity=SeverityEnum.CRITICAL,
            cvss_score=9.8,
            affected_service="testphp.vulnweb.com:80/login.php",
            port=80,
            protocol="tcp",
            service_name="http",
            discovered_by="nuclei",
            owasp_category="A03:2021 - Injection",
            mitre_techniques="T1190"
        )
        
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        
        print(f"Created vulnerability with ID: {vuln.id}")
        print(f"Title: {vuln.title}")
        print(f"Severity: {vuln.severity.value}")
        print(f"CVSS: {vuln.cvss_score}")
        
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()

def test_query_scans():
    """Test querying scans from database"""
    db = SessionLocal()
    
    try:
        # Get all scans
        scans = db.query(ScanResult).all()
        print(f"\nTotal scans in database: {len(scans)}")
        
        # Get scans with vulnerabilities
        for scan in scans:
            print(f"\n   Scan ID {scan.id}:")
            print(f"   - Target: {scan.target}")
            print(f"   - Status: {scan.status.value}")
            print(f"   - Vulnerabilities: {len(scan.vulnerabilities)}")
            
            for vuln in scan.vulnerabilities:
                print(f"     • {vuln.title} ({vuln.severity.value})")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()

def test_update_scan_status(scan_id):
    """Test updating scan status"""
    db = SessionLocal()
    
    try:
        # Find scan
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        
        if scan:
            # Update status
            scan.status = ScanStatusEnum.COMPLETED
            scan.progress = 100
            scan.completed_at = datetime.utcnow()
            
            db.commit()
            print(f"Updated scan {scan_id} to COMPLETED")
        else:
            print(f"Scan {scan_id} not found")
            
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    print("Testing Database Operations\n")
    print("="*50)
    
    # Run tests
    scan_id = test_create_scan()
    
    if scan_id:
        test_create_vulnerability(scan_id)
        test_update_scan_status(scan_id)
        test_query_scans()
    
    print("\n" + "="*50)
    print("All tests completed!")

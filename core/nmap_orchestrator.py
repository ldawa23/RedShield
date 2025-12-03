from integrations.nmap_scanner import run_nmap_basic
from models.vulnerability import Vulnerability
from core.constants import SEVERITY_LEVELS, COMMON_PORTS

def scannmap(target: str, ports: str = "1-1000") -> list:
    print(f"[*] Running Nmap scan on {target}...")
    
    #Run Nmap and get list of port and services
    try:
        port_service = run_nmap_basic(target, ports)
    except RuntimeError as e:
        print(f"[!] Nmap error: {e}")
        return []

    print(f"[+] FOund {len(port_service)} open ports")

    #Converting vulnerability to objects
    vulnerabilities = []

    for port, service in port_service:
        vuln_type, severity = vulntype_and_severity(service, port) #severity based on service and port

        #CREATE VULNERABILITY OBJECT
        vuln = Vulnerability(
            id=None,
            target=target,
            vuln_type=vuln_type,
            service=service,
            port=port,
            severity=severity,
            status="DISCOVERED",
        )
        
        vulnerabilities.append(vuln)
        print(f"  [{severity}] {vuln_type} on {service}:{port}")
    
    return vulnerabilities

def vultype_and_severity(service: str, port: int) -> tuple:
    """
    Determine vulnerability type and severity based on service and port
    Rules:
    - Database ports (27017, 3306, 5432, 6379): EXPOSED_DATABASE_PORT, CRITICAL
    - SSH (22): OPEN_PORT, HIGH (could have weak/default creds, brute force method)
    - HTTP (80): OPEN_PORT, MEDIUM (unencrypted, but not as immediate as DB)
    - HTTPS (443): OPEN_PORT, LOW (expected to be open)
    - Others: OPEN_PORT, MEDIUM
    """

    service_lower = service.lower()

    # Database ports - these are CRITICAL if exposed
    # Why? Direct access to sensitive data, often misconfigured (no auth, weak auth)
    database_services = { "mongodb": 27017, "mysql": 3306, "postgresql": 5432, "redis": 6379, "oracle": 1521, "mssql": 1433, }

    #CHeck for known database service
    for db_name, default_port in database_services.items():
        if db_name in service_lower or port == default_port:
            return ("EXPOSED_DATABASE_PORT", "Critical")

    #SSH - high risk
    #WHy? SSH itself is secure shell but weak credentials or keys or older keys versions can be exploited
    if service_lower == "ssh" or port == 22:
        return ("OPEN_PORT", "HIGH")

    #HTTP (unencrypted web) - medium risk
    #Why? Unencrypted traffic but not direct data access like DB
    if service_lower in ["http", "www"] or port == 80:
        return ("OPEN_PORT", "Medium")

    #HTTPS (encrypted web) - low risk)
    #Why? Expected to be open, encrypted
    if service_lower in ["https", "ssl"] or port == 443:
        return ("OPEN_PORT", "Low")

    #DNS - medium risk
    #WHy? It can enable DNS amplification attacks, info disclosure
    if service_lower == "dns" or port == 53:
        return ("OPEN_PORT", "Medium")

    #Mail services - medium risk
    if service_lower in ["smtp", "pop3", "imap"] or port in [25, 110, 143]:
        return ("OPEN_PORT", "Medium")

    #Everything else - medium risk by default
    return ("OPEN_PORT", "Medium")

if __name__ == "__main__":
    target = "127.0.0.1"
    vulns = scannmap(target, "1-1000")

    print(f"\n[*] Total Vulnerabilities: {len(vulns)}")
    for i in vulns:
        print(f" [{i.severity}] {i.vuln_type} on {i.service}:{i.port}")


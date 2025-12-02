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
        vuln_type, severity = _determine_vuln_type_and_severity(service, port)

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



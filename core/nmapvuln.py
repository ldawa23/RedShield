from integrations.nmapscan import scan
from models.vulnerability import Vulnerability
from models.scan import Scan

def scanrun(target, ports="1-1000"):
    #Scans target and returns scan object with vulnerabilities discovered inside
    # New scan create
    scan_new = Scan.new(target)
    print(f"[*] Starting scan of {target}.....")

    #Running nmap to scan
    try:
        open_ports = scan(target, ports)
    
    except Exception as e:
        print(f"[!] Error: {e}")
        scan_new.status = "Failed"
        return scan_new

    print(f"[+] Found {len(open_ports)} open ports")

    #WIth the founded open ports, deciding if its a vulnerability or not
    for port, service in open_ports:
        #Checking the found vuln are how much bad
        vuln_type, severity = risky_check(service, port)

        #Creating a vulnerability
        vuln = Vulnerability(id=None, target=target, vuln_type=vuln_type, service=service, port=port, severity=severity, status="DISCOVERED")

        #Add the found vulnerability to scan
        scan_new.vulnerabilities.append(vuln)
        print(f" [{severity}] {service}:{port}")

    #Mark the scan as done
    scan_new.status = "Completed"
    return scan_new

def risky_check(service, port):
    #Looks out for serivce and port, will decide if its risk or not
    #For easier checking, changing the service name to lowercase
    service=service.lower()

    # Databases = Crtitical (all have important data)
    if service in ["mongodb", "mysql", "postgres", "redis", "oracle"]:
        return ("EXPOSED_DATABASE_PORT", "Critical")

    if port in [27017, 3306, 5432, 6379, 1521]: #Commonly used DB ports
        return ("EXPOSED_DATABASE_PORT", "Critical")

    # SSH = High (mostly attack are brute force in this vulnerability)
    if service == "ssh" or port == 22:
        return ("OPEN_PORT", "High")

    #HTTP = Medium (unencrypted website)
    if service in ["http", "www"] or port == 80:
        return ("OPEN_PORT", "Medium")

    #HTTPS = Low (encrypted, expected to be open)
    if service in ["https", "ssl"] or port == 443:
        return ("OPEN_PORT", "Low")

    #Everythin else: medium
    return ("OPEN_PORT", "Medium")

if __name__ == "__main__":
    s = scanrun("127.0.0.1", "22,80")
    print(type(s))
    print(hasattr(s, "vulnerabilities"))

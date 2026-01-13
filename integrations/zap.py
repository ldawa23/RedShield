"""
RedShield - OWASP ZAP Integration

ZAP (Zed Attack Proxy) is a web application security scanner.
It provides active/passive scanning, spidering, and fuzzing.

Why ZAP?
- Industry standard for web app security testing
- Active scanning finds real vulnerabilities
- Spider crawls entire application
- API-driven for automation
- Great for OWASP Top 10 detection

Installation:
- Download: https://www.zaproxy.org/download/
- Docker: docker run -u zap -p 8080:8080 -i ghcr.io/zaproxy/zaproxy zap.sh -daemon -port 8080
- Kali: sudo apt install zaproxy

Usage in RedShield:
    redshield scan --target http://localhost/dvwa --scanner zap
"""

import subprocess
import shutil
import time
import json
from typing import Dict, List, Optional
from datetime import datetime

# ZAP API default settings
ZAP_API_URL = "http://localhost:8080"
ZAP_API_KEY = ""  # Empty by default in daemon mode


def check_zap_installed() -> bool:
    """Check if ZAP is installed and accessible."""
    # Check for zap.sh (Linux/Mac) or zap.bat (Windows)
    return (
        shutil.which("zap.sh") is not None or 
        shutil.which("zap.bat") is not None or
        shutil.which("zaproxy") is not None
    )


def check_zap_running(api_url: str = ZAP_API_URL, api_key: str = ZAP_API_KEY) -> bool:
    """Check if ZAP daemon is running and accessible."""
    try:
        import urllib.request
        url = f"{api_url}/JSON/core/view/version/"
        if api_key:
            url += f"?apikey={api_key}"
        
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 200
    except:
        return False


def start_zap_daemon(port: int = 8080, api_key: str = "") -> bool:
    """Start ZAP in daemon mode."""
    try:
        cmd = ["zap.sh", "-daemon", "-port", str(port), "-config", "api.disablekey=true"]
        
        # Windows uses zap.bat
        import platform
        if platform.system() == "Windows":
            cmd[0] = "zap.bat"
        
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Wait for ZAP to start
        for _ in range(30):
            if check_zap_running(f"http://localhost:{port}"):
                return True
            time.sleep(1)
        
        return False
    except:
        return False


def run_zap_scan(
    target: str,
    scan_type: str = "active",  # "active", "passive", "spider"
    api_url: str = ZAP_API_URL,
    api_key: str = ZAP_API_KEY,
    timeout: int = 600
) -> Dict:
    """
    Run ZAP scan against a target.
    
    Args:
        target: URL to scan (e.g., http://localhost/dvwa)
        scan_type: Type of scan (active, passive, spider)
        api_url: ZAP API URL
        api_key: ZAP API key
        timeout: Scan timeout in seconds
    
    Returns:
        Dict with scan results including findings
    """
    import urllib.request
    import urllib.parse
    
    if not check_zap_running(api_url, api_key):
        return {
            "success": False,
            "error": "ZAP is not running. Start ZAP daemon first or use: docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy zap.sh -daemon",
            "findings": []
        }
    
    try:
        findings = []
        
        # Step 1: Spider the target first
        spider_url = f"{api_url}/JSON/spider/action/scan/?url={urllib.parse.quote(target)}"
        if api_key:
            spider_url += f"&apikey={api_key}"
        
        with urllib.request.urlopen(spider_url, timeout=30) as response:
            spider_result = json.loads(response.read())
            spider_id = spider_result.get("scan")
        
        # Wait for spider to complete
        start_time = time.time()
        while time.time() - start_time < timeout // 2:
            status_url = f"{api_url}/JSON/spider/view/status/?scanId={spider_id}"
            if api_key:
                status_url += f"&apikey={api_key}"
            
            with urllib.request.urlopen(status_url, timeout=10) as response:
                status = json.loads(response.read())
                if int(status.get("status", 0)) >= 100:
                    break
            time.sleep(2)
        
        # Step 2: Run active scan if requested
        if scan_type == "active":
            active_url = f"{api_url}/JSON/ascan/action/scan/?url={urllib.parse.quote(target)}"
            if api_key:
                active_url += f"&apikey={api_key}"
            
            with urllib.request.urlopen(active_url, timeout=30) as response:
                active_result = json.loads(response.read())
                scan_id = active_result.get("scan")
            
            # Wait for active scan to complete
            while time.time() - start_time < timeout:
                status_url = f"{api_url}/JSON/ascan/view/status/?scanId={scan_id}"
                if api_key:
                    status_url += f"&apikey={api_key}"
                
                with urllib.request.urlopen(status_url, timeout=10) as response:
                    status = json.loads(response.read())
                    if int(status.get("status", 0)) >= 100:
                        break
                time.sleep(5)
        
        # Step 3: Get alerts
        alerts_url = f"{api_url}/JSON/core/view/alerts/?baseurl={urllib.parse.quote(target)}"
        if api_key:
            alerts_url += f"&apikey={api_key}"
        
        with urllib.request.urlopen(alerts_url, timeout=30) as response:
            alerts_data = json.loads(response.read())
            alerts = alerts_data.get("alerts", [])
        
        # Parse alerts into findings
        for alert in alerts:
            finding = {
                "vuln_type": alert.get("alert", "Unknown"),
                "name": alert.get("name", alert.get("alert", "Unknown")),
                "severity": map_zap_risk(alert.get("risk", "Informational")),
                "description": alert.get("description", ""),
                "matched_at": alert.get("url", ""),
                "host": target,
                "port": extract_port_from_url(target),
                "solution": alert.get("solution", ""),
                "reference": alert.get("reference", ""),
                "cwe_id": alert.get("cweid", ""),
                "wasc_id": alert.get("wascid", ""),
                "evidence": alert.get("evidence", ""),
            }
            findings.append(finding)
        
        return {
            "success": True,
            "target": target,
            "findings": findings,
            "total_findings": len(findings),
            "scan_time": datetime.utcnow().isoformat(),
            "scan_type": scan_type
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "findings": []
        }


def map_zap_risk(risk: str) -> str:
    """Map ZAP risk level to standard severity."""
    risk_map = {
        "High": "Critical",
        "Medium": "High", 
        "Low": "Medium",
        "Informational": "Low"
    }
    return risk_map.get(risk, "Low")


def extract_port_from_url(url: str) -> Optional[int]:
    """Extract port number from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.port:
            return parsed.port
        elif parsed.scheme == "https":
            return 443
        elif parsed.scheme == "http":
            return 80
    except:
        pass
    return None


# Demo mode for testing without ZAP installed
def generate_demo_zap_findings(target: str) -> List[Dict]:
    """Generate demo findings for testing (simulates DVWA ZAP scan)."""
    
    demo_findings = [
        {
            "vuln_type": "SQL Injection",
            "name": "SQL Injection",
            "severity": "Critical",
            "description": "SQL injection may be possible. The page results were successfully manipulated using the boolean conditions.",
            "matched_at": f"{target}/vulnerabilities/sqli/?id=1",
            "host": target,
            "port": 80,
            "solution": "Use parameterized queries (prepared statements) instead of string concatenation.",
            "cwe_id": "89",
            "evidence": "Error message revealed: You have an error in your SQL syntax",
        },
        {
            "vuln_type": "Cross Site Scripting (Reflected)",
            "name": "Cross Site Scripting (Reflected)",
            "severity": "Critical",
            "description": "Cross-site Scripting (XSS) is a security vulnerability that enables attackers to inject malicious scripts.",
            "matched_at": f"{target}/vulnerabilities/xss_r/?name=test",
            "host": target,
            "port": 80,
            "solution": "Encode all user-supplied input before including it in the page.",
            "cwe_id": "79",
            "evidence": "<script>alert(1)</script>",
        },
        {
            "vuln_type": "Cross Site Scripting (Stored)",
            "name": "Cross Site Scripting (Stored)",
            "severity": "Critical",
            "description": "Stored XSS vulnerability found. Malicious script is stored in the database.",
            "matched_at": f"{target}/vulnerabilities/xss_s/",
            "host": target,
            "port": 80,
            "solution": "Sanitize all user input before storing in database. Encode output when displaying.",
            "cwe_id": "79",
            "evidence": "Injected script executed on page load",
        },
        {
            "vuln_type": "Path Traversal",
            "name": "Path Traversal",
            "severity": "Critical",
            "description": "Path traversal vulnerability allows reading files outside the web root.",
            "matched_at": f"{target}/vulnerabilities/fi/?page=../../etc/passwd",
            "host": target,
            "port": 80,
            "solution": "Validate and sanitize file paths. Use allowlists for permitted files.",
            "cwe_id": "22",
            "evidence": "root:x:0:0:root:/root:/bin/bash",
        },
        {
            "vuln_type": "Remote OS Command Injection",
            "name": "Remote OS Command Injection", 
            "severity": "Critical",
            "description": "OS command injection allows execution of arbitrary system commands.",
            "matched_at": f"{target}/vulnerabilities/exec/?ip=127.0.0.1",
            "host": target,
            "port": 80,
            "solution": "Avoid using system calls with user input. Use allowlists for permitted characters.",
            "cwe_id": "78",
            "evidence": "uid=33(www-data) gid=33(www-data)",
        },
        {
            "vuln_type": "Absence of Anti-CSRF Tokens",
            "name": "Absence of Anti-CSRF Tokens",
            "severity": "High",
            "description": "No Anti-CSRF tokens were found in a HTML submission form.",
            "matched_at": f"{target}/vulnerabilities/csrf/",
            "host": target,
            "port": 80,
            "solution": "Implement anti-CSRF tokens on all state-changing forms.",
            "cwe_id": "352",
            "evidence": "Form without CSRF token",
        },
        {
            "vuln_type": "Cookie Without SameSite Attribute",
            "name": "Cookie Without SameSite Attribute",
            "severity": "Medium",
            "description": "A cookie has been set without the SameSite attribute, making it vulnerable to CSRF.",
            "matched_at": target,
            "host": target,
            "port": 80,
            "solution": "Set the SameSite attribute to 'strict' or 'lax' for cookies.",
            "cwe_id": "1275",
            "evidence": "Set-Cookie: PHPSESSID=...; path=/",
        },
        {
            "vuln_type": "X-Frame-Options Header Not Set",
            "name": "X-Frame-Options Header Not Set",
            "severity": "Medium",
            "description": "X-Frame-Options header is not included in the HTTP response to protect against clickjacking.",
            "matched_at": target,
            "host": target,
            "port": 80,
            "solution": "Add X-Frame-Options: DENY or SAMEORIGIN header.",
            "cwe_id": "1021",
            "evidence": "Missing header",
        },
        {
            "vuln_type": "Content-Security-Policy Header Not Set",
            "name": "Content-Security-Policy Header Not Set",
            "severity": "Medium",
            "description": "Content Security Policy (CSP) header not set, reducing XSS protection.",
            "matched_at": target,
            "host": target,
            "port": 80,
            "solution": "Implement a Content-Security-Policy header.",
            "cwe_id": "693",
            "evidence": "Missing CSP header",
        },
        {
            "vuln_type": "Server Leaks Version Information",
            "name": "Server Leaks Version Information via 'Server' HTTP Response Header",
            "severity": "Low",
            "description": "The web server discloses version information via the Server HTTP header.",
            "matched_at": target,
            "host": target,
            "port": 80,
            "solution": "Configure the server to not disclose version information.",
            "cwe_id": "200",
            "evidence": "Server: Apache/2.4.38 (Debian)",
        },
    ]
    
    return demo_findings

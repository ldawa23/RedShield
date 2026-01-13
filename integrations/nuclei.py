"""
RedShield - Nuclei Integration

Nuclei is a fast, template-based vulnerability scanner.
It uses YAML templates to detect vulnerabilities in web applications.

Why Nuclei?
- 1000s of pre-built templates for CVEs, misconfigs, etc.
- Fast and efficient scanning
- Perfect for web apps like DVWA, Juice Shop, bWAPP
- Easy to create custom templates

Installation:
- Go: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
- Binary: https://github.com/projectdiscovery/nuclei/releases
- Kali: sudo apt install nuclei

Usage in RedShield:
    redshield scan --target http://localhost/dvwa --scanner nuclei
"""

import subprocess
import json
import shutil
from typing import List, Dict, Optional
from datetime import datetime


def check_nuclei_installed() -> bool:
    """Check if Nuclei is installed and accessible."""
    return shutil.which("nuclei") is not None


def get_nuclei_version() -> Optional[str]:
    """Get Nuclei version string."""
    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Nuclei outputs version to stderr
        output = result.stderr or result.stdout
        for line in output.split("\n"):
            if "nuclei" in line.lower():
                return line.strip()
        return "Nuclei (version unknown)"
    except:
        return None


def run_nuclei_scan(
    target: str,
    templates: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    timeout: int = 300,
    rate_limit: int = 150
) -> Dict:
    """
    Run Nuclei scan against a target.
    
    Args:
        target: URL to scan (e.g., http://localhost/dvwa)
        templates: List of template paths or tags (e.g., ["cves", "misconfig"])
        severity: Filter by severity (e.g., ["critical", "high"])
        timeout: Scan timeout in seconds
        rate_limit: Requests per second
    
    Returns:
        Dict with scan results including findings
    """
    
    if not check_nuclei_installed():
        return {
            "success": False,
            "error": "Nuclei not installed. Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "findings": []
        }
    
    # Build command
    cmd = [
        "nuclei",
        "-u", target,
        "-json-export", "-",  # Output JSON to stdout
        "-silent",  # Suppress banner
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout // 60 or 1),  # Nuclei uses minutes
    ]
    
    # Add template filters
    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    
    # Add severity filter
    if severity:
        cmd.extend(["-severity", ",".join(severity)])
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        findings = parse_nuclei_output(result.stdout)
        
        return {
            "success": True,
            "target": target,
            "findings": findings,
            "total_findings": len(findings),
            "scan_time": datetime.utcnow().isoformat(),
            "raw_output": result.stdout
        }
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Scan timed out after {timeout} seconds",
            "findings": []
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "findings": []
        }


def parse_nuclei_output(output: str) -> List[Dict]:
    """Parse Nuclei JSON output into structured findings."""
    findings = []
    
    for line in output.strip().split("\n"):
        if not line:
            continue
        try:
            data = json.loads(line)
            finding = {
                "vuln_type": data.get("template-id", "unknown"),
                "name": data.get("info", {}).get("name", "Unknown Vulnerability"),
                "severity": data.get("info", {}).get("severity", "info"),
                "description": data.get("info", {}).get("description", ""),
                "matched_at": data.get("matched-at", ""),
                "host": data.get("host", ""),
                "port": extract_port_from_url(data.get("matched-at", "")),
                "matcher_name": data.get("matcher-name", ""),
                "template_url": data.get("template-url", ""),
                # Security framework mappings
                "cve_id": extract_cve(data.get("info", {}).get("classification", {})),
                "cwe_id": data.get("info", {}).get("classification", {}).get("cwe-id", []),
                "cvss_score": data.get("info", {}).get("classification", {}).get("cvss-score"),
                # Remediation
                "remediation": data.get("info", {}).get("remediation", ""),
                "reference": data.get("info", {}).get("reference", []),
            }
            findings.append(finding)
        except json.JSONDecodeError:
            continue
    
    return findings


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


def extract_cve(classification: Dict) -> Optional[str]:
    """Extract CVE ID from classification."""
    cve_ids = classification.get("cve-id", [])
    if cve_ids and len(cve_ids) > 0:
        return cve_ids[0]
    return None


def get_available_templates() -> Dict:
    """Get list of available Nuclei template categories."""
    return {
        "cves": "CVE-based detection templates",
        "vulnerabilities": "General vulnerability detection",
        "misconfigurations": "Security misconfigurations",
        "exposures": "Sensitive data exposures",
        "technologies": "Technology detection",
        "default-logins": "Default credential checks",
        "takeovers": "Subdomain takeover detection",
        "file": "Sensitive file detection",
        "fuzzing": "Fuzzing templates",
        "headless": "Browser-based detection",
    }


# Demo mode for testing without Nuclei installed
def generate_demo_nuclei_findings(target: str) -> List[Dict]:
    """Generate demo findings for testing (simulates DVWA scan)."""
    
    demo_findings = [
        {
            "vuln_type": "sqli-error-based",
            "name": "SQL Injection (Error Based)",
            "severity": "critical",
            "description": "SQL injection vulnerability detected via error-based technique",
            "matched_at": f"{target}/vulnerabilities/sqli/?id=1'",
            "host": target,
            "port": 80,
            "cve_id": None,
            "cwe_id": ["CWE-89"],
            "remediation": "Use parameterized queries or prepared statements",
            "reference": ["https://owasp.org/www-community/attacks/SQL_Injection"],
        },
        {
            "vuln_type": "xss-reflected",
            "name": "Cross-Site Scripting (Reflected)",
            "severity": "high",
            "description": "Reflected XSS vulnerability allows execution of arbitrary JavaScript",
            "matched_at": f"{target}/vulnerabilities/xss_r/?name=<script>alert(1)</script>",
            "host": target,
            "port": 80,
            "cve_id": None,
            "cwe_id": ["CWE-79"],
            "remediation": "Encode user input before rendering in HTML context",
            "reference": ["https://owasp.org/www-community/attacks/xss/"],
        },
        {
            "vuln_type": "command-injection",
            "name": "OS Command Injection",
            "severity": "critical",
            "description": "Command injection allows execution of arbitrary OS commands",
            "matched_at": f"{target}/vulnerabilities/exec/?ip=127.0.0.1;id",
            "host": target,
            "port": 80,
            "cve_id": None,
            "cwe_id": ["CWE-78"],
            "remediation": "Avoid system calls with user input, use allowlists",
            "reference": ["https://owasp.org/www-community/attacks/Command_Injection"],
        },
        {
            "vuln_type": "file-inclusion-lfi",
            "name": "Local File Inclusion (LFI)",
            "severity": "high",
            "description": "LFI vulnerability allows reading arbitrary files from server",
            "matched_at": f"{target}/vulnerabilities/fi/?page=../../etc/passwd",
            "host": target,
            "port": 80,
            "cve_id": None,
            "cwe_id": ["CWE-98"],
            "remediation": "Validate and sanitize file paths, use allowlists",
            "reference": ["https://owasp.org/www-project-web-security-testing-guide/"],
        },
        {
            "vuln_type": "csrf-token-missing",
            "name": "CSRF Token Missing",
            "severity": "medium",
            "description": "Form missing CSRF protection token",
            "matched_at": f"{target}/vulnerabilities/csrf/",
            "host": target,
            "port": 80,
            "cve_id": None,
            "cwe_id": ["CWE-352"],
            "remediation": "Implement anti-CSRF tokens on all state-changing requests",
            "reference": ["https://owasp.org/www-community/attacks/csrf"],
        },
        {
            "vuln_type": "weak-password-policy",
            "name": "Weak Password Policy",
            "severity": "medium",
            "description": "Application allows weak passwords (brute-force vulnerable)",
            "matched_at": f"{target}/vulnerabilities/brute/",
            "host": target,
            "port": 80,
            "cve_id": None,
            "cwe_id": ["CWE-521"],
            "remediation": "Implement rate limiting and strong password requirements",
            "reference": ["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
        },
        {
            "vuln_type": "insecure-file-upload",
            "name": "Insecure File Upload",
            "severity": "critical",
            "description": "File upload allows uploading malicious files (PHP webshell)",
            "matched_at": f"{target}/vulnerabilities/upload/",
            "host": target,
            "port": 80,
            "cve_id": None,
            "cwe_id": ["CWE-434"],
            "remediation": "Validate file types, store outside webroot, rename files",
            "reference": ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"],
        },
    ]
    
    return demo_findings

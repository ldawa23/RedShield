"""
RedShield - Security Framework Mappings

Maps vulnerabilities to industry-standard security frameworks:
- OWASP Top 10 (2021)
- MITRE ATT&CK
- CVE Database

This helps organizations understand vulnerabilities in context of
recognized security frameworks for compliance and reporting.
"""

from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class SecurityMapping:
    """Complete security framework mapping for a vulnerability."""
    owasp_category: Optional[str] = None
    owasp_id: Optional[str] = None
    owasp_description: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    risk_level: Optional[str] = None


# ============================================================
# OWASP Top 10 (2021) Mappings
# ============================================================

OWASP_TOP_10_2021 = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
        "examples": [
            "Bypassing access control checks",
            "Viewing or editing someone else's account",
            "Privilege escalation",
            "Metadata manipulation (JWT, cookies)",
            "CORS misconfiguration"
        ]
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often lead to sensitive data exposure.",
        "examples": [
            "Weak or old cryptographic algorithms",
            "Transmitting data in clear text",
            "Using hard-coded passwords",
            "Weak key generation"
        ]
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized by the application.",
        "examples": [
            "SQL Injection",
            "NoSQL Injection",
            "OS Command Injection",
            "LDAP Injection",
            "XPath Injection"
        ]
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": "Missing or ineffective control design in the application architecture.",
        "examples": [
            "Missing rate limiting",
            "Lack of input validation patterns",
            "Business logic flaws",
            "Missing threat modeling"
        ]
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Missing appropriate security hardening or improperly configured permissions.",
        "examples": [
            "Default credentials",
            "Unnecessary features enabled",
            "Error messages with sensitive data",
            "Missing security headers",
            "Exposed database ports"
        ]
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities.",
        "examples": [
            "Outdated operating systems",
            "Vulnerable libraries",
            "Unsupported software",
            "Unpatched systems"
        ]
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Weaknesses in authentication and session management.",
        "examples": [
            "Weak passwords allowed",
            "Credential stuffing",
            "Session fixation",
            "Missing MFA"
        ]
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations.",
        "examples": [
            "Insecure deserialization",
            "CI/CD pipeline vulnerabilities",
            "Auto-update without integrity checks"
        ]
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "Without logging and monitoring, breaches cannot be detected.",
        "examples": [
            "Insufficient logging",
            "Missing alerting",
            "Logs not protected",
            "No incident response"
        ]
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.",
        "examples": [
            "Accessing internal services",
            "Scanning internal networks",
            "Reading cloud metadata"
        ]
    }
}


# ============================================================
# MITRE ATT&CK Mappings
# ============================================================

MITRE_ATTACK = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system."
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Persistence",
        "description": "Adversaries may use credentials of existing accounts to gain Initial Access."
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts."
    },
    "T1212": {
        "id": "T1212",
        "name": "Exploitation for Credential Access",
        "tactic": "Credential Access",
        "description": "Adversaries may exploit software vulnerabilities to collect credentials."
    },
    "T1068": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to gain elevated access."
    },
    "T1203": {
        "id": "T1203",
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Adversaries may exploit software vulnerabilities in client applications."
    },
    "T1505": {
        "id": "T1505",
        "name": "Server Software Component",
        "tactic": "Persistence",
        "description": "Adversaries may abuse web application server software."
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols."
    },
    "T1557": {
        "id": "T1557",
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to position themselves between two or more networked devices."
    }
}


# ============================================================
# Vulnerability Type to Framework Mapping
# ============================================================

VULNERABILITY_MAPPINGS = {
    # SQL Injection variants
    "SQL Injection": {
        "owasp": "A03",
        "mitre": "T1190",
        "cwe": "CWE-89",
        "risk": "Critical",
        "cvss_base": 9.8
    },
    "Blind SQL Injection": {
        "owasp": "A03",
        "mitre": "T1190",
        "cwe": "CWE-89",
        "risk": "High",
        "cvss_base": 8.6
    },
    
    # XSS variants
    "Cross Site Scripting (Reflected)": {
        "owasp": "A03",
        "mitre": "T1059",
        "cwe": "CWE-79",
        "risk": "Medium",
        "cvss_base": 6.1
    },
    "Cross Site Scripting (Stored)": {
        "owasp": "A03",
        "mitre": "T1059",
        "cwe": "CWE-79",
        "risk": "High",
        "cvss_base": 7.2
    },
    "XSS": {
        "owasp": "A03",
        "mitre": "T1059",
        "cwe": "CWE-79",
        "risk": "Medium",
        "cvss_base": 6.1
    },
    
    # Command Injection
    "OS Command Injection": {
        "owasp": "A03",
        "mitre": "T1059",
        "cwe": "CWE-78",
        "risk": "Critical",
        "cvss_base": 9.8
    },
    "Remote OS Command Injection": {
        "owasp": "A03",
        "mitre": "T1059",
        "cwe": "CWE-78",
        "risk": "Critical",
        "cvss_base": 9.8
    },
    "Command Injection": {
        "owasp": "A03",
        "mitre": "T1059",
        "cwe": "CWE-78",
        "risk": "Critical",
        "cvss_base": 9.8
    },
    
    # Path Traversal
    "Path Traversal": {
        "owasp": "A01",
        "mitre": "T1083",
        "cwe": "CWE-22",
        "risk": "High",
        "cvss_base": 7.5
    },
    "Directory Traversal": {
        "owasp": "A01",
        "mitre": "T1083",
        "cwe": "CWE-22",
        "risk": "High",
        "cvss_base": 7.5
    },
    
    # Authentication issues
    "DEFAULT_CREDENTIALS": {
        "owasp": "A07",
        "mitre": "T1078",
        "cwe": "CWE-798",
        "risk": "Critical",
        "cvss_base": 9.8
    },
    "Weak Password": {
        "owasp": "A07",
        "mitre": "T1110",
        "cwe": "CWE-521",
        "risk": "High",
        "cvss_base": 7.5
    },
    "Brute Force": {
        "owasp": "A07",
        "mitre": "T1110",
        "cwe": "CWE-307",
        "risk": "Medium",
        "cvss_base": 5.3
    },
    
    # Misconfigurations
    "EXPOSED_DATABASE_PORT": {
        "owasp": "A05",
        "mitre": "T1190",
        "cwe": "CWE-284",
        "risk": "High",
        "cvss_base": 7.5
    },
    "OPEN_SSH": {
        "owasp": "A05",
        "mitre": "T1021",
        "cwe": "CWE-284",
        "risk": "Medium",
        "cvss_base": 5.3
    },
    "Security Misconfiguration": {
        "owasp": "A05",
        "mitre": "T1190",
        "cwe": "CWE-16",
        "risk": "Medium",
        "cvss_base": 5.3
    },
    
    # Outdated software
    "OUTDATED_COMPONENT": {
        "owasp": "A06",
        "mitre": "T1190",
        "cwe": "CWE-1104",
        "risk": "High",
        "cvss_base": 7.5
    },
    "Outdated Software": {
        "owasp": "A06",
        "mitre": "T1190",
        "cwe": "CWE-1104",
        "risk": "High",
        "cvss_base": 7.5
    },
    
    # CSRF
    "Absence of Anti-CSRF Tokens": {
        "owasp": "A01",
        "mitre": "T1185",
        "cwe": "CWE-352",
        "risk": "Medium",
        "cvss_base": 6.5
    },
    "CSRF": {
        "owasp": "A01",
        "mitre": "T1185",
        "cwe": "CWE-352",
        "risk": "Medium",
        "cvss_base": 6.5
    },
    
    # Security Headers
    "Missing Security Headers": {
        "owasp": "A05",
        "mitre": "T1190",
        "cwe": "CWE-693",
        "risk": "Low",
        "cvss_base": 4.3
    },
    "X-Frame-Options Header Not Set": {
        "owasp": "A05",
        "mitre": "T1185",
        "cwe": "CWE-1021",
        "risk": "Medium",
        "cvss_base": 5.4
    },
    "Content-Security-Policy Header Not Set": {
        "owasp": "A05",
        "mitre": "T1059",
        "cwe": "CWE-693",
        "risk": "Medium",
        "cvss_base": 5.4
    },
    "Cookie Without SameSite Attribute": {
        "owasp": "A05",
        "mitre": "T1185",
        "cwe": "CWE-1275",
        "risk": "Low",
        "cvss_base": 4.3
    },
    
    # Information Disclosure
    "Server Leaks Version Information via 'Server' HTTP Response Header": {
        "owasp": "A05",
        "mitre": "T1592",
        "cwe": "CWE-200",
        "risk": "Low",
        "cvss_base": 3.7
    },
    "Information Disclosure": {
        "owasp": "A01",
        "mitre": "T1592",
        "cwe": "CWE-200",
        "risk": "Low",
        "cvss_base": 4.3
    },
    
    # SSRF
    "Server-Side Request Forgery": {
        "owasp": "A10",
        "mitre": "T1090",
        "cwe": "CWE-918",
        "risk": "High",
        "cvss_base": 8.6
    },
    "SSRF": {
        "owasp": "A10",
        "mitre": "T1090",
        "cwe": "CWE-918",
        "risk": "High",
        "cvss_base": 8.6
    }
}


def get_security_mapping(vuln_type: str) -> SecurityMapping:
    """
    Get complete security framework mapping for a vulnerability type.
    
    Args:
        vuln_type: The vulnerability type string
        
    Returns:
        SecurityMapping with OWASP, MITRE, and CVE information
    """
    mapping = SecurityMapping()
    
    # Try exact match first
    vuln_info = VULNERABILITY_MAPPINGS.get(vuln_type)
    
    # Try partial match if exact match fails
    if not vuln_info:
        vuln_lower = vuln_type.lower()
        for key, value in VULNERABILITY_MAPPINGS.items():
            if key.lower() in vuln_lower or vuln_lower in key.lower():
                vuln_info = value
                break
    
    if vuln_info:
        # OWASP mapping
        owasp_key = vuln_info.get("owasp")
        if owasp_key and owasp_key in OWASP_TOP_10_2021:
            owasp = OWASP_TOP_10_2021[owasp_key]
            mapping.owasp_id = owasp["id"]
            mapping.owasp_category = owasp["name"]
            mapping.owasp_description = owasp["description"]
        
        # MITRE mapping
        mitre_key = vuln_info.get("mitre")
        if mitre_key and mitre_key in MITRE_ATTACK:
            mitre = MITRE_ATTACK[mitre_key]
            mapping.mitre_id = mitre["id"]
            mapping.mitre_technique = mitre["name"]
            mapping.mitre_tactic = mitre["tactic"]
        
        # Other mappings
        mapping.cwe_id = vuln_info.get("cwe")
        mapping.cvss_score = vuln_info.get("cvss_base")
        mapping.risk_level = vuln_info.get("risk")
    
    return mapping


def get_owasp_category(vuln_type: str) -> Optional[str]:
    """Get OWASP Top 10 category for a vulnerability type."""
    mapping = get_security_mapping(vuln_type)
    if mapping.owasp_id:
        return f"{mapping.owasp_id} - {mapping.owasp_category}"
    return None


def get_mitre_technique(vuln_type: str) -> Optional[str]:
    """Get MITRE ATT&CK technique for a vulnerability type."""
    mapping = get_security_mapping(vuln_type)
    if mapping.mitre_id:
        return f"{mapping.mitre_id}: {mapping.mitre_technique}"
    return None


def get_cwe_id(vuln_type: str) -> Optional[str]:
    """Get CWE ID for a vulnerability type."""
    mapping = get_security_mapping(vuln_type)
    return mapping.cwe_id


def enrich_vulnerability(vuln_type: str) -> Dict:
    """
    Get all security framework mappings for a vulnerability.
    
    Returns a dictionary with all framework information.
    """
    mapping = get_security_mapping(vuln_type)
    
    return {
        "owasp": {
            "id": mapping.owasp_id,
            "category": mapping.owasp_category,
            "description": mapping.owasp_description
        } if mapping.owasp_id else None,
        "mitre": {
            "id": mapping.mitre_id,
            "technique": mapping.mitre_technique,
            "tactic": mapping.mitre_tactic
        } if mapping.mitre_id else None,
        "cwe_id": mapping.cwe_id,
        "cvss_score": mapping.cvss_score,
        "risk_level": mapping.risk_level
    }


# Example usage and testing
if __name__ == "__main__":
    test_vulns = [
        "SQL Injection",
        "Cross Site Scripting (Reflected)",
        "OS Command Injection",
        "EXPOSED_DATABASE_PORT",
        "DEFAULT_CREDENTIALS",
        "Path Traversal"
    ]
    
    print("RedShield Security Framework Mappings Test")
    print("=" * 60)
    
    for vuln in test_vulns:
        print(f"\n{vuln}:")
        enriched = enrich_vulnerability(vuln)
        
        if enriched["owasp"]:
            print(f"  OWASP: {enriched['owasp']['id']} - {enriched['owasp']['category']}")
        if enriched["mitre"]:
            print(f"  MITRE: {enriched['mitre']['id']} ({enriched['mitre']['tactic']})")
        if enriched["cwe_id"]:
            print(f"  CWE: {enriched['cwe_id']}")
        if enriched["cvss_score"]:
            print(f"  CVSS: {enriched['cvss_score']}")
        if enriched["risk_level"]:
            print(f"  Risk: {enriched['risk_level']}")

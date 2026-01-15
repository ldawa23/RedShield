"""
RedShield Signature Format & Loader

This module defines the custom vulnerability signature format and loader.
Signatures are YAML files that describe how to detect specific vulnerabilities.

SIGNATURE FORMAT:
-----------------
Each signature file (*.sig.yaml) contains:
  - id: Unique identifier (e.g., "RS-001")
  - name: Human-readable name
  - description: What this vulnerability is
  - severity: Critical/High/Medium/Low
  - category: OWASP category (e.g., "A01:2021")
  - mitre_attack: MITRE ATT&CK mapping (e.g., "T1190")
  - detection: How to detect this vulnerability
  - remediation: How to fix it

Example signature:
------------------
id: RS-SQLI-001
name: SQL Injection in Login Form
severity: Critical
category: A03:2021-Injection
mitre_attack: T1190
detection:
  type: http
  method: POST
  path: /login
  payloads:
    - "' OR '1'='1"
    - "admin'--"
  match:
    - "SQL syntax"
    - "mysql_fetch"
    - "ORA-01756"
"""

import yaml
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class DetectionType(Enum):
    """Types of detection methods."""
    PORT = "port"           # Port-based detection
    BANNER = "banner"       # Service banner matching
    HTTP = "http"           # HTTP request/response
    VERSION = "version"     # Version comparison
    CREDENTIAL = "credential"  # Default credential check
    CONFIG = "config"       # Configuration check


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class DetectionRule:
    """Detection rule configuration."""
    type: DetectionType
    method: Optional[str] = None  # HTTP method for HTTP type
    path: Optional[str] = None    # Path for HTTP type
    port: Optional[int] = None    # Specific port to check
    service: Optional[str] = None # Service name to match
    payloads: List[str] = field(default_factory=list)  # Test payloads
    match_patterns: List[str] = field(default_factory=list)  # Patterns indicating vulnerability
    version_range: Optional[str] = None  # For version checks (e.g., "<2.0.0")
    credentials: List[Dict[str, str]] = field(default_factory=list)  # Default creds to try


@dataclass
class RemediationInfo:
    """Remediation information."""
    description: str
    playbook: Optional[str] = None  # Ansible playbook name
    manual_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class Signature:
    """
    Vulnerability Signature Definition.
    
    This is the core data structure for vulnerability detection.
    Each signature describes:
    - What vulnerability to look for
    - How to detect it
    - How severe it is
    - How to fix it
    """
    id: str
    name: str
    description: str
    severity: Severity
    category: str  # OWASP category
    mitre_attack: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    detection: DetectionRule = None
    remediation: RemediationInfo = None
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Signature':
        """Create a Signature from a dictionary (YAML data)."""
        # Parse detection rules
        detection_data = data.get('detection', {})
        detection = DetectionRule(
            type=DetectionType(detection_data.get('type', 'port')),
            method=detection_data.get('method'),
            path=detection_data.get('path'),
            port=detection_data.get('port'),
            service=detection_data.get('service'),
            payloads=detection_data.get('payloads', []),
            match_patterns=detection_data.get('match', []),
            version_range=detection_data.get('version_range'),
            credentials=detection_data.get('credentials', [])
        )
        
        # Parse remediation info
        remediation_data = data.get('remediation', {})
        remediation = RemediationInfo(
            description=remediation_data.get('description', 'Apply security best practices'),
            playbook=remediation_data.get('playbook'),
            manual_steps=remediation_data.get('steps', []),
            references=remediation_data.get('references', [])
        )
        
        return cls(
            id=data['id'],
            name=data['name'],
            description=data.get('description', ''),
            severity=Severity(data.get('severity', 'Medium')),
            category=data.get('category', 'Unknown'),
            mitre_attack=data.get('mitre_attack'),
            cve_ids=data.get('cve_ids', []),
            detection=detection,
            remediation=remediation,
            tags=data.get('tags', []),
            enabled=data.get('enabled', True)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity.value,
            'category': self.category,
            'mitre_attack': self.mitre_attack,
            'cve_ids': self.cve_ids,
            'tags': self.tags,
            'enabled': self.enabled
        }


class SignatureLoader:
    """
    Loads vulnerability signatures from YAML files.
    
    Usage:
        loader = SignatureLoader()
        loader.load_directory('./signatures')
        signatures = loader.get_all()
    """
    
    def __init__(self):
        self.signatures: Dict[str, Signature] = {}
        self._load_builtin_signatures()
    
    def _load_builtin_signatures(self):
        """Load built-in default signatures."""
        builtin = [
            {
                'id': 'RS-DB-001',
                'name': 'Exposed MongoDB',
                'description': 'MongoDB database is accessible without authentication',
                'severity': 'Critical',
                'category': 'A01:2021-Broken Access Control',
                'mitre_attack': 'T1190',
                'detection': {
                    'type': 'port',
                    'port': 27017,
                    'service': 'mongodb'
                },
                'remediation': {
                    'description': 'Enable authentication and restrict network access',
                    'playbook': 'fix_exposed_database.yml',
                    'steps': [
                        'Enable authentication in mongod.conf',
                        'Create admin user with strong password',
                        'Configure firewall to restrict access'
                    ]
                },
                'tags': ['database', 'mongodb', 'authentication']
            },
            {
                'id': 'RS-DB-002',
                'name': 'Exposed MySQL',
                'description': 'MySQL database is accessible from external networks',
                'severity': 'Critical',
                'category': 'A01:2021-Broken Access Control',
                'mitre_attack': 'T1190',
                'detection': {
                    'type': 'port',
                    'port': 3306,
                    'service': 'mysql'
                },
                'remediation': {
                    'description': 'Restrict MySQL to localhost and require authentication',
                    'playbook': 'fix_exposed_database.yml',
                    'steps': [
                        'Set bind-address to 127.0.0.1 in my.cnf',
                        'Remove anonymous users',
                        'Configure firewall rules'
                    ]
                },
                'tags': ['database', 'mysql', 'authentication']
            },
            {
                'id': 'RS-DB-003',
                'name': 'Exposed PostgreSQL',
                'description': 'PostgreSQL database is accessible without proper authentication',
                'severity': 'Critical',
                'category': 'A01:2021-Broken Access Control',
                'mitre_attack': 'T1190',
                'detection': {
                    'type': 'port',
                    'port': 5432,
                    'service': 'postgres'
                },
                'remediation': {
                    'description': 'Configure pg_hba.conf and restrict network access',
                    'playbook': 'fix_exposed_database.yml',
                    'steps': [
                        'Configure pg_hba.conf for authentication',
                        'Set listen_addresses in postgresql.conf',
                        'Enable SSL connections'
                    ]
                },
                'tags': ['database', 'postgresql', 'authentication']
            },
            {
                'id': 'RS-DB-004',
                'name': 'Exposed Redis',
                'description': 'Redis is accessible without authentication',
                'severity': 'Critical',
                'category': 'A01:2021-Broken Access Control',
                'mitre_attack': 'T1190',
                'detection': {
                    'type': 'port',
                    'port': 6379,
                    'service': 'redis'
                },
                'remediation': {
                    'description': 'Enable Redis authentication and protected mode',
                    'playbook': 'fix_exposed_database.yml',
                    'steps': [
                        'Set requirepass in redis.conf',
                        'Enable protected-mode yes',
                        'Bind to localhost only'
                    ]
                },
                'tags': ['database', 'redis', 'authentication']
            },
            {
                'id': 'RS-SSH-001',
                'name': 'SSH with Password Authentication',
                'description': 'SSH allows password authentication which is vulnerable to brute force',
                'severity': 'High',
                'category': 'A07:2021-Identification and Authentication Failures',
                'mitre_attack': 'T1110',
                'detection': {
                    'type': 'banner',
                    'port': 22,
                    'service': 'ssh'
                },
                'remediation': {
                    'description': 'Disable password authentication and use SSH keys',
                    'playbook': 'fix_ssh_hardening.yml',
                    'steps': [
                        'Generate SSH key pair',
                        'Set PasswordAuthentication no in sshd_config',
                        'Restart SSH service'
                    ]
                },
                'tags': ['ssh', 'authentication', 'brute-force']
            },
            {
                'id': 'RS-HTTP-001',
                'name': 'Unencrypted HTTP Service',
                'description': 'Web server is using unencrypted HTTP instead of HTTPS',
                'severity': 'Medium',
                'category': 'A02:2021-Cryptographic Failures',
                'mitre_attack': 'T1557',
                'detection': {
                    'type': 'port',
                    'port': 80,
                    'service': 'http'
                },
                'remediation': {
                    'description': 'Enable HTTPS with valid SSL/TLS certificate',
                    'playbook': 'fix_enable_https.yml',
                    'steps': [
                        'Obtain SSL certificate (Let\'s Encrypt)',
                        'Configure web server for HTTPS',
                        'Set up HTTP to HTTPS redirect'
                    ]
                },
                'tags': ['http', 'https', 'encryption', 'ssl']
            },
            {
                'id': 'RS-SQLI-001',
                'name': 'SQL Injection',
                'description': 'Application is vulnerable to SQL injection attacks',
                'severity': 'Critical',
                'category': 'A03:2021-Injection',
                'mitre_attack': 'T1190',
                'cve_ids': [],
                'detection': {
                    'type': 'http',
                    'method': 'POST',
                    'payloads': [
                        "' OR '1'='1",
                        "admin'--",
                        "1' AND '1'='1",
                        "1; DROP TABLE users--"
                    ],
                    'match': [
                        'SQL syntax',
                        'mysql_fetch',
                        'pg_query',
                        'ORA-01756',
                        'sqlite3.OperationalError'
                    ]
                },
                'remediation': {
                    'description': 'Use parameterized queries and input validation',
                    'playbook': 'fix_sql_injection.yml',
                    'steps': [
                        'Use prepared statements/parameterized queries',
                        'Implement input validation',
                        'Apply principle of least privilege to DB accounts'
                    ]
                },
                'tags': ['injection', 'sql', 'database', 'owasp-top-10']
            },
            {
                'id': 'RS-XSS-001',
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Application is vulnerable to XSS attacks',
                'severity': 'High',
                'category': 'A03:2021-Injection',
                'mitre_attack': 'T1059.007',
                'detection': {
                    'type': 'http',
                    'method': 'GET',
                    'payloads': [
                        '<script>alert(1)</script>',
                        '"><script>alert(1)</script>',
                        "javascript:alert(1)"
                    ],
                    'match': [
                        '<script>alert(1)</script>',
                        'javascript:alert'
                    ]
                },
                'remediation': {
                    'description': 'Implement output encoding and Content Security Policy',
                    'playbook': 'fix_xss.yml',
                    'steps': [
                        'HTML-encode all user input before display',
                        'Implement Content Security Policy headers',
                        'Use HTTPOnly cookies'
                    ]
                },
                'tags': ['xss', 'injection', 'javascript', 'owasp-top-10']
            },
            {
                'id': 'RS-CMD-001',
                'name': 'Command Injection',
                'description': 'Application is vulnerable to OS command injection',
                'severity': 'Critical',
                'category': 'A03:2021-Injection',
                'mitre_attack': 'T1059',
                'detection': {
                    'type': 'http',
                    'payloads': [
                        '; id',
                        '| whoami',
                        '`id`',
                        '$(whoami)'
                    ],
                    'match': [
                        'uid=',
                        'root:',
                        'www-data'
                    ]
                },
                'remediation': {
                    'description': 'Avoid system commands, use safe APIs instead',
                    'playbook': 'fix_command_injection.yml',
                    'steps': [
                        'Avoid calling OS commands from application',
                        'If unavoidable, use parameterized APIs',
                        'Implement strict input validation'
                    ]
                },
                'tags': ['command-injection', 'rce', 'owasp-top-10']
            },
            {
                'id': 'RS-CRED-001',
                'name': 'Default Credentials',
                'description': 'Service is using factory default credentials',
                'severity': 'Critical',
                'category': 'A07:2021-Identification and Authentication Failures',
                'mitre_attack': 'T1078.001',
                'detection': {
                    'type': 'credential',
                    'credentials': [
                        {'username': 'admin', 'password': 'admin'},
                        {'username': 'admin', 'password': 'password'},
                        {'username': 'root', 'password': 'root'},
                        {'username': 'admin', 'password': '123456'},
                        {'username': 'admin', 'password': 'admin123'}
                    ]
                },
                'remediation': {
                    'description': 'Change default credentials immediately',
                    'playbook': 'fix_default_credentials.yml',
                    'steps': [
                        'Generate strong random password',
                        'Update service credentials',
                        'Document new credentials securely'
                    ]
                },
                'tags': ['credentials', 'authentication', 'default-password']
            },
            {
                'id': 'RS-VER-001',
                'name': 'Outdated Software Version',
                'description': 'Service is running an outdated version with known vulnerabilities',
                'severity': 'High',
                'category': 'A06:2021-Vulnerable and Outdated Components',
                'mitre_attack': 'T1190',
                'detection': {
                    'type': 'version'
                },
                'remediation': {
                    'description': 'Update to the latest stable version',
                    'playbook': 'fix_outdated_software.yml',
                    'steps': [
                        'Check for available updates',
                        'Review changelog for security fixes',
                        'Apply updates following change management'
                    ]
                },
                'tags': ['version', 'update', 'patch', 'cve']
            }
        ]
        
        for sig_data in builtin:
            sig = Signature.from_dict(sig_data)
            self.signatures[sig.id] = sig
    
    def load_file(self, filepath: str) -> Optional[Signature]:
        """Load a single signature file."""
        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
                if data:
                    sig = Signature.from_dict(data)
                    self.signatures[sig.id] = sig
                    return sig
        except Exception as e:
            print(f"Error loading signature {filepath}: {e}")
        return None
    
    def load_directory(self, directory: str) -> List[Signature]:
        """Load all signatures from a directory."""
        loaded = []
        if not os.path.exists(directory):
            return loaded
            
        for filename in os.listdir(directory):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                filepath = os.path.join(directory, filename)
                sig = self.load_file(filepath)
                if sig:
                    loaded.append(sig)
        return loaded
    
    def get(self, sig_id: str) -> Optional[Signature]:
        """Get a signature by ID."""
        return self.signatures.get(sig_id)
    
    def get_all(self) -> List[Signature]:
        """Get all loaded signatures."""
        return list(self.signatures.values())
    
    def get_by_severity(self, severity: Severity) -> List[Signature]:
        """Get signatures by severity level."""
        return [s for s in self.signatures.values() if s.severity == severity]
    
    def get_by_tag(self, tag: str) -> List[Signature]:
        """Get signatures by tag."""
        return [s for s in self.signatures.values() if tag in s.tags]
    
    def get_by_category(self, category: str) -> List[Signature]:
        """Get signatures by OWASP category."""
        return [s for s in self.signatures.values() if category in s.category]
    
    def search(self, query: str) -> List[Signature]:
        """Search signatures by name, description, or tags."""
        query = query.lower()
        results = []
        for sig in self.signatures.values():
            if (query in sig.name.lower() or 
                query in sig.description.lower() or
                any(query in tag.lower() for tag in sig.tags)):
                results.append(sig)
        return results

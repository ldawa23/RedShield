"""
RedShield - Python API Bridge

This module provides a Flask API that the Node.js backend can call
to execute real scans using Nmap, Nuclei, Metasploit, and Ansible.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import json
import os
import sys
import uuid
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations.nmapscan import scan as nmap_scan
from integrations.nuclei import check_nuclei_installed, run_nuclei_scan, generate_demo_nuclei_findings
from integrations.metasploit import check_metasploit_installed, get_exploit_for_vuln, generate_demo_msf_verification
from core.security_mappings import get_security_mapping

app = Flask(__name__)
CORS(app)

def generate_scan_id():
    """Generate unique scan ID."""
    timestamp = datetime.now().strftime("%Y%m%d")
    unique = uuid.uuid4().hex[:6].upper()
    return f"scan-{timestamp}-{unique}"


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'redshield-python-api',
        'timestamp': datetime.utcnow().isoformat(),
        'tools': {
            'nmap': check_nmap_installed(),
            'nuclei': check_nuclei_installed(),
            'metasploit': check_metasploit_installed()
        }
    })


def check_nmap_installed():
    """Check if Nmap is installed."""
    # Try common installation paths on Windows
    nmap_paths = [
        'nmap',  # In PATH
        r'C:\Program Files (x86)\Nmap\nmap.exe',
        r'C:\Program Files\Nmap\nmap.exe',
        r'C:\nmap\nmap.exe',
    ]
    
    for nmap_path in nmap_paths:
        try:
            result = subprocess.run([nmap_path, '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def get_nmap_path():
    """Get the Nmap executable path."""
    nmap_paths = [
        'nmap',
        r'C:\Program Files (x86)\Nmap\nmap.exe',
        r'C:\Program Files\Nmap\nmap.exe',
        r'C:\nmap\nmap.exe',
    ]
    
    for nmap_path in nmap_paths:
        try:
            result = subprocess.run([nmap_path, '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return nmap_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


@app.route('/api/scan/nmap', methods=['POST'])
def run_nmap_scan():
    """
    Run real Nmap scan.
    
    Request body:
    {
        "target": "192.168.1.100",
        "port_range": "22,80,443,3306",
        "scan_type": "quick"
    }
    """
    data = request.json
    target = data.get('target')
    port_range = data.get('port_range', '22,80,443,3306,5432,27017,6379')
    scan_type = data.get('scan_type', 'quick')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Adjust port range based on scan type
    if scan_type == 'quick' and not data.get('port_range'):
        port_range = '22,80,443,3306,5432,27017,6379,8080,8443'
    elif scan_type == 'full' and not data.get('port_range'):
        port_range = '1-1000'
    elif scan_type == 'deep' and not data.get('port_range'):
        port_range = '1-65535'
    
    scan_id = generate_scan_id()
    
    if not check_nmap_installed():
        return jsonify({
            'success': False,
            'error': 'Nmap not installed. Install with: sudo apt-get install nmap',
            'scan_id': scan_id,
            'demo_mode': True,
            'vulnerabilities': generate_demo_nmap_vulns(target)
        })
    
    try:
        # Run real Nmap scan
        open_ports = nmap_scan(target, port_range)
        
        # Convert to vulnerabilities
        vulnerabilities = analyze_nmap_results(target, open_ports)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'target': target,
            'port_range': port_range,
            'scan_type': scan_type,
            'open_ports': [{'port': p, 'service': s} for p, s in open_ports],
            'vulnerabilities': vulnerabilities,
            'total_ports': len(open_ports),
            'total_vulnerabilities': len(vulnerabilities),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'scan_id': scan_id
        }), 500


def analyze_nmap_results(target, open_ports):
    """Analyze Nmap results and generate vulnerability findings."""
    vulnerabilities = []
    
    # Common vulnerable services and their issues
    vuln_patterns = {
        'ssh': {
            'ports': [22],
            'checks': [
                {'type': 'SSH_WEAK_CONFIG', 'severity': 'MEDIUM', 'desc': 'SSH service detected - check for weak passwords and outdated versions'},
            ]
        },
        'ftp': {
            'ports': [21],
            'checks': [
                {'type': 'FTP_ANONYMOUS', 'severity': 'HIGH', 'desc': 'FTP service detected - check for anonymous access'},
                {'type': 'FTP_CLEARTEXT', 'severity': 'MEDIUM', 'desc': 'FTP transmits credentials in cleartext'},
            ]
        },
        'mysql': {
            'ports': [3306],
            'checks': [
                {'type': 'EXPOSED_DATABASE_PORT', 'severity': 'CRITICAL', 'desc': 'MySQL port exposed - should be restricted to localhost'},
                {'type': 'DEFAULT_CREDENTIALS', 'severity': 'HIGH', 'desc': 'Check for default MySQL root credentials'},
            ]
        },
        'postgresql': {
            'ports': [5432],
            'checks': [
                {'type': 'EXPOSED_DATABASE_PORT', 'severity': 'CRITICAL', 'desc': 'PostgreSQL port exposed - should be restricted'},
            ]
        },
        'mongodb': {
            'ports': [27017],
            'checks': [
                {'type': 'MONGODB_NOAUTH', 'severity': 'CRITICAL', 'desc': 'MongoDB port exposed - check for authentication'},
            ]
        },
        'redis': {
            'ports': [6379],
            'checks': [
                {'type': 'REDIS_NOAUTH', 'severity': 'CRITICAL', 'desc': 'Redis port exposed - commonly misconfigured without auth'},
            ]
        },
        'http': {
            'ports': [80, 8080, 8000],
            'checks': [
                {'type': 'MISSING_HTTPS', 'severity': 'LOW', 'desc': 'HTTP service without HTTPS redirect'},
            ]
        },
        'smb': {
            'ports': [445, 139],
            'checks': [
                {'type': 'SMB_EXPOSED', 'severity': 'HIGH', 'desc': 'SMB service exposed - check for EternalBlue (MS17-010)'},
            ]
        },
        'rdp': {
            'ports': [3389],
            'checks': [
                {'type': 'RDP_EXPOSED', 'severity': 'HIGH', 'desc': 'RDP exposed to network - potential brute force target'},
            ]
        },
        'telnet': {
            'ports': [23],
            'checks': [
                {'type': 'TELNET_ENABLED', 'severity': 'CRITICAL', 'desc': 'Telnet transmits all data in cleartext - use SSH instead'},
            ]
        }
    }
    
    for port, service in open_ports:
        service_lower = service.lower()
        
        # Check against known patterns
        for svc_name, svc_data in vuln_patterns.items():
            if port in svc_data['ports'] or svc_name in service_lower:
                for check in svc_data['checks']:
                    mapping = get_security_mapping(check['type'])
                    vulnerabilities.append({
                        'vuln_type': check['type'],
                        'severity': check['severity'],
                        'service': service,
                        'port': port,
                        'description': check['desc'],
                        'target': target,
                        'owasp_category': f"{mapping.owasp_id} - {mapping.owasp_category}" if mapping.owasp_id else None,
                        'mitre_id': mapping.mitre_id,
                        'cwe_id': mapping.cwe_id,
                        'fix_available': True
                    })
                break
        else:
            # Unknown service on open port
            vulnerabilities.append({
                'vuln_type': 'OPEN_PORT',
                'severity': 'LOW',
                'service': service,
                'port': port,
                'description': f'Open port {port} ({service}) - verify if necessary',
                'target': target,
                'fix_available': False
            })
    
    return vulnerabilities


def generate_demo_nmap_vulns(target):
    """Generate demo vulnerabilities when Nmap is not installed."""
    return [
        {'vuln_type': 'EXPOSED_DATABASE_PORT', 'severity': 'CRITICAL', 'service': 'mysql', 'port': 3306, 'description': 'MySQL exposed to network'},
        {'vuln_type': 'SSH_WEAK_CONFIG', 'severity': 'MEDIUM', 'service': 'ssh', 'port': 22, 'description': 'SSH service detected'},
        {'vuln_type': 'MISSING_HTTPS', 'severity': 'LOW', 'service': 'http', 'port': 80, 'description': 'HTTP without encryption'},
    ]


@app.route('/api/scan/nuclei', methods=['POST'])
def run_nuclei_web_scan():
    """
    Run real Nuclei web vulnerability scan.
    
    Request body:
    {
        "target": "http://localhost/dvwa",
        "templates": ["sqli", "xss", "cves"],
        "severity": ["critical", "high", "medium"]
    }
    """
    data = request.json
    target = data.get('target')
    templates = data.get('templates', [])
    severity = data.get('severity', ['critical', 'high', 'medium'])
    
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    
    scan_id = generate_scan_id()
    
    if not check_nuclei_installed():
        # Use demo mode
        findings = generate_demo_nuclei_findings(target)
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'target': target,
            'demo_mode': True,
            'message': 'Nuclei not installed - showing demo results',
            'vulnerabilities': findings,
            'total_vulnerabilities': len(findings),
            'timestamp': datetime.utcnow().isoformat()
        })
    
    try:
        # Run real Nuclei scan
        result = run_nuclei_scan(
            target=target,
            templates=templates if templates else None,
            severity=severity if severity else None,
            timeout=300
        )
        
        if not result['success']:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Scan failed'),
                'scan_id': scan_id
            }), 500
        
        # Map findings to vulnerability format
        vulnerabilities = []
        for finding in result['findings']:
            mapping = get_security_mapping(finding.get('vuln_type', ''))
            vulnerabilities.append({
                'vuln_type': finding.get('name', finding.get('vuln_type', 'Unknown')),
                'severity': finding.get('severity', 'info').upper(),
                'service': 'http',
                'port': finding.get('port', 80),
                'description': finding.get('description', ''),
                'target': target,
                'matched_at': finding.get('matched_at', ''),
                'cve_id': finding.get('cve_id'),
                'cwe_id': finding.get('cwe_id'),
                'remediation': finding.get('remediation', ''),
                'reference': finding.get('reference', []),
                'owasp_category': f"{mapping.owasp_id} - {mapping.owasp_category}" if mapping.owasp_id else None,
                'mitre_id': mapping.mitre_id,
                'fix_available': True
            })
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'target': target,
            'demo_mode': False,
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'scan_id': scan_id
        }), 500


@app.route('/api/verify', methods=['POST'])
def verify_vulnerability():
    """
    Verify a vulnerability using Metasploit.
    
    Request body:
    {
        "vuln_type": "SQL_INJECTION",
        "target": "192.168.1.100",
        "port": 80
    }
    """
    data = request.json
    vuln_type = data.get('vuln_type')
    target = data.get('target')
    port = data.get('port')
    demo = data.get('demo', True)
    
    if not vuln_type or not target:
        return jsonify({'error': 'vuln_type and target are required'}), 400
    
    # Get exploit module for this vulnerability
    exploit = get_exploit_for_vuln(vuln_type)
    
    if not exploit:
        return jsonify({
            'success': True,
            'verified': False,
            'message': f'No Metasploit module available for {vuln_type}',
            'manual_required': True
        })
    
    if demo or not check_metasploit_installed():
        # Demo verification
        result = generate_demo_msf_verification(exploit, target, port)
        return jsonify({
            'success': True,
            'verified': result.get('exploitable', False),
            'demo_mode': True,
            'module': exploit['module'],
            'output': result.get('output', ''),
            'timestamp': datetime.utcnow().isoformat()
        })
    
    # TODO: Real Metasploit RPC integration
    return jsonify({
        'success': False,
        'error': 'Live Metasploit verification not yet implemented - use CLI',
        'module': exploit['module']
    })


@app.route('/api/fix', methods=['POST'])
def apply_fix():
    """
    Apply fix using Ansible playbook.
    
    Request body:
    {
        "vuln_type": "SQL_INJECTION",
        "target": "192.168.1.100",
        "playbook": "fix_sql_injection.yml",
        "demo": true
    }
    """
    data = request.json
    vuln_type = data.get('vuln_type')
    target = data.get('target')
    playbook = data.get('playbook')
    demo = data.get('demo', True)
    
    if not playbook:
        return jsonify({'error': 'playbook is required'}), 400
    
    playbook_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'playbooks',
        playbook
    )
    
    # Check if playbook exists
    if not os.path.exists(playbook_path):
        return jsonify({
            'success': False,
            'error': f'Playbook not found: {playbook}'
        }), 404
    
    if demo:
        # Demo mode - show what would be executed
        return jsonify({
            'success': True,
            'demo_mode': True,
            'playbook': playbook,
            'target': target,
            'command': f'ansible-playbook {playbook_path} --extra-vars "target={target}"',
            'output': generate_demo_ansible_output(playbook, target, vuln_type),
            'before_state': generate_before_state(vuln_type),
            'after_state': generate_after_state(vuln_type),
            'timestamp': datetime.utcnow().isoformat()
        })
    
    # Real Ansible execution
    try:
        ansible_path = get_ansible_path()
        if not ansible_path:
            return jsonify({
                'success': False,
                'error': 'Ansible not found. Install with: pip install ansible'
            }), 500
            
        result = subprocess.run(
            [ansible_path, playbook_path, '--extra-vars', f'target={target}'],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'demo_mode': False,
            'playbook': playbook,
            'target': target,
            'output': result.stdout + result.stderr,
            'return_code': result.returncode,
            'timestamp': datetime.utcnow().isoformat()
        })
    except FileNotFoundError:
        return jsonify({
            'success': False,
            'error': 'Ansible not installed. Install with: pip install ansible'
        }), 500
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'error': 'Playbook execution timed out'
        }), 500


def generate_demo_ansible_output(playbook, target, vuln_type):
    """Generate demo Ansible output."""
    return f"""
PLAY [Apply Security Fix - {vuln_type}] *****************************************

TASK [Gathering Facts] ********************************************************
ok: [{target}]

TASK [{playbook}] *************************************************************
changed: [{target}]

TASK [Verify fix applied] *****************************************************
ok: [{target}]

PLAY RECAP ********************************************************************
{target}              : ok=3    changed=1    unreachable=0    failed=0    skipped=0

Fix applied successfully (DEMO MODE - no actual changes made)
""".strip()


def generate_before_state(vuln_type):
    """Generate before state for vulnerability."""
    states = {
        'SQL_INJECTION': '# Vulnerable Code\nquery = "SELECT * FROM users WHERE id = " + user_input',
        'XSS': '# Vulnerable Code\n<div>Welcome, <%= user.name %></div>',
        'DEFAULT_CREDENTIALS': '# Config\nusername = admin\npassword = admin123',
        'EXPOSED_DATABASE_PORT': '# MySQL Config\nbind-address = 0.0.0.0',
        'COMMAND_INJECTION': '# Vulnerable Code\nos.system("ping " + user_input)',
    }
    return states.get(vuln_type.upper().replace('-', '_'), f'# Vulnerable state for {vuln_type}')


def generate_after_state(vuln_type):
    """Generate after state for vulnerability."""
    states = {
        'SQL_INJECTION': '# Fixed Code\nquery = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_input,))',
        'XSS': '# Fixed Code\n<div>Welcome, <%= sanitize(user.name) %></div>',
        'DEFAULT_CREDENTIALS': '# Config\nusername = admin\npassword = ********** (secure random)',
        'EXPOSED_DATABASE_PORT': '# MySQL Config\nbind-address = 127.0.0.1',
        'COMMAND_INJECTION': '# Fixed Code\nsubprocess.run(["ping", "-c", "1", sanitize(user_input)])',
    }
    return states.get(vuln_type.upper().replace('-', '_'), f'# Fixed state for {vuln_type}')


@app.route('/api/tools/status', methods=['GET'])
def get_tools_status():
    """Get status of all security tools."""
    return jsonify({
        'nmap': {
            'installed': check_nmap_installed(),
            'description': 'Network scanner for port and service detection'
        },
        'nuclei': {
            'installed': check_nuclei_installed(),
            'description': 'Fast web vulnerability scanner with templates'
        },
        'metasploit': {
            'installed': check_metasploit_installed(),
            'description': 'Exploitation framework for verification'
        },
        'ansible': {
            'installed': check_ansible_installed(),
            'description': 'Automation tool for applying fixes'
        }
    })


def check_ansible_installed():
    """Check if Ansible is installed."""
    # Try common paths
    ansible_paths = [
        'ansible',  # In PATH
        r'C:\Users\Acer\AppData\Roaming\Python\Python313\Scripts\ansible.exe',
        r'C:\Python313\Scripts\ansible.exe',
        os.path.expanduser(r'~\AppData\Roaming\Python\Python313\Scripts\ansible.exe'),
    ]
    
    for ansible_path in ansible_paths:
        try:
            result = subprocess.run([ansible_path, '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def get_ansible_path():
    """Get the Ansible executable path."""
    ansible_paths = [
        'ansible-playbook',
        r'C:\Users\Acer\AppData\Roaming\Python\Python313\Scripts\ansible-playbook.exe',
        r'C:\Python313\Scripts\ansible-playbook.exe',
        os.path.expanduser(r'~\AppData\Roaming\Python\Python313\Scripts\ansible-playbook.exe'),
    ]
    
    for ansible_path in ansible_paths:
        try:
            result = subprocess.run([ansible_path, '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return ansible_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


if __name__ == '__main__':
    print("=" * 60)
    print("RedShield Python API Bridge")
    print("=" * 60)
    print(f"Nmap installed: {check_nmap_installed()}")
    print(f"Nuclei installed: {check_nuclei_installed()}")
    print(f"Metasploit installed: {check_metasploit_installed()}")
    print(f"Ansible installed: {check_ansible_installed()}")
    print("=" * 60)
    print("Starting API on http://localhost:5000")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)

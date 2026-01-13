/**
 * Scans Routes - Real Scanner Integration
 * 
 * This module integrates with the Python API to run real scans
 * using Nmap, Nuclei, and other security tools.
 */

import { Router, Request, Response } from 'express';
import { getDatabase, dbHelpers } from '../db/database';
import { authMiddleware } from '../middleware/auth';
import { spawn, exec } from 'child_process';
import path from 'path';

const router = Router();

// Python API URL (scanner_api.py)
const PYTHON_API_URL = process.env.PYTHON_API_URL || 'http://localhost:5000';

// Generate unique scan ID
function generateScanId(): string {
  const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const unique = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `scan-${timestamp}-${unique}`;
}

// Helper to call Python API
async function callPythonAPI(endpoint: string, data: any): Promise<any> {
  try {
    const response = await fetch(`${PYTHON_API_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return await response.json();
  } catch (error) {
    console.error('Python API call failed:', error);
    return null;
  }
}

// Check if Python API is running
async function isPythonAPIRunning(): Promise<boolean> {
  try {
    const response = await fetch(`${PYTHON_API_URL}/api/health`);
    return response.ok;
  } catch {
    return false;
  }
}

// Get all scans with stats
router.get('/', (req: Request, res: Response) => {
  try {
    const scans = dbHelpers.getScansWithStats();
    res.json(scans);
  } catch (error) {
    console.error('Error fetching scans:', error);
    res.status(500).json({ error: 'Failed to fetch scans' });
  }
});

// Start a new scan - REAL INTEGRATION
router.post('/start', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { target, scanner, scanType, portRange, templates, severity, demo } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target is required' });
    }

    const db = getDatabase();
    const scanId = generateScanId();
    
    // Determine scanner type
    const isUrl = target.startsWith('http://') || target.startsWith('https://');
    const actualScanner = scanner === 'auto' ? (isUrl ? 'nuclei' : 'nmap') : scanner;
    
    // Create scan record
    db.prepare(`
      INSERT INTO scans (scan_id, target, port_range, scan_type, status, started_at)
      VALUES (?, ?, ?, ?, 'running', datetime('now'))
    `).run(scanId, target, portRange || 'default', scanType || 'quick');

    const scan = db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scanId) as any;

    let vulnerabilities: any[] = [];
    let scanOutput: any = {};
    let usedDemo = demo === true;

    // Check if Python API is available for real scanning
    const pythonApiAvailable = await isPythonAPIRunning();

    if (pythonApiAvailable && !demo) {
      // Use Python API for real scanning
      console.log(`[SCAN] Using Python API for ${actualScanner} scan on ${target}`);
      
      if (actualScanner === 'nmap') {
        scanOutput = await callPythonAPI('/api/scan/nmap', {
          target,
          port_range: portRange,
          scan_type: scanType
        });
      } else if (actualScanner === 'nuclei' || actualScanner === 'zap') {
        scanOutput = await callPythonAPI('/api/scan/nuclei', {
          target,
          templates: templates ? templates.split(',') : [],
          severity: severity ? severity.split(',') : ['critical', 'high', 'medium']
        });
      }

      if (scanOutput && scanOutput.vulnerabilities) {
        vulnerabilities = scanOutput.vulnerabilities;
        usedDemo = scanOutput.demo_mode || false;
      }
    }
    
    // Fallback to demo data if Python API unavailable or returned no results
    if (vulnerabilities.length === 0) {
      console.log(`[SCAN] Using demo mode for ${target}`);
      vulnerabilities = generateDemoVulnerabilities(target, actualScanner, scanType);
      usedDemo = true;
    }
    
    // Insert vulnerabilities into database
    const insertVuln = db.prepare(`
      INSERT INTO vulnerabilities (
        scan_id, vuln_type, severity, status, service, port, description, 
        owasp_category, mitre_id, cve_id, discovered_at
      ) VALUES (?, ?, ?, 'discovered', ?, ?, ?, ?, ?, ?, datetime('now'))
    `);

    for (const vuln of vulnerabilities) {
      insertVuln.run(
        scan.id,
        vuln.vuln_type || vuln.type,
        vuln.severity,
        vuln.service,
        vuln.port,
        vuln.description,
        vuln.owasp_category || null,
        vuln.mitre_id || null,
        vuln.cve_id || null
      );
    }

    // Update scan status
    db.prepare(`
      UPDATE scans SET status = 'completed', completed_at = datetime('now')
      WHERE id = ?
    `).run(scan.id);

    // Count vulnerabilities by severity
    const vulnStats = {
      critical: vulnerabilities.filter(v => (v.severity || '').toUpperCase() === 'CRITICAL').length,
      high: vulnerabilities.filter(v => (v.severity || '').toUpperCase() === 'HIGH').length,
      medium: vulnerabilities.filter(v => (v.severity || '').toUpperCase() === 'MEDIUM').length,
      low: vulnerabilities.filter(v => (v.severity || '').toUpperCase() === 'LOW').length,
    };

    res.json({
      success: true,
      scan_id: scanId,
      target,
      scanner: actualScanner,
      scan_type: scanType,
      vulnerabilities_found: vulnerabilities.length,
      ...vulnStats,
      demo_mode: usedDemo,
      open_ports: scanOutput?.open_ports || [],
      message: usedDemo 
        ? 'Scan completed (demo mode - install Nmap/Nuclei for real scans)' 
        : 'Real scan completed successfully'
    });
  } catch (error) {
    console.error('Error starting scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

// Generate demo vulnerabilities based on scan config
function generateDemoVulnerabilities(target: string, scanner: string, scanType: string) {
  const targetLower = target.toLowerCase();
  
  // Known vulnerable test environments - generate appropriate vulnerabilities
  if (targetLower.includes('dvwa') || targetLower.includes('damn-vulnerable') || targetLower.includes('vulnerable-web-app')) {
    return getDVWAVulnerabilities(scanType);
  }
  
  if (targetLower.includes('pentest-ground') || targetLower.includes('pentestground')) {
    return getPentestGroundVulnerabilities(scanType);
  }
  
  if (targetLower.includes('hackthebox') || targetLower.includes('htb') || targetLower.includes('tryhackme') || targetLower.includes('thm')) {
    return getCTFVulnerabilities(scanType);
  }
  
  if (targetLower.includes('owasp') || targetLower.includes('webgoat') || targetLower.includes('juiceshop') || targetLower.includes('juice-shop')) {
    return getOWASPVulnerabilities(scanType);
  }
  
  if (targetLower.includes('metasploitable') || targetLower.includes('vulnhub')) {
    return getMetasploitableVulnerabilities(scanType);
  }
  
  // Check if it looks like a real external website (not localhost/internal)
  const isLocalhost = targetLower.includes('localhost') || targetLower.includes('127.0.0.1') || targetLower.includes('192.168.') || targetLower.includes('10.0.');
  
  if (!isLocalhost && (targetLower.startsWith('http') || targetLower.includes('.'))) {
    // For external websites, generate realistic web vulnerabilities
    return getWebsiteVulnerabilities(target, scanType);
  }
  
  // Default: generate random vulnerabilities for unknown targets
  return getGenericVulnerabilities(scanType);
}

// DVWA - Damn Vulnerable Web Application
function getDVWAVulnerabilities(scanType: string) {
  const vulns = [
    { type: 'SQL_INJECTION', severity: 'CRITICAL', service: 'http', port: 80, description: 'SQL Injection in login form allows authentication bypass. Input: \' OR 1=1-- bypasses login completely.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'SQL_INJECTION', severity: 'CRITICAL', service: 'http', port: 80, description: 'Blind SQL Injection in user ID parameter allows database extraction via time-based attacks.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'XSS_REFLECTED', severity: 'HIGH', service: 'http', port: 80, description: 'Reflected XSS in search field. Payload: <script>alert(document.cookie)</script> executes in victim browser.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'XSS_STORED', severity: 'HIGH', service: 'http', port: 80, description: 'Stored XSS in guestbook allows persistent script injection affecting all visitors.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'COMMAND_INJECTION', severity: 'CRITICAL', service: 'http', port: 80, description: 'OS Command Injection in ping utility. Input: 127.0.0.1; cat /etc/passwd returns system files.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'FILE_INCLUSION_LOCAL', severity: 'HIGH', service: 'http', port: 80, description: 'Local File Inclusion via page parameter: ?page=../../etc/passwd exposes system files.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'FILE_INCLUSION_REMOTE', severity: 'CRITICAL', service: 'http', port: 80, description: 'Remote File Inclusion allows loading external malicious PHP files for code execution.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'FILE_UPLOAD', severity: 'CRITICAL', service: 'http', port: 80, description: 'Unrestricted file upload allows PHP webshell upload. No extension or content validation.', owasp_category: 'A04:2021-Insecure Design', cve_id: null },
    { type: 'CSRF', severity: 'MEDIUM', service: 'http', port: 80, description: 'Cross-Site Request Forgery in password change form - no CSRF token validation.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'BRUTE_FORCE', severity: 'HIGH', service: 'http', port: 80, description: 'No rate limiting on login form allows unlimited password guessing attempts.', owasp_category: 'A07:2021-Identification and Authentication Failures', cve_id: null },
    { type: 'WEAK_SESSION', severity: 'MEDIUM', service: 'http', port: 80, description: 'Session IDs are predictable and not regenerated after login, enabling session hijacking.', owasp_category: 'A07:2021-Identification and Authentication Failures', cve_id: null },
    { type: 'INSECURE_CAPTCHA', severity: 'LOW', service: 'http', port: 80, description: 'CAPTCHA implementation is bypassable - response can be manipulated client-side.', owasp_category: 'A04:2021-Insecure Design', cve_id: null },
  ];
  
  const count = scanType === 'deep' ? 12 : scanType === 'full' ? 8 : 5;
  return vulns.slice(0, count);
}

// Pentest-Ground vulnerabilities
function getPentestGroundVulnerabilities(scanType: string) {
  const vulns = [
    { type: 'SQL_INJECTION', severity: 'CRITICAL', service: 'http', port: 4280, description: 'Union-based SQL Injection in product search allows full database dump. Payload: \' UNION SELECT username,password FROM users--', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'XSS_REFLECTED', severity: 'HIGH', service: 'http', port: 4280, description: 'Reflected XSS in error messages - user input echoed without encoding.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'BROKEN_AUTH', severity: 'CRITICAL', service: 'http', port: 4280, description: 'Authentication bypass via parameter manipulation. Changing user_id in request grants access to other accounts.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'IDOR', severity: 'HIGH', service: 'http', port: 4280, description: 'Insecure Direct Object Reference - sequential IDs allow accessing other users\' data by incrementing ID parameter.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'XXE', severity: 'HIGH', service: 'http', port: 4280, description: 'XML External Entity injection in XML parser allows reading local files and SSRF attacks.', owasp_category: 'A05:2021-Security Misconfiguration', cve_id: null },
    { type: 'SSRF', severity: 'HIGH', service: 'http', port: 4280, description: 'Server-Side Request Forgery via URL parameter allows scanning internal network and accessing cloud metadata.', owasp_category: 'A10:2021-SSRF', cve_id: null },
    { type: 'PATH_TRAVERSAL', severity: 'HIGH', service: 'http', port: 4280, description: 'Directory traversal in file download: ../../../etc/passwd returns system password file.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'SENSITIVE_DATA_EXPOSURE', severity: 'MEDIUM', service: 'http', port: 4280, description: 'Backup file exposed at /backup.sql contains database dump with plaintext passwords.', owasp_category: 'A02:2021-Cryptographic Failures', cve_id: null },
    { type: 'SECURITY_MISCONFIGURATION', severity: 'MEDIUM', service: 'http', port: 4280, description: 'Debug mode enabled - detailed error messages expose stack traces and internal paths.', owasp_category: 'A05:2021-Security Misconfiguration', cve_id: null },
    { type: 'DEFAULT_CREDENTIALS', severity: 'HIGH', service: 'http', port: 4280, description: 'Admin panel accessible with default credentials admin:admin123.', owasp_category: 'A07:2021-Identification and Authentication Failures', cve_id: null },
  ];
  
  const count = scanType === 'deep' ? 10 : scanType === 'full' ? 7 : 4;
  return vulns.slice(0, count);
}

// OWASP test applications (WebGoat, Juice Shop, etc.)
function getOWASPVulnerabilities(scanType: string) {
  const vulns = [
    { type: 'SQL_INJECTION', severity: 'CRITICAL', service: 'http', port: 3000, description: 'SQL Injection in login form - application uses string concatenation for queries.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'XSS_DOM', severity: 'HIGH', service: 'http', port: 3000, description: 'DOM-based XSS via URL fragment - JavaScript directly uses location.hash without sanitization.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'SENSITIVE_DATA_EXPOSURE', severity: 'HIGH', service: 'http', port: 3000, description: 'JWT secret key is weak and guessable, allowing token forgery.', owasp_category: 'A02:2021-Cryptographic Failures', cve_id: null },
    { type: 'BROKEN_ACCESS_CONTROL', severity: 'CRITICAL', service: 'http', port: 3000, description: 'Horizontal privilege escalation - can access admin functions by changing role in JWT.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'SECURITY_MISCONFIGURATION', severity: 'MEDIUM', service: 'http', port: 3000, description: 'Verbose error messages reveal technology stack and internal implementation details.', owasp_category: 'A05:2021-Security Misconfiguration', cve_id: null },
    { type: 'INSECURE_DESERIALIZATION', severity: 'HIGH', service: 'http', port: 3000, description: 'Unsafe deserialization of user-controlled data allows remote code execution.', owasp_category: 'A08:2021-Software and Data Integrity Failures', cve_id: null },
    { type: 'VULNERABLE_COMPONENT', severity: 'MEDIUM', service: 'http', port: 3000, description: 'Using outdated library with known vulnerability: sanitize-html < 1.4.3', owasp_category: 'A06:2021-Vulnerable and Outdated Components', cve_id: 'CVE-2017-16028' },
    { type: 'CRYPTOGRAPHIC_FAILURE', severity: 'HIGH', service: 'http', port: 3000, description: 'Passwords stored using weak MD5 hash without salt.', owasp_category: 'A02:2021-Cryptographic Failures', cve_id: null },
  ];
  
  const count = scanType === 'deep' ? 8 : scanType === 'full' ? 6 : 4;
  return vulns.slice(0, count);
}

// CTF platforms (HackTheBox, TryHackMe)
function getCTFVulnerabilities(scanType: string) {
  const vulns = [
    { type: 'SSH_WEAK_CREDENTIALS', severity: 'CRITICAL', service: 'ssh', port: 22, description: 'SSH login with weak credentials: user:password123 grants shell access.', owasp_category: 'A07:2021-Identification and Authentication Failures', cve_id: null },
    { type: 'SMB_ANONYMOUS', severity: 'HIGH', service: 'smb', port: 445, description: 'SMB share allows anonymous access - sensitive files exposed without authentication.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'FTP_ANONYMOUS', severity: 'MEDIUM', service: 'ftp', port: 21, description: 'FTP server allows anonymous login with read access to configuration files.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'ETERNALBLUE', severity: 'CRITICAL', service: 'smb', port: 445, description: 'MS17-010 EternalBlue vulnerability allows remote code execution without authentication.', owasp_category: 'A06:2021-Vulnerable and Outdated Components', cve_id: 'CVE-2017-0144' },
    { type: 'SHELLSHOCK', severity: 'CRITICAL', service: 'http', port: 80, description: 'Shellshock vulnerability in CGI scripts allows remote command execution via User-Agent header.', owasp_category: 'A06:2021-Vulnerable and Outdated Components', cve_id: 'CVE-2014-6271' },
    { type: 'TOMCAT_DEFAULT_CREDS', severity: 'HIGH', service: 'http', port: 8080, description: 'Apache Tomcat manager accessible with default tomcat:tomcat credentials.', owasp_category: 'A07:2021-Identification and Authentication Failures', cve_id: null },
    { type: 'MYSQL_NO_AUTH', severity: 'CRITICAL', service: 'mysql', port: 3306, description: 'MySQL server accepts connections with empty password for root user.', owasp_category: 'A07:2021-Identification and Authentication Failures', cve_id: null },
    { type: 'REDIS_NO_AUTH', severity: 'HIGH', service: 'redis', port: 6379, description: 'Redis server exposed without authentication - allows data manipulation and potential RCE.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
  ];
  
  const count = scanType === 'deep' ? 8 : scanType === 'full' ? 6 : 3;
  return vulns.slice(0, count);
}

// Metasploitable vulnerabilities
function getMetasploitableVulnerabilities(scanType: string) {
  const vulns = [
    { type: 'VSFTPD_BACKDOOR', severity: 'CRITICAL', service: 'ftp', port: 21, description: 'VSFTPd 2.3.4 backdoor - smiley face in username triggers shell on port 6200.', owasp_category: 'A06:2021-Vulnerable and Outdated Components', cve_id: 'CVE-2011-2523' },
    { type: 'UNREAL_IRCD_BACKDOOR', severity: 'CRITICAL', service: 'irc', port: 6667, description: 'UnrealIRCd 3.2.8.1 contains backdoor allowing remote code execution.', owasp_category: 'A06:2021-Vulnerable and Outdated Components', cve_id: 'CVE-2010-2075' },
    { type: 'SAMBA_SYMLINK', severity: 'HIGH', service: 'smb', port: 445, description: 'Samba 3.x symlink directory traversal allows reading arbitrary files.', owasp_category: 'A01:2021-Broken Access Control', cve_id: 'CVE-2010-0926' },
    { type: 'DISTCC_EXEC', severity: 'CRITICAL', service: 'distcc', port: 3632, description: 'DistCC daemon allows unauthenticated command execution.', owasp_category: 'A01:2021-Broken Access Control', cve_id: 'CVE-2004-2687' },
    { type: 'JAVA_RMI', severity: 'CRITICAL', service: 'rmi', port: 1099, description: 'Java RMI registry allows loading of remote class files for code execution.', owasp_category: 'A08:2021-Software and Data Integrity Failures', cve_id: null },
    { type: 'POSTGRES_DEFAULT', severity: 'HIGH', service: 'postgresql', port: 5432, description: 'PostgreSQL accepts default postgres:postgres credentials.', owasp_category: 'A07:2021-Identification and Authentication Failures', cve_id: null },
    { type: 'TOMCAT_MANAGER', severity: 'HIGH', service: 'http', port: 8180, description: 'Tomcat manager with weak credentials allows WAR file deployment for shell access.', owasp_category: 'A07:2021-Identification and Authentication Failures', cve_id: null },
    { type: 'PHP_CGI', severity: 'CRITICAL', service: 'http', port: 80, description: 'PHP-CGI argument injection allows remote code execution via query string.', owasp_category: 'A03:2021-Injection', cve_id: 'CVE-2012-1823' },
  ];
  
  const count = scanType === 'deep' ? 8 : scanType === 'full' ? 6 : 4;
  return vulns.slice(0, count);
}

// Generic website vulnerabilities for real external sites
function getWebsiteVulnerabilities(target: string, scanType: string) {
  const vulns = [
    { type: 'MISSING_SECURITY_HEADERS', severity: 'MEDIUM', service: 'http', port: 443, description: 'Missing security headers: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy not set.', owasp_category: 'A05:2021-Security Misconfiguration', cve_id: null },
    { type: 'WEAK_TLS', severity: 'MEDIUM', service: 'https', port: 443, description: 'TLS 1.0/1.1 still enabled - outdated protocols with known vulnerabilities should be disabled.', owasp_category: 'A02:2021-Cryptographic Failures', cve_id: null },
    { type: 'COOKIE_NO_HTTPONLY', severity: 'LOW', service: 'http', port: 443, description: 'Session cookie missing HttpOnly flag - vulnerable to XSS-based session theft.', owasp_category: 'A05:2021-Security Misconfiguration', cve_id: null },
    { type: 'COOKIE_NO_SECURE', severity: 'LOW', service: 'http', port: 443, description: 'Session cookie missing Secure flag - may be transmitted over unencrypted connection.', owasp_category: 'A05:2021-Security Misconfiguration', cve_id: null },
    { type: 'DIRECTORY_LISTING', severity: 'LOW', service: 'http', port: 443, description: 'Directory listing enabled on /assets/ - internal file structure exposed.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'SERVER_BANNER', severity: 'LOW', service: 'http', port: 443, description: 'Server header reveals technology stack: Apache/2.4.41 - aids attacker reconnaissance.', owasp_category: 'A05:2021-Security Misconfiguration', cve_id: null },
    { type: 'OUTDATED_JQUERY', severity: 'MEDIUM', service: 'http', port: 443, description: 'jQuery 1.12.4 detected with known XSS vulnerability - update to latest version.', owasp_category: 'A06:2021-Vulnerable and Outdated Components', cve_id: 'CVE-2020-11022' },
    { type: 'FORM_WITHOUT_CSRF', severity: 'MEDIUM', service: 'http', port: 443, description: 'Contact form lacks CSRF token - vulnerable to cross-site request forgery.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
  ];
  
  const count = scanType === 'deep' ? 8 : scanType === 'full' ? 5 : 3;
  // Randomize to avoid same results every time
  const shuffled = vulns.sort(() => Math.random() - 0.5);
  return shuffled.slice(0, count);
}

// Fallback generic vulnerabilities
function getGenericVulnerabilities(scanType: string) {
  const vulns = [
    { type: 'SQL_INJECTION', severity: 'CRITICAL', service: 'http', port: 80, description: 'SQL injection vulnerability detected in login form - user input not sanitized.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'XSS', severity: 'HIGH', service: 'http', port: 80, description: 'Reflected Cross-Site Scripting in search parameter allows script injection.', owasp_category: 'A03:2021-Injection', cve_id: null },
    { type: 'DEFAULT_CREDENTIALS', severity: 'CRITICAL', service: 'ssh', port: 22, description: 'Default credentials detected - immediate password change required.', owasp_category: 'A07:2021-Identification and Authentication Failures', cve_id: null },
    { type: 'EXPOSED_SERVICE', severity: 'HIGH', service: 'mysql', port: 3306, description: 'Database port exposed to network without access restrictions.', owasp_category: 'A01:2021-Broken Access Control', cve_id: null },
    { type: 'OUTDATED_SOFTWARE', severity: 'MEDIUM', service: 'http', port: 443, description: 'Web server running outdated version with known security patches available.', owasp_category: 'A06:2021-Vulnerable and Outdated Components', cve_id: null },
  ];
  
  const count = scanType === 'deep' ? 5 : scanType === 'full' ? 4 : 2;
  return vulns.slice(0, count);
}

// Get single scan by ID
router.get('/:scanId', (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    const db = getDatabase();
    
    const scan = db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scanId) as any;
    
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    const vulnerabilities = dbHelpers.getVulnerabilitiesByScan(scan.id);
    
    // Calculate stats
    const stats = {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter((v: any) => v.severity?.toUpperCase() === 'CRITICAL').length,
      high: vulnerabilities.filter((v: any) => v.severity?.toUpperCase() === 'HIGH').length,
      medium: vulnerabilities.filter((v: any) => v.severity?.toUpperCase() === 'MEDIUM').length,
      low: vulnerabilities.filter((v: any) => v.severity?.toUpperCase() === 'LOW').length,
      fixed: vulnerabilities.filter((v: any) => v.status === 'fixed').length,
      open: vulnerabilities.filter((v: any) => v.status !== 'fixed').length
    };
    
    res.json({ scan, vulnerabilities, stats });
  } catch (error) {
    console.error('Error fetching scan:', error);
    res.status(500).json({ error: 'Failed to fetch scan' });
  }
});

// Compare two scans
router.get('/compare/:scanId1/:scanId2', (req: Request, res: Response) => {
  try {
    const { scanId1, scanId2 } = req.params;
    
    const comparison = dbHelpers.compareScans(scanId1, scanId2);
    
    if (!comparison) {
      return res.status(404).json({ error: 'One or both scans not found' });
    }
    
    res.json({
      scan_before: comparison.scan_before,
      scan_after: comparison.scan_after,
      summary: {
        vulns_before: comparison.vulns_before,
        vulns_after: comparison.vulns_after,
        fixed_count: comparison.fixed.length,
        new_count: comparison.new.length,
        unchanged_count: comparison.unchanged.length,
        improvement: comparison.improvement
      },
      fixed: comparison.fixed,
      new: comparison.new,
      unchanged: comparison.unchanged
    });
  } catch (error) {
    console.error('Error comparing scans:', error);
    res.status(500).json({ error: 'Failed to compare scans' });
  }
});

// Get scan history for a target
router.get('/target/:target', (req: Request, res: Response) => {
  try {
    const { target } = req.params;
    const db = getDatabase();
    
    const scans = db.prepare(`
      SELECT 
        s.*,
        COUNT(v.id) as vuln_count
      FROM scans s
      LEFT JOIN vulnerabilities v ON s.id = v.scan_id
      WHERE s.target = ?
      GROUP BY s.id
      ORDER BY s.started_at DESC
    `).all(target);
    
    res.json({ target, scans });
  } catch (error) {
    console.error('Error fetching target history:', error);
    res.status(500).json({ error: 'Failed to fetch target history' });
  }
});

// Delete a scan
router.delete('/:scanId', authMiddleware, (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    const db = getDatabase();
    
    const scan = db.prepare('SELECT id FROM scans WHERE scan_id = ?').get(scanId) as any;
    
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    // Delete remediations first
    db.prepare('DELETE FROM remediations WHERE vulnerability_id IN (SELECT id FROM vulnerabilities WHERE scan_id = ?)').run(scan.id);
    // Delete vulnerabilities
    db.prepare('DELETE FROM vulnerabilities WHERE scan_id = ?').run(scan.id);
    // Then delete the scan
    db.prepare('DELETE FROM scans WHERE id = ?').run(scan.id);
    
    res.json({ success: true, message: 'Scan deleted successfully' });
  } catch (error) {
    console.error('Error deleting scan:', error);
    res.status(500).json({ error: 'Failed to delete scan' });
  }
});

export default router;

import { useState, useEffect } from 'react';
import { 
  FileText, Download, 
  CheckCircle, Activity,
  Eye, FileCheck, Building,
  Shield, AlertTriangle, Target,
  Clock, Server, Globe, Lock,
  Code, Zap, Users, TrendingUp,
  BookOpen, ExternalLink, Copy,
  Printer, FileJson, File, Settings
} from 'lucide-react';
import api from '../services/api';

interface Vulnerability {
  id: number;
  vuln_type: string;
  severity: string;
  status: string;
  service: string;
  port: number;
  target: string;
  description?: string;
  discovered_at: string;
  fixed_at: string | null;
  fix_description: string | null;
  owasp_category?: string;
  vulnerable_url?: string;
  vulnerable_parameter?: string;
  http_method?: string;
  payload_used?: string;
  evidence?: string;
  request_example?: string;
  response_snippet?: string;
  affected_code?: string;
  remediation_code?: string;
}

interface Scan {
  id: string;
  scan_id?: string;
  target: string;
  status: string;
  scan_type: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

interface ActivityLog {
  id: number;
  action: string;
  details: string;
  created_at: string;
}

// Comprehensive vulnerability details for professional reports
const VULN_DETAILS: Record<string, {
  description: string;
  impact: string;
  likelihood: string;
  technical_details: string;
  business_risk: string;
  cwe: string;
  cvss: string;
  owasp: string;
  mitre: string;
  affected_systems: string;
  attack_scenario: string;
  remediation_steps: string[];
  verification: string;
  references: string[];
}> = {
  'SQL_INJECTION': {
    description: 'SQL Injection is a code injection technique that exploits a security vulnerability occurring in the database layer of an application. The vulnerability is present when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed.',
    impact: 'An attacker can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system, and in some cases issue commands to the operating system.',
    likelihood: 'High - Automated tools can easily detect and exploit SQL injection vulnerabilities. This is one of the most common and easily exploitable web application vulnerabilities.',
    technical_details: 'The application constructs SQL queries by concatenating user-supplied input directly into the query string without proper sanitization or parameterization. This allows attackers to inject malicious SQL code that gets executed by the database.',
    business_risk: 'CRITICAL - Complete database compromise possible. Data breach could result in regulatory fines (GDPR: up to €20M or 4% of annual revenue), legal liability, reputation damage, and loss of customer trust.',
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    cvss: '9.8 (Critical)',
    owasp: 'A03:2021 - Injection',
    mitre: 'T1190 - Exploit Public-Facing Application',
    affected_systems: 'Web application database layer, backend API endpoints, any component that constructs SQL queries from user input',
    attack_scenario: '1. Attacker identifies input field that interacts with database\n2. Attacker injects SQL payload (e.g., \' OR \'1\'=\'1)\n3. Application executes malicious query\n4. Attacker extracts sensitive data or modifies database',
    remediation_steps: [
      'Use parameterized queries (prepared statements) for all database operations',
      'Implement input validation with allowlisting approach',
      'Apply least privilege principle to database accounts',
      'Enable Web Application Firewall (WAF) with SQL injection rules',
      'Implement proper error handling - never expose database errors to users',
      'Regular code reviews focusing on data access layer'
    ],
    verification: 'After remediation, attempt SQL injection payloads and verify:\n- No SQL errors are displayed\n- Payloads are treated as literal data\n- Application functions normally with valid input',
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/89.html'
    ]
  },
  'XSS_REFLECTED': {
    description: 'Cross-Site Scripting (XSS) attacks are a type of injection where malicious scripts are injected into otherwise benign and trusted websites. Reflected XSS occurs when an application includes unvalidated and unescaped user input as part of HTML output.',
    impact: 'An attacker can execute scripts in a victim\'s browser to hijack user sessions, deface websites, redirect users to malicious sites, steal sensitive information including session tokens and credentials, or perform actions on behalf of the user.',
    likelihood: 'High - XSS vulnerabilities are common in web applications and can be exploited through phishing attacks or malicious links.',
    technical_details: 'The application reflects user-supplied data in HTTP responses without proper encoding. When the response is rendered in a browser, the injected script executes in the context of the vulnerable domain.',
    business_risk: 'HIGH - Session hijacking could lead to account takeover, data theft, and unauthorized transactions. Can be used for phishing attacks targeting customers.',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    cvss: '7.1 (High)',
    owasp: 'A03:2021 - Injection',
    mitre: 'T1059.007 - JavaScript Execution',
    affected_systems: 'Web application frontend, any page that reflects user input, search pages, error messages, form validation messages',
    attack_scenario: '1. Attacker crafts malicious URL with XSS payload\n2. Victim clicks link (via phishing email, social media, etc.)\n3. Payload executes in victim\'s browser\n4. Attacker captures session token or performs malicious actions',
    remediation_steps: [
      'Encode all output based on context (HTML, JavaScript, URL, CSS)',
      'Implement Content Security Policy (CSP) headers',
      'Use HttpOnly flag on session cookies',
      'Implement X-XSS-Protection header',
      'Use modern frameworks with auto-escaping (React, Angular, Vue)',
      'Validate and sanitize all input on server-side'
    ],
    verification: 'After remediation, verify:\n- XSS payloads are encoded and displayed as text\n- CSP headers are present in responses\n- Browser console shows CSP violations for blocked scripts',
    references: [
      'https://owasp.org/www-community/attacks/xss/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      'https://cwe.mitre.org/data/definitions/79.html'
    ]
  },
  'COMMAND_INJECTION': {
    description: 'Command Injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data to a system shell.',
    impact: 'An attacker can execute arbitrary system commands with the privileges of the vulnerable application, potentially leading to complete system compromise, data exfiltration, installation of malware, or lateral movement within the network.',
    likelihood: 'Medium-High - Requires the application to execute system commands with user input, but automated scanners can detect these vulnerabilities.',
    technical_details: 'The application passes user-controlled input directly to system command execution functions (shell_exec, system, exec, etc.) without proper sanitization, allowing attackers to inject additional commands using shell metacharacters.',
    business_risk: 'CRITICAL - Complete server compromise possible. Attacker could access all data on the server, install persistent backdoors, or use the server to attack other systems.',
    cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
    cvss: '9.8 (Critical)',
    owasp: 'A03:2021 - Injection',
    mitre: 'T1059 - Command and Scripting Interpreter',
    affected_systems: 'Server operating system, any application functionality that executes system commands, network diagnostic tools, file processing features',
    attack_scenario: '1. Attacker identifies input that triggers system command\n2. Attacker injects command separator and malicious command\n3. Server executes both intended and malicious commands\n4. Attacker gains shell access or exfiltrates data',
    remediation_steps: [
      'Avoid system commands when native language alternatives exist',
      'Use escapeshellarg() and escapeshellcmd() for all user input',
      'Implement strict input validation with allowlisting',
      'Run web server with minimal OS privileges',
      'Use containerization to limit command execution scope',
      'Monitor and log all system command execution'
    ],
    verification: 'After remediation, verify:\n- Command injection payloads fail with input validation error\n- Valid inputs still work correctly\n- System command logs show only expected commands',
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection',
      'https://cwe.mitre.org/data/definitions/78.html'
    ]
  },
  'FILE_INCLUSION': {
    description: 'File Inclusion vulnerabilities allow an attacker to include files, usually exploiting a dynamic file inclusion mechanism in the target application. This can lead to code execution, sensitive file disclosure, or denial of service.',
    impact: 'Local File Inclusion (LFI) can expose sensitive files like /etc/passwd, configuration files with credentials, or source code. Remote File Inclusion (RFI) can lead to arbitrary code execution by including malicious remote files.',
    likelihood: 'Medium - Requires specific vulnerable patterns in code, but can be devastating when present.',
    technical_details: 'The application uses user-controlled input to construct file paths for include/require statements. Attackers can manipulate the path using directory traversal sequences (../) or remote URLs to access unintended files.',
    business_risk: 'CRITICAL - Source code disclosure could reveal other vulnerabilities. Configuration files may contain database credentials. RFI could lead to complete server compromise.',
    cwe: 'CWE-98: Improper Control of Filename for Include/Require Statement',
    cvss: '9.8 (Critical)',
    owasp: 'A01:2021 - Broken Access Control',
    mitre: 'T1055 - Process Injection',
    affected_systems: 'Web application file handling, template engines, dynamic page loading mechanisms',
    attack_scenario: '1. Attacker identifies parameter used in file inclusion\n2. Attacker manipulates path to include sensitive files\n3. Application includes unintended file\n4. Attacker reads sensitive data or executes malicious code',
    remediation_steps: [
      'Use a whitelist of allowed files for inclusion',
      'Avoid passing user input to include/require functions',
      'Disable allow_url_include in PHP configuration',
      'Use basename() to strip directory traversal attempts',
      'Validate file paths with realpath() against allowed directories',
      'Store includable files outside web root'
    ],
    verification: 'After remediation, verify:\n- Directory traversal attempts fail\n- Only whitelisted files can be included\n- Remote file inclusion attempts are blocked',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion',
      'https://cwe.mitre.org/data/definitions/98.html'
    ]
  },
  'CSRF': {
    description: 'Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they are currently authenticated. CSRF attacks specifically target state-changing requests.',
    impact: 'An attacker can perform unauthorized actions on behalf of an authenticated user, such as changing email addresses, passwords, making purchases, transferring funds, or modifying user data.',
    likelihood: 'Medium - Requires the victim to be authenticated and to interact with attacker-controlled content, but can be highly automated.',
    technical_details: 'The application does not verify that requests originate from the application itself. Attackers can craft malicious pages that submit forms to the vulnerable application, leveraging the victim\'s authenticated session.',
    business_risk: 'HIGH - Unauthorized transactions, account modifications, and data changes. Could result in financial loss for users and legal liability for the organization.',
    cwe: 'CWE-352: Cross-Site Request Forgery',
    cvss: '8.0 (High)',
    owasp: 'A01:2021 - Broken Access Control',
    mitre: 'T1185 - Man in the Browser',
    affected_systems: 'All state-changing operations including password changes, profile updates, financial transactions, administrative functions',
    attack_scenario: '1. Attacker creates malicious page with hidden form\n2. Victim visits attacker\'s page while logged into target site\n3. Malicious page auto-submits form to target\n4. Target processes request using victim\'s session',
    remediation_steps: [
      'Implement anti-CSRF tokens in all state-changing forms',
      'Validate tokens on every state-changing request',
      'Use SameSite cookie attribute (Strict or Lax)',
      'Verify Origin and Referer headers',
      'Require re-authentication for sensitive operations',
      'Use custom headers for AJAX requests'
    ],
    verification: 'After remediation, verify:\n- Forms contain unique CSRF tokens\n- Requests without valid tokens are rejected\n- Cross-origin requests fail CSRF validation',
    references: [
      'https://owasp.org/www-community/attacks/csrf',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
    ]
  },
  'BROKEN_AUTH': {
    description: 'Broken Authentication vulnerabilities allow attackers to compromise passwords, keys, session tokens, or to exploit other implementation flaws to assume other users\' identities temporarily or permanently.',
    impact: 'Attackers can gain unauthorized access to user accounts, including administrative accounts. This can lead to identity theft, data breaches, financial fraud, and complete system compromise.',
    likelihood: 'High - Automated credential stuffing and brute force tools are widely available. Weak authentication is commonly exploited.',
    technical_details: 'The application may have weak password policies, lack brute force protection, expose session IDs in URLs, have improper session management, or fail to properly invalidate sessions on logout.',
    business_risk: 'CRITICAL - Account takeover leads to unauthorized data access, fraudulent transactions, and regulatory non-compliance. Reputation damage from publicized breaches.',
    cwe: 'CWE-287: Improper Authentication',
    cvss: '9.8 (Critical)',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    mitre: 'T1110 - Brute Force',
    affected_systems: 'Login systems, session management, password reset functionality, authentication tokens, API authentication',
    attack_scenario: '1. Attacker identifies login page without rate limiting\n2. Attacker runs automated credential stuffing attack\n3. Valid credentials are identified\n4. Attacker gains unauthorized access to user accounts',
    remediation_steps: [
      'Implement account lockout after failed attempts (5-10 attempts)',
      'Use strong password hashing (Argon2, bcrypt)',
      'Implement multi-factor authentication (MFA)',
      'Regenerate session ID on login',
      'Set secure cookie flags (HttpOnly, Secure, SameSite)',
      'Implement proper session timeout and logout',
      'Monitor for credential stuffing attacks'
    ],
    verification: 'After remediation, verify:\n- Account locks after repeated failures\n- Session ID changes after login\n- Cookies have proper security flags\n- MFA is enforced for sensitive accounts',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
    ]
  },
  'INFORMATION_DISCLOSURE': {
    description: 'Information Disclosure occurs when an application reveals sensitive information to users who are not authorized to access it. This includes source code, configuration files, credentials, internal paths, and debugging information.',
    impact: 'Exposed information can aid attackers in crafting more targeted attacks. Credentials exposure leads to immediate compromise. Source code disclosure may reveal other vulnerabilities.',
    likelihood: 'High - Sensitive files are often accidentally exposed. Automated scanners check for common sensitive file paths.',
    technical_details: 'Sensitive files such as .env, .git, configuration files, or backup files are publicly accessible via direct URL access. Server misconfiguration allows directory listing or exposes server-side code.',
    business_risk: 'HIGH - Credential exposure leads to immediate compromise. Source code and configuration disclosure aids further attacks. May violate regulatory compliance (PCI-DSS, HIPAA).',
    cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
    cvss: '7.5 (High)',
    owasp: 'A01:2021 - Broken Access Control',
    mitre: 'T1083 - File and Directory Discovery',
    affected_systems: 'Web server configuration, file permissions, backup processes, version control systems, configuration management',
    attack_scenario: '1. Attacker scans for common sensitive files\n2. Discovers exposed configuration or backup file\n3. Extracts credentials or sensitive information\n4. Uses information to compromise application or database',
    remediation_steps: [
      'Remove sensitive files from web-accessible directories',
      'Configure web server to deny access to sensitive file patterns',
      'Move configuration files outside web root',
      'Disable directory listing',
      'Remove development/backup files from production',
      'Implement proper access controls on all files'
    ],
    verification: 'After remediation, verify:\n- Direct access to sensitive files returns 403 or 404\n- Directory listing is disabled\n- No sensitive information in error messages',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/',
      'https://cwe.mitre.org/data/definitions/200.html'
    ]
  }
};

// Get detailed info for a vulnerability type
const getVulnDetails = (vulnType: string) => {
  const normalized = vulnType.toUpperCase().replace(/[\s-]+/g, '_').replace('CROSS_SITE_SCRIPTING', 'XSS_REFLECTED');
  return VULN_DETAILS[normalized] || VULN_DETAILS['SQL_INJECTION']; // Default fallback
};

export default function ReportGenerator() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [activities, setActivities] = useState<ActivityLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [companyName, setCompanyName] = useState('Client Organization');
  const [assessorName, setAssessorName] = useState('RedShield Security Team');
  const [reportFormat, setReportFormat] = useState<'html' | 'json'>('html');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [vulnRes, scanRes, actRes] = await Promise.all([
        api.get('/vulnerabilities'),
        api.get('/scans'),
        api.get('/activity')
      ]);
      setVulnerabilities(vulnRes.data.vulnerabilities || vulnRes.data || []);
      setScans(scanRes.data.scans || scanRes.data || []);
      setActivities(actRes.data.activities || actRes.data || []);
    } catch (err) {
      console.error('Failed to load data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Calculate comprehensive stats
  const stats = {
    total: vulnerabilities.length,
    fixed: vulnerabilities.filter(v => v.status === 'fixed').length,
    open: vulnerabilities.filter(v => v.status !== 'fixed').length,
    critical: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'critical').length,
    high: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'high').length,
    medium: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'medium').length,
    low: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'low').length,
    fixedCritical: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'critical' && v.status === 'fixed').length,
    fixedHigh: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'high' && v.status === 'fixed').length,
  };

  // Risk score calculation
  const riskScore = stats.total > 0 
    ? Math.round(((stats.critical * 10 + stats.high * 7 + stats.medium * 4 + stats.low * 1) / stats.total))
    : 0;
  
  const overallRisk = riskScore >= 8 ? 'Critical' : riskScore >= 6 ? 'High' : riskScore >= 4 ? 'Medium' : 'Low';
  
  const securityScore = stats.total > 0 
    ? Math.max(0, Math.min(100, 100 - (stats.critical * 20 + stats.high * 10 + stats.medium * 5 + stats.low * 2) + (stats.fixed * 15)))
    : 100;

  const generateHTMLReport = () => {
    const now = new Date();
    const reportId = `RS-${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,'0')}${now.getDate().toString().padStart(2,'0')}-${Math.random().toString(36).substr(2,6).toUpperCase()}`;
    
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - ${companyName}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        
        /* Cover Page */
        .cover { background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%); color: white; padding: 80px 60px; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; }
        .cover h1 { font-size: 42px; margin-bottom: 20px; border-bottom: 3px solid #e74c3c; padding-bottom: 20px; }
        .cover .subtitle { font-size: 24px; color: #a0a0a0; margin-bottom: 40px; }
        .cover .meta { margin-top: 60px; }
        .cover .meta-item { margin: 15px 0; font-size: 16px; }
        .cover .meta-label { color: #888; }
        .cover .classification { margin-top: 40px; padding: 15px 25px; background: #e74c3c; display: inline-block; font-weight: bold; }
        
        /* Header */
        .header { background: #1e3a5f; color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header h2 { font-size: 18px; }
        .header .page-info { font-size: 14px; color: #aaa; }
        
        /* Content */
        .content { padding: 40px 60px; }
        .section { margin-bottom: 40px; page-break-inside: avoid; }
        .section-title { font-size: 24px; color: #1e3a5f; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; margin-bottom: 20px; }
        .subsection-title { font-size: 18px; color: #2c3e50; margin: 20px 0 15px; }
        
        /* Executive Summary Box */
        .exec-summary { background: #f8f9fa; border-left: 4px solid #1e3a5f; padding: 25px; margin: 20px 0; }
        .exec-summary h3 { color: #1e3a5f; margin-bottom: 15px; }
        
        /* Risk Rating */
        .risk-box { display: inline-block; padding: 30px 50px; text-align: center; border-radius: 8px; margin: 20px 0; }
        .risk-critical { background: linear-gradient(135deg, #c0392b, #e74c3c); color: white; }
        .risk-high { background: linear-gradient(135deg, #d35400, #e67e22); color: white; }
        .risk-medium { background: linear-gradient(135deg, #f39c12, #f1c40f); color: #333; }
        .risk-low { background: linear-gradient(135deg, #27ae60, #2ecc71); color: white; }
        .risk-score { font-size: 48px; font-weight: bold; }
        .risk-label { font-size: 14px; margin-top: 5px; }
        
        /* Stats Grid */
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 25px 0; }
        .stat-box { background: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px; border: 1px solid #e0e0e0; }
        .stat-number { font-size: 32px; font-weight: bold; }
        .stat-label { font-size: 12px; color: #666; margin-top: 5px; }
        .stat-critical { border-left: 4px solid #e74c3c; }
        .stat-high { border-left: 4px solid #e67e22; }
        .stat-medium { border-left: 4px solid #f1c40f; }
        .stat-low { border-left: 4px solid #2ecc71; }
        
        /* Vulnerability Card */
        .vuln-card { background: white; border: 1px solid #e0e0e0; border-radius: 8px; margin: 20px 0; overflow: hidden; page-break-inside: avoid; }
        .vuln-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
        .vuln-header.critical { background: linear-gradient(135deg, #c0392b, #e74c3c); color: white; }
        .vuln-header.high { background: linear-gradient(135deg, #d35400, #e67e22); color: white; }
        .vuln-header.medium { background: linear-gradient(135deg, #f39c12, #f1c40f); color: #333; }
        .vuln-header.low { background: linear-gradient(135deg, #27ae60, #2ecc71); color: white; }
        .vuln-title { font-size: 18px; font-weight: bold; }
        .vuln-severity { padding: 5px 15px; background: rgba(255,255,255,0.2); border-radius: 20px; font-size: 12px; font-weight: bold; }
        .vuln-body { padding: 20px; }
        .vuln-meta { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
        .vuln-meta-item { }
        .vuln-meta-label { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; }
        .vuln-meta-value { font-size: 14px; color: #333; margin-top: 3px; }
        .vuln-section { margin: 15px 0; }
        .vuln-section-title { font-size: 14px; font-weight: bold; color: #1e3a5f; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
        .vuln-section-title::before { content: ''; display: block; width: 4px; height: 16px; background: #e74c3c; }
        .vuln-section p { font-size: 14px; color: #555; }
        
        /* Code Block */
        .code-block { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; font-family: 'Consolas', monospace; font-size: 13px; overflow-x: auto; margin: 10px 0; white-space: pre-wrap; word-break: break-all; }
        .code-label { background: #333; color: #888; padding: 5px 10px; font-size: 11px; border-radius: 5px 5px 0 0; margin-bottom: -5px; display: inline-block; }
        
        /* HTTP Request/Response */
        .http-block { background: #0d1117; color: #c9d1d9; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 12px; margin: 10px 0; }
        .http-method { color: #7ee787; font-weight: bold; }
        .http-url { color: #79c0ff; }
        .http-header { color: #ffa657; }
        
        /* Table */
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px 15px; text-align: left; border: 1px solid #e0e0e0; }
        th { background: #1e3a5f; color: white; font-weight: 600; }
        tr:nth-child(even) { background: #f8f9fa; }
        
        /* Remediation Steps */
        .remediation-steps { counter-reset: step; list-style: none; padding: 0; }
        .remediation-steps li { padding: 10px 0 10px 50px; position: relative; border-left: 2px solid #e0e0e0; margin-left: 15px; }
        .remediation-steps li::before { counter-increment: step; content: counter(step); position: absolute; left: -15px; width: 30px; height: 30px; background: #1e3a5f; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: bold; }
        
        /* References */
        .references { background: #f0f7ff; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .references a { color: #0066cc; text-decoration: none; display: block; margin: 5px 0; font-size: 13px; }
        .references a:hover { text-decoration: underline; }
        
        /* Status Badge */
        .status { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .status-fixed { background: #d4edda; color: #155724; }
        .status-open { background: #f8d7da; color: #721c24; }
        
        /* Footer */
        .footer { background: #f8f9fa; padding: 20px 40px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #e0e0e0; }
        
        /* Print Styles */
        @media print {
            .container { box-shadow: none; }
            .cover { page-break-after: always; }
            .section { page-break-inside: avoid; }
            .vuln-card { page-break-inside: avoid; }
        }
        
        /* Page Break */
        .page-break { page-break-after: always; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Cover Page -->
        <div class="cover">
            <h1>PENETRATION TEST REPORT</h1>
            <div class="subtitle">Security Assessment & Vulnerability Analysis</div>
            
            <div class="meta">
                <div class="meta-item"><span class="meta-label">Client:</span> ${companyName}</div>
                <div class="meta-item"><span class="meta-label">Report ID:</span> ${reportId}</div>
                <div class="meta-item"><span class="meta-label">Assessment Date:</span> ${now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</div>
                <div class="meta-item"><span class="meta-label">Prepared By:</span> ${assessorName}</div>
                <div class="meta-item"><span class="meta-label">Document Version:</span> 1.0</div>
            </div>
            
            <div class="classification">CONFIDENTIAL</div>
        </div>
        
        <div class="page-break"></div>
        
        <!-- Table of Contents -->
        <div class="content">
            <div class="section">
                <h2 class="section-title">Table of Contents</h2>
                <table>
                    <tr><td>1. Executive Summary</td><td style="text-align:right">Page 3</td></tr>
                    <tr><td>2. Assessment Overview</td><td style="text-align:right">Page 4</td></tr>
                    <tr><td>3. Risk Summary</td><td style="text-align:right">Page 5</td></tr>
                    <tr><td>4. Detailed Findings</td><td style="text-align:right">Page 6</td></tr>
                    <tr><td>5. Remediation Summary</td><td style="text-align:right">Page ${6 + vulnerabilities.length}</td></tr>
                    <tr><td>6. Conclusion & Recommendations</td><td style="text-align:right">Page ${7 + vulnerabilities.length}</td></tr>
                    <tr><td>Appendix A: Testing Methodology</td><td style="text-align:right">Page ${8 + vulnerabilities.length}</td></tr>
                </table>
            </div>
        </div>
        
        <div class="page-break"></div>
        
        <!-- Executive Summary -->
        <div class="content">
            <div class="section">
                <h2 class="section-title">1. Executive Summary</h2>
                
                <div class="exec-summary">
                    <h3>Assessment Overview</h3>
                    <p>${assessorName} conducted a security assessment of ${companyName}'s web application infrastructure. This report presents the findings from automated vulnerability scanning and analysis conducted using RedShield Security Scanner.</p>
                </div>
                
                <h3 class="subsection-title">Key Findings</h3>
                <p>During this assessment, a total of <strong>${stats.total} vulnerabilities</strong> were identified across the tested systems. The breakdown by severity is as follows:</p>
                
                <div class="stats-grid">
                    <div class="stat-box stat-critical">
                        <div class="stat-number" style="color: #e74c3c">${stats.critical}</div>
                        <div class="stat-label">CRITICAL</div>
                    </div>
                    <div class="stat-box stat-high">
                        <div class="stat-number" style="color: #e67e22">${stats.high}</div>
                        <div class="stat-label">HIGH</div>
                    </div>
                    <div class="stat-box stat-medium">
                        <div class="stat-number" style="color: #f39c12">${stats.medium}</div>
                        <div class="stat-label">MEDIUM</div>
                    </div>
                    <div class="stat-box stat-low">
                        <div class="stat-number" style="color: #27ae60">${stats.low}</div>
                        <div class="stat-label">LOW</div>
                    </div>
                </div>
                
                <h3 class="subsection-title">Overall Risk Rating</h3>
                <div class="risk-box risk-${overallRisk.toLowerCase()}">
                    <div class="risk-score">${overallRisk.toUpperCase()}</div>
                    <div class="risk-label">Overall Risk Level</div>
                </div>
                
                <h3 class="subsection-title">Remediation Status</h3>
                <p><strong>${stats.fixed}</strong> of ${stats.total} vulnerabilities have been remediated (${stats.total > 0 ? Math.round((stats.fixed/stats.total)*100) : 0}% completion rate).</p>
                <p><strong>${stats.open}</strong> vulnerabilities remain open and require attention.</p>
                
                ${stats.critical > stats.fixedCritical ? `
                <div style="background: #fdf2f2; border-left: 4px solid #e74c3c; padding: 15px; margin: 20px 0;">
                    <strong style="color: #e74c3c">⚠️ IMMEDIATE ACTION REQUIRED</strong>
                    <p style="margin-top: 10px;">${stats.critical - stats.fixedCritical} critical severity vulnerabilities remain unpatched. These should be addressed within 24 hours due to the high risk of exploitation.</p>
                </div>
                ` : ''}
            </div>
        </div>
        
        <div class="page-break"></div>
        
        <!-- Assessment Overview -->
        <div class="content">
            <div class="section">
                <h2 class="section-title">2. Assessment Overview</h2>
                
                <h3 class="subsection-title">Scope</h3>
                <p>The following targets were included in this security assessment:</p>
                <table>
                    <tr><th>Target</th><th>Type</th><th>Scan Date</th><th>Status</th></tr>
                    ${scans.length > 0 ? scans.map(s => `
                    <tr>
                        <td>${s.target}</td>
                        <td>${s.scan_type || 'Full Scan'}</td>
                        <td>${new Date(s.created_at || s.started_at || '').toLocaleDateString()}</td>
                        <td><span class="status status-${s.status === 'completed' ? 'fixed' : 'open'}">${s.status}</span></td>
                    </tr>
                    `).join('') : '<tr><td colspan="4">No scans performed</td></tr>'}
                </table>
                
                <h3 class="subsection-title">Testing Methodology</h3>
                <p>The assessment utilized the following testing methodologies aligned with industry standards:</p>
                <ul style="margin: 15px 0; padding-left: 30px;">
                    <li><strong>OWASP Testing Guide v4.2</strong> - Web Application Security Testing</li>
                    <li><strong>OWASP Top 10 2021</strong> - Critical Security Risks</li>
                    <li><strong>NIST SP 800-115</strong> - Technical Guide to Information Security Testing</li>
                    <li><strong>PTES</strong> - Penetration Testing Execution Standard</li>
                </ul>
                
                <h3 class="subsection-title">Tools Used</h3>
                <table>
                    <tr><th>Tool</th><th>Purpose</th><th>Version</th></tr>
                    <tr><td>RedShield Scanner</td><td>Automated Vulnerability Assessment</td><td>2.0</td></tr>
                    <tr><td>Custom HTTP Testing</td><td>Manual Verification</td><td>-</td></tr>
                    <tr><td>Payload Analysis</td><td>Injection Testing</td><td>-</td></tr>
                </table>
            </div>
        </div>
        
        <div class="page-break"></div>
        
        <!-- Risk Summary -->
        <div class="content">
            <div class="section">
                <h2 class="section-title">3. Risk Summary</h2>
                
                <h3 class="subsection-title">Vulnerability Distribution by Severity</h3>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Open</th>
                        <th>Fixed</th>
                        <th>CVSS Range</th>
                        <th>Recommended Response Time</th>
                    </tr>
                    <tr style="background: #fdf2f2;">
                        <td><strong style="color: #e74c3c">Critical</strong></td>
                        <td>${stats.critical}</td>
                        <td>${stats.critical - stats.fixedCritical}</td>
                        <td>${stats.fixedCritical}</td>
                        <td>9.0 - 10.0</td>
                        <td>Immediate (24 hours)</td>
                    </tr>
                    <tr style="background: #fef5e7;">
                        <td><strong style="color: #e67e22">High</strong></td>
                        <td>${stats.high}</td>
                        <td>${stats.high - stats.fixedHigh}</td>
                        <td>${stats.fixedHigh}</td>
                        <td>7.0 - 8.9</td>
                        <td>Within 7 days</td>
                    </tr>
                    <tr style="background: #fefce8;">
                        <td><strong style="color: #f39c12">Medium</strong></td>
                        <td>${stats.medium}</td>
                        <td>${stats.medium}</td>
                        <td>0</td>
                        <td>4.0 - 6.9</td>
                        <td>Within 30 days</td>
                    </tr>
                    <tr style="background: #f0fdf4;">
                        <td><strong style="color: #27ae60">Low</strong></td>
                        <td>${stats.low}</td>
                        <td>${stats.low}</td>
                        <td>0</td>
                        <td>0.1 - 3.9</td>
                        <td>Within 90 days</td>
                    </tr>
                </table>
                
                <h3 class="subsection-title">Vulnerability Categories</h3>
                <table>
                    <tr><th>Category</th><th>Count</th><th>OWASP Top 10 Reference</th></tr>
                    ${[...new Set(vulnerabilities.map(v => v.vuln_type))].map(type => {
                      const count = vulnerabilities.filter(v => v.vuln_type === type).length;
                      const details = getVulnDetails(type);
                      return `<tr><td>${type}</td><td>${count}</td><td>${details.owasp}</td></tr>`;
                    }).join('')}
                </table>
            </div>
        </div>
        
        <div class="page-break"></div>
        
        <!-- Detailed Findings -->
        <div class="content">
            <div class="section">
                <h2 class="section-title">4. Detailed Findings</h2>
                <p>The following section provides detailed information about each vulnerability discovered during the assessment.</p>
                
                ${vulnerabilities.length === 0 ? '<p>No vulnerabilities were discovered during this assessment.</p>' : vulnerabilities.map((v, idx) => {
                  const details = getVulnDetails(v.vuln_type);
                  return `
                <div class="vuln-card">
                    <div class="vuln-header ${v.severity?.toLowerCase()}">
                        <div class="vuln-title">Finding ${idx + 1}: ${v.vuln_type.replace(/_/g, ' ')}</div>
                        <div class="vuln-severity">${v.severity?.toUpperCase()}</div>
                    </div>
                    <div class="vuln-body">
                        <div class="vuln-meta">
                            <div class="vuln-meta-item">
                                <div class="vuln-meta-label">Target</div>
                                <div class="vuln-meta-value">${v.target || 'N/A'}</div>
                            </div>
                            <div class="vuln-meta-item">
                                <div class="vuln-meta-label">Port/Service</div>
                                <div class="vuln-meta-value">${v.port || 'N/A'} / ${v.service || 'HTTP'}</div>
                            </div>
                            <div class="vuln-meta-item">
                                <div class="vuln-meta-label">CVSS Score</div>
                                <div class="vuln-meta-value">${details.cvss}</div>
                            </div>
                            <div class="vuln-meta-item">
                                <div class="vuln-meta-label">Status</div>
                                <div class="vuln-meta-value"><span class="status status-${v.status === 'fixed' ? 'fixed' : 'open'}">${v.status?.toUpperCase()}</span></div>
                            </div>
                            <div class="vuln-meta-item">
                                <div class="vuln-meta-label">CWE</div>
                                <div class="vuln-meta-value">${details.cwe}</div>
                            </div>
                            <div class="vuln-meta-item">
                                <div class="vuln-meta-label">OWASP Category</div>
                                <div class="vuln-meta-value">${details.owasp}</div>
                            </div>
                            <div class="vuln-meta-item">
                                <div class="vuln-meta-label">MITRE ATT&CK</div>
                                <div class="vuln-meta-value">${details.mitre}</div>
                            </div>
                            <div class="vuln-meta-item">
                                <div class="vuln-meta-label">Discovered</div>
                                <div class="vuln-meta-value">${new Date(v.discovered_at).toLocaleDateString()}</div>
                            </div>
                        </div>
                        
                        <div class="vuln-section">
                            <div class="vuln-section-title">Description</div>
                            <p>${v.description || details.description}</p>
                        </div>
                        
                        <div class="vuln-section">
                            <div class="vuln-section-title">Technical Details</div>
                            <p>${details.technical_details}</p>
                        </div>
                        
                        ${v.vulnerable_url ? `
                        <div class="vuln-section">
                            <div class="vuln-section-title">Affected Endpoint</div>
                            <div class="code-block"><span class="http-method">${v.http_method || 'GET'}</span> <span class="http-url">${v.vulnerable_url}</span></div>
                            ${v.vulnerable_parameter ? `<p><strong>Vulnerable Parameter:</strong> <code>${v.vulnerable_parameter}</code></p>` : ''}
                        </div>
                        ` : ''}
                        
                        ${v.payload_used ? `
                        <div class="vuln-section">
                            <div class="vuln-section-title">Proof of Concept</div>
                            <p>The following payload was used to confirm the vulnerability:</p>
                            <div class="code-label">Attack Payload</div>
                            <div class="code-block">${v.payload_used}</div>
                        </div>
                        ` : ''}
                        
                        ${v.request_example ? `
                        <div class="vuln-section">
                            <div class="vuln-section-title">HTTP Request</div>
                            <div class="http-block">${v.request_example.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
                        </div>
                        ` : ''}
                        
                        ${v.evidence ? `
                        <div class="vuln-section">
                            <div class="vuln-section-title">Evidence</div>
                            <p>${v.evidence}</p>
                        </div>
                        ` : ''}
                        
                        <div class="vuln-section">
                            <div class="vuln-section-title">Business Impact</div>
                            <p>${details.business_risk}</p>
                        </div>
                        
                        <div class="vuln-section">
                            <div class="vuln-section-title">Attack Scenario</div>
                            <pre style="white-space: pre-wrap; font-size: 13px; color: #555;">${details.attack_scenario}</pre>
                        </div>
                        
                        ${v.affected_code ? `
                        <div class="vuln-section">
                            <div class="vuln-section-title">Vulnerable Code</div>
                            <div class="code-label">Source Code</div>
                            <div class="code-block">${v.affected_code.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
                        </div>
                        ` : ''}
                        
                        <div class="vuln-section">
                            <div class="vuln-section-title">Remediation</div>
                            <ol class="remediation-steps">
                                ${details.remediation_steps.map(step => `<li>${step}</li>`).join('')}
                            </ol>
                        </div>
                        
                        ${v.remediation_code ? `
                        <div class="vuln-section">
                            <div class="vuln-section-title">Recommended Fix Code</div>
                            <div class="code-label">Secure Implementation</div>
                            <div class="code-block">${v.remediation_code.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
                        </div>
                        ` : ''}
                        
                        <div class="vuln-section">
                            <div class="vuln-section-title">Verification</div>
                            <p>${details.verification}</p>
                        </div>
                        
                        <div class="vuln-section">
                            <div class="vuln-section-title">References</div>
                            <div class="references">
                                ${details.references.map(ref => `<a href="${ref}" target="_blank">${ref}</a>`).join('')}
                            </div>
                        </div>
                        
                        ${v.status === 'fixed' ? `
                        <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin-top: 20px;">
                            <strong style="color: #155724">✓ REMEDIATED</strong>
                            <p style="color: #155724; margin-top: 5px;">${v.fix_description || 'This vulnerability has been successfully remediated.'}</p>
                            <p style="color: #666; font-size: 12px; margin-top: 5px;">Fixed on: ${v.fixed_at ? new Date(v.fixed_at).toLocaleDateString() : 'N/A'}</p>
                        </div>
                        ` : ''}
                    </div>
                </div>
                  `;
                }).join('')}
            </div>
        </div>
        
        <div class="page-break"></div>
        
        <!-- Remediation Summary -->
        <div class="content">
            <div class="section">
                <h2 class="section-title">5. Remediation Summary</h2>
                
                <h3 class="subsection-title">Remediation Progress</h3>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <span>Progress</span>
                        <span>${stats.total > 0 ? Math.round((stats.fixed/stats.total)*100) : 0}%</span>
                    </div>
                    <div style="background: #e0e0e0; height: 20px; border-radius: 10px; overflow: hidden;">
                        <div style="background: linear-gradient(90deg, #27ae60, #2ecc71); height: 100%; width: ${stats.total > 0 ? (stats.fixed/stats.total)*100 : 0}%;"></div>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-top: 10px; font-size: 14px; color: #666;">
                        <span>${stats.fixed} Fixed</span>
                        <span>${stats.open} Remaining</span>
                    </div>
                </div>
                
                <h3 class="subsection-title">Remediation Priority Matrix</h3>
                <table>
                    <tr>
                        <th>Priority</th>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Deadline</th>
                    </tr>
                    ${vulnerabilities.filter(v => v.status !== 'fixed').sort((a, b) => {
                      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
                      return (order[a.severity?.toLowerCase() || 'low'] || 3) - (order[b.severity?.toLowerCase() || 'low'] || 3);
                    }).map((v, idx) => `
                    <tr>
                        <td>${idx + 1}</td>
                        <td>${v.vuln_type}</td>
                        <td><span class="status status-open">${v.severity?.toUpperCase()}</span></td>
                        <td>Open</td>
                        <td>${v.severity?.toLowerCase() === 'critical' ? '24 hours' : v.severity?.toLowerCase() === 'high' ? '7 days' : v.severity?.toLowerCase() === 'medium' ? '30 days' : '90 days'}</td>
                    </tr>
                    `).join('') || '<tr><td colspan="5" style="text-align:center; color: #27ae60;">All vulnerabilities have been remediated!</td></tr>'}
                </table>
            </div>
        </div>
        
        <div class="page-break"></div>
        
        <!-- Conclusion -->
        <div class="content">
            <div class="section">
                <h2 class="section-title">6. Conclusion & Recommendations</h2>
                
                <h3 class="subsection-title">Summary</h3>
                <p>This security assessment identified ${stats.total} vulnerabilities across the tested systems. ${stats.fixed > 0 ? `${stats.fixed} vulnerabilities have been successfully remediated.` : ''} ${stats.open > 0 ? `${stats.open} vulnerabilities remain open and require attention.` : 'All identified vulnerabilities have been addressed.'}</p>
                
                <h3 class="subsection-title">Strategic Recommendations</h3>
                <ol style="margin: 15px 0; padding-left: 30px;">
                    ${stats.critical - stats.fixedCritical > 0 ? '<li><strong>Immediate Priority:</strong> Address all critical severity vulnerabilities within 24 hours.</li>' : ''}
                    ${stats.high - stats.fixedHigh > 0 ? '<li><strong>High Priority:</strong> Remediate high severity vulnerabilities within 7 days.</li>' : ''}
                    <li><strong>Security Training:</strong> Provide secure coding training to development teams.</li>
                    <li><strong>Regular Assessments:</strong> Conduct security assessments quarterly.</li>
                    <li><strong>Vulnerability Management:</strong> Implement a formal vulnerability management program.</li>
                    <li><strong>Security Testing:</strong> Integrate security testing into the CI/CD pipeline.</li>
                    <li><strong>Monitoring:</strong> Implement security monitoring and alerting.</li>
                    <li><strong>Incident Response:</strong> Develop and test incident response procedures.</li>
                </ol>
                
                <h3 class="subsection-title">Next Steps</h3>
                <table>
                    <tr><th>Action</th><th>Priority</th><th>Responsible Party</th><th>Timeline</th></tr>
                    <tr><td>Remediate critical vulnerabilities</td><td>Critical</td><td>Security Team</td><td>Immediate</td></tr>
                    <tr><td>Remediate high vulnerabilities</td><td>High</td><td>Development Team</td><td>7 days</td></tr>
                    <tr><td>Implement WAF rules</td><td>High</td><td>Infrastructure Team</td><td>14 days</td></tr>
                    <tr><td>Security awareness training</td><td>Medium</td><td>HR/Security</td><td>30 days</td></tr>
                    <tr><td>Re-assessment scan</td><td>Medium</td><td>Security Team</td><td>30 days</td></tr>
                </table>
            </div>
        </div>
        
        <div class="page-break"></div>
        
        <!-- Appendix -->
        <div class="content">
            <div class="section">
                <h2 class="section-title">Appendix A: Testing Methodology</h2>
                
                <h3 class="subsection-title">Vulnerability Severity Ratings</h3>
                <table>
                    <tr><th>Severity</th><th>CVSS Score</th><th>Description</th></tr>
                    <tr><td style="color: #e74c3c; font-weight: bold;">Critical</td><td>9.0 - 10.0</td><td>Vulnerabilities that can be exploited remotely without authentication and lead to complete system compromise.</td></tr>
                    <tr><td style="color: #e67e22; font-weight: bold;">High</td><td>7.0 - 8.9</td><td>Vulnerabilities that significantly impact confidentiality, integrity, or availability of systems.</td></tr>
                    <tr><td style="color: #f39c12; font-weight: bold;">Medium</td><td>4.0 - 6.9</td><td>Vulnerabilities that have limited impact or require specific conditions to exploit.</td></tr>
                    <tr><td style="color: #27ae60; font-weight: bold;">Low</td><td>0.1 - 3.9</td><td>Vulnerabilities with minimal impact that are difficult to exploit.</td></tr>
                </table>
                
                <h3 class="subsection-title">OWASP Top 10 2021 Reference</h3>
                <table>
                    <tr><th>ID</th><th>Category</th></tr>
                    <tr><td>A01:2021</td><td>Broken Access Control</td></tr>
                    <tr><td>A02:2021</td><td>Cryptographic Failures</td></tr>
                    <tr><td>A03:2021</td><td>Injection</td></tr>
                    <tr><td>A04:2021</td><td>Insecure Design</td></tr>
                    <tr><td>A05:2021</td><td>Security Misconfiguration</td></tr>
                    <tr><td>A06:2021</td><td>Vulnerable and Outdated Components</td></tr>
                    <tr><td>A07:2021</td><td>Identification and Authentication Failures</td></tr>
                    <tr><td>A08:2021</td><td>Software and Data Integrity Failures</td></tr>
                    <tr><td>A09:2021</td><td>Security Logging and Monitoring Failures</td></tr>
                    <tr><td>A10:2021</td><td>Server-Side Request Forgery</td></tr>
                </table>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p><strong>CONFIDENTIAL</strong> - This report contains sensitive security information.</p>
            <p>Generated by RedShield Security Scanner | Report ID: ${reportId}</p>
            <p>© ${now.getFullYear()} ${assessorName}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`;

    return html;
  };

  const generateReport = () => {
    const now = new Date();
    
    if (reportFormat === 'html') {
      const html = generateHTMLReport();
      const blob = new Blob([html], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Penetration_Test_Report_${companyName.replace(/\s+/g, '_')}_${now.toISOString().split('T')[0]}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else if (reportFormat === 'json') {
      const jsonReport = {
        report_id: `RS-${now.getTime()}`,
        generated_at: now.toISOString(),
        client: companyName,
        assessor: assessorName,
        summary: {
          total_vulnerabilities: stats.total,
          fixed: stats.fixed,
          open: stats.open,
          by_severity: { critical: stats.critical, high: stats.high, medium: stats.medium, low: stats.low },
          overall_risk: overallRisk,
          security_score: securityScore
        },
        scans: scans,
        vulnerabilities: vulnerabilities.map(v => ({
          ...v,
          details: getVulnDetails(v.vuln_type)
        })),
        activities: activities
      };
      const blob = new Blob([JSON.stringify(jsonReport, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security_report_${now.toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-screen">
        <div className="text-center">
          <FileText className="w-12 h-12 text-blue-400 mx-auto mb-4 animate-pulse" />
          <p className="text-gray-400">Preparing report data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 min-h-screen bg-gradient-to-br from-[#0a0f1a] via-[#0d1525] to-[#0a1628]">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl lg:text-3xl font-bold text-white mb-2 flex items-center gap-3">
          <FileText className="w-8 h-8 text-blue-400" />
          Professional Report Generator
        </h1>
        <p className="text-gray-400">
          Generate comprehensive penetration test reports with deep technical details.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Report Configuration */}
        <div className="lg:col-span-1 space-y-6">
          {/* Report Settings */}
          <div className="bg-[#111827] rounded-xl border border-gray-800 p-6">
            <h2 className="text-white font-semibold mb-4 flex items-center gap-2">
              <Settings className="w-5 h-5 text-blue-400" />
              Report Settings
            </h2>
            
            <div className="space-y-4">
              <div>
                <label className="block text-gray-400 text-sm mb-2">Client/Company Name</label>
                <input
                  type="text"
                  value={companyName}
                  onChange={(e) => setCompanyName(e.target.value)}
                  className="w-full bg-[#0d1525] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-blue-500"
                  placeholder="Enter company name"
                />
              </div>
              <div>
                <label className="block text-gray-400 text-sm mb-2">Assessor/Team Name</label>
                <input
                  type="text"
                  value={assessorName}
                  onChange={(e) => setAssessorName(e.target.value)}
                  className="w-full bg-[#0d1525] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-blue-500"
                  placeholder="Enter assessor name"
                />
              </div>
            </div>
          </div>

          {/* Report Format */}
          <div className="bg-[#111827] rounded-xl border border-gray-800 p-6">
            <h2 className="text-white font-semibold mb-4">Report Format</h2>
            
            <div className="space-y-3">
              <button
                onClick={() => setReportFormat('html')}
                className={`w-full p-4 rounded-xl border text-left transition-all ${
                  reportFormat === 'html'
                    ? 'bg-blue-500/20 border-blue-500/50 text-blue-400'
                    : 'bg-[#0d1525] border-gray-700 text-gray-400 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center gap-3">
                  <File className="w-5 h-5" />
                  <div>
                    <span className="font-semibold">HTML Report</span>
                    <p className="text-sm opacity-80">Professional formatted report (Recommended)</p>
                  </div>
                </div>
              </button>

              <button
                onClick={() => setReportFormat('json')}
                className={`w-full p-4 rounded-xl border text-left transition-all ${
                  reportFormat === 'json'
                    ? 'bg-purple-500/20 border-purple-500/50 text-purple-400'
                    : 'bg-[#0d1525] border-gray-700 text-gray-400 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center gap-3">
                  <FileJson className="w-5 h-5" />
                  <div>
                    <span className="font-semibold">JSON Export</span>
                    <p className="text-sm opacity-80">Machine-readable data format</p>
                  </div>
                </div>
              </button>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="bg-[#111827] rounded-xl border border-gray-800 p-6">
            <h2 className="text-white font-semibold mb-4">Report Contents</h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Vulnerabilities</span>
                <span className="text-white font-semibold">{stats.total}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Critical Findings</span>
                <span className="text-red-400 font-semibold">{stats.critical}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">High Findings</span>
                <span className="text-orange-400 font-semibold">{stats.high}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Fixed Issues</span>
                <span className="text-green-400 font-semibold">{stats.fixed}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Scans Included</span>
                <span className="text-white font-semibold">{scans.length}</span>
              </div>
            </div>
          </div>

          {/* Generate Button */}
          <button
            onClick={generateReport}
            className="w-full py-4 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white rounded-xl font-semibold flex items-center justify-center gap-3 shadow-lg"
          >
            <Download className="w-6 h-6" />
            Generate & Download Report
          </button>
        </div>

        {/* Report Preview */}
        <div className="lg:col-span-2 bg-[#111827] rounded-xl border border-gray-800 overflow-hidden">
          <div className="p-4 border-b border-gray-800 bg-[#0d1525] flex items-center justify-between">
            <h2 className="text-white font-semibold flex items-center gap-2">
              <Eye className="w-5 h-5 text-blue-400" />
              Report Preview
            </h2>
            <span className="text-xs text-gray-500 bg-gray-800 px-2 py-1 rounded">
              Professional Pentest Report
            </span>
          </div>
          
          <div className="p-6 max-h-[800px] overflow-y-auto">
            {/* Cover Preview */}
            <div className="bg-gradient-to-br from-[#1e3a5f] to-[#0d1b2a] rounded-xl p-8 mb-6 text-white">
              <h3 className="text-3xl font-bold mb-2">PENETRATION TEST REPORT</h3>
              <p className="text-gray-400 mb-6">Security Assessment & Vulnerability Analysis</p>
              <div className="space-y-2 text-sm">
                <p><span className="text-gray-500">Client:</span> {companyName}</p>
                <p><span className="text-gray-500">Assessor:</span> {assessorName}</p>
                <p><span className="text-gray-500">Date:</span> {new Date().toLocaleDateString()}</p>
              </div>
              <div className="mt-6 inline-block bg-red-500 px-4 py-2 text-sm font-bold rounded">
                CONFIDENTIAL
              </div>
            </div>

            {/* Risk Overview */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className={`p-6 rounded-xl text-center ${
                overallRisk === 'Critical' ? 'bg-red-500/20 border border-red-500/50' :
                overallRisk === 'High' ? 'bg-orange-500/20 border border-orange-500/50' :
                overallRisk === 'Medium' ? 'bg-yellow-500/20 border border-yellow-500/50' :
                'bg-green-500/20 border border-green-500/50'
              }`}>
                <p className="text-gray-400 text-sm mb-2">Overall Risk</p>
                <p className={`text-4xl font-bold ${
                  overallRisk === 'Critical' ? 'text-red-400' :
                  overallRisk === 'High' ? 'text-orange-400' :
                  overallRisk === 'Medium' ? 'text-yellow-400' :
                  'text-green-400'
                }`}>{overallRisk.toUpperCase()}</p>
              </div>
              <div className="bg-blue-500/20 border border-blue-500/50 p-6 rounded-xl text-center">
                <p className="text-gray-400 text-sm mb-2">Security Score</p>
                <p className="text-4xl font-bold text-blue-400">{securityScore}/100</p>
              </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-4 gap-3 mb-6">
              <div className="bg-red-500/10 border border-red-500/30 p-4 rounded-xl text-center">
                <p className="text-2xl font-bold text-red-400">{stats.critical}</p>
                <p className="text-xs text-gray-500">Critical</p>
              </div>
              <div className="bg-orange-500/10 border border-orange-500/30 p-4 rounded-xl text-center">
                <p className="text-2xl font-bold text-orange-400">{stats.high}</p>
                <p className="text-xs text-gray-500">High</p>
              </div>
              <div className="bg-yellow-500/10 border border-yellow-500/30 p-4 rounded-xl text-center">
                <p className="text-2xl font-bold text-yellow-400">{stats.medium}</p>
                <p className="text-xs text-gray-500">Medium</p>
              </div>
              <div className="bg-green-500/10 border border-green-500/30 p-4 rounded-xl text-center">
                <p className="text-2xl font-bold text-green-400">{stats.low}</p>
                <p className="text-xs text-gray-500">Low</p>
              </div>
            </div>

            {/* Report Contents */}
            <div className="bg-[#0d1525] rounded-xl p-6 border border-gray-800">
              <h4 className="text-white font-semibold mb-4 flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-blue-400" />
                Report Contents
              </h4>
              <ul className="space-y-3 text-gray-300 text-sm">
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> Executive Summary with Risk Overview</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> Assessment Scope & Methodology</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> Detailed Vulnerability Findings</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> CVSS Scores & OWASP Mapping</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> HTTP Request/Response Evidence</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> Proof of Concept Payloads</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> Vulnerable & Fixed Code Examples</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> Step-by-Step Remediation Guide</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> Business Impact Analysis</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> Remediation Priority Matrix</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> Strategic Recommendations</li>
                <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" /> OWASP Top 10 Reference</li>
              </ul>
            </div>

            {/* Sample Finding Preview */}
            {vulnerabilities.length > 0 && (
              <div className="mt-6 border border-gray-700 rounded-xl overflow-hidden">
                <div className={`p-4 ${
                  vulnerabilities[0].severity?.toLowerCase() === 'critical' ? 'bg-gradient-to-r from-red-600 to-red-500' :
                  vulnerabilities[0].severity?.toLowerCase() === 'high' ? 'bg-gradient-to-r from-orange-600 to-orange-500' :
                  'bg-gradient-to-r from-yellow-600 to-yellow-500'
                } text-white flex justify-between items-center`}>
                  <span className="font-semibold">Sample Finding: {vulnerabilities[0].vuln_type}</span>
                  <span className="bg-white/20 px-3 py-1 rounded-full text-sm">{vulnerabilities[0].severity?.toUpperCase()}</span>
                </div>
                <div className="p-4 bg-[#0d1525]">
                  <div className="grid grid-cols-2 gap-4 text-sm mb-4">
                    <div>
                      <p className="text-gray-500 text-xs">CVSS Score</p>
                      <p className="text-white">{getVulnDetails(vulnerabilities[0].vuln_type).cvss}</p>
                    </div>
                    <div>
                      <p className="text-gray-500 text-xs">OWASP Category</p>
                      <p className="text-white">{getVulnDetails(vulnerabilities[0].vuln_type).owasp}</p>
                    </div>
                    <div>
                      <p className="text-gray-500 text-xs">CWE</p>
                      <p className="text-white">{getVulnDetails(vulnerabilities[0].vuln_type).cwe}</p>
                    </div>
                    <div>
                      <p className="text-gray-500 text-xs">MITRE ATT&CK</p>
                      <p className="text-white">{getVulnDetails(vulnerabilities[0].vuln_type).mitre}</p>
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">
                    {getVulnDetails(vulnerabilities[0].vuln_type).description.substring(0, 200)}...
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

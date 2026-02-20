import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  AlertTriangle, Search, ChevronRight,
  CheckCircle, Info, Bug, Wrench, Shield,
  Code, FileText, ExternalLink, Copy, Globe,
  Target, BookOpen, Fingerprint, Server, Lock, Zap
} from 'lucide-react';
import api from '../services/api';

// Comprehensive vulnerability data with OWASP, MITRE ATT&CK mappings
const VULN_DATABASE: Record<string, {
  whatItIs: string;
  whyItMatters: string;
  realWorldExample: string;
  howToFix: string;
  owasp: { id: string; name: string; description: string };
  mitre: { technique: string; tactic: string; description: string };
  cwe: { id: string; name: string };
  cvss: { score: number; vector: string };
  affectedCode: string;
  remediationCode: string;
  references: string[];
}> = {
  'SQL Injection': {
    whatItIs: "A code injection technique that exploits security vulnerabilities in an application's database layer. Attackers can insert malicious SQL statements into input fields that are executed by the database.",
    whyItMatters: "SQL Injection can lead to unauthorized data access, data manipulation, authentication bypass, and in severe cases, complete server compromise. It's consistently ranked in OWASP Top 10.",
    realWorldExample: "In 2019, a SQL injection vulnerability in Fortnite exposed 200 million user accounts. Attackers used a simple ' OR '1'='1 payload to bypass login authentication.",
    howToFix: "Use parameterized queries (prepared statements), implement input validation, apply principle of least privilege to database accounts, and use Web Application Firewalls.",
    owasp: { 
      id: 'A03:2021', 
      name: 'Injection',
      description: 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.'
    },
    mitre: {
      technique: 'T1190',
      tactic: 'Initial Access',
      description: 'Exploit Public-Facing Application - Adversaries may attempt to take advantage of a weakness in an Internet-facing application.'
    },
    cwe: { id: 'CWE-89', name: 'SQL Injection' },
    cvss: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    affectedCode: `// VULNERABLE CODE
$query = "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'";
$result = mysqli_query($conn, $query);`,
    remediationCode: `// SECURE CODE - Using Prepared Statements
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("s", $_GET['id']);
$stmt->execute();
$result = $stmt->get_result();`,
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
    ]
  },
  'Cross-Site Scripting': {
    whatItIs: "XSS attacks occur when malicious scripts are injected into trusted websites. The attacker's script runs in the victim's browser, accessing cookies, session tokens, or other sensitive information.",
    whyItMatters: "XSS can steal user sessions, deface websites, redirect users to malicious sites, and spread malware. It affects millions of websites worldwide.",
    realWorldExample: "In 2018, British Airways suffered an XSS attack that compromised 380,000 customers' payment details through malicious JavaScript injected into their payment page.",
    howToFix: "Encode output data, validate and sanitize input, use Content Security Policy (CSP) headers, and implement HttpOnly cookies.",
    owasp: {
      id: 'A03:2021',
      name: 'Injection',
      description: 'Cross-site scripting is a type of injection that inserts malicious scripts into web pages.'
    },
    mitre: {
      technique: 'T1059.007',
      tactic: 'Execution',
      description: 'Command and Scripting Interpreter: JavaScript - Adversaries may abuse JavaScript for execution.'
    },
    cwe: { id: 'CWE-79', name: 'Cross-site Scripting (XSS)' },
    cvss: { score: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
    affectedCode: `// VULNERABLE CODE
echo "<div>Welcome, " . $_GET['name'] . "</div>";`,
    remediationCode: `// SECURE CODE - Using htmlspecialchars
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "<div>Welcome, " . $name . "</div>";`,
    references: [
      'https://owasp.org/www-community/attacks/xss/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
    ]
  },
  'XSS': {
    whatItIs: "XSS (Cross-Site Scripting) attacks occur when malicious scripts are injected into trusted websites. The attacker's script runs in the victim's browser.",
    whyItMatters: "XSS can steal user sessions, deface websites, redirect users to malicious sites, and spread malware.",
    realWorldExample: "In 2018, British Airways suffered an XSS attack that compromised 380,000 customers' payment details.",
    howToFix: "Use htmlspecialchars() to encode output, implement Content Security Policy (CSP), validate all input.",
    owasp: { id: 'A03:2021', name: 'Injection', description: 'Cross-site scripting is a type of injection.' },
    mitre: { technique: 'T1059.007', tactic: 'Execution', description: 'JavaScript execution via XSS.' },
    cwe: { id: 'CWE-79', name: 'Cross-site Scripting' },
    cvss: { score: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
    affectedCode: `// VULNERABLE: Direct output of user input
echo "Hello " . $_GET['name'];`,
    remediationCode: `// FIXED: Sanitized output
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "Hello " . $name;`,
    references: ['https://owasp.org/www-community/attacks/xss/']
  },
  'Command Injection': {
    whatItIs: "Command injection allows attackers to execute arbitrary operating system commands on the server through a vulnerable application. User input is passed directly to system shell commands.",
    whyItMatters: "This vulnerability gives attackers complete control of the server - they can read files, install backdoors, pivot to other systems, and exfiltrate data.",
    realWorldExample: "The Shellshock bug (CVE-2014-6271) in Bash allowed command injection through HTTP headers, affecting millions of servers worldwide.",
    howToFix: "Never pass user input to system commands. If necessary, use allowlists, escape shell arguments, and run commands with minimal privileges.",
    owasp: {
      id: 'A03:2021',
      name: 'Injection',
      description: 'OS command injection occurs when untrusted data is passed to a system shell.'
    },
    mitre: {
      technique: 'T1059',
      tactic: 'Execution',
      description: 'Command and Scripting Interpreter - Adversaries may abuse command interpreters to execute commands.'
    },
    cwe: { id: 'CWE-78', name: 'OS Command Injection' },
    cvss: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    affectedCode: `// VULNERABLE CODE
$ip = $_REQUEST['ip'];
$output = shell_exec("ping " . $ip);`,
    remediationCode: `// SECURE CODE - Validate input + escapeshellarg
$ip = $_REQUEST['ip'];
if (filter_var($ip, FILTER_VALIDATE_IP)) {
    $output = shell_exec("ping " . escapeshellarg($ip));
} else {
    echo "Invalid IP address";
}`,
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection',
      'https://cwe.mitre.org/data/definitions/78.html'
    ]
  },
  'Exposed Database': {
    whatItIs: "A database is accessible from the internet without proper authentication or firewall protection. This includes MongoDB, MySQL, PostgreSQL, Redis exposed on public ports.",
    whyItMatters: "The 2017 MongoDB ransom attacks affected 27,000+ databases that were left exposed without authentication. Attackers deleted data and demanded Bitcoin ransoms.",
    realWorldExample: "In January 2017, attackers used Shodan to find exposed MongoDB instances, connected without passwords, deleted all data, and left ransom notes demanding 0.2 BTC.",
    howToFix: "Enable authentication, bind to localhost or internal IPs only, use firewalls to restrict access, encrypt connections with TLS.",
    owasp: {
      id: 'A05:2021',
      name: 'Security Misconfiguration',
      description: 'Missing security hardening, default configurations, or exposed services.'
    },
    mitre: {
      technique: 'T1190',
      tactic: 'Initial Access',
      description: 'Exploit Public-Facing Application through misconfigured database.'
    },
    cwe: { id: 'CWE-306', name: 'Missing Authentication for Critical Function' },
    cvss: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    affectedCode: `# MongoDB config - VULNERABLE
net:
  bindIp: 0.0.0.0  # Exposed to all
security:
  authorization: disabled`,
    remediationCode: `# MongoDB config - SECURE
net:
  bindIp: 127.0.0.1  # Local only
security:
  authorization: enabled
  # Add users with proper roles`,
    references: [
      'https://www.enisa.europa.eu/publications/info-notes/mongodb-ransomware-attacks',
      'https://docs.mongodb.com/manual/administration/security-checklist/'
    ]
  },
  'Default Credentials': {
    whatItIs: "The system is using factory-default usernames and passwords (like admin/admin, root/root) that are publicly documented and known to attackers.",
    whyItMatters: "Default credentials are the #1 entry point for botnets like Mirai. Attackers maintain lists of default passwords and automatically try them on exposed services.",
    realWorldExample: "The Mirai botnet in 2016 infected 600,000+ IoT devices using just 62 default username/password combinations, causing massive DDoS attacks.",
    howToFix: "Change all default passwords immediately. Implement password complexity requirements. Use credential rotation policies.",
    owasp: {
      id: 'A07:2021',
      name: 'Identification and Authentication Failures',
      description: 'Permits automated attacks such as credential stuffing or default credentials.'
    },
    mitre: {
      technique: 'T1078.001',
      tactic: 'Initial Access',
      description: 'Valid Accounts: Default Accounts - Adversaries may use default credentials.'
    },
    cwe: { id: 'CWE-1392', name: 'Use of Default Credentials' },
    cvss: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    affectedCode: `# Default credentials in use
Username: admin
Password: admin123
# OR
Username: root
Password: (blank)`,
    remediationCode: `# Strong credential policy
- Minimum 12 characters
- Mix of upper, lower, numbers, symbols
- No dictionary words
- Unique per service
- Regular rotation (90 days)`,
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials',
      'https://cwe.mitre.org/data/definitions/1392.html'
    ]
  },
  'File Inclusion': {
    whatItIs: "Local/Remote File Inclusion (LFI/RFI) allows attackers to include files from the server or remote locations, potentially executing malicious code or reading sensitive files.",
    whyItMatters: "LFI can expose sensitive configuration files (/etc/passwd, wp-config.php). RFI can execute remote malicious scripts on your server.",
    realWorldExample: "Attackers commonly use LFI to read /etc/passwd, then escalate to reading database credentials from config files, leading to full database compromise.",
    howToFix: "Validate and whitelist allowed files, disable allow_url_include in PHP, use absolute paths, never use user input directly in include statements.",
    owasp: {
      id: 'A03:2021',
      name: 'Injection',
      description: 'Path traversal and file inclusion are forms of injection attacks.'
    },
    mitre: {
      technique: 'T1055',
      tactic: 'Defense Evasion',
      description: 'Process Injection through file inclusion vulnerabilities.'
    },
    cwe: { id: 'CWE-98', name: 'PHP Remote File Inclusion' },
    cvss: { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    affectedCode: `// VULNERABLE CODE
$page = $_GET['page'];
include($page . '.php');
// Attack: ?page=../../../etc/passwd%00`,
    remediationCode: `// SECURE CODE - Whitelist approach
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (in_array($page, $allowed)) {
    include($page . '.php');
} else {
    include('404.php');
}`,
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion',
      'https://cwe.mitre.org/data/definitions/98.html'
    ]
  },
  'Brute Force': {
    whatItIs: "The login system has no protection against repeated password guessing attempts. Attackers can try thousands of password combinations automatically.",
    whyItMatters: "Without rate limiting or account lockout, attackers can crack weak passwords in minutes. Tools like Hydra can try 1000+ passwords per second.",
    realWorldExample: "In 2012, LinkedIn suffered a breach where 6.5 million hashed passwords were cracked through brute force due to weak hashing (unsalted SHA-1).",
    howToFix: "Implement rate limiting, CAPTCHA after failed attempts, account lockout policies, and multi-factor authentication.",
    owasp: {
      id: 'A07:2021',
      name: 'Identification and Authentication Failures',
      description: 'Permits automated attacks like credential stuffing and brute force.'
    },
    mitre: {
      technique: 'T1110',
      tactic: 'Credential Access',
      description: 'Brute Force - Adversaries may use brute force to obtain account credentials.'
    },
    cwe: { id: 'CWE-307', name: 'Improper Restriction of Excessive Authentication Attempts' },
    cvss: { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    affectedCode: `// VULNERABLE - No rate limiting
if ($_POST['password'] === $stored_password) {
    login_user();
} else {
    echo "Invalid password";
}`,
    remediationCode: `// SECURE - With rate limiting
$attempts = get_login_attempts($_POST['username']);
if ($attempts > 5) {
    sleep(pow(2, $attempts - 5)); // Exponential backoff
    if ($attempts > 10) {
        lock_account($_POST['username']);
    }
}
// ... authentication logic`,
    references: [
      'https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks',
      'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
    ]
  },
  'Outdated Software': {
    whatItIs: "The system is running software versions with known, publicly disclosed vulnerabilities. Exploit code is often readily available online.",
    whyItMatters: "Attackers prioritize known vulnerabilities because exploits are reliable and well-documented. Unpatched systems are low-hanging fruit.",
    realWorldExample: "The 2017 Equifax breach exposing 147 million records was caused by an unpatched Apache Struts vulnerability (CVE-2017-5638) that had a fix available for 2 months.",
    howToFix: "Implement a patch management program, subscribe to security advisories, use automated vulnerability scanning, and maintain an software inventory.",
    owasp: {
      id: 'A06:2021',
      name: 'Vulnerable and Outdated Components',
      description: 'Using components with known vulnerabilities undermines application security.'
    },
    mitre: {
      technique: 'T1190',
      tactic: 'Initial Access',
      description: 'Exploit Public-Facing Application using known CVEs.'
    },
    cwe: { id: 'CWE-1104', name: 'Use of Unmaintained Third Party Components' },
    cvss: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    affectedCode: `# Detected vulnerable versions:
Apache 2.4.49 (CVE-2021-41773)
PHP 7.4.0 (Multiple CVEs)
OpenSSL 1.0.2 (End of life)`,
    remediationCode: `# Update to latest stable versions:
Apache 2.4.58+
PHP 8.2+
OpenSSL 3.0+

# Or use package manager:
apt update && apt upgrade
yum update`,
    references: [
      'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      'https://nvd.nist.gov/'
    ]
  }
};

const getVulnData = (vulnType: string) => {
  const key = Object.keys(VULN_DATABASE).find(k => 
    vulnType.toLowerCase().includes(k.toLowerCase())
  );
  return VULN_DATABASE[key || ''] || {
    whatItIs: "A security weakness that could allow unauthorized access to your system.",
    whyItMatters: "This vulnerability could lead to data breach, system compromise, or service disruption.",
    realWorldExample: "Similar vulnerabilities have been exploited in major breaches affecting millions of users.",
    howToFix: "Apply the recommended security patches and configurations based on industry best practices.",
    owasp: { id: 'A00:2021', name: 'Security Vulnerability', description: 'General security weakness detected.' },
    mitre: { technique: 'T1190', tactic: 'Initial Access', description: 'Potential exploitation vector.' },
    cwe: { id: 'CWE-000', name: 'Security Vulnerability' },
    cvss: { score: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N' },
    affectedCode: '// Vulnerable code pattern detected',
    remediationCode: '// Apply security best practices',
    references: ['https://owasp.org/']
  };
};

interface Vulnerability {
  id: number;
  vuln_type: string;
  severity: string;
  status: string;
  service: string;
  port: number;
  description: string;
  discovered_at: string;
  fixed_at: string | null;
  cve_id: string | null;
  fix_description: string | null;
  scan_id: string;
  target: string;
  owasp_category?: string;
  mitre_technique?: string;
  evidence?: string;
  affected_code?: string;
  remediation_code?: string;
  // HTTP Request/Response data
  vulnerable_url?: string;
  vulnerable_parameter?: string;
  http_method?: string;
  payload_used?: string;
  request_example?: string;
  response_snippet?: string;
  source_file?: string;
  source_line?: number;
}

function SeverityBadge({ severity }: { severity: string }) {
  const config: Record<string, { bg: string; label: string }> = {
    critical: { bg: 'bg-red-500/20 text-red-400 border-red-500/50', label: 'CRITICAL' },
    high: { bg: 'bg-orange-500/20 text-orange-400 border-orange-500/50', label: 'HIGH' },
    medium: { bg: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50', label: 'MEDIUM' },
    low: { bg: 'bg-green-500/20 text-green-400 border-green-500/50', label: 'LOW' },
  };
  const style = config[severity?.toLowerCase()] || config.low;
  return (
    <span className={`px-3 py-1 rounded-lg text-sm font-semibold border ${style.bg}`}>
      {style.label}
    </span>
  );
}

function CVSSBadge({ score }: { score: number }) {
  let color = 'text-green-400 bg-green-500/20';
  let label = 'Low';
  if (score >= 9.0) { color = 'text-red-400 bg-red-500/20'; label = 'Critical'; }
  else if (score >= 7.0) { color = 'text-orange-400 bg-orange-500/20'; label = 'High'; }
  else if (score >= 4.0) { color = 'text-yellow-400 bg-yellow-500/20'; label = 'Medium'; }
  
  return (
    <span className={`px-2 py-1 rounded text-xs font-mono ${color}`}>
      CVSS {score.toFixed(1)} ({label})
    </span>
  );
}

function CodeBlock({ code, title }: { code: string; title: string }) {
  const [copied, setCopied] = useState(false);
  
  const copyCode = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#0a0f1a] rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-[#1a1f2e] border-b border-gray-700">
        <span className="text-gray-400 text-sm font-medium">{title}</span>
        <button 
          onClick={copyCode}
          className="text-gray-400 hover:text-white flex items-center gap-1 text-xs"
        >
          <Copy className="w-3 h-3" />
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <pre className="p-4 text-sm overflow-x-auto">
        <code className="text-gray-300 font-mono whitespace-pre">{code}</code>
      </pre>
    </div>
  );
}

function VulnerabilityCard({ vuln, onSelect }: { vuln: Vulnerability; onSelect: () => void }) {
  const data = getVulnData(vuln.vuln_type);
  const isFixed = vuln.status === 'fixed';

  return (
    <div 
      onClick={onSelect}
      className={`bg-gradient-to-br from-[#111827] to-[#0d1525] rounded-xl border cursor-pointer transition-all hover:scale-[1.01] hover:shadow-lg ${
        isFixed ? 'border-green-500/30' : 
        vuln.severity?.toLowerCase() === 'critical' ? 'border-red-500/30 hover:border-red-500/50' :
        vuln.severity?.toLowerCase() === 'high' ? 'border-orange-500/30 hover:border-orange-500/50' : 'border-gray-700 hover:border-gray-600'
      }`}
    >
      <div className="p-5">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${
              vuln.severity?.toLowerCase() === 'critical' ? 'bg-red-500/20' :
              vuln.severity?.toLowerCase() === 'high' ? 'bg-orange-500/20' : 'bg-yellow-500/20'
            }`}>
              <Bug className={`w-5 h-5 ${
                vuln.severity?.toLowerCase() === 'critical' ? 'text-red-400' :
                vuln.severity?.toLowerCase() === 'high' ? 'text-orange-400' : 'text-yellow-400'
              }`} />
            </div>
            <div>
              <h3 className="text-white font-semibold text-lg">{vuln.vuln_type}</h3>
              <p className="text-gray-500 text-sm">{vuln.target}:{vuln.port} • {vuln.service}</p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2">
            <SeverityBadge severity={vuln.severity} />
            {isFixed ? (
              <span className="text-green-400 text-sm flex items-center gap-1">
                <CheckCircle className="w-4 h-4" /> Fixed
              </span>
            ) : (
              <span className="text-red-400 text-sm flex items-center gap-1">
                <AlertTriangle className="w-4 h-4" /> Open
              </span>
            )}
          </div>
        </div>

        {/* Quick Info Tags */}
        <div className="flex flex-wrap gap-2 mb-4">
          <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs font-medium">
            {data.owasp.id}
          </span>
          <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs font-medium">
            MITRE {data.mitre.technique}
          </span>
          <span className="px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded text-xs font-medium">
            {data.cwe.id}
          </span>
          <CVSSBadge score={data.cvss.score} />
        </div>

        {/* Description */}
        <p className="text-gray-400 text-sm mb-4 line-clamp-2">{data.whatItIs}</p>

        {/* Footer */}
        <div className="flex items-center justify-between pt-3 border-t border-gray-800">
          <div className="text-gray-500 text-sm">
            {new Date(vuln.discovered_at).toLocaleDateString()}
          </div>
          <button className="text-blue-400 text-sm flex items-center gap-1 hover:text-blue-300">
            View Full Details <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

function VulnerabilityDetailModal({ vuln, onClose }: { vuln: Vulnerability; onClose: () => void }) {
  const navigate = useNavigate();
  const data = getVulnData(vuln.vuln_type);
  const isFixed = vuln.status === 'fixed';
  const [activeTab, setActiveTab] = useState<'overview' | 'http' | 'technical' | 'remediation'>('overview');

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div 
        className="bg-[#0d1525] rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto border border-gray-700"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-6 border-b border-gray-800 sticky top-0 bg-[#0d1525] z-10">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <h2 className="text-2xl font-bold text-white">{vuln.vuln_type}</h2>
                <SeverityBadge severity={vuln.severity} />
              </div>
              <p className="text-gray-400">{vuln.target}:{vuln.port} • {vuln.service}</p>
              <div className="flex flex-wrap gap-2 mt-3">
                <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">{data.owasp.id} {data.owasp.name}</span>
                <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">MITRE {data.mitre.technique}</span>
                <span className="px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded text-xs">{data.cwe.id}</span>
                <CVSSBadge score={data.cvss.score} />
              </div>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-white text-2xl">&times;</button>
          </div>

          {/* Tabs */}
          <div className="flex gap-2 mt-4">
            {['overview', 'http', 'technical', 'remediation'].map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab as typeof activeTab)}
                className={`px-4 py-2 rounded-lg font-medium text-sm transition-colors ${
                  activeTab === tab 
                    ? 'bg-blue-600 text-white' 
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                }`}
              >
                {tab === 'http' ? 'HTTP Analysis' : tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {activeTab === 'overview' && (
            <>
              {/* Status Banner */}
              {isFixed ? (
                <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4 flex items-center gap-3">
                  <CheckCircle className="w-6 h-6 text-green-400" />
                  <div>
                    <p className="text-green-400 font-semibold">Vulnerability Fixed</p>
                    <p className="text-gray-400 text-sm">Fixed on {vuln.fixed_at ? new Date(vuln.fixed_at).toLocaleString() : 'N/A'}</p>
                  </div>
                </div>
              ) : (
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center gap-3">
                  <AlertTriangle className="w-6 h-6 text-red-400" />
                  <div>
                    <p className="text-red-400 font-semibold">Immediate Action Required</p>
                    <p className="text-gray-400 text-sm">This vulnerability is actively exploitable</p>
                  </div>
                </div>
              )}

              {/* What Is This */}
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-5">
                <h3 className="text-blue-400 font-semibold mb-3 flex items-center gap-2 text-lg">
                  <Info className="w-5 h-5" /> What Is This Vulnerability?
                </h3>
                <p className="text-gray-200 leading-relaxed">{data.whatItIs}</p>
              </div>

              {/* Why It Matters */}
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-5">
                <h3 className="text-red-400 font-semibold mb-3 flex items-center gap-2 text-lg">
                  <AlertTriangle className="w-5 h-5" /> Business Impact
                </h3>
                <p className="text-gray-200 leading-relaxed">{data.whyItMatters}</p>
              </div>

              {/* Real World Example */}
              <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-5">
                <h3 className="text-purple-400 font-semibold mb-3 flex items-center gap-2 text-lg">
                  <Globe className="w-5 h-5" /> Real-World Attack Example
                </h3>
                <p className="text-gray-200 leading-relaxed italic">"{data.realWorldExample}"</p>
              </div>

              {/* Security Standards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-[#0a0f1a] rounded-xl p-4 border border-purple-500/30">
                  <div className="flex items-center gap-2 mb-2">
                    <BookOpen className="w-5 h-5 text-purple-400" />
                    <span className="text-purple-400 font-semibold">OWASP</span>
                  </div>
                  <p className="text-white font-medium">{data.owasp.id}</p>
                  <p className="text-gray-400 text-sm">{data.owasp.name}</p>
                </div>
                <div className="bg-[#0a0f1a] rounded-xl p-4 border border-blue-500/30">
                  <div className="flex items-center gap-2 mb-2">
                    <Target className="w-5 h-5 text-blue-400" />
                    <span className="text-blue-400 font-semibold">MITRE ATT&CK</span>
                  </div>
                  <p className="text-white font-medium">{data.mitre.technique}</p>
                  <p className="text-gray-400 text-sm">{data.mitre.tactic}</p>
                </div>
                <div className="bg-[#0a0f1a] rounded-xl p-4 border border-cyan-500/30">
                  <div className="flex items-center gap-2 mb-2">
                    <Fingerprint className="w-5 h-5 text-cyan-400" />
                    <span className="text-cyan-400 font-semibold">CWE</span>
                  </div>
                  <p className="text-white font-medium">{data.cwe.id}</p>
                  <p className="text-gray-400 text-sm">{data.cwe.name}</p>
                </div>
              </div>
            </>
          )}

          {activeTab === 'technical' && (
            <>
              {/* CVSS Details */}
              <div className="bg-[#0a0f1a] rounded-xl p-5 border border-gray-700">
                <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-400" /> CVSS Score Analysis
                </h3>
                <div className="flex items-center gap-4 mb-4">
                  <div className={`text-4xl font-bold ${
                    data.cvss.score >= 9.0 ? 'text-red-400' :
                    data.cvss.score >= 7.0 ? 'text-orange-400' :
                    data.cvss.score >= 4.0 ? 'text-yellow-400' : 'text-green-400'
                  }`}>
                    {data.cvss.score.toFixed(1)}
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">CVSS v3.1 Base Score</p>
                    <p className="text-gray-500 text-xs font-mono">{data.cvss.vector}</p>
                  </div>
                </div>
              </div>

              {/* Vulnerable Code */}
              <div>
                <h3 className="text-red-400 font-semibold mb-3 flex items-center gap-2">
                  <Code className="w-5 h-5" /> Vulnerable Code Pattern
                </h3>
                <CodeBlock 
                  code={vuln.affected_code || data.affectedCode} 
                  title="⚠️ VULNERABLE CODE - DO NOT USE"
                />
              </div>

              {/* Evidence */}
              {(vuln.evidence || vuln.description) && (
                <div className="bg-[#0a0f1a] rounded-xl p-5 border border-gray-700">
                  <h3 className="text-gray-300 font-semibold mb-3 flex items-center gap-2">
                    <Server className="w-5 h-5" /> Detection Evidence
                  </h3>
                  <pre className="text-gray-400 font-mono text-sm whitespace-pre-wrap">
                    {vuln.evidence || vuln.description}
                  </pre>
                </div>
              )}

              {/* CVE Info */}
              {vuln.cve_id && (
                <div className="bg-orange-500/10 border border-orange-500/30 rounded-xl p-4">
                  <h3 className="text-orange-400 font-semibold mb-2">CVE Reference</h3>
                  <a 
                    href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 flex items-center gap-1"
                  >
                    {vuln.cve_id} <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              )}
            </>
          )}

          {activeTab === 'http' && (
            <>
              {/* Real scan indicator */}
              {vuln.request_example ? (
                <div className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle className="w-5 h-5 text-green-400" />
                    <span className="text-green-400 font-semibold">📡 REAL HTTP DATA FROM SCAN</span>
                  </div>
                  <p className="text-gray-300 text-sm">This vulnerability was found during actual HTTP request analysis.</p>
                </div>
              ) : (
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Info className="w-5 h-5 text-blue-400" />
                    <span className="text-blue-400 font-semibold">🔍 VULNERABILITY SOURCE</span>
                  </div>
                  <p className="text-gray-300 text-sm">This vulnerability was identified through {vuln.service} service analysis on port {vuln.port}.</p>
                </div>
              )}

              {/* HTTP Request Analysis */}
              <div className="bg-[#0a0f1a] rounded-xl border border-gray-700 p-5">
                <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                  <Globe className="w-5 h-5 text-blue-400" /> HTTP Request Analysis
                </h3>
                
                {vuln.vulnerable_url ? (
                  <div className="space-y-4">
                    {/* Request Method and URL */}
                    <div className="flex items-center gap-3">
                      <span className={`px-3 py-1 rounded text-sm font-bold ${
                        (vuln.http_method || 'GET') === 'GET' ? 'bg-green-500/20 text-green-400' : 
                        (vuln.http_method || 'GET') === 'POST' ? 'bg-blue-500/20 text-blue-400' : 
                        'bg-purple-500/20 text-purple-400'
                      }`}>
                        {vuln.http_method || 'GET'}
                      </span>
                      <code className="text-gray-300 text-sm bg-black/30 px-3 py-1 rounded flex-1 overflow-x-auto">
                        {vuln.vulnerable_url}
                      </code>
                    </div>

                    {/* Vulnerable Parameter */}
                    {vuln.vulnerable_parameter && (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                        <h4 className="text-yellow-400 font-semibold mb-2">🎯 Vulnerable Parameter:</h4>
                        <code className="text-yellow-300 text-lg bg-black/30 px-3 py-2 rounded block font-bold">
                          {vuln.vulnerable_parameter}
                        </code>
                      </div>
                    )}

                    {/* Attack Payload */}
                    {vuln.payload_used && (
                      <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                        <h4 className="text-red-400 font-semibold mb-2">💉 Attack Payload Used:</h4>
                        <code className="text-red-300 text-sm bg-black/30 px-3 py-2 rounded block">
                          {vuln.payload_used}
                        </code>
                      </div>
                    )}

                    {/* Full HTTP Request */}
                    {vuln.request_example && (
                      <div>
                        <h4 className="text-blue-400 font-semibold mb-2">📤 HTTP Request Sent:</h4>
                        <CodeBlock 
                          code={vuln.request_example} 
                          title="Raw HTTP Request" 
                        />
                      </div>
                    )}

                    {/* Server Response */}
                    {vuln.response_snippet && (
                      <div>
                        <h4 className="text-gray-400 font-semibold mb-2">📥 Server Response:</h4>
                        <CodeBlock 
                          code={vuln.response_snippet} 
                          title="HTTP Response (Vulnerable)" 
                        />
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Globe className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                    <h4 className="text-gray-400 font-semibold mb-2">No HTTP Data Available</h4>
                    <p className="text-gray-500 text-sm">
                      This vulnerability was detected through {vuln.service} service analysis.
                    </p>
                  </div>
                )}
              </div>

              {/* Source Code Location */}
              {(vuln.source_file || vuln.affected_code) && (
                <div className="bg-[#0a0f1a] rounded-xl border border-gray-700 p-5">
                  <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                    <Code className="w-5 h-5 text-purple-400" /> Vulnerability Source
                  </h3>
                  
                  {vuln.source_file && (
                    <div className="mb-4">
                      <div className="flex items-center gap-2 mb-2">
                        <FileText className="w-4 h-4 text-cyan-400" />
                        <span className="text-cyan-400 font-semibold">File Location:</span>
                      </div>
                      <code className="text-gray-300 bg-black/30 px-3 py-1 rounded block">
                        {vuln.source_file}{vuln.source_line ? `:${vuln.source_line}` : ''}
                      </code>
                    </div>
                  )}

                  {vuln.affected_code && (
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className="w-4 h-4 text-red-400" />
                        <span className="text-red-400 font-semibold">Vulnerable Code:</span>
                      </div>
                      <CodeBlock 
                        code={vuln.affected_code} 
                        title="Affected Code Snippet" 
                      />
                    </div>
                  )}
                </div>
              )}

              {/* Discovery Information */}
              <div className="bg-[#0a0f1a] rounded-xl border border-gray-700 p-5">
                <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                  <Search className="w-5 h-5 text-green-400" /> Discovery Details
                </h3>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-400">Discovered:</span>
                    <p className="text-gray-200">{new Date(vuln.discovered_at).toLocaleString()}</p>
                  </div>
                  <div>
                    <span className="text-gray-400">Scan ID:</span>
                    <p className="text-gray-200 font-mono">{vuln.scan_id}</p>
                  </div>
                  <div>
                    <span className="text-gray-400">Target Service:</span>
                    <p className="text-gray-200">{vuln.service} on port {vuln.port}</p>
                  </div>
                  <div>
                    <span className="text-gray-400">Detection Method:</span>
                    <p className="text-gray-200">
                      {vuln.request_example ? 'HTTP Request Analysis' : 'Service Enumeration'}
                    </p>
                  </div>
                </div>
              </div>

              {/* How Vulnerability Occurred */}
              <div className="bg-orange-500/10 border border-orange-500/30 rounded-xl p-5">
                <h3 className="text-orange-400 font-semibold mb-3 flex items-center gap-2">
                  <Target className="w-5 h-5" /> How This Vulnerability Occurred
                </h3>
                <div className="space-y-3">
                  {vuln.vulnerable_url ? (
                    <>
                      <p className="text-gray-200">
                        <strong>1. Target Identification:</strong> The scanner identified the URL <code className="text-orange-300">{vuln.vulnerable_url}</code>
                      </p>
                      {vuln.vulnerable_parameter && (
                        <p className="text-gray-200">
                          <strong>2. Parameter Testing:</strong> The parameter <code className="text-orange-300">{vuln.vulnerable_parameter}</code> was identified as user-controllable input
                        </p>
                      )}
                      {vuln.payload_used && (
                        <p className="text-gray-200">
                          <strong>3. Exploit Confirmation:</strong> The payload <code className="text-orange-300">{vuln.payload_used}</code> was injected and caused unexpected behavior
                        </p>
                      )}
                      <p className="text-gray-200">
                        <strong>4. Vulnerability Confirmed:</strong> The application failed to properly validate/sanitize input, leading to {vuln.vuln_type}
                      </p>
                    </>
                  ) : (
                    <p className="text-gray-200">
                      This {vuln.vuln_type} vulnerability was discovered through analysis of the {vuln.service} service running on port {vuln.port}. 
                      The vulnerability exists due to improper security configuration or coding practices in the application.
                    </p>
                  )}
                </div>
              </div>
            </>
          )}

          {activeTab === 'remediation' && (
            <>
              {/* How to Fix */}
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-5">
                <h3 className="text-green-400 font-semibold mb-3 flex items-center gap-2 text-lg">
                  <Wrench className="w-5 h-5" /> Remediation Steps
                </h3>
                <p className="text-gray-200 leading-relaxed">{data.howToFix}</p>
              </div>

              {/* Fixed Code */}
              <div>
                <h3 className="text-green-400 font-semibold mb-3 flex items-center gap-2">
                  <Lock className="w-5 h-5" /> Secure Code Example
                </h3>
                <CodeBlock 
                  code={vuln.remediation_code || data.remediationCode} 
                  title="✓ SECURE CODE - RECOMMENDED"
                />
              </div>

              {/* References */}
              <div className="bg-[#0a0f1a] rounded-xl p-5 border border-gray-700">
                <h3 className="text-gray-300 font-semibold mb-3 flex items-center gap-2">
                  <BookOpen className="w-5 h-5" /> Security References
                </h3>
                <ul className="space-y-2">
                  {data.references.map((ref, i) => (
                    <li key={i}>
                      <a 
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:text-blue-300 flex items-center gap-1 text-sm"
                      >
                        <ExternalLink className="w-3 h-3" /> {ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Action Buttons */}
              {!isFixed && (
                <div className="flex gap-3 pt-4">
                  <button
                    onClick={() => { onClose(); navigate('/fix'); }}
                    className="flex-1 px-6 py-3 bg-green-600 hover:bg-green-500 text-white rounded-xl font-semibold flex items-center justify-center gap-2"
                  >
                    <Wrench className="w-5 h-5" /> Apply Automated Fix
                  </button>
                  <button
                    onClick={() => { onClose(); navigate('/report-generator'); }}
                    className="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold flex items-center justify-center gap-2"
                  >
                    <FileText className="w-5 h-5" /> Generate Report
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Vulnerabilities() {
  const navigate = useNavigate();
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [sortBy, setSortBy] = useState<'severity' | 'date' | 'type'>('severity');

  useEffect(() => {
    loadVulnerabilities();
  }, []);

  const loadVulnerabilities = async () => {
    try {
      const response = await api.get('/vulnerabilities');
      setVulnerabilities(response.data.vulnerabilities || response.data || []);
    } catch (err) {
      console.error('Failed to load vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  };

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

  const filteredVulns = vulnerabilities
    .filter(v => {
      const matchesSearch = v.vuln_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
                            v.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
                            v.service?.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesSeverity = filterSeverity === 'all' || v.severity?.toLowerCase() === filterSeverity;
      const matchesStatus = filterStatus === 'all' || v.status === filterStatus;
      return matchesSearch && matchesSeverity && matchesStatus;
    })
    .sort((a, b) => {
      if (sortBy === 'severity') {
        return (severityOrder[a.severity?.toLowerCase()] || 4) - (severityOrder[b.severity?.toLowerCase()] || 4);
      } else if (sortBy === 'date') {
        return new Date(b.discovered_at).getTime() - new Date(a.discovered_at).getTime();
      }
      return a.vuln_type.localeCompare(b.vuln_type);
    });

  const stats = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'critical').length,
    high: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'high').length,
    medium: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'medium').length,
    low: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'low').length,
    fixed: vulnerabilities.filter(v => v.status === 'fixed').length,
    open: vulnerabilities.filter(v => v.status !== 'fixed').length,
  };

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-screen">
        <div className="text-center">
          <Bug className="w-12 h-12 text-red-400 mx-auto mb-4 animate-pulse" />
          <p className="text-gray-400">Analyzing security vulnerabilities...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 min-h-screen bg-gradient-to-br from-[#0a0f1a] via-[#0d1525] to-[#0a1628]">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl lg:text-3xl font-bold text-white mb-2 flex items-center gap-3">
          <Bug className="w-8 h-8 text-red-400" />
          Vulnerability Analysis
        </h1>
        <p className="text-gray-400">
          Comprehensive security assessment with OWASP Top 10 and MITRE ATT&CK mappings
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-8">
        <div className="bg-[#111827] rounded-xl p-4 border border-gray-800">
          <p className="text-gray-400 text-sm">Total</p>
          <p className="text-2xl font-bold text-white">{stats.total}</p>
        </div>
        <div className="bg-red-500/10 rounded-xl p-4 border border-red-500/30 cursor-pointer hover:bg-red-500/20" onClick={() => setFilterSeverity(filterSeverity === 'critical' ? 'all' : 'critical')}>
          <p className="text-red-400 text-sm">Critical</p>
          <p className="text-2xl font-bold text-red-400">{stats.critical}</p>
        </div>
        <div className="bg-orange-500/10 rounded-xl p-4 border border-orange-500/30 cursor-pointer hover:bg-orange-500/20" onClick={() => setFilterSeverity(filterSeverity === 'high' ? 'all' : 'high')}>
          <p className="text-orange-400 text-sm">High</p>
          <p className="text-2xl font-bold text-orange-400">{stats.high}</p>
        </div>
        <div className="bg-yellow-500/10 rounded-xl p-4 border border-yellow-500/30 cursor-pointer hover:bg-yellow-500/20" onClick={() => setFilterSeverity(filterSeverity === 'medium' ? 'all' : 'medium')}>
          <p className="text-yellow-400 text-sm">Medium</p>
          <p className="text-2xl font-bold text-yellow-400">{stats.medium}</p>
        </div>
        <div className="bg-blue-500/10 rounded-xl p-4 border border-blue-500/30 cursor-pointer hover:bg-blue-500/20" onClick={() => setFilterSeverity(filterSeverity === 'low' ? 'all' : 'low')}>
          <p className="text-blue-400 text-sm">Low</p>
          <p className="text-2xl font-bold text-blue-400">{stats.low}</p>
        </div>
        <div className="bg-green-500/10 rounded-xl p-4 border border-green-500/30 cursor-pointer hover:bg-green-500/20" onClick={() => setFilterStatus(filterStatus === 'fixed' ? 'all' : 'fixed')}>
          <p className="text-green-400 text-sm">Fixed</p>
          <p className="text-2xl font-bold text-green-400">{stats.fixed}</p>
        </div>
        <div className="bg-gray-700/30 rounded-xl p-4 border border-gray-600 cursor-pointer hover:bg-gray-700/50" onClick={() => setFilterStatus(filterStatus === 'open' ? 'all' : 'open')}>
          <p className="text-gray-400 text-sm">Open</p>
          <p className="text-2xl font-bold text-gray-300">{stats.open}</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 mb-8">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search vulnerabilities, targets, services..."
            className="w-full pl-10 pr-4 py-3 bg-[#111827] border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="px-4 py-3 bg-[#111827] border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="px-4 py-3 bg-[#111827] border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Status</option>
          <option value="open">Open</option>
          <option value="fixed">Fixed</option>
        </select>
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
          className="px-4 py-3 bg-[#111827] border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500"
        >
          <option value="severity">Sort by Severity</option>
          <option value="date">Sort by Date</option>
          <option value="type">Sort by Type</option>
        </select>
        {stats.open > 0 && (
          <button
            onClick={() => navigate('/fix')}
            className="px-6 py-3 bg-green-600 hover:bg-green-500 text-white rounded-xl font-semibold flex items-center gap-2"
          >
            <Wrench className="w-5 h-5" /> Fix All Issues
          </button>
        )}
      </div>

      {/* Vulnerability List */}
      {filteredVulns.length === 0 ? (
        <div className="text-center py-16">
          <Shield className="w-20 h-20 text-green-500/30 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-green-400 mb-2">
            {vulnerabilities.length === 0 ? 'No Vulnerabilities Yet' : 'No Matches Found'}
          </h2>
          <p className="text-gray-400 mb-6">
            {vulnerabilities.length === 0 
              ? "Run a security scan to discover vulnerabilities in your systems."
              : "Try adjusting your filters to see more results."}
          </p>
          {vulnerabilities.length === 0 && (
            <button
              onClick={() => navigate('/new-scan')}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold"
            >
              Start Security Scan
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {filteredVulns.map((vuln) => (
            <VulnerabilityCard 
              key={vuln.id} 
              vuln={vuln} 
              onSelect={() => setSelectedVuln(vuln)} 
            />
          ))}
        </div>
      )}

      {/* Detail Modal */}
      {selectedVuln && (
        <VulnerabilityDetailModal 
          vuln={selectedVuln} 
          onClose={() => setSelectedVuln(null)} 
        />
      )}
    </div>
  );
}

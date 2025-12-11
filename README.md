# RedShield 

**End-to-End Red Team Remediation Toolkit**

A comprehensive security toolkit that scans for vulnerabilities, verifies exploitability, and applies automated fixes.

## Features

- **Multi-Scanner Support**: Nmap (network), Nuclei (web), ZAP (active web)
- **Exploit Verification**: Metasploit integration to confirm vulnerabilities
- **Automated Remediation**: Ansible playbooks for common fixes
- **Report Generation**: HTML, JSON, PDF formats
- **Role-Based Access**: Admin vs User permissions
- **Database Storage**: Track all scans and remediations

## Quick Start

```bash
# Clone the repository
git clone https://github.com/ldawa23/RedShield.git
cd RedShield

# Install dependencies
pip install -r requirements.txt

# Initialize the database
python -m cli.main init

# Register (first user is admin)
python -m cli.main register

# Run your first scan
python -m cli.main scan 192.168.1.100 --demo
```

## Commands

| Command | Description | Access |
|---------|-------------|--------|
| `scan` | Scan targets for vulnerabilities | All users |
| `status` | View scan results | All users |
| `report` | Generate security reports | All users |
| `verify` | Verify exploitability with Metasploit | All users |
| `fix` | Apply automated fixes | **Admin only** |
| `login` | Log into your account | Public |
| `register` | Create new account | Public |
| `whoami` | Show current user | Logged in |

## Scanners

### Nmap (Network Scanning)
```bash
# Network scan (auto-detected for IPs)
python -m cli.main scan 192.168.1.100

# With specific ports
python -m cli.main scan 192.168.1.100 -p 22,80,443,3306
```

### Nuclei (Web Application Scanning)
```bash
# Web scan (auto-detected for URLs)
python -m cli.main scan http://target.com

# With specific templates
python -m cli.main scan http://target.com -t sqli,xss
```

### OWASP ZAP (Active Web Scanning)
```bash
# Active scan with spider
python -m cli.main scan http://target.com -S zap
```

##  Testing with Vulnerable Apps

### DVWA (Damn Vulnerable Web Application)

```bash
# Start DVWA with Docker
docker run -d -p 80:80 vulnerables/web-dvwa

# Scan DVWA (demo mode - no tools required)
python -m cli.main scan http://localhost/dvwa --demo

# Or with real Nuclei
python -m cli.main scan http://localhost/dvwa -S nuclei

# View results
python -m cli.main status

# Generate report
python -m cli.main report <scan_id> --format html
```

### OWASP Juice Shop

```bash
# Start Juice Shop with Docker
docker run -d -p 3000:3000 bkimminich/juice-shop

# Scan Juice Shop
python -m cli.main scan http://localhost:3000 --demo

# Active scan with ZAP
python -m cli.main scan http://localhost:3000 -S zap --demo
```

### bWAPP

```bash
# Start bWAPP with Docker
docker run -d -p 80:80 raesene/bwapp

# Scan bWAPP
python -m cli.main scan http://localhost/bWAPP --demo
```

### Metasploitable2 (Network Testing)

```bash
# Download Metasploitable2 VM and run it
# IP will be shown on boot (e.g., 192.168.1.50)

# Network scan
python -m cli.main scan 192.168.1.50 --demo

# Verify exploits with Metasploit
python -m cli.main verify <scan_id> --demo

# See available exploits
python -m cli.main exploits
```

## Workflow Example

```bash
# 1. Initialize
python -m cli.main init

# 2. Register as admin
python -m cli.main register -u admin -p securepass -e admin@example.com

# 3. Scan a target
python -m cli.main scan http://localhost/dvwa --demo

# 4. Check status
python -m cli.main status

# 5. View specific scan
python -m cli.main status scan-20251211-ABC123

# 6. Verify vulnerabilities (Metasploit)
python -m cli.main verify scan-20251211-ABC123 --demo

# 7. Fix vulnerabilities (admin only)
python -m cli.main fix scan-20251211-ABC123 --dry-run
python -m cli.main fix scan-20251211-ABC123 --auto

# 8. Generate report
python -m cli.main report scan-20251211-ABC123 --format html
```

## Tool Requirements

| Tool | Required For | Install |
|------|--------------|---------|
| Python 3.8+ | Core | `apt install python3` |
| Nmap | Network scanning | `apt install nmap` |
| Nuclei | Web scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| ZAP | Active web scan | `apt install zaproxy` |
| Metasploit | Exploit verification | Pre-installed on Kali |
| Ansible | Remediation | `pip install ansible` |

> **Note**: RedShield works in demo mode without these tools installed!

## User Roles

- **Admin**: First registered user. Can scan, verify, fix, and generate reports.
- **User**: Can scan, verify, and view reports. Cannot apply fixes.

## Project Structure

```
RedShield/
├── cli/                    # Command-line interface
│   ├── commands/           # CLI commands (scan, fix, report, etc.)
│   └── utils/              # Auth, formatters, validators
├── config/                 # Configuration settings
├── core/                   # Core scanning logic
├── database/               # SQLAlchemy models
├── integrations/           # Nmap, Nuclei, ZAP, Metasploit
├── playbooks/              # Ansible remediation playbooks
├── reports/                # Generated reports
└── tests/                  # Unit tests
```

## License

MIT License - See LICENSE file for details.

---

**Disclaimer**: Only use RedShield against systems you own or have explicit permission to test. Unauthorized scanning/exploitation is illegal.


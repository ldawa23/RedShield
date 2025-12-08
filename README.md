# RedShield 

<p align="center">
  <b>Red Team Remediation Toolkit</b><br>
  <i>Scan. Detect. Remediate. Report.</i>
</p>

---

## Overview

RedShield is a comprehensive security assessment and remediation platform designed for red team operations. It streamlines the workflow from vulnerability discovery to automated remediation, providing a complete toolkit for security professionals.

### Key Features

- **Vulnerability Scanning** - Nmap-powered network and service discovery
- **Intelligent Detection** - OWASP Top 10 and MITRE ATT&CK mappings
- **Automated Remediation** - Ansible playbook generation and execution
- **Professional Reports** - PDF, HTML, and JSON report generation
- **Modern Dashboard** - Real-time security metrics and analytics
- **Role-Based Access** - Admin and user dashboards

---

## Architecture

```
RedShield Workflow
──────────────────

┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
   RECON   ───▶   SCAN    ───▶   FIX    ───▶  REPORT  
└─────────┘    └─────────┘    └─────────┘    └─────────┘
     │              │              │              │
     ▼              ▼              ▼              ▼
  Target        Nmap +         Ansible       PDF/HTML
 Discovery    Vuln Check      Playbooks      Reports
```

---

## Installation

### Prerequisites

- Python 3.10+
- Nmap 7.x
- Ansible 2.15+ (for remediation)
- Node.js 18+ (for frontend)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/redshield.git
cd redshield

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your settings

# Initialize database
python -c "from database.connection import init_db; init_db()"

# Run the API server
uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
```

---

## Usage

### CLI Interface

```bash
# Scan a target
redshield scan 192.168.1.100 --scan-type full

# View scan status
redshield status scan-abc12345 --verbose

# Apply fixes
redshield fix scan-abc12345 --auto --severity High

# Generate report
redshield report scan-abc12345 --format pdf
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/register` | POST | Register new user |
| `/api/auth/login` | POST | Authenticate user |
| `/api/scans` | POST | Create new scan |
| `/api/scans` | GET | List user scans |
| `/api/vulnerabilities` | GET | List vulnerabilities |
| `/api/remediations` | POST | Start remediation |
| `/api/reports` | POST | Generate report |
| `/api/dashboard/stats` | GET | Dashboard statistics |

---

## Project Structure

```
redshield/
├── api/                    # FastAPI backend
│   ├── app.py             # Main application
│   ├── routes/            # API endpoints
│   ├── schemas/           # Pydantic models
│   └── services/          # Business logic
├── cli/                    # Click CLI
│   ├── main.py            # CLI entry point
│   ├── commands/          # CLI commands
│   └── utils/             # CLI utilities
├── core/                   # Core modules
│   ├── scanner.py         # Nmap scanner
│   ├── fixer.py           # Remediation engine
│   ├── reporter.py        # Report generator
│   └── vulnerability_db.py # Vulnerability signatures
├── database/               # Database layer
│   ├── models.py          # SQLAlchemy models
│   └── connection.py      # DB connection
├── playbooks/              # Ansible playbooks
├── config/                 # Configuration
└── tests/                  # Unit tests
```

---

## Vulnerability Coverage

RedShield detects and remediates:

| Category | Vulnerabilities |
|----------|-----------------|
| **Databases** | MongoDB, MySQL, PostgreSQL, Redis exposed |
| **Protocols** | Telnet, FTP, unencrypted HTTP |
| **Services** | SSH misconfigurations, RDP exposure |
| **Network** | SMB vulnerabilities, open ports |
| **Web** | HTTP security headers, SSL issues |

---

## OWASP & MITRE Mappings

### OWASP Top 10 2021

- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A05:2021 - Security Misconfiguration
- A07:2021 - Identification and Authentication Failures

### MITRE ATT&CK

- T1190 - Exploit Public-Facing Application
- T1021 - Remote Services
- T1133 - External Remote Services
- T1210 - Exploitation of Remote Services

---

## Configuration

Create a `.env` file with:

```env
# Database
DB_TYPE=sqlite
DATABASE_URL=sqlite:///./redshield.db

# Security
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Scanning
SCAN_TIMEOUT_SECONDS=3600
NMAP_PATH=/usr/bin/nmap

# Reports
REPORT_OUTPUT_PATH=./reports
```

---

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Formatting

```bash
black .
flake8 .
mypy .
```

### Database Migrations

```bash
alembic revision --autogenerate -m "Description"
alembic upgrade head
```

---

## API Documentation

Interactive API documentation is available at:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## Security Considerations

**Important**: RedShield is a security tool that should be used responsibly:

- Only scan systems you have authorization to test
- Use dry-run mode before applying fixes in production
- Review Ansible playbooks before execution
- Store credentials securely using environment variables

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [Nmap](https://nmap.org/) - Network scanning
- [Ansible](https://www.ansible.com/) - Automation
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
- [OWASP](https://owasp.org/) - Security standards
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat intelligence

---

<p align="center">
  Made with for security professionals
</p>

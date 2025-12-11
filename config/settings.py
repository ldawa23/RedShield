import os
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass    #if python-dotenv not installed then use environment variables directly

class Settings:
    def __init__(self):
        self.base_dir: Path = Path(__file__).parent.parent

        #Database settings
        #db_type means what database to use like sqlite for simple and mysql for production
        self.db_type: str = os.getenv("DB_TYPE", "sqlite")

        #database_url: Connection string for the database
        #SQLite is file-based and MySQL requires a server
        default_db_url = f"sqlite:///{self.base_dir}/redshield.db"
        self.database_url: str = os.getenv("DATABASE_URL", default_db_url)

        #Scanning settings
        #scan_timeout_seconds: Maximum time for a scan before its cancelled
        self.scan_timeout_seconds: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "3600"))

        #nmap_path where namp is installed
        self.nmap_path: str = os.getenv("NMAP_PATH", "nmap")

        #default_ports is for ports to scan if user doesnot specify
        default_ports: str = os.getenv("DEFAULT_PORTS", "1-1000")

        #Report settings
        #report_output_path is to locate generated reports that are saved
        self.report_output_path: str = os.getenv("REPORT_OUTPUT_PATH", str(self.base_dir / "reports"))

        #Remediation settings
        #playbook_path is to locate Ansible playbooks stored
        self.playbooks_path: str = os.getenv("PLAYBOOKS_PATH", str(self.base_dir / "playbooks"))

        #safe_mode for not actually applying fixes (dry-run) if its true
        self.safe_mode: bool = os.getenv("SAFE_MODE", "True").lower() == "true"

        #Security settings
        #secret_key for encrypting passwords and tokens
        self.secret_key: str = os.getenv("SECRET_KEY", "change-this-in-production-use-a-real-secret")

        #token_expires_minutes for checking how long login tokens are valid
        self.token_expires_minutes: int = int(os.getenv("TOKEN_EXPIRE_MINUTES", "60"))

        #API settings
        #api_host for finding address the API listens on
        self.api_host: str = os.getenv("API_HOST", "0.0.0.0")

        #api_port for finding port the API listens on
        self.api_port: int = int(os.getenv("API_PORT", "8000"))

        #Logging settings
        #log_level for showing the logging done by verbose (DEBUG, INFO, WARNING, ERROR)
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO")

        #log_file for saving the log files
        self.log_file: str = os.getenv("LOG_FILE", str(self.base_dir / "logs" / "redshield.log"))

    @property
    def reports_dir(self) -> str:
        return self.report_output_path


settings = Settings()



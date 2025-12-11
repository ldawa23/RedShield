"""
RedShield Configuration Settings

This file contains all the configuration settings for the RedShield toolkit.
Settings can be overridden using environment variables or a .env file.

WHY THIS FILE EXISTS:
- Centralizes all configuration in one place
- Makes it easy to change settings without modifying code
- Supports different environments (development, production)
"""

import os
from pathlib import Path
from typing import Optional

# Try to load .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use environment variables directly


class Settings:
    """
    Central configuration class for RedShield.
    
    All settings have sensible defaults but can be overridden via environment variables.
    """
    
    def __init__(self):
        # Base directory (project root)
        self.base_dir: Path = Path(__file__).parent.parent
        
        # ============ DATABASE SETTINGS ============
        # db_type: What database to use (sqlite for simple, mysql for production)
        self.db_type: str = os.getenv("DB_TYPE", "sqlite")
        
        # database_url: Connection string for the database
        # SQLite is file-based (easy for development)
        # MySQL requires a server (better for production)
        self.database_url: str = os.getenv(
            "DATABASE_URL", 
            f"sqlite:///{self.base_dir}/redshield.db"
        )
        
        # ============ SCANNING SETTINGS ============
        # scan_timeout_seconds: Maximum time for a scan before it's cancelled
        self.scan_timeout_seconds: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "3600"))
        
        # nmap_path: Where nmap is installed
        self.nmap_path: str = os.getenv("NMAP_PATH", "nmap")
        
        # default_ports: Ports to scan if user doesn't specify
        self.default_ports: str = os.getenv("DEFAULT_PORTS", "1-1000")
        
        # ============ REPORT SETTINGS ============
        # report_output_path: Where generated reports are saved
        self.report_output_path: str = os.getenv(
            "REPORT_OUTPUT_PATH", 
            str(self.base_dir / "reports")
        )
        
        # ============ REMEDIATION SETTINGS ============
        # playbooks_path: Where Ansible playbooks are stored
        self.playbooks_path: str = os.getenv(
            "PLAYBOOKS_PATH",
            str(self.base_dir / "playbooks")
        )
        
        # safe_mode: If True, won't actually apply fixes (dry-run)
        self.safe_mode: bool = os.getenv("SAFE_MODE", "True").lower() == "true"
        
        # ============ SECURITY SETTINGS ============
        # secret_key: Used for encrypting passwords and tokens
        self.secret_key: str = os.getenv(
            "SECRET_KEY", 
            "change-this-in-production-use-a-real-secret"
        )
        
        # token_expire_minutes: How long login tokens are valid
        self.token_expire_minutes: int = int(os.getenv("TOKEN_EXPIRE_MINUTES", "60"))
        
        # ============ API SETTINGS ============
        # api_host: What address the API listens on
        self.api_host: str = os.getenv("API_HOST", "0.0.0.0")
        
        # api_port: What port the API listens on
        self.api_port: int = int(os.getenv("API_PORT", "8000"))
        
        # ============ LOGGING SETTINGS ============
        # log_level: How verbose the logging is (DEBUG, INFO, WARNING, ERROR)
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO")
        
        # log_file: Where to save log files
        self.log_file: str = os.getenv(
            "LOG_FILE",
            str(self.base_dir / "logs" / "redshield.log")
        )
    
    @property
    def reports_dir(self) -> str:
        """Alias for report_output_path (used by API)."""
        return self.report_output_path


# Create a global settings instance
# This is imported as: from config.settings import settings
settings = Settings()

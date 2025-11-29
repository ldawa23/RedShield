from typing import Dict
from config.vuln_config import  Vulnerability_types
from models.vulnerability import Vulnerability

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

def apply_default_severity(vuln: Vulnerability) -> None:
    """
    Look up vuln.vuln_Type in config and set its severity if not already set
    """
    config: Dict[str, Dict] = Vulnerability_types.get(vuln.vuln_type, {})
    default = config.get("default_severity")

    if default and not vuln.severity:
        vuln.severity = default

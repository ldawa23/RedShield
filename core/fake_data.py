from typing import List
from models.vulnerability import Vulnerability
from core.constants import COMMON_PORTS

def build_demo_vulnerabilities(target: str) -> List[Vulnerability]:
    """Return a fixed list of demo vulnerabilities for a target"""
    return [
            Vulnerability(
                id=1,
                target=target,
                vuln_type="EXPOSED_DATABASE_PORT",
                service=COMMON_PORTS.get(27017, "UNKNOWN"),
                port=27017,
                severity="Critical",
                status="Discovered",
            ),
            Vulnerability(
                id=2,
                target=target,
                vuln_type="DEFAULT_CREDENTIALS",
                service=COMMON_PORTS.get(22, "UNKNOWN"),
                port=22,
                severity="CRITICAL",
                status="DISCOVERED",
            ),
            Vulnerability(
                id=3,
                target=target,
                vuln_type="OUTDATED_COMPONENT",
                service=COMMON_PORTS.get(80, "UNKNOWN"),
                port=80,
                severity="HIGH",
                status="DISCOVERED",
            ),
    ]

from datetime import datetime
from typing import List
from dataclasses import dataclass, field
from .vulnerability import Vulnerability
import uuid

@dataclass
class Scan:
    id: str                 
    target: str
    started_at: datetime
    status: str             # eg: Running, COmpleted, Failed
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    @staticmethod
    def new(target: str) -> "Scan":
        """Scan with default values for practise"""
        return Scan(
                id=str(uuid.uuid4()),
                target=target,
                started_at=datetime.now(),
                status="Running",
        )

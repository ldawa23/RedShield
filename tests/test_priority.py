from models.vulnerability import Vulnerability
from core.constants import SEVERITY_LEVELS

def testSeverity():
    v_high = Vulnerability(
            id=1,
            target="127.0.0.1",
            vuln_type="Test",
            service="Test",
            port=1234,
            severity="High",
            status="Discovered",
    )
    assert v_high.priority_Score() == SEVERITY_LEVELS["High"]

    v_critical = Vulnerability(
            id=2,
            target="127.0.0.1",
            vuln_type="Test",
            service="Test",
            port=1234,
            severity="Critical",
            status="Discovered",
    )
    assert v_critical.priority_score() > v_high.priority_score()
    print("✓ test_severity_to_score passed")

if __name__ == "__main__":
    testSeverity()

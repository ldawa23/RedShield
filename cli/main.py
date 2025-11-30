import click
from models.scan import Scan
from models.vulnerability import Vulnerability
from core.severity import apply_default_severity, SEVERITY_ORDER
from core.fake_data import build_demo_vulnerabilities

@click.group()
def cli():
    """Redshield - Red Team Remediation Toolkit."""
    pass

@cli.command()
@click.argument("target")
def scan(target):
    """Scan TARGET for vulnerabilities """
    scan = Scan.new(target=target)
    
    vulns = build_demo_vulnerabilities(target)
    for v in vulns:
        scan.vulnerabilities.append(v)

    scan.status = "Completed"

@cli.command()
@click.argument("scan_id")
def report(scan_id):
    """Generate report for a scan"""
    click.echo(f"[REPORT] Would generate report for scan: {scan_id}")

@cli.command()
@click.argument("vuln_id")
@click.option("--auto", is_flag=True, help="Automatically apply safe fixes")
def fix(vuln_id, auto):
    """Fix a specific  vulnerability"""
    mode = "AUTO" if auto else "MANUAL"
    click.echo(f"[FIX] Would {mode}-fix vulnerability: {vuln_id}")

if __name__ == "__main__":
    cli()

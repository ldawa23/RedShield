import click
import ipaddress

from models.scan import Scan
from models.vulnerability import Vulnerability
from core.constants import COMMON_PORTS, SEVERITY_LEVELS

def validate_ip(ctx, param, value):
    """
    Click callback to validate that value is a valid IPv4 or IPv6 address.
    If invalid it raises a click error and shows a nice message.
    """
    try:
        ipaddress.ip_address(value) # this accepts both IPv4 and IPv6
        return value
    except ValueError:
        raise click.BadParameter(f"'{value}' is not a valid IPv4 or IPv6 address")

@click.group()
def cli():
    """Redshield - Red Team Remediation Toolkit."""
    pass

@cli.command()
@click.argument("target", callback=validate_ip)
def scan(target):
    """Scan TARGET for vulnerabilities """
    scan = Scan.new(target=target)

    vulns = [
        Vulnerability(
            id=1,
            target=target,
            vuln_type="EXPOSED_DATABASE_PORT",
            service=COMMON_PORTS.get(27017, "UNKNOWN"),
            port=27017,
            severity="CRITICAL",
            status="DISCOVERED",
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
            vuln_type="MISSING_HTTPS",
            service=COMMON_PORTS.get(80, "UNKNOWN"),
            port=80,
            severity="HIGH",
            status="DISCOVERED",
        ),
    ]

    for v in vulns:
        scan.vulnerabilities.append(v)

    scan.status = "Completed"
    click.echo(f"\n[SCAN]  Target: {scan.target}")
    click.echo(f"✓ Scan ID: {scan.id}")
    click.echo(f"  Status: {scan.status}")
    click.echo(f"  Found: {len(scan.vulnerabilities)} issues\n")

    for v in scan.vulnerabilities:
        click.echo(
                f"- ({v.severity}, score={v.priority_score()}) "
                f"{v.vuln_type} on {v.service}:{v.port}"
        )
        

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

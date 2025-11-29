import click
from models.scan import Scan
from models.vulnerability import Vulnerability

@click.group()
def cli():
    """Redshield - Red Team Remediation Toolkit."""
    pass

@cli.command()
@click.argument("target")
def scan(target):
    """Scan TARGET for vulnerabilities """
    scan = Scan.new(target=target)

    v1 = Vulnerability(
            id=1,
            target=target,
            vuln_type="DEFAULT_CREDENTIALS",
            service="SSH",
            port=22,
            severity="Critical",
            status="Discovered",
    )
    v2 = Vulnerability(
            id=2,
            target=target,
            vuln_type="EXPOSED_DATABASE_PORT",
            service="MongoDB",
            port=27017,
            severity="Critical",
            status="Discovered",
    )

    scan.vulnerabilities.extend([v1,v2])
    scan.status="Completed"

    click.echo(f"[SCAN] Would scan target: {scan.target}")
    click.echo(f"       Scan ID: {scan.id}")
    click.echo(f"       Status: {scan.status}")
    click.echo("       Vulnerabilities:")
    for v in scan.vulnerabilities:
        click.echo(f"   - ({v.severity}) {v.vuln_type} on {v.service}:{v.port}")

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

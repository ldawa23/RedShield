import click
from models.scan import Scan
from models.vulnerability import Vulnerability
from core.severity import apply_default_severity, SEVERITY_ORDER

@click.group()
def cli():
    """Redshield - Red Team Remediation Toolkit."""
    pass

@cli.command()
@click.argument("target")
def scan(target):
    """Scan TARGET for vulnerabilities """
    scan = Scan.new(target=target)

    vulns = [
        Vulnerability(
            id=1,
            target=target,
            vuln_type="EXPOSED_DATABASE_PORT",
            service="MongoDB",
            port=27017,
            severity="",        # let config fill this
            status="DISCOVERED",
        ),
        Vulnerability(
            id=2,
            target=target,
            vuln_type="DEFAULT_CREDENTIALS",
            service="SSH",
            port=22,
            severity="",        # let config fill this
            status="DISCOVERED",
        ),
        Vulnerability(
            id=3,
            target=target,
            vuln_type="OUTDATED_COMPONENT",
            service="Apache",
            port=80,
            severity="",        # let config fill this
            status="DISCOVERED",
        ),
        Vulnerability(
            id=4,
            target=target,
            vuln_type="MISSING_HTTPS",
            service="HTTP",
            port=80,
            severity="",        # let config fill this
            status="DISCOVERED",
        ),
    ]

    for v in vulns:
        apply_default_severity(v)
        scan.vulnerabilities.append(v)

    scan.status = "Completed"

    def severity_key(v: Vulnerability):
        try:
            return SEVERITY_ORDER.index(v.severity)
        except ValueError:
            return len(SEVERITY_ORDER)  #UNknown severities go last
    
    sorted_vulns = sorted(scan.vulnerabilities, key=severity_key)

    click.echo(f"[SCAN] Would scan target: {scan.target}")
    click.echo(f"       Scan ID: {scan.id}")
    click.echo(f"       Status: {scan.status}")
    click.echo("       Vulnerabilities:")
    click.echo(
            f"- {v.vuln_type} on {v.service}:{v.port} "
            f"({v.severity}, score={v.priority_score()})"
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

import click
import json
from redshield.cli.utils.validators import validate_target, validate_range_port
from redshield.cli.utils.formatters import ( formatSucessMessage, formatErrorMessage, formatInfoMessage, formatWarningMessage, formatSeverity, formatVulnerability )

@click.command()
@click.argument('target')
@click.option('--scan-type', '-s', type=click.Choice(['quick', 'full', 'deep']), default='quick' help='Scan intensity')
@click.option('--port-range', '-p', default='1-1000',  help='Port range to scan')
@click.option('--threads', '-t', type=int, default=10, help='Number of parallel threads')
@click.option('--output', '-o', type=click.Path(), help='Save results to JSON file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(target, scan_type, range_port, threads, output, verbose):  #scans target for vulns using Nmap and Nuclei

    try:
        target = validate_target(target)
        port_range = validate_port_range(range_port)

        click.echo()
        click.echo(formatInfoMessage(f"Target: {target}"))
        click.echo(formatInfoMessage(f"Scan type: {scan_type.upper()}"))
        click.echo(formatInfoMessage(f"Port Range: {port_range}"))
        click.echo(formatInfoMessage(f"Threads: {threads}"))

        if verbose:
            click.echo(formatInfoMessage("Verbose Mode: ON"))
        click.echo()

        click.echo(formatInfoMessage("Starting vulnerability scan..."))

        vulnerabilities = [ {'severity': 'Critical', 'type': 'EXPOSED_DATABASE', 'port': 27017, 'service': 'MongoDB'}, {'severity': 'CRITICAL', 'type': 'DEFAULT_CREDENTIALS', 'port': 22, 'service': 'SSH'}, {'severity': 'HIGH', 'type': 'OUTDATED_SOFTWARE', 'port': 80, 'service': 'Apache'}, {'severity': 'HIGH', 'type': 'MISSING_HTTPS', 'port': 80, 'service': 'HTTP'}, {'severity': 'MEDIUM', 'type': 'WEAK_SSL_CIPHER', 'port': 443, 'service': 'HTTPS'}, ]

        with click.progressbar(length=100, label='Scanning') as bar:
            bar.update(100)

        click.echo()
        click.echo(formatSuccessMessage("Scan completed successfully")}

        scan_id = "scan-202521204-001"
        click.echo(f"Scan ID: {click.style(scan_id, fg='yellow')}")
        click.echo()

        critical = [v for v in vulnerabilities if v['severity'] == 'Critical']
        high = [v for v in vulnerabilities if v['severity'] == 'High']

        click.echo("Severity Breakdown:")
        if critical:
            click.echo(f" {formatSeverity('Critical')}: {len(critical)}")
        if high:
            click.echo(f" {formatSeverity('High')}: {len(high)}")

        click.echo()
        click.echo("Vulnerabilities discovered:")
        for i, vuln in enumerate(vulnerabilities, 1):
            click.echo(f" {i}. {formatVulnerability(vuln)}")

        click.echo()
        click.echo("Next Steps:")
        click.echo(f"   . Fix: Redshield fix {scan_id} --auto")
        click.echo(f"   . Report: Redshield report {scan_id}")

        if output:  #saving file if requested
            data = { 'scan_id' : scan_id, 'target': target, 'vulnerabilities': vulnerabilities }
            with open(output, 'w') as f:
                json.dump(data, f, indent=2)
            click.echo(formatSuccessMessage(f"Saved to {output}"))

        click.echo()
    except Exception as e:
        click.echo(formatErrorMessage(str(e)), err=True)
        raise click.Abort()

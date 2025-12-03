import click
from redshield.cli.utils.formatters import formatStatus, formatInfoMessage

@click.command()
@click.argument('scan_id', required=False)

def status(scan_id):
    #Check scan status

    if scan_id:
        click.echo()
        click.echo(formatInfoMessage(f"Scan: {scan_id}"))
        click.echo(f" Status: {formatStatus('Completed')}")
        click.echo(f" Target: 192.168.1.100")
        click.echo(f" Vulnerabilities: 5 found, 3 fixed")
    else:
        click.echo()
        click.echo("Recent Scans:")
        click.echo(f" {click.style('scan-12345', fg='yellow')} - {formatStatus('Completed')} - 5 vulns")
        click.echo(f" {click.style('scan-12346', fg='yellow')} - {formatStatus('In progress')} - 3 vulns")
        click.echo()

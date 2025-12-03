import click
from cli.utils.formatters import formatSuccessMessage, formatErrorMessage
from cli.commands.scan import scan
from cli.commands.fix import fix
from cli.commands.report import report
from cli.commands.status import status

@click.group()
@click.version_option(version='1.0.0', prog_name="RedShield")
def cli():
    # RedShield - Red Team Remediation and Automation Toolkit
    # Scans networks, finds vulnerabilities, and fix them automatically

    pass

@cli.command()
def version():
    #Show version and system info
    import sys
    import platform

    click.echo(f"RedShield v1.0.0")
    click.echo(f"Python: {sys.version.split()[0]}")
    click.echo(f"Platform: {platform.system()} {platform.release()}")
    click.echo(f"Status: Ready")

@cli.command()
def config():
    #Show configuration
    click.echo("RedShield Configuration:")
    click.echo(" Database: MySQL (localhost:3306)")
    click.echo(" Scanning tools: Nmap, Nuclei")
    click.echo(" Remediation: Ansible")

#Register commands
cli.add_command(scan)
cli.add_command(fix)
cli.add_command(report)
cli.add_command(status)

if __name__ == '__main__':
    try:
        cli()
    except Exception as e:
        click.echo(formatErrorMessage(str(e)), err=True)
        raise

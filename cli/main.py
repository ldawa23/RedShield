"""
RedShield CLI - Command Line Interface
Red Team Remediation Toolkit

Usage:
    redshield scan <target> [options]
    redshield fix <scan_id> [options]
    redshield report <scan_id> [options]
    redshield status [scan_id] [options]
"""

import click
import sys
import platform
from cli.utils.formatters import formatSuccessMessage, formatErrorMessage, formatInfoMessage
from cli.commands.scan import scan
from cli.commands.fix import fix
from cli.commands.report import report
from cli.commands.status import status


BANNER = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗ ███████╗██████╗ ███████╗██╗  ██╗██╗███████╗██╗  ║
║   ██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔════╝██║  ║
║   ██████╔╝█████╗  ██║  ██║███████╗███████║██║█████╗  ██║  ║
║   ██╔══██╗██╔══╝  ██║  ██║╚════██║██╔══██║██║██╔══╝  ██║  ║
║   ██║  ██║███████╗██████╔╝███████║██║  ██║██║███████╗██║  ║
║   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ║
║                                                           ║
║        Red Team Remediation & Automation Toolkit          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""


@click.group()
@click.version_option(version='1.0.0', prog_name="RedShield")
@click.option('--quiet', '-q', is_flag=True, help='Suppress banner')
@click.pass_context
def cli(ctx, quiet):
    """
    RedShield - Red Team Remediation & Automation Toolkit
    
    Scan networks, discover vulnerabilities, apply fixes automatically,
    and generate professional security reports.
    
    \b
    Workflow:
      1. SCAN   - Discover open ports and services
      2. DETECT - Identify vulnerabilities  
      3. FIX    - Apply remediation (Ansible)
      4. REPORT - Generate PDF/HTML reports
    
    \b
    Examples:
      redshield scan 192.168.1.100 --scan-type full
      redshield fix scan-abc123 --auto
      redshield report scan-abc123 --format pdf
    """
    ctx.ensure_object(dict)
    ctx.obj['quiet'] = quiet
    
    if not quiet and ctx.invoked_subcommand not in ['version', None]:
        pass  # Don't show banner for subcommands


@cli.command()
def version():
    """Show version and system information."""
    click.echo(BANNER)
    click.echo()
    click.echo(formatInfoMessage("System Information:"))
    click.echo(f"  RedShield Version:  1.0.0")
    click.echo(f"  Python Version:     {sys.version.split()[0]}")
    click.echo(f"  Platform:           {platform.system()} {platform.release()}")
    click.echo(f"  Architecture:       {platform.machine()}")
    click.echo()
    
    # Check for dependencies
    click.echo(formatInfoMessage("Dependencies:"))
    
    # Check nmap
    try:
        import subprocess
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        nmap_version = result.stdout.split('\n')[0] if result.returncode == 0 else "Not found"
        click.echo(f"  Nmap:               {nmap_version}")
    except FileNotFoundError:
        click.echo(f"  Nmap:               Not installed")
    
    # Check ansible
    try:
        import subprocess
        result = subprocess.run(['ansible', '--version'], capture_output=True, text=True)
        ansible_version = result.stdout.split('\n')[0] if result.returncode == 0 else "Not found"
        click.echo(f"  Ansible:            {ansible_version}")
    except FileNotFoundError:
        click.echo(f"  Ansible:            Not installed")
    
    click.echo()
    click.echo(formatSuccessMessage("Status: Ready"))
    click.echo()


@cli.command()
def config():
    """Show current configuration."""
    click.echo()
    click.echo(formatInfoMessage("RedShield Configuration:"))
    click.echo("-" * 40)
    
    try:
        from config.settings import settings
        click.echo(f"  Database Type:      {settings.db_type}")
        click.echo(f"  Scan Timeout:       {settings.scan_timeout_seconds}s")
        click.echo(f"  Report Path:        {settings.report_output_path}")
        click.echo(f"  Playbooks Path:     {settings.playbooks_path}")
    except Exception as e:
        click.echo(f"  Error loading config: {str(e)}")
    
    click.echo()
    click.echo(formatInfoMessage("Scanning Tools:"))
    click.echo("  • Nmap (network scanning)")
    click.echo()
    click.echo(formatInfoMessage("Remediation:"))
    click.echo("  • Ansible playbooks")
    click.echo()


@cli.command()
def init():
    """Initialize RedShield database and directories."""
    click.echo()
    click.echo(formatInfoMessage("Initializing RedShield..."))
    click.echo()
    
    try:
        # Initialize database
        from database.connection import init_db
        init_db()
        click.echo(formatSuccessMessage("Database initialized"))
        
        # Create directories
        import os
        from config.settings import settings
        
        os.makedirs(settings.report_output_path, exist_ok=True)
        click.echo(formatSuccessMessage(f"Created reports directory: {settings.report_output_path}"))
        
        os.makedirs(settings.playbooks_path, exist_ok=True)
        click.echo(formatSuccessMessage(f"Created playbooks directory: {settings.playbooks_path}"))
        
        os.makedirs("./logs", exist_ok=True)
        click.echo(formatSuccessMessage("Created logs directory"))
        
        click.echo()
        click.echo(formatSuccessMessage("RedShield initialized successfully!"))
        click.echo()
        click.echo(formatInfoMessage("Next steps:"))
        click.echo("  1. Run 'redshield scan <target>' to start scanning")
        click.echo("  2. Run 'redshield --help' to see all commands")
        click.echo()
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Initialization failed: {str(e)}"))
        raise click.Abort()


# Register commands
cli.add_command(scan)
cli.add_command(fix)
cli.add_command(report)
cli.add_command(status)


def main():
    """Main entry point."""
    try:
        cli()
    except Exception as e:
        click.echo(formatErrorMessage(str(e)), err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

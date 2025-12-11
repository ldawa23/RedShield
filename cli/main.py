import click
from cli.utils.formatters import formatSuccessMessage, formatErrorMessage
from cli.commands.scan import scan
from cli.commands.fix import fix
from cli.commands.report import report
from cli.commands.status import status
from cli.commands.verify import verify, list_exploits

@click.group()
@click.version_option(version='1.0.0', prog_name="RedShield")
def cli():
    """RedShield - Red Team Remediation and Automation Toolkit"""
    pass

@cli.command()
def version():
    """Show version and system info."""
    import sys
    import platform
    click.echo(f"RedShield v1.0.0")
    click.echo(f"Python: {sys.version.split()[0]}")
    click.echo(f"Platform: {platform.system()} {platform.release()}")
    click.echo(f"Status: Ready")

@cli.command()
def config():
    """Show configuration."""
    click.echo("RedShield Configuration:")
    try:
        from config.settings import settings
        click.echo(f"  Database: {settings.database_url}")
        click.echo(f"  Reports: {settings.report_output_path}")
        click.echo(f"  Playbooks: {settings.playbooks_path}")
    except:
        click.echo("  Database: SQLite")
    click.echo("  Scanning tools: Nmap, Nuclei")
    click.echo("  Remediation: Ansible")

@cli.command()
def init():
    """Initialize RedShield database and directories."""
    import os
    click.echo()
    click.echo("[*] Initializing RedShield...")
    click.echo()
    try:
        from database.connection import init_db
        from config.settings import settings
        init_db()
        click.echo(formatSuccessMessage("Database initialized"))
        os.makedirs(settings.report_output_path, exist_ok=True)
        click.echo(formatSuccessMessage(f"Created reports directory: {settings.report_output_path}"))
        os.makedirs(settings.playbooks_path, exist_ok=True)
        click.echo(formatSuccessMessage(f"Created playbooks directory: {settings.playbooks_path}"))
        os.makedirs("./logs", exist_ok=True)
        click.echo(formatSuccessMessage("Created logs directory"))
        click.echo()
        click.echo(formatSuccessMessage("RedShield initialized successfully!"))
        click.echo()
    except Exception as e:
        click.echo(formatErrorMessage(f"Initialization failed: {str(e)}"))

# ============ AUTHENTICATION COMMANDS ============

@cli.command()
@click.option('--username', '-u', prompt=True, help='Username')
@click.option('--password', '-p', prompt=True, hide_input=True, confirmation_prompt=True, help='Password')
@click.option('--email', '-e', prompt=True, help='Email address')
def register(username, password, email):
    """Register a new user account."""
    from cli.utils.auth import create_user, get_user_count, authenticate_user, save_session
    click.echo()
    user_count = get_user_count()
    is_admin = user_count == 0
    if is_admin:
        click.echo("[*] First user - creating as admin")
    result = create_user(username, password, email, role="admin" if is_admin else "user")
    if result is True:
        click.echo(formatSuccessMessage(f"User '{username}' created!"))
        click.echo(f"  Role: {'Admin' if is_admin else 'User'}")
        user = authenticate_user(username, password)
        if user:
            save_session(user)
            click.echo(formatSuccessMessage("You are now logged in"))
    else:
        click.echo(formatErrorMessage(f"Registration failed: {result}"))
    click.echo()

@cli.command()
@click.option('--username', '-u', prompt=True, help='Username')
@click.option('--password', '-p', prompt=True, hide_input=True, help='Password')
def login(username, password):
    """Log in to your account."""
    from cli.utils.auth import authenticate_user, save_session
    click.echo()
    user = authenticate_user(username, password)
    if user:
        save_session(user)
        click.echo(formatSuccessMessage(f"Welcome back, {username}!"))
        click.echo(f"  Role: {user['role'].capitalize()}")
    else:
        click.echo(formatErrorMessage("Invalid username or password"))
    click.echo()

@cli.command()
def logout():
    """Log out of your account."""
    from cli.utils.auth import clear_session, get_current_user
    click.echo()
    user = get_current_user()
    if user:
        clear_session()
        click.echo(formatSuccessMessage(f"Goodbye, {user['username']}!"))
    else:
        click.echo("[*] You are not logged in")
    click.echo()

@cli.command()
def whoami():
    """Show current logged-in user."""
    from cli.utils.auth import get_current_user
    click.echo()
    user = get_current_user()
    if user:
        click.echo(f"Logged in as: {click.style(user['username'], fg='green', bold=True)}")
        click.echo(f"  Email: {user['email']}")
        click.echo(f"  Role:  {user['role'].capitalize()}")
        click.echo(f"  Admin: {'Yes' if user['is_admin'] else 'No'}")
    else:
        click.echo("[*] Not logged in")
        click.echo("  Run 'redshield login' or 'redshield register'")
    click.echo()

# Register commands
cli.add_command(scan)
cli.add_command(fix)
cli.add_command(report)
cli.add_command(status)
cli.add_command(verify)
cli.add_command(list_exploits)

if __name__ == '__main__':
    try:
        cli()
    except Exception as e:
        click.echo(formatErrorMessage(str(e)), err=True)
        raise


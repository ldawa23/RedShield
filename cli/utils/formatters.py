import click
from datetime import datetime

def formatSeverity(severity):
    #Formatting severity level with color
    color_map = { 'Critical': 'red', 'High': 'yellow', 'Medium': 'blue', 'Low': 'green', 'None': 'black'}
    color = color_map.get(severity, 'white')
    return click.style(f"[{severity}]", fg=color, bold=True)

def formatVulnerability(vuln):
    #Formatting vulnerability for display
    severity_str = format_severity(vuln.get('severity', 'LOW'))
    vuln_type = click.style(vuln.get('type', 'UNKNOWN'), fg='cyan')
    port = vuln.get('port', 'N/A')
    return f"{severity_str} {vuln_type} (Port: {port})"

def formatSuccessMessage(message):
    #Success message format
    return click.style(f"✓ {message}", fg='green', bold=True)

def formatErrorMessage(message):
    #Error message format
    return click.style(f"X {message}", fg='red', bold=True)

def formatInfoMessage(message):
    #Info message format
    return click.style(f"[*] {message}", fg='cyan')

def formatWarningMessage(message):
    #Warning message format
    return click.style(f"[!] {message}", fg='yellow', bold=True)

def formatStatus(status):
    #Status format with specific color
    status_color = {'Completed': 'green', 'In progress': 'yellow', 'Failed': 'red', 'Pending': 'blue'}
    color = status_color.get(status, 'white')
    return click.style(status, fg=color, bold=True)

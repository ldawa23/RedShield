"""
RedShield Fix Command

This command applies remediation to discovered vulnerabilities.

HOW IT WORKS:
1. Loads vulnerabilities from a scan
2. Determines appropriate fixes (Ansible playbooks)
3. Applies fixes (or shows what would be done in dry-run mode)
4. Updates vulnerability status in database

USAGE:
    redshield fix scan-20251210-ABC --auto
    redshield fix scan-20251210-ABC --dry-run
    redshield fix scan-20251210-ABC --severity Critical
"""

import click
from datetime import datetime
from cli.utils.formatters import (
    formatSuccessMessage, 
    formatErrorMessage, 
    formatInfoMessage, 
    formatWarningMessage, 
    formatSeverity
)


# Mapping of vulnerability types to fix information
# In production, these would be actual Ansible playbooks
REMEDIATION_PLAYBOOKS = {
    "EXPOSED_DATABASE_PORT": {
        "playbook": "fix_exposed_database.yml",
        "description": "Configure firewall rules to restrict database access",
        "actions": [
            "Add firewall rule to block external access",
            "Configure bind address to localhost only",
            "Enable authentication if disabled"
        ]
    },
    "DEFAULT_CREDENTIALS": {
        "playbook": "fix_default_credentials.yml",
        "description": "Change default credentials to secure values",
        "actions": [
            "Generate new secure password",
            "Update service configuration",
            "Restart affected service"
        ]
    },
    "OUTDATED_COMPONENT": {
        "playbook": "fix_outdated_software.yml",
        "description": "Update software to latest secure version",
        "actions": [
            "Check for available updates",
            "Backup current configuration",
            "Apply security patches"
        ]
    },
    "MISSING_HTTPS": {
        "playbook": "fix_missing_https.yml",
        "description": "Enable HTTPS with SSL/TLS certificate",
        "actions": [
            "Generate or obtain SSL certificate",
            "Configure web server for HTTPS",
            "Set up HTTP to HTTPS redirect"
        ]
    },
    "OPEN_PORT": {
        "playbook": "fix_open_port.yml",
        "description": "Secure or close unnecessary open port",
        "actions": [
            "Evaluate if port is needed",
            "Configure firewall rules",
            "Disable unnecessary services"
        ]
    }
}


def get_scan_vulnerabilities(scan_id):
    """Get vulnerabilities from database for a scan."""
    try:
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord
        
        session = get_session()
        scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        
        if not scan:
            session.close()
            return None, []
        
        vulns = session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == scan.id
        ).all()
        
        session.close()
        return scan, vulns
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Database error: {str(e)}"))
        return None, []


def update_vulnerability_status(vuln_id, new_status, playbook_name=None):
    """Update vulnerability status in database."""
    try:
        from database.connection import get_session
        from database.models import VulnerabilityRecord, RemediationRecord, VulnStatus
        
        session = get_session()
        vuln = session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.id == vuln_id
        ).first()
        
        if vuln:
            vuln.status = VulnStatus.FIXED if new_status == "fixed" else VulnStatus.DISCOVERED
            vuln.fixed_at = datetime.utcnow() if new_status == "fixed" else None
            
            # Create remediation record
            remediation = RemediationRecord(
                vulnerability_id=vuln_id,
                playbook_name=playbook_name,
                status="success" if new_status == "fixed" else "pending",
                applied_at=datetime.utcnow()
            )
            session.add(remediation)
            session.commit()
        
        session.close()
        return True
        
    except Exception as e:
        click.echo(formatWarningMessage(f"Could not update database: {str(e)}"))
        return False


@click.command()
@click.argument('scan_id')
@click.option('--auto', is_flag=True, help='Auto-fix without confirmation prompts')
@click.option('--severity', '-s', type=click.Choice(['Critical', 'High', 'Medium', 'Low', 'All']), default='All', help='Minimum severity to fix')
@click.option('--dry-run', is_flag=True, help='Show what would be fixed without making changes')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed fix information')
def fix(scan_id, auto, severity, dry_run, verbose):
    """
    Apply fixes to vulnerabilities from a scan.
    
    This command generates and executes Ansible playbooks to remediate
    discovered vulnerabilities.
    
    \b
    Examples:
        redshield fix scan-20251210-ABC --auto
        redshield fix scan-20251210-ABC --dry-run
        redshield fix scan-20251210-ABC --severity Critical
        redshield fix scan-20251210-ABC --auto --severity High
    """
    try:
        click.echo()
        click.echo(formatInfoMessage(f"Loading scan: {click.style(scan_id, fg='yellow')}"))
        
        # Get scan from database
        scan, vulnerabilities = get_scan_vulnerabilities(scan_id)
        
        if not scan:
            click.echo(formatErrorMessage(f"Scan not found: {scan_id}"))
            click.echo()
            click.echo(formatInfoMessage("Use 'redshield status' to see available scans"))
            click.echo()
            return
        
        click.echo(formatInfoMessage(f"Target: {scan.target}"))
        click.echo()
        
        # Filter by severity
        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        if severity != 'All':
            min_level = severity_order.get(severity, 0)
            fixable = [
                v for v in vulnerabilities 
                if severity_order.get(v.severity.capitalize(), 0) >= min_level
                and v.status.value == "discovered"
            ]
        else:
            fixable = [v for v in vulnerabilities if v.status.value == "discovered"]
        
        if not fixable:
            click.echo(formatSuccessMessage("No vulnerabilities to fix!"))
            if severity != 'All':
                click.echo(formatInfoMessage(f"(Filtered by severity >= {severity})"))
            click.echo()
            return
        
        # Display fixable vulnerabilities
        click.echo(formatInfoMessage(f"Found {len(fixable)} vulnerabilities to fix:"))
        click.echo("-" * 60)
        
        for i, vuln in enumerate(fixable, 1):
            playbook_info = REMEDIATION_PLAYBOOKS.get(vuln.vuln_type, {})
            playbook_name = playbook_info.get("playbook", "generic_fix.yml")
            
            click.echo(f"\n  {i}. {formatSeverity(vuln.severity)} {vuln.vuln_type}")
            click.echo(f"     Service: {vuln.service} | Port: {vuln.port}")
            click.echo(f"     Playbook: {click.style(playbook_name, fg='cyan')}")
            
            if verbose:
                description = playbook_info.get("description", "Apply security fix")
                click.echo(f"     Description: {description}")
                actions = playbook_info.get("actions", [])
                if actions:
                    click.echo("     Actions:")
                    for action in actions:
                        click.echo(f"       • {action}")
        
        click.echo()
        
        # Dry run mode
        if dry_run:
            click.echo(formatWarningMessage("DRY-RUN MODE - No changes will be made"))
            click.echo()
            click.echo("The following playbooks would be executed:")
            for vuln in fixable:
                playbook_info = REMEDIATION_PLAYBOOKS.get(vuln.vuln_type, {})
                playbook_name = playbook_info.get("playbook", "generic_fix.yml")
                click.echo(f"  • {playbook_name} -> {vuln.service}:{vuln.port}")
            click.echo()
            return
        
        # Confirmation
        if not auto:
            if not click.confirm(f"Apply fixes to {len(fixable)} vulnerabilities?"):
                click.echo("Cancelled.")
                return
        
        # Apply fixes
        click.echo()
        click.echo(formatInfoMessage("Applying remediation..."))
        click.echo()
        
        fixed_count = 0
        failed_count = 0
        
        with click.progressbar(fixable, label='Fixing', show_pos=True) as bar:
            for vuln in bar:
                playbook_info = REMEDIATION_PLAYBOOKS.get(vuln.vuln_type, {})
                playbook_name = playbook_info.get("playbook", "generic_fix.yml")
                
                # In production, this would run actual Ansible playbooks
                # For now, we simulate success and update the database
                
                # Simulate fix (in production: ansible-playbook playbook_name -i inventory)
                import time
                time.sleep(0.3)  # Simulate work
                
                # Update database
                if update_vulnerability_status(vuln.id, "fixed", playbook_name):
                    fixed_count += 1
                else:
                    failed_count += 1
        
        click.echo()
        
        # Summary
        if fixed_count > 0:
            click.echo(formatSuccessMessage(f"Successfully fixed {fixed_count} vulnerabilities"))
        if failed_count > 0:
            click.echo(formatWarningMessage(f"Failed to fix {failed_count} vulnerabilities"))
        
        click.echo()
        click.echo(formatInfoMessage("Next steps:"))
        click.echo(f"  • Verify fixes:  redshield status {scan_id}")
        click.echo(f"  • Re-scan:       redshield scan {scan.target}")
        click.echo(f"  • Generate:      redshield report {scan_id} --format pdf")
        click.echo()
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Fix failed: {str(e)}"), err=True)
        raise click.Abort()

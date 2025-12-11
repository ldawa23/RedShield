"""
RedShield Status Command

This command shows the status of scans and their vulnerabilities.

HOW IT WORKS:
- With scan_id: Shows details of a specific scan
- Without scan_id: Shows all recent scans

USAGE:
    redshield status                    # Show all scans
    redshield status scan-20251210-ABC  # Show specific scan
"""

import click
from cli.utils.formatters import (
    formatStatus, 
    formatInfoMessage, 
    formatSuccessMessage,
    formatErrorMessage,
    formatSeverity
)


def get_scan_from_database(scan_id):
    """Retrieve a scan and its vulnerabilities from the database."""
    try:
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord
        
        session = get_session()
        scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        
        if scan:
            vulns = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.scan_id == scan.id
            ).all()
            session.close()
            return scan, vulns
        
        session.close()
        return None, []
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Database error: {str(e)}"))
        return None, []


def get_all_scans_from_database(limit=10):
    """Retrieve recent scans from the database."""
    try:
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord
        
        session = get_session()
        scans = session.query(ScanRecord).order_by(
            ScanRecord.started_at.desc()
        ).limit(limit).all()
        
        result = []
        for scan in scans:
            vuln_count = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.scan_id == scan.id
            ).count()
            result.append((scan, vuln_count))
        
        session.close()
        return result
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Database error: {str(e)}"))
        return []


@click.command()
@click.argument('scan_id', required=False)
@click.option('--all', '-a', 'show_all', is_flag=True, help='Show all scans (not just recent)')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed information')
def status(scan_id, show_all, verbose):
    """
    Check scan status and view results.
    
    Without SCAN_ID: Shows list of recent scans.
    With SCAN_ID: Shows detailed results of that scan.
    
    \b
    Examples:
        redshield status                    # List recent scans
        redshield status scan-20251210-ABC  # Show specific scan
        redshield status --all              # Show all scans
    """
    click.echo()
    
    if scan_id:
        # Show specific scan details
        scan, vulns = get_scan_from_database(scan_id)
        
        if not scan:
            click.echo(formatErrorMessage(f"Scan not found: {scan_id}"))
            click.echo()
            click.echo(formatInfoMessage("Use 'redshield status' to see available scans"))
            click.echo()
            return
        
        # Display scan info
        click.echo(formatInfoMessage(f"Scan Details: {click.style(scan.scan_id, fg='yellow')}"))
        click.echo("-" * 50)
        click.echo(f"  Target:      {scan.target}")
        click.echo(f"  Status:      {formatStatus(scan.status.value.capitalize())}")
        click.echo(f"  Scan Type:   {scan.scan_type}")
        click.echo(f"  Port Range:  {scan.port_range}")
        click.echo(f"  Started:     {scan.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if scan.completed_at:
            click.echo(f"  Completed:   {scan.completed_at.strftime('%Y-%m-%d %H:%M:%S')}")
        
        click.echo()
        
        # Vulnerability summary
        if vulns:
            critical = sum(1 for v in vulns if v.severity.upper() == 'CRITICAL')
            high = sum(1 for v in vulns if v.severity.upper() == 'HIGH')
            medium = sum(1 for v in vulns if v.severity.upper() == 'MEDIUM')
            low = sum(1 for v in vulns if v.severity.upper() == 'LOW')
            
            click.echo(formatInfoMessage(f"Vulnerabilities Found: {len(vulns)}"))
            click.echo("-" * 50)
            
            if critical:
                click.echo(f"  {formatSeverity('Critical')}: {critical}")
            if high:
                click.echo(f"  {formatSeverity('High')}: {high}")
            if medium:
                click.echo(f"  {formatSeverity('Medium')}: {medium}")
            if low:
                click.echo(f"  {formatSeverity('Low')}: {low}")
            
            click.echo()
            click.echo("Vulnerability List:")
            click.echo("-" * 50)
            
            for i, vuln in enumerate(vulns, 1):
                status_icon = "✓" if vuln.status.value == "fixed" else "○"
                click.echo(f"  {i}. [{status_icon}] {formatSeverity(vuln.severity)} {vuln.vuln_type}")
                click.echo(f"       Service: {vuln.service} | Port: {vuln.port}")
                if verbose and vuln.description:
                    click.echo(f"       Description: {vuln.description}")
                if vuln.status.value != "discovered":
                    click.echo(f"       Status: {vuln.status.value}")
        else:
            click.echo(formatSuccessMessage("No vulnerabilities found in this scan"))
        
        # Next steps
        unfixed = [v for v in vulns if v.status.value == "discovered"]
        if unfixed:
            click.echo()
            click.echo(formatInfoMessage("Actions:"))
            click.echo(f"  • Fix all:    redshield fix {scan_id} --auto")
            click.echo(f"  • Generate:   redshield report {scan_id} --format pdf")
        
    else:
        # Show list of all scans
        limit = 100 if show_all else 10
        scans = get_all_scans_from_database(limit=limit)
        
        if not scans:
            click.echo(formatInfoMessage("No scans found"))
            click.echo()
            click.echo("Run a scan with: redshield scan <target>")
            click.echo()
            return
        
        click.echo(formatInfoMessage(f"Recent Scans ({len(scans)} found):"))
        click.echo("-" * 70)
        click.echo(f"  {'SCAN ID':<25} {'TARGET':<20} {'STATUS':<12} {'VULNS'}")
        click.echo("-" * 70)
        
        for scan, vuln_count in scans:
            status_str = formatStatus(scan.status.value.capitalize())
            vuln_str = f"{vuln_count} found" if vuln_count > 0 else "none"
            click.echo(f"  {click.style(scan.scan_id, fg='yellow'):<25} {scan.target:<20} {status_str:<12} {vuln_str}")
        
        click.echo()
        click.echo(formatInfoMessage("View details: redshield status <scan_id>"))
    
    click.echo()

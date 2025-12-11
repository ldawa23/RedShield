"""
RedShield Scan Command

This command scans a target for vulnerabilities using Nmap.

HOW IT WORKS:
1. Validates the target (IP, hostname, or CIDR)
2. Runs Nmap to find open ports and services
3. Analyzes results to identify vulnerabilities
4. Saves results to the database
5. Shows summary and next steps

USAGE:
    redshield scan 192.168.1.100
    redshield scan 192.168.1.0/24 --scan-type full
    redshield scan example.com -p 22,80,443 --output results.json
"""

import click
import json
import uuid
from datetime import datetime
from cli.utils.validators import validate, validate_port
from cli.utils.formatters import (
    formatSuccessMessage, 
    formatErrorMessage, 
    formatInfoMessage, 
    formatWarningMessage, 
    formatSeverity, 
    formatVulnerability
)


def generate_scan_id():
    """Generate a unique, human-readable scan ID."""
    timestamp = datetime.now().strftime("%Y%m%d")
    unique = uuid.uuid4().hex[:6].upper()
    return f"scan-{timestamp}-{unique}"


def check_nmap_installed():
    """Check if Nmap is installed on the system."""
    import subprocess
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def save_scan_to_database(scan_id, target, port_range, scan_type, vulnerabilities, status="completed"):
    """
    Save scan results to the database.
    
    This allows us to:
    - Track scan history
    - Generate reports later
    - Apply fixes to specific scans
    """
    try:
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord, ScanStatus, VulnStatus
        from datetime import datetime
        
        session = get_session()
        
        # Create scan record
        scan_record = ScanRecord(
            scan_id=scan_id,
            target=target,
            port_range=port_range,
            scan_type=scan_type,
            status=ScanStatus.COMPLETED if status == "completed" else ScanStatus.FAILED,
            completed_at=datetime.utcnow()
        )
        session.add(scan_record)
        session.flush()  # Get the scan ID
        
        # Add vulnerabilities
        for vuln in vulnerabilities:
            vuln_record = VulnerabilityRecord(
                scan_id=scan_record.id,
                vuln_type=vuln['type'],
                service=vuln.get('service', 'unknown'),
                port=vuln.get('port'),
                severity=vuln['severity'],
                status=VulnStatus.DISCOVERED,
                description=vuln.get('description', ''),
                fix_available=True  # We'll have Ansible playbooks for common issues
            )
            session.add(vuln_record)
        
        session.commit()
        session.close()
        return True
        
    except Exception as e:
        click.echo(formatWarningMessage(f"Could not save to database: {str(e)}"))
        return False


@click.command()
@click.argument('target')
@click.option('--scan-type', '-s', type=click.Choice(['quick', 'full', 'deep']), default='quick', help='Scan intensity: quick (common ports), full (1-1000), deep (all ports)')
@click.option('--port-range', '-p', default=None, help='Port range to scan (e.g., 22,80,443 or 1-1000)')
@click.option('--threads', '-t', type=int, default=10, help='Number of parallel threads')
@click.option('--output', '-o', type=click.Path(), help='Save results to JSON file')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed output')
@click.option('--demo', is_flag=True, help='Use demo data (when Nmap not installed)')
def scan(target, scan_type, port_range, threads, output, verbose, demo):
    """
    Scan a target for vulnerabilities.
    
    TARGET can be an IP address (192.168.1.100), hostname (example.com),
    or CIDR range (192.168.1.0/24).
    
    \b
    Examples:
        redshield scan 192.168.1.100
        redshield scan 192.168.1.100 --scan-type full
        redshield scan example.com -p 22,80,443 -o results.json
        redshield scan 127.0.0.1 --demo  # Use demo data
    """
    try:
        # Validate inputs
        target = validate(target)
        
        # Set port range based on scan type if not specified
        if port_range is None:
            if scan_type == 'quick':
                port_range = "22,80,443,3306,5432,27017,6379"  # Common vulnerable ports
            elif scan_type == 'full':
                port_range = "1-1000"
            else:  # deep
                port_range = "1-65535"
        
        port_range = validate_port(port_range)
        
        # Generate unique scan ID
        scan_id = generate_scan_id()
        
        # Display scan info
        click.echo()
        click.echo(formatInfoMessage(f"Scan ID: {click.style(scan_id, fg='yellow')}"))
        click.echo(formatInfoMessage(f"Target: {target}"))
        click.echo(formatInfoMessage(f"Scan Type: {scan_type.upper()}"))
        click.echo(formatInfoMessage(f"Port Range: {port_range}"))
        
        if verbose:
            click.echo(formatInfoMessage(f"Threads: {threads}"))
            click.echo(formatInfoMessage("Verbose Mode: ON"))
        
        click.echo()
        
        # Check if we should use demo mode
        nmap_available = check_nmap_installed()
        use_demo = demo or not nmap_available
        
        if use_demo and not demo:
            click.echo(formatWarningMessage("Nmap not installed - using demo mode"))
            click.echo(formatInfoMessage("Install Nmap for real scanning: https://nmap.org/download.html"))
            click.echo()
        
        # Run scan
        click.echo(formatInfoMessage("Starting vulnerability scan..."))
        click.echo()
        
        if use_demo:
            # Demo mode - use fake data for testing
            from core.fake_data import build_demo_vulnerabilities
            
            with click.progressbar(length=100, label='Scanning (demo)') as bar:
                import time
                for i in range(10):
                    time.sleep(0.1)
                    bar.update(10)
            
            demo_vulns = build_demo_vulnerabilities(target)
            vulnerabilities = [
                {
                    'severity': v.severity,
                    'type': v.vuln_type,
                    'port': v.port,
                    'service': v.service,
                    'description': f"Demo vulnerability on port {v.port}"
                }
                for v in demo_vulns
            ]
        else:
            # Real Nmap scan
            from core.nmapvuln import scanrun
            
            with click.progressbar(length=100, label='Scanning') as bar:
                bar.update(10)
                scan_result = scanrun(target, ports=port_range)
                bar.update(90)
            
            vulnerabilities = [
                {
                    'severity': v.severity,
                    'type': v.vuln_type,
                    'port': v.port,
                    'service': v.service,
                    'description': f"Discovered {v.service} on port {v.port}"
                }
                for v in scan_result.vulnerabilities
            ]
        
        click.echo()
        
        # Show results
        if not vulnerabilities:
            click.echo(formatSuccessMessage("No vulnerabilities found!"))
            click.echo(formatInfoMessage("The target appears to be secure (no open vulnerable ports detected)"))
        else:
            click.echo(formatSuccessMessage(f"Scan completed - Found {len(vulnerabilities)} issue(s)"))
            click.echo()
            
            # Severity breakdown
            critical = [v for v in vulnerabilities if v['severity'] == 'Critical']
            high = [v for v in vulnerabilities if v['severity'] == 'High']
            medium = [v for v in vulnerabilities if v['severity'] == 'Medium']
            low = [v for v in vulnerabilities if v['severity'] == 'Low']
            
            click.echo("Severity Breakdown:")
            if critical:
                click.echo(f"  {formatSeverity('Critical')}: {len(critical)}")
            if high:
                click.echo(f"  {formatSeverity('High')}: {len(high)}")
            if medium:
                click.echo(f"  {formatSeverity('Medium')}: {len(medium)}")
            if low:
                click.echo(f"  {formatSeverity('Low')}: {len(low)}")
            
            click.echo()
            click.echo("Vulnerabilities Discovered:")
            click.echo("-" * 50)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                click.echo(f"  {i}. {formatVulnerability(vuln)}")
                if verbose and vuln.get('description'):
                    click.echo(f"     └── {vuln['description']}")
        
        # Save to database
        click.echo()
        saved = save_scan_to_database(scan_id, target, port_range, scan_type, vulnerabilities)
        if saved:
            click.echo(formatSuccessMessage("Results saved to database"))
        
        # Save to file if requested
        if output:
            data = {
                'scan_id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'port_range': port_range,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': vulnerabilities,
                'summary': {
                    'total': len(vulnerabilities),
                    'critical': len(critical) if vulnerabilities else 0,
                    'high': len(high) if vulnerabilities else 0,
                    'medium': len(medium) if vulnerabilities else 0,
                    'low': len(low) if vulnerabilities else 0,
                }
            }
            with open(output, 'w') as f:
                json.dump(data, f, indent=2)
            click.echo(formatSuccessMessage(f"Results saved to: {output}"))
        
        # Next steps
        if vulnerabilities:
            click.echo()
            click.echo(formatInfoMessage("Next Steps:"))
            click.echo(f"  • View details: redshield status {scan_id}")
            click.echo(f"  • Fix issues:   redshield fix {scan_id} --auto")
            click.echo(f"  • Get report:   redshield report {scan_id} --format pdf")
        
        click.echo()
        
    except click.BadParameter as e:
        click.echo(formatErrorMessage(str(e)), err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(formatErrorMessage(f"Scan failed: {str(e)}"), err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        raise click.Abort()

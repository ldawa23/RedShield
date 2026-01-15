"""
RedShield Detect Command

Run the built-in detection engine against a target.
This uses custom vulnerability signatures instead of external tools like Nuclei.

HOW IT WORKS:
1. Takes target and open ports from a previous scan (or scans first)
2. Runs each signature against the target
3. Reports detected vulnerabilities with confidence scores
4. Maps findings to OWASP Top 10 and MITRE ATT&CK

USAGE:
    redshield detect 192.168.1.100
    redshield detect 192.168.1.100 --ports 22,80,443
    redshield detect scan-20251210-ABC
    redshield detect 192.168.1.100 --category A03:2021
"""

import click
from datetime import datetime
from cli.utils.validators import validate, validate_port
from cli.utils.formatters import (
    formatSuccessMessage, 
    formatErrorMessage, 
    formatInfoMessage,
    formatWarningMessage,
    formatSeverity
)


def get_scan_from_database(scan_id):
    """Get scan data from database."""
    try:
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord
        
        session = get_session()
        scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        
        if not scan:
            session.close()
            return None
        
        vulns = session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == scan.id
        ).all()
        
        # Convert to format we need
        open_ports = [(v.port, v.service) for v in vulns]
        
        session.close()
        return {
            'target': scan.target,
            'ports': open_ports
        }
        
    except Exception as e:
        click.echo(formatWarningMessage(f"Database error: {str(e)}"))
        return None


def save_detections_to_database(scan_id, detections):
    """Save detection results to database."""
    try:
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord, VulnStatus
        
        session = get_session()
        scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        
        if not scan:
            session.close()
            return False
        
        for detection in detections:
            # Check if already exists
            existing = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.scan_id == scan.id,
                VulnerabilityRecord.vuln_type == detection['vuln_type'],
                VulnerabilityRecord.port == detection['port']
            ).first()
            
            if not existing:
                vuln = VulnerabilityRecord(
                    scan_id=scan.id,
                    vuln_type=detection['vuln_type'],
                    service=detection.get('service', 'unknown'),
                    port=detection.get('port'),
                    severity=detection.get('severity', 'Medium'),
                    status=VulnStatus.DISCOVERED,
                    description=detection.get('description', ''),
                    owasp_category=detection.get('category'),
                    mitre_id=detection.get('mitre_attack'),
                    fix_available=True
                )
                session.add(vuln)
        
        session.commit()
        session.close()
        return True
        
    except Exception as e:
        click.echo(formatWarningMessage(f"Could not save to database: {str(e)}"))
        return False


@click.command()
@click.argument('target')
@click.option('--ports', '-p', help='Specific ports to check (e.g., 22,80,443)')
@click.option('--category', '-c', help='Only use signatures from OWASP category (e.g., A03:2021)')
@click.option('--severity', '-s', type=click.Choice(['Critical', 'High', 'Medium', 'Low', 'All']), 
              default='All', help='Minimum severity to report')
@click.option('--scan-first', is_flag=True, help='Run port scan before detection')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed output')
@click.option('--output', '-o', type=click.Path(), help='Save results to JSON file')
def detect(target, ports, category, severity, scan_first, verbose, output):
    """
    Run detection engine against a target.
    
    TARGET can be an IP address, hostname, or a scan ID from a previous scan.
    
    \b
    Examples:
        redshield detect 192.168.1.100 --scan-first
        redshield detect scan-20251210-ABC
        redshield detect 192.168.1.100 -p 22,80,443 --category A03:2021
    """
    try:
        click.echo()
        
        # Check if target is a scan ID
        scan_data = None
        if target.startswith('scan-'):
            click.echo(formatInfoMessage(f"Loading scan: {click.style(target, fg='yellow')}"))
            scan_data = get_scan_from_database(target)
            
            if not scan_data:
                click.echo(formatErrorMessage(f"Scan not found: {target}"))
                return
            
            target_ip = scan_data['target']
            open_ports = scan_data['ports']
            click.echo(formatInfoMessage(f"Target: {target_ip}"))
            click.echo(formatInfoMessage(f"Found {len(open_ports)} open ports from scan"))
        else:
            # Validate target
            target_ip = validate(target)
            open_ports = []
            
            if ports:
                # Parse provided ports
                port_str = validate_port(ports)
                open_ports = [(int(p.strip()), 'unknown') for p in port_str.split(',') if p.strip().isdigit()]
            elif scan_first:
                # Run a quick port scan first
                click.echo(formatInfoMessage(f"Scanning target: {target_ip}"))
                
                try:
                    from integrations.nmapscan import scan as nmap_scan
                    
                    with click.progressbar(length=100, label='Port scanning') as bar:
                        bar.update(10)
                        open_ports = nmap_scan(target_ip, "22,80,443,3306,5432,27017,6379,8080")
                        bar.update(90)
                    
                    click.echo(formatInfoMessage(f"Found {len(open_ports)} open ports"))
                except Exception as e:
                    click.echo(formatWarningMessage(f"Nmap not available: {e}"))
                    # Use demo ports
                    open_ports = [(80, 'http'), (443, 'https'), (22, 'ssh')]
            else:
                # Default common ports
                click.echo(formatWarningMessage("No ports specified, using common ports"))
                open_ports = [(80, 'http'), (443, 'https'), (22, 'ssh')]
        
        if not open_ports:
            click.echo(formatWarningMessage("No open ports to analyze"))
            return
        
        click.echo()
        click.echo(formatInfoMessage("Running detection engine..."))
        click.echo()
        
        # Load signatures and run detection
        from core.signatures.matcher import DetectionEngine
        from core.signatures.loader import Severity
        
        engine = DetectionEngine()
        
        # Filter signatures if category specified
        if category:
            engine.signatures = [s for s in engine.signatures if category.lower() in s.category.lower()]
            click.echo(formatInfoMessage(f"Using {len(engine.signatures)} signatures for category {category}"))
        
        with click.progressbar(length=100, label='Detecting vulnerabilities') as bar:
            bar.update(10)
            detections = engine.scan(target_ip, open_ports)
            bar.update(90)
        
        # Filter by severity
        if severity != 'All':
            severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
            min_level = severity_order.get(severity, 0)
            detections = [d for d in detections if severity_order.get(d['severity'], 0) >= min_level]
        
        click.echo()
        
        # Display results
        if not detections:
            click.echo(formatSuccessMessage("No vulnerabilities detected!"))
            click.echo(formatInfoMessage("The target appears to be secure against known signature patterns"))
        else:
            click.echo(formatWarningMessage(f"Detected {len(detections)} potential vulnerabilities"))
            click.echo()
            
            # Group by severity
            by_severity = {}
            for d in detections:
                sev = d['severity']
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(d)
            
            for sev in ['Critical', 'High', 'Medium', 'Low']:
                if sev not in by_severity:
                    continue
                
                click.echo(f"{formatSeverity(sev)} Vulnerabilities ({len(by_severity[sev])})")
                click.echo("-" * 50)
                
                for d in by_severity[sev]:
                    confidence = d.get('confidence', 0) * 100
                    click.echo(f"  [{d['signature_id']}] {d['type']}")
                    click.echo(f"    Port: {d['port']}, Service: {d['service']}")
                    click.echo(f"    Confidence: {confidence:.0f}%")
                    
                    if verbose:
                        click.echo(f"    Description: {d['description'][:60]}...")
                        click.echo(f"    Category: {d['category']}")
                        if d.get('mitre_attack'):
                            click.echo(f"    MITRE ATT&CK: {d['mitre_attack']}")
                        if d.get('evidence'):
                            click.echo(f"    Evidence: {d['evidence'][0]}")
                        if d.get('remediation'):
                            click.echo(f"    Remediation: {d['remediation']['description'][:50]}...")
                    click.echo()
                
                click.echo()
        
        # Save to database if we have a scan ID
        if target.startswith('scan-') and detections:
            saved = save_detections_to_database(target, detections)
            if saved:
                click.echo(formatSuccessMessage("Detections saved to database"))
        
        # Save to file if requested
        if output and detections:
            import json
            data = {
                'target': target_ip,
                'timestamp': datetime.now().isoformat(),
                'ports_checked': len(open_ports),
                'detections': detections,
                'summary': {
                    'total': len(detections),
                    'critical': len(by_severity.get('Critical', [])),
                    'high': len(by_severity.get('High', [])),
                    'medium': len(by_severity.get('Medium', [])),
                    'low': len(by_severity.get('Low', []))
                }
            }
            with open(output, 'w') as f:
                json.dump(data, f, indent=2)
            click.echo(formatSuccessMessage(f"Results saved to: {output}"))
        
        # Next steps
        if detections:
            click.echo()
            click.echo(formatInfoMessage("Next Steps:"))
            click.echo(f"  • View signature details: redshield signatures info <ID>")
            if target.startswith('scan-'):
                click.echo(f"  • Apply fixes: redshield fix {target} --auto")
                click.echo(f"  • Generate report: redshield report {target} --format pdf")
            click.echo()
        
    except click.BadParameter as e:
        click.echo(formatErrorMessage(str(e)), err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(formatErrorMessage(f"Detection failed: {str(e)}"), err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        raise click.Abort()

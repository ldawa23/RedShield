"""
Scan Comparison Command - Compare two scans to show vulnerability remediation progress

Usage:
    redshield compare <scan_id_before> <scan_id_after>
    redshield compare --list   # Show comparison history
"""

import click
import json
from datetime import datetime
from cli.utils.formatters import (
    formatSuccessMessage, 
    formatErrorMessage,
    formatInfoMessage,
    formatWarningMessage,
    formatSeverity
)


def get_scan_with_vulns(scan_id):
    """Get scan and its vulnerabilities from database."""
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


def save_comparison(scan_before, scan_after, comparison_data):
    """Save comparison to database."""
    try:
        from database.connection import get_session
        from database.models import ScanComparison
        
        session = get_session()
        
        comparison = ScanComparison(
            scan_before_id=scan_before.id,
            scan_after_id=scan_after.id,
            vulns_before=comparison_data['vulns_before'],
            vulns_after=comparison_data['vulns_after'],
            vulns_fixed=comparison_data['vulns_fixed'],
            vulns_new=comparison_data['vulns_new'],
            vulns_unchanged=comparison_data['vulns_unchanged'],
            critical_fixed=comparison_data['critical_fixed'],
            high_fixed=comparison_data['high_fixed'],
            medium_fixed=comparison_data['medium_fixed'],
            low_fixed=comparison_data['low_fixed'],
            compared_at=datetime.utcnow()
        )
        
        session.add(comparison)
        session.commit()
        session.close()
        return True
        
    except Exception as e:
        click.echo(formatWarningMessage(f"Could not save comparison: {str(e)}"))
        return False


def compare_scans(vulns_before, vulns_after):
    """Compare two sets of vulnerabilities."""
    
    # Create fingerprints for comparison (type + port + service)
    def vuln_fingerprint(v):
        return f"{v.vuln_type}|{v.port}|{v.service}|{v.vulnerable_parameter or ''}"
    
    before_fingerprints = {vuln_fingerprint(v): v for v in vulns_before}
    after_fingerprints = {vuln_fingerprint(v): v for v in vulns_after}
    
    before_set = set(before_fingerprints.keys())
    after_set = set(after_fingerprints.keys())
    
    # Find fixed, new, and unchanged
    fixed_fps = before_set - after_set
    new_fps = after_set - before_set
    unchanged_fps = before_set & after_set
    
    # Get actual vulnerability objects
    fixed_vulns = [before_fingerprints[fp] for fp in fixed_fps]
    new_vulns = [after_fingerprints[fp] for fp in new_fps]
    unchanged_vulns = [before_fingerprints[fp] for fp in unchanged_fps]
    
    # Count by severity
    def count_by_severity(vulns):
        return {
            'critical': sum(1 for v in vulns if v.severity.upper() == 'CRITICAL'),
            'high': sum(1 for v in vulns if v.severity.upper() == 'HIGH'),
            'medium': sum(1 for v in vulns if v.severity.upper() == 'MEDIUM'),
            'low': sum(1 for v in vulns if v.severity.upper() == 'LOW')
        }
    
    return {
        'vulns_before': len(vulns_before),
        'vulns_after': len(vulns_after),
        'vulns_fixed': len(fixed_vulns),
        'vulns_new': len(new_vulns),
        'vulns_unchanged': len(unchanged_vulns),
        'fixed_vulns': fixed_vulns,
        'new_vulns': new_vulns,
        'unchanged_vulns': unchanged_vulns,
        'critical_fixed': count_by_severity(fixed_vulns)['critical'],
        'high_fixed': count_by_severity(fixed_vulns)['high'],
        'medium_fixed': count_by_severity(fixed_vulns)['medium'],
        'low_fixed': count_by_severity(fixed_vulns)['low'],
        'severity_before': count_by_severity(vulns_before),
        'severity_after': count_by_severity(vulns_after)
    }


@click.command()
@click.argument('scan_before', required=False)
@click.argument('scan_after', required=False)
@click.option('--list', '-l', 'show_list', is_flag=True, help='Show comparison history')
@click.option('--export', '-e', type=click.Path(), help='Export comparison to JSON file')
def compare(scan_before, scan_after, show_list, export):
    """
    Compare two scans to show remediation progress.
    
    Shows which vulnerabilities were fixed, which are new,
    and which remain unchanged between scans.
    
    \b
    Examples:
        redshield compare scan-001 scan-002    # Compare two scans
        redshield compare --list               # Show comparison history
    """
    click.echo()
    
    if show_list:
        # Show comparison history
        try:
            from database.connection import get_session
            from database.models import ScanComparison, ScanRecord
            
            session = get_session()
            comparisons = session.query(ScanComparison).order_by(
                ScanComparison.compared_at.desc()
            ).limit(20).all()
            
            if not comparisons:
                click.echo(formatInfoMessage("No comparison history found"))
                click.echo()
                click.echo("Use: redshield compare <scan_before> <scan_after>")
                session.close()
                return
            
            click.echo(formatInfoMessage("📊 Comparison History"))
            click.echo("=" * 90)
            click.echo(f"  {'DATE':<20} {'BEFORE → AFTER':<30} {'FIXED':<8} {'NEW':<8} {'PROGRESS':<15}")
            click.echo("-" * 90)
            
            for c in comparisons:
                before_scan = session.query(ScanRecord).filter(ScanRecord.id == c.scan_before_id).first()
                after_scan = session.query(ScanRecord).filter(ScanRecord.id == c.scan_after_id).first()
                
                before_id = before_scan.scan_id[:12] if before_scan else "?"
                after_id = after_scan.scan_id[:12] if after_scan else "?"
                
                # Calculate progress percentage
                if c.vulns_before > 0:
                    progress = ((c.vulns_before - c.vulns_after) / c.vulns_before) * 100
                    progress_str = f"{progress:+.1f}%" if progress != 0 else "0%"
                else:
                    progress_str = "N/A"
                
                fixed_color = 'green' if c.vulns_fixed > 0 else 'white'
                new_color = 'red' if c.vulns_new > 0 else 'white'
                
                click.echo(
                    f"  {c.compared_at.strftime('%Y-%m-%d %H:%M'):<20} "
                    f"{before_id} → {after_id:<15} "
                    f"{click.style(str(c.vulns_fixed), fg=fixed_color):<8} "
                    f"{click.style(str(c.vulns_new), fg=new_color):<8} "
                    f"{progress_str:<15}"
                )
            
            session.close()
            
        except Exception as e:
            click.echo(formatErrorMessage(f"Error: {str(e)}"))
        
        click.echo()
        return
    
    # Need both scan IDs for comparison
    if not scan_before or not scan_after:
        click.echo(formatErrorMessage("Both scan IDs required for comparison"))
        click.echo()
        click.echo("Usage: redshield compare <scan_before> <scan_after>")
        click.echo("       redshield compare --list")
        click.echo()
        return
    
    # Get both scans
    scan1, vulns1 = get_scan_with_vulns(scan_before)
    scan2, vulns2 = get_scan_with_vulns(scan_after)
    
    if not scan1:
        click.echo(formatErrorMessage(f"Scan not found: {scan_before}"))
        return
    
    if not scan2:
        click.echo(formatErrorMessage(f"Scan not found: {scan_after}"))
        return
    
    # Perform comparison
    result = compare_scans(vulns1, vulns2)
    
    # Display comparison header
    click.echo(formatInfoMessage("🔄 SCAN COMPARISON REPORT"))
    click.echo("=" * 80)
    
    # Scan details
    click.echo(f"\n  📌 BEFORE: {click.style(scan1.scan_id, fg='yellow')}")
    click.echo(f"     Target: {scan1.target}")
    click.echo(f"     Date:   {scan1.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    click.echo(f"     Vulns:  {result['vulns_before']}")
    
    click.echo(f"\n  📌 AFTER:  {click.style(scan2.scan_id, fg='cyan')}")
    click.echo(f"     Target: {scan2.target}")
    click.echo(f"     Date:   {scan2.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    click.echo(f"     Vulns:  {result['vulns_after']}")
    
    # Progress summary
    click.echo("\n" + "=" * 80)
    click.echo(formatInfoMessage("📊 PROGRESS SUMMARY"))
    click.echo("-" * 80)
    
    # Calculate improvement percentage
    if result['vulns_before'] > 0:
        improvement = ((result['vulns_before'] - result['vulns_after']) / result['vulns_before']) * 100
    else:
        improvement = 0
    
    # Progress bar
    bar_width = 40
    filled = int(bar_width * (improvement / 100)) if improvement > 0 else 0
    bar = "█" * filled + "░" * (bar_width - filled)
    
    if improvement > 0:
        click.echo(f"\n  Improvement: [{click.style(bar, fg='green')}] {improvement:.1f}%")
    elif improvement < 0:
        click.echo(f"\n  Regression:  [{click.style(bar, fg='red')}] {improvement:.1f}%")
    else:
        click.echo(f"\n  No Change:   [{bar}] 0%")
    
    click.echo(f"\n  ✅ Fixed:     {click.style(str(result['vulns_fixed']), fg='green', bold=True)} vulnerabilities")
    click.echo(f"  🆕 New:       {click.style(str(result['vulns_new']), fg='red' if result['vulns_new'] > 0 else 'white')} vulnerabilities")
    click.echo(f"  ⏳ Remaining: {click.style(str(result['vulns_unchanged']), fg='yellow' if result['vulns_unchanged'] > 0 else 'green')} vulnerabilities")
    
    # Severity breakdown of fixed
    if result['vulns_fixed'] > 0:
        click.echo("\n  Fixed by Severity:")
        if result['critical_fixed']:
            click.echo(f"    {formatSeverity('Critical')}: {result['critical_fixed']}")
        if result['high_fixed']:
            click.echo(f"    {formatSeverity('High')}: {result['high_fixed']}")
        if result['medium_fixed']:
            click.echo(f"    {formatSeverity('Medium')}: {result['medium_fixed']}")
        if result['low_fixed']:
            click.echo(f"    {formatSeverity('Low')}: {result['low_fixed']}")
    
    # List fixed vulnerabilities
    if result['fixed_vulns']:
        click.echo("\n" + "-" * 80)
        click.echo(formatSuccessMessage("✅ FIXED VULNERABILITIES"))
        click.echo("-" * 80)
        for i, v in enumerate(result['fixed_vulns'], 1):
            click.echo(f"  {i}. [{formatSeverity(v.severity)}] {v.vuln_type}")
            if v.service:
                click.echo(f"     Service: {v.service} | Port: {v.port}")
            if v.vulnerable_parameter:
                click.echo(f"     Parameter: {v.vulnerable_parameter}")
    
    # List new vulnerabilities
    if result['new_vulns']:
        click.echo("\n" + "-" * 80)
        click.echo(formatErrorMessage("🆕 NEW VULNERABILITIES (Need Attention)"))
        click.echo("-" * 80)
        for i, v in enumerate(result['new_vulns'], 1):
            click.echo(f"  {i}. [{formatSeverity(v.severity)}] {v.vuln_type}")
            if v.service:
                click.echo(f"     Service: {v.service} | Port: {v.port}")
    
    # List unchanged vulnerabilities
    if result['unchanged_vulns']:
        click.echo("\n" + "-" * 80)
        click.echo(formatWarningMessage("⏳ STILL OPEN (Unchanged)"))
        click.echo("-" * 80)
        for i, v in enumerate(result['unchanged_vulns'], 1):
            click.echo(f"  {i}. [{formatSeverity(v.severity)}] {v.vuln_type}")
            if v.service:
                click.echo(f"     Service: {v.service} | Port: {v.port}")
    
    # Save comparison to database
    save_comparison(scan1, scan2, result)
    
    # Export to JSON if requested
    if export:
        export_data = {
            'comparison_date': datetime.utcnow().isoformat(),
            'scan_before': {
                'scan_id': scan1.scan_id,
                'target': scan1.target,
                'date': scan1.started_at.isoformat(),
                'total_vulns': result['vulns_before']
            },
            'scan_after': {
                'scan_id': scan2.scan_id,
                'target': scan2.target,
                'date': scan2.started_at.isoformat(),
                'total_vulns': result['vulns_after']
            },
            'summary': {
                'fixed': result['vulns_fixed'],
                'new': result['vulns_new'],
                'unchanged': result['vulns_unchanged'],
                'improvement_percentage': improvement
            },
            'fixed_vulns': [{'type': v.vuln_type, 'severity': v.severity, 'port': v.port} for v in result['fixed_vulns']],
            'new_vulns': [{'type': v.vuln_type, 'severity': v.severity, 'port': v.port} for v in result['new_vulns']],
            'unchanged_vulns': [{'type': v.vuln_type, 'severity': v.severity, 'port': v.port} for v in result['unchanged_vulns']]
        }
        
        with open(export, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        click.echo(f"\n  📁 Comparison exported to: {export}")
    
    click.echo("\n" + "=" * 80)
    click.echo()

"""
RedShield Report Command

This command generates professional security reports from scan results.

HOW IT WORKS:
1. Loads scan data from the database
2. Formats data into a report template
3. Generates output in requested format (HTML, PDF, JSON)
4. Saves report to the reports directory

USAGE:
    redshield report scan-20251210-ABC --format pdf
    redshield report scan-20251210-ABC --format html -o my_report.html
"""

import click
import json
import os
from datetime import datetime
from cli.utils.formatters import (
    formatSuccessMessage, 
    formatErrorMessage,
    formatInfoMessage,
    formatWarningMessage
)


def get_scan_data(scan_id):
    """Get complete scan data from database."""
    try:
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord, RemediationRecord
        
        session = get_session()
        scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        
        if not scan:
            session.close()
            return None
        
        vulns = session.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.scan_id == scan.id
        ).all()
        
        # Get remediation info for each vuln
        vuln_data = []
        for v in vulns:
            remediation = session.query(RemediationRecord).filter(
                RemediationRecord.vulnerability_id == v.id
            ).first()
            
            vuln_data.append({
                'type': v.vuln_type,
                'service': v.service,
                'port': v.port,
                'severity': v.severity,
                'status': v.status.value,
                'description': v.description or '',
                'cve_id': v.cve_id,
                'owasp_category': v.owasp_category,
                'mitre_id': v.mitre_id,
                'discovered_at': v.discovered_at.isoformat() if v.discovered_at else None,
                'fixed_at': v.fixed_at.isoformat() if v.fixed_at else None,
                'remediation': {
                    'playbook': remediation.playbook_name if remediation else None,
                    'status': remediation.status if remediation else None,
                    'applied_at': remediation.applied_at.isoformat() if remediation and remediation.applied_at else None
                } if remediation else None
            })
        
        session.close()
        
        return {
            'scan_id': scan.scan_id,
            'target': scan.target,
            'scan_type': scan.scan_type,
            'port_range': scan.port_range,
            'status': scan.status.value,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'vulnerabilities': vuln_data,
            'summary': {
                'total': len(vuln_data),
                'critical': sum(1 for v in vuln_data if v['severity'].upper() == 'CRITICAL'),
                'high': sum(1 for v in vuln_data if v['severity'].upper() == 'HIGH'),
                'medium': sum(1 for v in vuln_data if v['severity'].upper() == 'MEDIUM'),
                'low': sum(1 for v in vuln_data if v['severity'].upper() == 'LOW'),
                'fixed': sum(1 for v in vuln_data if v['status'] == 'fixed'),
                'unfixed': sum(1 for v in vuln_data if v['status'] != 'fixed'),
            }
        }
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Database error: {str(e)}"))
        return None


def generate_html_report(data):
    """Generate an HTML report from scan data."""
    
    # Severity colors
    severity_colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14', 
        'MEDIUM': '#ffc107',
        'LOW': '#28a745'
    }
    
    # Generate vulnerability rows
    vuln_rows = ""
    for i, v in enumerate(data['vulnerabilities'], 1):
        status_badge = '<span style="color: green;">✓ Fixed</span>' if v['status'] == 'fixed' else '<span style="color: red;">○ Open</span>'
        severity_color = severity_colors.get(v['severity'].upper(), '#6c757d')
        
        vuln_rows += f"""
        <tr>
            <td>{i}</td>
            <td><span style="background-color: {severity_color}; color: white; padding: 2px 8px; border-radius: 4px;">{v['severity']}</span></td>
            <td>{v['type']}</td>
            <td>{v['service']}</td>
            <td>{v['port']}</td>
            <td>{status_badge}</td>
        </tr>
        """
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedShield Security Report - {data['scan_id']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ font-size: 28px; margin-bottom: 5px; }}
        .header p {{ opacity: 0.9; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-bottom: 20px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }}
        .info-item {{ background: #f8f9fa; padding: 15px; border-radius: 6px; }}
        .info-item label {{ color: #666; font-size: 12px; text-transform: uppercase; }}
        .info-item value {{ color: #333; font-size: 16px; font-weight: 600; display: block; margin-top: 5px; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }}
        .card {{ padding: 20px; border-radius: 8px; text-align: center; color: white; }}
        .card.critical {{ background: #dc3545; }}
        .card.high {{ background: #fd7e14; }}
        .card.medium {{ background: #ffc107; color: #333; }}
        .card.low {{ background: #28a745; }}
        .card .number {{ font-size: 36px; font-weight: bold; }}
        .card .label {{ font-size: 12px; text-transform: uppercase; opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #333; }}
        tr:hover {{ background: #f8f9fa; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; border-top: 1px solid #dee2e6; }}
        .status-fixed {{ color: #28a745; }}
        .status-open {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ RedShield Security Report</h1>
            <p>Vulnerability Assessment Report</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>Scan Information</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <label>Scan ID</label>
                        <value>{data['scan_id']}</value>
                    </div>
                    <div class="info-item">
                        <label>Target</label>
                        <value>{data['target']}</value>
                    </div>
                    <div class="info-item">
                        <label>Scan Type</label>
                        <value>{data['scan_type'].upper()}</value>
                    </div>
                    <div class="info-item">
                        <label>Port Range</label>
                        <value>{data['port_range']}</value>
                    </div>
                    <div class="info-item">
                        <label>Started</label>
                        <value>{data['started_at']}</value>
                    </div>
                    <div class="info-item">
                        <label>Completed</label>
                        <value>{data['completed_at']}</value>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="summary-cards">
                    <div class="card critical">
                        <div class="number">{data['summary']['critical']}</div>
                        <div class="label">Critical</div>
                    </div>
                    <div class="card high">
                        <div class="number">{data['summary']['high']}</div>
                        <div class="label">High</div>
                    </div>
                    <div class="card medium">
                        <div class="number">{data['summary']['medium']}</div>
                        <div class="label">Medium</div>
                    </div>
                    <div class="card low">
                        <div class="number">{data['summary']['low']}</div>
                        <div class="label">Low</div>
                    </div>
                </div>
                <p><strong>Total Vulnerabilities:</strong> {data['summary']['total']} | 
                   <strong class="status-fixed">Fixed:</strong> {data['summary']['fixed']} | 
                   <strong class="status-open">Open:</strong> {data['summary']['unfixed']}</p>
            </div>
            
            <div class="section">
                <h2>Vulnerability Details</h2>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Service</th>
                            <th>Port</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {vuln_rows}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by RedShield - Red Team Remediation Toolkit</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
    """
    return html


def generate_json_report(data):
    """Generate a JSON report from scan data."""
    data['generated_at'] = datetime.now().isoformat()
    data['generator'] = 'RedShield v1.0.0'
    return json.dumps(data, indent=2)


@click.command()
@click.argument('scan_id')
@click.option('--format', '-f', 'report_format', type=click.Choice(['pdf', 'html', 'json']), default='html', help='Report format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--open', 'open_report', is_flag=True, help='Open report after generation')
def report(scan_id, report_format, output, open_report):
    """
    Generate a security report from scan results.
    
    Creates professional reports in HTML, PDF, or JSON format.
    
    \b
    Examples:
        redshield report scan-20251210-ABC --format html
        redshield report scan-20251210-ABC --format pdf -o report.pdf
        redshield report scan-20251210-ABC --format json --open
    """
    try:
        click.echo()
        click.echo(formatInfoMessage(f"Generating {report_format.upper()} report for: {click.style(scan_id, fg='yellow')}"))
        
        # Get scan data
        data = get_scan_data(scan_id)
        
        if not data:
            click.echo(formatErrorMessage(f"Scan not found: {scan_id}"))
            click.echo()
            click.echo(formatInfoMessage("Use 'redshield status' to see available scans"))
            click.echo()
            return
        
        click.echo(formatInfoMessage(f"Target: {data['target']}"))
        click.echo(formatInfoMessage(f"Vulnerabilities: {data['summary']['total']}"))
        click.echo()
        
        # Generate report
        with click.progressbar(length=100, label='Generating') as bar:
            bar.update(30)
            
            if report_format == 'html':
                content = generate_html_report(data)
                extension = 'html'
            elif report_format == 'json':
                content = generate_json_report(data)
                extension = 'json'
            elif report_format == 'pdf':
                # For PDF, we generate HTML first, then note that PDF requires weasyprint
                content = generate_html_report(data)
                extension = 'html'
                click.echo()
                click.echo(formatWarningMessage("PDF generation requires weasyprint library"))
                click.echo(formatInfoMessage("Generating HTML report instead (can be printed to PDF)"))
            
            bar.update(70)
        
        # Determine output path
        if output:
            output_file = output
        else:
            from config.settings import settings
            os.makedirs(settings.report_output_path, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(
                settings.report_output_path, 
                f"report_{scan_id}_{timestamp}.{extension}"
            )
        
        # Write report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        click.echo()
        click.echo(formatSuccessMessage(f"Report saved: {output_file}"))
        
        # Report summary
        click.echo()
        click.echo(formatInfoMessage("Report Summary:"))
        click.echo(f"  • Target: {data['target']}")
        click.echo(f"  • Total Issues: {data['summary']['total']}")
        click.echo(f"  • Critical: {data['summary']['critical']}")
        click.echo(f"  • High: {data['summary']['high']}")
        click.echo(f"  • Fixed: {data['summary']['fixed']}/{data['summary']['total']}")
        
        # Open report if requested
        if open_report:
            try:
                import webbrowser
                webbrowser.open(f'file://{os.path.abspath(output_file)}')
                click.echo()
                click.echo(formatInfoMessage("Opening report in browser..."))
            except Exception:
                click.echo(formatWarningMessage("Could not open report automatically"))
        
        click.echo()
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Report generation failed: {str(e)}"), err=True)
        raise click.Abort()

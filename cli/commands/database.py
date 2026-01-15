"""
RedShield Database CLI Command

Manage the SQLite/PostgreSQL database using SQLAlchemy.

USAGE:
    redshield db init          # Initialize database tables
    redshield db status        # Show database status
    redshield db migrate       # Run pending migrations
    redshield db backup        # Create database backup
    redshield db clear         # Clear all data (careful!)
"""

import click
import os
from datetime import datetime
from cli.utils.formatters import (
    formatSuccessMessage, 
    formatErrorMessage, 
    formatInfoMessage,
    formatWarningMessage
)


@click.group()
def db():
    """
    Database management commands.
    
    RedShield uses SQLAlchemy ORM with SQLite (default) or PostgreSQL.
    All scan results, vulnerabilities, and remediation records are stored
    in the database for persistence and reporting.
    """
    pass


@db.command('init')
@click.option('--force', is_flag=True, help='Drop existing tables and recreate')
def init_database(force):
    """Initialize database tables."""
    try:
        from database.connection import engine, Base
        from database import models  # Import to register all models
        
        click.echo(formatInfoMessage("Initializing database..."))
        
        if force:
            click.echo(formatWarningMessage("Dropping existing tables..."))
            Base.metadata.drop_all(engine)
        
        # Create all tables
        Base.metadata.create_all(engine)
        
        click.echo(formatSuccessMessage("Database initialized successfully!"))
        click.echo()
        
        # Show created tables
        click.echo(formatInfoMessage("Created tables:"))
        for table in Base.metadata.sorted_tables:
            click.echo(f"  • {table.name}")
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Database initialization failed: {str(e)}"))
        raise click.Abort()


@db.command('status')
def database_status():
    """Show database connection status and statistics."""
    try:
        from database.connection import get_session, engine
        from database.models import User, ScanRecord, VulnerabilityRecord, RemediationRecord
        from sqlalchemy import inspect
        
        click.echo()
        click.echo(formatInfoMessage("Database Status"))
        click.echo("=" * 50)
        click.echo()
        
        # Connection info
        click.echo(f"  {click.style('Connection:', bold=True)}")
        click.echo(f"    Engine: {engine.name}")
        click.echo(f"    URL: {str(engine.url).replace(str(engine.url.password or ''), '***') if engine.url.password else str(engine.url)}")
        
        # Check connection
        session = get_session()
        try:
            session.execute("SELECT 1")
            click.echo(f"    Status: {click.style('Connected', fg='green')}")
        except:
            click.echo(f"    Status: {click.style('Disconnected', fg='red')}")
            return
        
        click.echo()
        
        # Table statistics
        click.echo(f"  {click.style('Statistics:', bold=True)}")
        
        try:
            users = session.query(User).count()
            click.echo(f"    Users: {users}")
        except:
            click.echo(f"    Users: (table not found)")
        
        try:
            scans = session.query(ScanRecord).count()
            click.echo(f"    Scans: {scans}")
        except:
            click.echo(f"    Scans: (table not found)")
        
        try:
            vulns = session.query(VulnerabilityRecord).count()
            click.echo(f"    Vulnerabilities: {vulns}")
            
            # Status breakdown
            from database.models import VulnStatus
            discovered = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.status == VulnStatus.DISCOVERED
            ).count()
            fixed = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.status == VulnStatus.FIXED
            ).count()
            click.echo(f"      - Discovered: {discovered}")
            click.echo(f"      - Fixed: {fixed}")
        except:
            click.echo(f"    Vulnerabilities: (table not found)")
        
        try:
            remediations = session.query(RemediationRecord).count()
            click.echo(f"    Remediations: {remediations}")
        except:
            click.echo(f"    Remediations: (table not found)")
        
        click.echo()
        
        # Check tables exist
        click.echo(f"  {click.style('Tables:', bold=True)}")
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        for table in tables:
            columns = len(inspector.get_columns(table))
            click.echo(f"    • {table} ({columns} columns)")
        
        session.close()
        click.echo()
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Error: {str(e)}"))


@db.command('backup')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def backup_database(output):
    """Create a database backup."""
    try:
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord, User
        import json
        
        session = get_session()
        
        # Determine output path
        if not output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = f"redshield_backup_{timestamp}.json"
        
        click.echo(formatInfoMessage(f"Creating backup: {output}"))
        
        # Export all data
        data = {
            'backup_date': datetime.now().isoformat(),
            'version': '1.0.0',
            'users': [],
            'scans': [],
            'vulnerabilities': []
        }
        
        # Export users (excluding passwords)
        for user in session.query(User).all():
            data['users'].append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role.value,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if user.created_at else None
            })
        
        # Export scans
        for scan in session.query(ScanRecord).all():
            data['scans'].append({
                'id': scan.id,
                'scan_id': scan.scan_id,
                'target': scan.target,
                'port_range': scan.port_range,
                'scan_type': scan.scan_type,
                'status': scan.status.value,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
            })
        
        # Export vulnerabilities
        for vuln in session.query(VulnerabilityRecord).all():
            data['vulnerabilities'].append({
                'id': vuln.id,
                'scan_id': vuln.scan_id,
                'vuln_type': vuln.vuln_type,
                'service': vuln.service,
                'port': vuln.port,
                'severity': vuln.severity,
                'status': vuln.status.value,
                'description': vuln.description,
                'cve_id': vuln.cve_id,
                'owasp_category': vuln.owasp_category,
                'mitre_id': vuln.mitre_id,
                'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
                'fixed_at': vuln.fixed_at.isoformat() if vuln.fixed_at else None
            })
        
        session.close()
        
        # Write to file
        with open(output, 'w') as f:
            json.dump(data, f, indent=2)
        
        click.echo(formatSuccessMessage(f"Backup created: {output}"))
        click.echo(formatInfoMessage(f"  Users: {len(data['users'])}"))
        click.echo(formatInfoMessage(f"  Scans: {len(data['scans'])}"))
        click.echo(formatInfoMessage(f"  Vulnerabilities: {len(data['vulnerabilities'])}"))
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Backup failed: {str(e)}"))


@db.command('restore')
@click.argument('backup_file', type=click.Path(exists=True))
@click.option('--force', is_flag=True, help='Overwrite existing data')
def restore_database(backup_file, force):
    """Restore database from a backup file."""
    try:
        import json
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord, User, ScanStatus, VulnStatus, UserRole
        from datetime import datetime
        
        click.echo(formatInfoMessage(f"Restoring from: {backup_file}"))
        
        with open(backup_file, 'r') as f:
            data = json.load(f)
        
        click.echo(formatInfoMessage(f"  Backup date: {data.get('backup_date', 'Unknown')}"))
        click.echo(formatInfoMessage(f"  Users: {len(data.get('users', []))}"))
        click.echo(formatInfoMessage(f"  Scans: {len(data.get('scans', []))}"))
        click.echo(formatInfoMessage(f"  Vulnerabilities: {len(data.get('vulnerabilities', []))}"))
        
        if not force:
            if not click.confirm("Proceed with restore?"):
                click.echo("Aborted.")
                return
        
        session = get_session()
        
        # Restore scans
        for scan_data in data.get('scans', []):
            existing = session.query(ScanRecord).filter(
                ScanRecord.scan_id == scan_data['scan_id']
            ).first()
            
            if not existing:
                scan = ScanRecord(
                    scan_id=scan_data['scan_id'],
                    target=scan_data['target'],
                    port_range=scan_data.get('port_range', '1-1000'),
                    scan_type=scan_data.get('scan_type', 'quick'),
                    status=ScanStatus(scan_data.get('status', 'completed')),
                    started_at=datetime.fromisoformat(scan_data['started_at']) if scan_data.get('started_at') else None,
                    completed_at=datetime.fromisoformat(scan_data['completed_at']) if scan_data.get('completed_at') else None
                )
                session.add(scan)
        
        session.commit()
        click.echo(formatSuccessMessage("Restore completed!"))
        session.close()
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Restore failed: {str(e)}"))


@db.command('clear')
@click.option('--confirm', is_flag=True, help='Confirm data deletion')
def clear_database(confirm):
    """Clear all data from the database (dangerous!)."""
    if not confirm:
        click.echo(formatWarningMessage("This will delete ALL data from the database!"))
        click.echo()
        click.echo("Use --confirm flag to proceed:")
        click.echo("  redshield db clear --confirm")
        return
    
    try:
        from database.connection import get_session
        from database.models import VulnerabilityRecord, RemediationRecord, ScanRecord
        
        session = get_session()
        
        # Delete in order (foreign key constraints)
        remediations = session.query(RemediationRecord).delete()
        vulnerabilities = session.query(VulnerabilityRecord).delete()
        scans = session.query(ScanRecord).delete()
        
        session.commit()
        session.close()
        
        click.echo(formatSuccessMessage("Database cleared!"))
        click.echo(formatInfoMessage(f"  Deleted {scans} scans"))
        click.echo(formatInfoMessage(f"  Deleted {vulnerabilities} vulnerabilities"))
        click.echo(formatInfoMessage(f"  Deleted {remediations} remediations"))
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Clear failed: {str(e)}"))


@db.command('export')
@click.option('--format', '-f', type=click.Choice(['json', 'csv']), default='json', help='Export format')
@click.option('--output', '-o', type=click.Path(), help='Output file')
def export_data(format, output):
    """Export database to JSON or CSV."""
    try:
        from database.connection import get_session
        from database.models import ScanRecord, VulnerabilityRecord
        
        session = get_session()
        
        if not output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = f"redshield_export_{timestamp}.{format}"
        
        if format == 'json':
            import json
            data = {
                'export_date': datetime.now().isoformat(),
                'scans': [],
                'vulnerabilities': []
            }
            
            for scan in session.query(ScanRecord).all():
                data['scans'].append({
                    'scan_id': scan.scan_id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'status': scan.status.value
                })
            
            for vuln in session.query(VulnerabilityRecord).all():
                data['vulnerabilities'].append({
                    'vuln_type': vuln.vuln_type,
                    'service': vuln.service,
                    'port': vuln.port,
                    'severity': vuln.severity,
                    'status': vuln.status.value
                })
            
            with open(output, 'w') as f:
                json.dump(data, f, indent=2)
                
        elif format == 'csv':
            import csv
            
            with open(output, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'Target', 'Port', 'Service', 'Severity', 'Status'])
                
                for vuln in session.query(VulnerabilityRecord).all():
                    scan = session.query(ScanRecord).filter(ScanRecord.id == vuln.scan_id).first()
                    writer.writerow([
                        vuln.vuln_type,
                        scan.target if scan else 'Unknown',
                        vuln.port,
                        vuln.service,
                        vuln.severity,
                        vuln.status.value
                    ])
        
        session.close()
        click.echo(formatSuccessMessage(f"Exported to: {output}"))
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Export failed: {str(e)}"))

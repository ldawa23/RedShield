"""
RedShield - DVWA Fix Command

Dedicated command for fixing DVWA vulnerabilities with real code changes.
This is the command you use to demonstrate actual fixes to professionals.
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
from cli.utils.auth import require_admin


@click.command('dvwa-fix')
@click.option('--path', '-p', type=str, help='Path to DVWA installation')
@click.option('--vuln', '-v', type=click.Choice([
    'all', 'sqli', 'xss-reflected', 'xss-stored', 
    'command-injection', 'file-inclusion', 'csrf'
]), default='all', help='Specific vulnerability to fix')
@click.option('--verify', is_flag=True, help='Verify fixes after applying')
@click.option('--restore', is_flag=True, help='Restore original vulnerable files from backup')
@click.option('--list-backups', is_flag=True, help='List available backups')
@require_admin
def dvwa_fix(path, vuln, verify, restore, list_backups):
    """
    Fix DVWA vulnerabilities with REAL code changes.
    
    This command modifies actual PHP files in your DVWA installation
    to demonstrate proper vulnerability remediation.
    
    \b
    USAGE:
        redshield dvwa-fix                     # Fix all vulnerabilities
        redshield dvwa-fix --vuln sqli         # Fix only SQL Injection
        redshield dvwa-fix --verify            # Fix and verify
        redshield dvwa-fix --restore           # Undo fixes (restore original)
    
    \b
    COMMON DVWA PATHS:
        Windows XAMPP:  C:/xampp/htdocs/DVWA
        Linux:          /var/www/html/DVWA
        Docker:         /var/www/html
    
    \b
    VULNERABILITIES FIXED:
        • SQL Injection - Uses prepared statements
        • XSS (Reflected) - Adds htmlspecialchars() encoding  
        • XSS (Stored) - Sanitizes stored input
        • Command Injection - Validates IP + escapeshellarg()
        • File Inclusion - Whitelist allowed files
        • CSRF - Adds token validation
    """
    from core.actual_remediation import DVWARemediator, verify_fix
    
    click.echo()
    click.echo(click.style("╔══════════════════════════════════════════════════════════╗", fg='cyan', bold=True))
    click.echo(click.style("║             🛡️  REDSHIELD DVWA REMEDIATOR 🛡️              ║", fg='cyan', bold=True))
    click.echo(click.style("╚══════════════════════════════════════════════════════════╝", fg='cyan', bold=True))
    click.echo()
    
    # Initialize remediator
    remediator = DVWARemediator(dvwa_path=path)
    
    if not remediator.dvwa_path:
        click.echo(formatErrorMessage("DVWA installation not found!"))
        click.echo()
        click.echo(formatInfoMessage("Please specify the path with --path option:"))
        click.echo()
        click.echo("  Common locations:")
        click.echo(click.style("    • Windows XAMPP: ", fg='white') + click.style("C:/xampp/htdocs/DVWA", fg='yellow'))
        click.echo(click.style("    • Linux Apache:  ", fg='white') + click.style("/var/www/html/DVWA", fg='yellow'))
        click.echo(click.style("    • Docker:        ", fg='white') + click.style("/var/www/html", fg='yellow'))
        click.echo()
        click.echo(formatInfoMessage("Example: redshield dvwa-fix --path C:/xampp/htdocs/DVWA"))
        click.echo()
        return
    
    click.echo(formatSuccessMessage(f"Found DVWA at: {remediator.dvwa_path}"))
    click.echo()
    
    # List backups mode
    if list_backups:
        click.echo(formatInfoMessage("Looking for backups..."))
        backup_dirs = []
        for item in os.listdir(remediator.dvwa_path):
            if item.startswith(".redshield_backup_"):
                backup_dirs.append(item)
        
        if backup_dirs:
            click.echo(f"\nFound {len(backup_dirs)} backup(s):")
            for bd in sorted(backup_dirs):
                full_path = os.path.join(remediator.dvwa_path, bd)
                files = os.listdir(full_path)
                click.echo(f"  • {bd} ({len(files)} files)")
        else:
            click.echo(formatWarningMessage("No backups found"))
        return
    
    # Restore mode
    if restore:
        click.echo(formatWarningMessage("Restore mode - will undo fixes"))
        click.echo()
        
        # Find most recent backup
        backup_dirs = []
        for item in os.listdir(remediator.dvwa_path):
            if item.startswith(".redshield_backup_"):
                backup_dirs.append(item)
        
        if not backup_dirs:
            click.echo(formatErrorMessage("No backups found to restore"))
            return
        
        latest_backup = sorted(backup_dirs)[-1]
        backup_path = os.path.join(remediator.dvwa_path, latest_backup)
        
        click.echo(formatInfoMessage(f"Restoring from: {latest_backup}"))
        
        if not click.confirm("Restore vulnerable files?"):
            click.echo("Cancelled.")
            return
        
        # Restore files
        restored = 0
        for backup_file in os.listdir(backup_path):
            src = os.path.join(backup_path, backup_file)
            
            # Find where this file belongs
            for root, dirs, files in os.walk(remediator.dvwa_path):
                if backup_file in files and ".redshield_backup" not in root:
                    dst = os.path.join(root, backup_file)
                    import shutil
                    shutil.copy2(src, dst)
                    restored += 1
                    click.echo(f"  Restored: {backup_file}")
                    break
        
        click.echo()
        click.echo(formatSuccessMessage(f"Restored {restored} files"))
        click.echo(formatWarningMessage("DVWA is now VULNERABLE again (for testing)"))
        return
    
    # Normal fix mode
    click.echo(click.style("⚠️  WARNING: This will modify PHP files!", fg='yellow', bold=True))
    click.echo(formatInfoMessage("Backups will be created before any changes."))
    click.echo()
    
    if not click.confirm("Proceed with fixing DVWA?"):
        click.echo("Cancelled.")
        return
    
    click.echo()
    click.echo(click.style("═══ APPLYING FIXES ═══", fg='green', bold=True))
    click.echo()
    
    results = []
    
    # Map of vuln option to fix method
    fixes = {
        'sqli': ('SQL Injection', remediator.fix_sql_injection),
        'xss-reflected': ('XSS (Reflected)', lambda v=False: remediator.fix_xss('reflected', v)),
        'xss-stored': ('XSS (Stored)', lambda v=False: remediator.fix_xss('stored', v)),
        'command-injection': ('Command Injection', remediator.fix_command_injection),
        'file-inclusion': ('File Inclusion', remediator.fix_file_inclusion),
        'csrf': ('CSRF', remediator.fix_csrf),
    }
    
    if vuln == 'all':
        vulns_to_fix = fixes.keys()
    else:
        vulns_to_fix = [vuln]
    
    fixed_count = 0
    failed_count = 0
    
    for v in vulns_to_fix:
        name, fix_func = fixes[v]
        click.echo(f"[*] Fixing {name}...")
        
        result = fix_func(verbose=True)
        results.append(result)
        
        if result.success:
            fixed_count += 1
            click.echo(click.style(f"    ✓ {name} FIXED", fg='green'))
            click.echo(f"      Before: {result.before_state[:60]}...")
            click.echo(f"      After:  {result.after_state[:60]}...")
        else:
            failed_count += 1
            click.echo(click.style(f"    ✗ {name} FAILED", fg='red'))
            if result.error_message:
                click.echo(f"      Error: {result.error_message}")
        click.echo()
    
    # Verification
    if verify and fixed_count > 0:
        click.echo()
        click.echo(click.style("═══ VERIFICATION ═══", fg='magenta', bold=True))
        click.echo(formatInfoMessage("Testing if vulnerabilities are actually fixed..."))
        click.echo()
        click.echo(formatWarningMessage("Note: DVWA must be running for verification"))
        click.echo()
        
        for result in results:
            if result.success:
                click.echo(f"  Testing {result.vulnerability_type}...")
                is_fixed, evidence = verify_fix('localhost', 80, result.vulnerability_type)
                
                if is_fixed:
                    click.echo(click.style(f"    ✓ VERIFIED FIXED", fg='green'))
                elif is_fixed is False:
                    click.echo(click.style(f"    ✗ STILL VULNERABLE", fg='red'))
                else:
                    click.echo(click.style(f"    ? Could not verify", fg='yellow'))
                click.echo(f"      {evidence}")
    
    # Summary
    click.echo()
    click.echo("═" * 60)
    click.echo(click.style("REMEDIATION COMPLETE", fg='cyan', bold=True))
    click.echo("═" * 60)
    click.echo()
    
    if fixed_count > 0:
        click.echo(formatSuccessMessage(f"Fixed {fixed_count} vulnerabilities"))
    if failed_count > 0:
        click.echo(formatWarningMessage(f"Failed {failed_count} vulnerabilities"))
    
    if remediator.backup_dir:
        click.echo()
        click.echo(formatInfoMessage(f"Backup location: {remediator.backup_dir}"))
        click.echo(formatInfoMessage("To restore: redshield dvwa-fix --restore"))
    
    click.echo()
    click.echo(click.style("WHAT WAS CHANGED:", fg='cyan'))
    click.echo("""
    SQL Injection:     Replaced string concatenation with prepared statements
    XSS (Reflected):   Added htmlspecialchars() output encoding
    XSS (Stored):      Added input sanitization with htmlspecialchars()
    Command Injection: Added IP validation + escapeshellarg()
    File Inclusion:    Added whitelist for allowed include files
    CSRF:              Added session token validation
    """)
    
    click.echo(click.style("HOW TO DEMONSTRATE TO PROFESSIONALS:", fg='yellow'))
    click.echo("""
    1. BEFORE: Show DVWA vulnerability working (e.g., SQL injection ' OR '1'='1)
    2. RUN:    redshield dvwa-fix --vuln sqli
    3. AFTER:  Show same attack now fails
    4. SHOW:   The actual code changes (backup vs new file)
    5. EXPLAIN: Why prepared statements prevent injection
    """)

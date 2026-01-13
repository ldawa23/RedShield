"""
RedShield - Verify Command

Verify vulnerabilities using Metasploit exploit modules.
This confirms that discovered vulnerabilities are actually exploitable.
"""

import click
from cli.utils.formatters import (
    formatSuccessMessage,
    formatErrorMessage,
    formatInfoMessage,
    formatWarningMessage,
    formatSeverity
)


@click.command()
@click.argument('scan_id')
@click.option('--vuln-id', '-v', type=int, default=None, help='Specific vulnerability ID to verify')
@click.option('--demo', is_flag=True, help='Use demo mode (no actual exploitation)')
@click.option('--all', 'verify_all', is_flag=True, help='Verify all vulnerabilities in scan')
def verify(scan_id, vuln_id, demo, verify_all):
    """
    Verify vulnerabilities are exploitable using Metasploit.
    
    This command attempts to exploit discovered vulnerabilities
    to confirm they are real security issues, not false positives.
    
    WARNING: Only run against systems you own or have permission to test!
    
    \b
    Examples:
        redshield verify scan-20251211-ABC123 --demo
        redshield verify scan-20251211-ABC123 -v 1
        redshield verify scan-20251211-ABC123 --all
    """
    from integrations.metasploit import (
        check_metasploit_installed,
        check_msf_rpc_running,
        get_exploit_for_vuln,
        generate_demo_msf_verification,
        list_available_exploits
    )
    from database.connection import get_session
    from database.models import ScanRecord, VulnerabilityRecord, VulnStatus
    
    click.echo()
    click.echo(formatInfoMessage(f"Verifying vulnerabilities for: {scan_id}"))
    click.echo()
    
    # Check Metasploit availability
    msf_installed = check_metasploit_installed()
    msf_running = check_msf_rpc_running()
    
    use_demo = demo or not msf_installed or not msf_running
    
    if use_demo and not demo:
        if not msf_installed:
            click.echo(formatWarningMessage("Metasploit not installed - using demo mode"))
            click.echo(formatInfoMessage("Install from: https://www.metasploit.com/download"))
        elif not msf_running:
            click.echo(formatWarningMessage("Metasploit RPC not running - using demo mode"))
            click.echo(formatInfoMessage("Start with: msfrpcd -P password -S"))
        click.echo()
    
    # Get scan from database
    try:
        session = get_session()
        scan = session.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
        
        if not scan:
            click.echo(formatErrorMessage(f"Scan not found: {scan_id}"))
            click.echo(formatInfoMessage("Run 'redshield status' to see available scans"))
            session.close()
            return
        
        # Get vulnerabilities
        if vuln_id:
            vulns = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.scan_id == scan.id,
                VulnerabilityRecord.id == vuln_id
            ).all()
        else:
            vulns = session.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.scan_id == scan.id
            ).all()
        
        if not vulns:
            click.echo(formatWarningMessage("No vulnerabilities found to verify"))
            session.close()
            return
        
        click.echo(f"Found {len(vulns)} vulnerability(ies) to verify")
        click.echo("-" * 50)
        click.echo()
        
        verified_count = 0
        no_module_count = 0
        
        for v in vulns:
            click.echo(f"[*] Checking: {v.vuln_type} on port {v.port}")
            
            # Check if we have an exploit module for this vuln
            exploit_info = get_exploit_for_vuln(v.vuln_type)
            
            if not exploit_info:
                click.echo(f"    {click.style('⊘', fg='yellow')} No Metasploit module available")
                no_module_count += 1
                continue
            
            click.echo(f"    Module: {exploit_info['module']}")
            
            if use_demo:
                # Demo verification
                result = generate_demo_msf_verification(v.vuln_type, scan.target, v.port)
            else:
                # Real Metasploit verification would go here
                from integrations.metasploit import run_msf_verify
                result = run_msf_verify(scan.target, v.vuln_type, v.port)
            
            if result['verified']:
                click.echo(f"    {click.style('✓ EXPLOITABLE', fg='red', bold=True)} - Confirmed vulnerable!")
                v.status = VulnStatus.VERIFIED
                verified_count += 1
            else:
                click.echo(f"    {click.style('○', fg='green')} Not exploitable or protected")
            
            click.echo()
        
        session.commit()
        session.close()
        
        # Summary
        click.echo("-" * 50)
        click.echo()
        click.echo("Verification Summary:")
        click.echo(f"  {click.style('Verified Exploitable:', fg='red')} {verified_count}")
        click.echo(f"  {click.style('No Module Available:', fg='yellow')} {no_module_count}")
        click.echo(f"  Total Checked: {len(vulns)}")
        click.echo()
        
        if verified_count > 0:
            click.echo(formatWarningMessage(f"{verified_count} vulnerabilities confirmed exploitable!"))
            click.echo(formatInfoMessage("Run 'redshield fix' to apply remediations"))
        else:
            click.echo(formatSuccessMessage("No vulnerabilities were confirmed exploitable"))
        
        click.echo()
        
    except Exception as e:
        click.echo(formatErrorMessage(f"Verification failed: {str(e)}"))
        raise click.Abort()


@click.command('exploits')
def list_exploits():
    """
    List available Metasploit exploit modules.
    
    Shows which vulnerability types can be verified with Metasploit.
    """
    from integrations.metasploit import list_available_exploits
    
    click.echo()
    click.echo(formatInfoMessage("Available Metasploit Modules for Verification"))
    click.echo("-" * 60)
    click.echo()
    
    exploits = list_available_exploits()
    
    for exp in exploits:
        click.echo(f"  {click.style(exp['vuln_type'], fg='cyan')}")
        click.echo(f"    Module: {exp['module']}")
        click.echo(f"    {exp['description']}")
        click.echo()
    
    click.echo(f"Total: {len(exploits)} exploit modules available")
    click.echo()

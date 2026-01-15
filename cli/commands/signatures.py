"""
RedShield Signatures CLI Command

Manage vulnerability signatures - list, search, enable/disable, and import custom signatures.

USAGE:
    redshield signatures list
    redshield signatures search sql
    redshield signatures info RS-SQLI-001
    redshield signatures enable RS-SQLI-001
    redshield signatures disable RS-SQLI-001
    redshield signatures import ./custom_signatures/
    redshield signatures stats
"""

import click
from cli.utils.formatters import (
    formatSuccessMessage, 
    formatErrorMessage, 
    formatInfoMessage,
    formatWarningMessage,
    formatSeverity
)


def get_registry():
    """Get the signature registry."""
    from core.signatures.registry import SignatureRegistry
    return SignatureRegistry()


@click.group()
def signatures():
    """
    Manage vulnerability signatures.
    
    Signatures define how to detect specific vulnerabilities.
    RedShield includes built-in signatures for common issues like:
    - SQL Injection
    - XSS (Cross-Site Scripting)
    - Exposed databases
    - Default credentials
    - And more...
    
    You can also import custom signatures or disable built-in ones.
    """
    pass


@signatures.command('list')
@click.option('--severity', '-s', type=click.Choice(['Critical', 'High', 'Medium', 'Low', 'All']), 
              default='All', help='Filter by severity')
@click.option('--category', '-c', help='Filter by OWASP category (e.g., A01:2021)')
@click.option('--tag', '-t', help='Filter by tag (e.g., sql, xss, database)')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed information')
def list_signatures(severity, category, tag, verbose):
    """List all available signatures."""
    registry = get_registry()
    
    # Get and filter signatures
    sigs = registry.signatures
    
    if severity != 'All':
        from core.signatures.loader import Severity
        sigs = [s for s in sigs if s.severity.value == severity]
    
    if category:
        sigs = [s for s in sigs if category.lower() in s.category.lower()]
    
    if tag:
        sigs = [s for s in sigs if tag.lower() in [t.lower() for t in s.tags]]
    
    if not sigs:
        click.echo(formatWarningMessage("No signatures found matching criteria"))
        return
    
    click.echo()
    click.echo(formatInfoMessage(f"Found {len(sigs)} signatures"))
    click.echo("-" * 70)
    click.echo()
    
    # Group by severity
    by_severity = {}
    for sig in sigs:
        sev = sig.severity.value
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(sig)
    
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        if sev not in by_severity:
            continue
        
        click.echo(f"{formatSeverity(sev)} ({len(by_severity[sev])} signatures)")
        click.echo()
        
        for sig in by_severity[sev]:
            click.echo(f"  {click.style(sig.id, fg='cyan')}  {sig.name}")
            if verbose:
                click.echo(f"      {click.style(sig.description[:60] + '...' if len(sig.description) > 60 else sig.description, dim=True)}")
                click.echo(f"      Category: {sig.category}")
                if sig.tags:
                    click.echo(f"      Tags: {', '.join(sig.tags)}")
                click.echo()
        
        click.echo()


@signatures.command('info')
@click.argument('signature_id')
def signature_info(signature_id):
    """Show detailed information about a signature."""
    registry = get_registry()
    
    sig = registry.get_signature(signature_id)
    
    if not sig:
        click.echo(formatErrorMessage(f"Signature not found: {signature_id}"))
        click.echo()
        click.echo(formatInfoMessage("Use 'redshield signatures list' to see all signatures"))
        return
    
    click.echo()
    click.echo(f"{'='*60}")
    click.echo(f" {click.style(sig.name, fg='cyan', bold=True)}")
    click.echo(f"{'='*60}")
    click.echo()
    
    click.echo(f"  {click.style('ID:', bold=True)}          {sig.id}")
    click.echo(f"  {click.style('Severity:', bold=True)}    {formatSeverity(sig.severity.value)}")
    click.echo(f"  {click.style('Category:', bold=True)}    {sig.category}")
    
    if sig.mitre_attack:
        click.echo(f"  {click.style('MITRE:', bold=True)}       {sig.mitre_attack}")
    
    if sig.cve_ids:
        click.echo(f"  {click.style('CVEs:', bold=True)}        {', '.join(sig.cve_ids)}")
    
    if sig.tags:
        click.echo(f"  {click.style('Tags:', bold=True)}        {', '.join(sig.tags)}")
    
    click.echo()
    click.echo(f"  {click.style('Description:', bold=True)}")
    click.echo(f"  {sig.description}")
    
    # Detection info
    if sig.detection:
        click.echo()
        click.echo(f"  {click.style('Detection Method:', bold=True)}")
        click.echo(f"    Type: {sig.detection.type.value}")
        if sig.detection.port:
            click.echo(f"    Port: {sig.detection.port}")
        if sig.detection.service:
            click.echo(f"    Service: {sig.detection.service}")
        if sig.detection.payloads:
            click.echo(f"    Payloads: {len(sig.detection.payloads)} test cases")
    
    # Remediation info
    if sig.remediation:
        click.echo()
        click.echo(f"  {click.style('Remediation:', bold=True)}")
        click.echo(f"    {sig.remediation.description}")
        if sig.remediation.playbook:
            click.echo(f"    Playbook: {sig.remediation.playbook}")
        if sig.remediation.manual_steps:
            click.echo()
            click.echo(f"    {click.style('Manual Steps:', bold=True)}")
            for i, step in enumerate(sig.remediation.manual_steps, 1):
                click.echo(f"      {i}. {step}")
    
    click.echo()


@signatures.command('search')
@click.argument('query')
def search_signatures(query):
    """Search signatures by name, description, or tags."""
    registry = get_registry()
    
    results = registry.search(query)
    
    if not results:
        click.echo(formatWarningMessage(f"No signatures found matching '{query}'"))
        return
    
    click.echo()
    click.echo(formatInfoMessage(f"Found {len(results)} signatures matching '{query}'"))
    click.echo("-" * 60)
    click.echo()
    
    for sig in results:
        click.echo(f"  {click.style(sig.id, fg='cyan')}  [{formatSeverity(sig.severity.value)}]")
        click.echo(f"    {sig.name}")
        click.echo(f"    {click.style(sig.description[:70] + '...' if len(sig.description) > 70 else sig.description, dim=True)}")
        click.echo()


@signatures.command('stats')
def signature_stats():
    """Show signature statistics."""
    registry = get_registry()
    
    stats = registry.get_statistics()
    
    click.echo()
    click.echo(formatInfoMessage("Signature Statistics"))
    click.echo("=" * 50)
    click.echo()
    
    click.echo(f"  Total Signatures:     {stats['total']}")
    click.echo(f"  Built-in:             {stats['builtin']}")
    click.echo(f"  Custom:               {stats['custom']}")
    click.echo(f"  Disabled:             {stats['disabled']}")
    click.echo()
    
    click.echo("  By Severity:")
    for sev, count in stats['by_severity'].items():
        if count > 0:
            click.echo(f"    {formatSeverity(sev)}: {count}")
    
    click.echo()
    click.echo(f"  OWASP Categories: {len(stats['categories'])}")
    click.echo(f"  Tags: {len(stats['tags'])}")
    click.echo()


@signatures.command('enable')
@click.argument('signature_id')
def enable_signature(signature_id):
    """Enable a disabled signature."""
    registry = get_registry()
    
    if not registry.get_signature(signature_id):
        click.echo(formatErrorMessage(f"Signature not found: {signature_id}"))
        return
    
    registry.enable_signature(signature_id)
    click.echo(formatSuccessMessage(f"Enabled signature: {signature_id}"))


@signatures.command('disable')
@click.argument('signature_id')
def disable_signature(signature_id):
    """Disable a signature (won't be used in scans)."""
    registry = get_registry()
    
    if not registry.get_signature(signature_id):
        click.echo(formatErrorMessage(f"Signature not found: {signature_id}"))
        return
    
    registry.disable_signature(signature_id)
    click.echo(formatSuccessMessage(f"Disabled signature: {signature_id}"))


@signatures.command('import')
@click.argument('path', type=click.Path(exists=True))
def import_signatures(path):
    """Import custom signatures from a directory."""
    registry = get_registry()
    
    click.echo(formatInfoMessage(f"Importing signatures from: {path}"))
    
    count = registry.load_custom_signatures(path)
    
    if count > 0:
        click.echo(formatSuccessMessage(f"Imported {count} signatures"))
    else:
        click.echo(formatWarningMessage("No valid signatures found"))


@signatures.command('owasp')
def owasp_mapping():
    """Show signatures grouped by OWASP Top 10 categories."""
    registry = get_registry()
    
    mapping = registry.get_owasp_mapping()
    
    click.echo()
    click.echo(formatInfoMessage("OWASP Top 10 Coverage"))
    click.echo("=" * 60)
    click.echo()
    
    for category in sorted(mapping.keys()):
        sigs = mapping[category]
        click.echo(f"  {click.style(category, fg='cyan', bold=True)} ({len(sigs)} signatures)")
        for sig in sigs[:3]:  # Show first 3
            click.echo(f"    - {sig.name}")
        if len(sigs) > 3:
            click.echo(f"    ... and {len(sigs) - 3} more")
        click.echo()


@signatures.command('mitre')
def mitre_mapping():
    """Show signatures grouped by MITRE ATT&CK techniques."""
    registry = get_registry()
    
    mapping = registry.get_mitre_mapping()
    
    click.echo()
    click.echo(formatInfoMessage("MITRE ATT&CK Coverage"))
    click.echo("=" * 60)
    click.echo()
    
    for technique in sorted(mapping.keys()):
        sigs = mapping[technique]
        click.echo(f"  {click.style(technique, fg='cyan', bold=True)} ({len(sigs)} signatures)")
        for sig in sigs:
            click.echo(f"    - [{sig.severity.value}] {sig.name}")
        click.echo()

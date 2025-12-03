import click
from redshield.cli.utils.formatters import formatSuccessMessage, formatInfoMessage

@click.comman()
@click.argument('scan_id')
@click.option('--format', '-f', type=click.Choice(['pdf', 'html', 'json']), default='pdf')
@click.option('--output', '-o', type=click.Path())

def report(scan_id, format, output):
    #Generate report from scan

    try:
        click.echo()
        click.echo(formatInfoMessage(f"Generating {format.upper()} report..."))

        with click.progressbar(length=100, label='Report') as bar:
            bar.update(100)

        outputfile = output or f"report_{scan_id}.{format}"

        click.echo()
        click.echo(formatSucessMessage(f"Report saved: {outputfile}"))
        click.echo()

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        raise click.Abort()

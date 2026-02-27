"""CLI entry point for aumai-opensafety."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click


@click.group()
@click.version_option()
def main() -> None:
    """AumAI OpenSafety — AI safety incident aggregator."""


@main.command("serve")
@click.option("--port", default=8000, show_default=True, type=int, help="HTTP port.")
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind host.")  # noqa: S104
@click.option(
    "--seed",
    "seed_file",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON file with initial incidents to load.",
)
def serve(port: int, host: str, seed_file: Path | None) -> None:
    """Start the FastAPI incident dashboard server."""
    try:
        import uvicorn  # type: ignore[import-untyped]
    except ImportError:
        click.echo(
            "uvicorn is required to run the server. Install with: pip install uvicorn",
            err=True,
        )
        sys.exit(1)

    from aumai_opensafety.dashboard import create_app, load_into_store

    if seed_file:
        raw = json.loads(seed_file.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            create_app()
            count = load_into_store(raw)
            click.echo(f"Loaded {count} incidents from {seed_file.name}")
        else:
            click.echo("Seed file must be a JSON array of incidents.", err=True)

    uvicorn.run("aumai_opensafety.dashboard:app", host=host, port=port, reload=False)


@main.command("ingest")
@click.option(
    "--file",
    "input_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON file containing an array of incident objects.",
)
@click.option(
    "--auto-classify",
    is_flag=True,
    default=False,
    help="Auto-classify severity and category using keyword rules.",
)
def ingest(input_file: Path, auto_classify: bool) -> None:
    """Ingest incidents from a JSON file and print a summary."""
    from aumai_opensafety.core import IncidentClassifier, IncidentCollector
    from aumai_opensafety.models import SafetyIncident

    raw: list[dict[str, object]] = json.loads(input_file.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        click.echo("Input file must be a JSON array.", err=True)
        sys.exit(1)

    collector = IncidentCollector()
    classifier = IncidentClassifier()

    incidents = [SafetyIncident.model_validate(item) for item in raw]
    if auto_classify:
        incidents = [classifier.reclassify(i) for i in incidents]

    count = collector.bulk_import(incidents)
    click.echo(f"Ingested {count} new incidents from {input_file.name}")

    # Print severity breakdown
    from collections import Counter
    severity_counts: Counter[str] = Counter(
        i.severity.value for i in collector.all_incidents()
    )
    for severity, n in sorted(severity_counts.items()):
        click.echo(f"  {severity:15s}: {n}")


@main.command("stats")
@click.option(
    "--file",
    "input_file",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON file to read incidents from. Uses in-memory state if omitted.",
)
def stats(input_file: Path | None) -> None:
    """Print dashboard statistics to the console."""
    from aumai_opensafety.core import IncidentCollector, TimelineAnalyzer

    if input_file is None:
        click.echo("Provide --file to load incidents for stats.", err=True)
        sys.exit(1)

    raw: list[dict[str, object]] = json.loads(input_file.read_text(encoding="utf-8"))
    collector = IncidentCollector()
    collector.bulk_import_json(raw)  # type: ignore[arg-type]

    analyzer = TimelineAnalyzer()
    dashboard = analyzer.build_dashboard_stats(collector.all_incidents())

    click.echo(f"Total incidents : {dashboard.total_incidents}")
    click.echo(f"Verified        : {dashboard.verified_count}")
    click.echo(f"Unverified      : {dashboard.unverified_count}")
    click.echo("\nBy severity:")
    for sev, n in sorted(dashboard.by_severity.items(), key=lambda x: -x[1]):
        click.echo(f"  {sev:15s}: {n}")
    click.echo("\nBy category:")
    for cat, n in sorted(dashboard.by_category.items(), key=lambda x: -x[1]):
        click.echo(f"  {cat:20s}: {n}")


if __name__ == "__main__":
    main()

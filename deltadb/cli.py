import logging

import click
import yaml
from rich.console import Console

from deltadb.exceptions import DeltaDbError
from deltadb.loader.factory import create_loader
from deltadb.model.schema import SchemaModel
from deltadb.security.credentials import mask_url
from deltadb.security.path_safety import validate_output_path

console = Console()


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )


def _schema_to_dict(schema: SchemaModel) -> dict:
    tables: dict = {}
    for tname, table in schema.tables.items():
        t: dict = {"columns": []}
        for col in table.columns:
            col_dict: dict = {
                "name": col.name,
                "type": col.type,
                "nullable": col.nullable,
            }
            if col.primary_key:
                col_dict["primary_key"] = True
            if col.autoincrement:
                col_dict["autoincrement"] = True
            if col.default is not None:
                col_dict["default"] = col.default
            t["columns"].append(col_dict)
        if table.indexes:
            t["indexes"] = [
                {"name": idx.name, "columns": list(idx.columns), "unique": idx.unique}
                for idx in table.indexes
            ]
        if table.foreign_keys:
            t["foreign_keys"] = [
                {
                    "name": fk.name,
                    "columns": list(fk.columns),
                    "referred_table": fk.referred_table,
                    "referred_columns": list(fk.referred_columns),
                    **({"on_delete": fk.on_delete} if fk.on_delete else {}),
                    **({"on_update": fk.on_update} if fk.on_update else {}),
                }
                for fk in table.foreign_keys
            ]
        if table.unique_constraints:
            t["unique_constraints"] = [
                {"name": uc.name, "columns": list(uc.columns)}
                for uc in table.unique_constraints
            ]
        tables[tname] = t
    result: dict = {"tables": tables}
    if schema.dialect:
        result = {"dialect": schema.dialect, **result}
    return result


@click.group()
@click.version_option(version="0.1.0")
def deltadb() -> None:
    """deltadb -- Schema Diff & Migration Generator"""


@deltadb.command()
@click.argument("source")
@click.option("--output", "-o", help="Output .yml file path")
@click.option("--verbose", is_flag=True)
def snapshot(source: str, output: str | None, verbose: bool) -> None:
    """Take a snapshot of a database schema."""
    _configure_logging(verbose)
    try:
        # [SECURITY] Never display raw connection string — mask credentials
        source_display = mask_url(source) if "://" in source else source
        console.print(f"[dim]Loading: {source_display}[/dim]")
        schema = create_loader(source).load()
        yml_data = _schema_to_dict(schema)
        yml_str = yaml.dump(
            yml_data, default_flow_style=False, sort_keys=False, allow_unicode=True
        )
        if output:
            out = validate_output_path(output)
            out.write_text(yml_str, encoding="utf-8")
            console.print(f"[green]Snapshot saved to {output}[/green]")
        else:
            click.echo(yml_str)
    except DeltaDbError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise SystemExit(1)


@deltadb.command("diff")
@click.argument("source")
@click.argument("target")
@click.option("--dialect", type=click.Choice(["postgresql", "mysql", "sqlite"]))
@click.option("--output", "-o")
@click.option("--no-destructive", is_flag=True)
@click.option("--detect-renames", is_flag=True)
@click.option("--rename-threshold", type=float, default=0.7)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["rich", "sql", "json"]),
    default="rich",
)
@click.option("--verbose", is_flag=True)
def diff_cmd(
    source: str,
    target: str,
    dialect: str | None,
    output: str | None,
    no_destructive: bool,
    detect_renames: bool,
    rename_threshold: float,
    fmt: str,
    verbose: bool,
) -> None:
    """Compare two schemas and generate migration."""
    console.print("[yellow]Diff not yet implemented.[/yellow]")

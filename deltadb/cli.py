import logging

import click
import yaml
from rich.console import Console
from rich.markup import escape as markup_escape


class _QuotedStr(str):
    """String subclass that forces YAML double-quoting to prevent type coercion.

    YAML parses bare values like 'true', 'null', '1e5' as non-string types.
    Wrapping column defaults in _QuotedStr ensures they survive the round-trip.
    """


def _quoted_str_representer(dumper: yaml.Dumper, data: "_QuotedStr") -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')


class _SafeDumperWithQuotedStr(yaml.SafeDumper):
    pass


_SafeDumperWithQuotedStr.add_representer(_QuotedStr, _quoted_str_representer)

from deltadb.diff.engine import DiffEngine
from deltadb.diff.rename import RenameDetector
from deltadb.exceptions import DeltaDbError, SecurityError
from deltadb.generator.dialects import Dialect, detect_dialect
from deltadb.generator.sql_generator import SqlGenerator
from deltadb.loader.factory import create_loader
from deltadb.model.schema import SchemaModel
from deltadb.output.json_writer import export_json
from deltadb.output.rich_printer import print_diff
from deltadb.output.sql_writer import write_sql
from deltadb.security.credentials import mask_url
from deltadb.security.path_safety import validate_output_path

console = Console()
logger = logging.getLogger(__name__)


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,  # clears existing handlers — prevents no-op on repeated CLI calls in same process
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
                # [SECURITY] _QuotedStr forces YAML double-quoting — prevents type coercion
                # of values like "true", "null", "1e5" on snapshot round-trip
                col_dict["default"] = _QuotedStr(col.default)
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


class _SnapshotCommand:
    """Business logic for schema snapshot. No I/O decisions, no error handling."""

    def execute(self, source: str) -> tuple["SchemaModel", str]:
        schema = create_loader(source).load()
        yml_str = yaml.dump(
            _schema_to_dict(schema),
            Dumper=_SafeDumperWithQuotedStr,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
        return schema, yml_str


class _DiffCommand:
    """Business logic for schema diff. No output formatting, no error handling."""

    def execute(
        self,
        source: str,
        target: str,
        detect_renames: bool,
        rename_threshold: float,
    ) -> tuple[list, "SchemaModel", "SchemaModel"]:
        if detect_renames and not (0.0 < rename_threshold <= 1.0):
            # [SECURITY] Reject out-of-range threshold before it reaches RenameDetector.
            # threshold <= 0.0 matches every DROP+ADD pair, hiding destructive operations.
            raise ValueError(
                f"--rename-threshold must be in range (0.0, 1.0], got {rename_threshold!r}"
            )
        source_schema = create_loader(source).load()
        target_schema = create_loader(target).load()
        changes = DiffEngine().diff(source_schema, target_schema)
        if detect_renames:
            changes = RenameDetector(threshold=rename_threshold).apply(changes)
        return changes, source_schema, target_schema


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
        _, yml_str = _SnapshotCommand().execute(source)
        if output:
            out = validate_output_path(output)
            out.write_text(yml_str, encoding="utf-8")
            # [SECURITY] markup_escape prevents Rich injection via user-supplied output path
            console.print(f"[green]Snapshot saved to {markup_escape(output)}[/green]")
        else:
            click.echo(yml_str)
    except DeltaDbError as e:
        # [SECURITY] mask_url always — error may embed connection string with credentials
        console.print(f"[red]Error: {markup_escape(mask_url(str(e)))}[/red]")
        raise SystemExit(1)
    except Exception as e:
        # [SECURITY] Generic handler — mask credentials, never expose raw traceback
        safe_msg = mask_url(str(e))
        logger.error("Unexpected error: %s", safe_msg, exc_info=verbose)
        console.print("[red]Unexpected error. Use --verbose for details.[/red]")
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
    _configure_logging(verbose)
    try:
        # [SECURITY] Always mask URLs in output — never expose credentials
        source_display = mask_url(source) if "://" in source else source
        target_display = mask_url(target) if "://" in target else target
        if fmt == "rich":
            console.print(f"[dim]Source: {source_display}[/dim]")
            console.print(f"[dim]Target: {target_display}[/dim]")

        changes, source_schema, target_schema = _DiffCommand().execute(
            source, target, detect_renames, rename_threshold
        )

        def _resolved_dialect() -> Dialect:
            return (
                Dialect(dialect)
                if dialect
                else detect_dialect(
                    source if "://" in source else None,
                    source_schema.dialect or target_schema.dialect,
                )
            )

        if output:
            # [SECURITY] markup_escape prevents Rich injection via user-supplied output path
            safe_out = markup_escape(output)
            if output.endswith(".json"):
                export_json(changes, output)
                console.print(f"[green]✓ Diff exported to {safe_out}[/green]")
            else:
                sql = SqlGenerator(_resolved_dialect()).generate(
                    changes, target_schema, no_destructive=no_destructive
                )
                write_sql(sql, output)
                console.print(f"[green]✓ Migration saved to {safe_out}[/green]")
        elif fmt == "sql":
            sql = SqlGenerator(_resolved_dialect()).generate(
                changes, target_schema, no_destructive=no_destructive
            )
            write_sql(sql)
        elif fmt == "json":
            import json
            import sys

            payload = [
                {
                    "type": c.type.value,
                    "table": c.table,
                    "column": c.column,
                    "destructive": c.destructive,
                    "detail": c.detail,
                }
                for c in changes
            ]
            sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        else:
            print_diff(changes, console)

    except ValueError as e:
        console.print(f"[red]Invalid argument: {markup_escape(str(e))}[/red]")
        raise SystemExit(1)
    except SecurityError as e:
        # [SECURITY] markup_escape + mask_url — security error messages are safe to show
        console.print(f"[red]Security error: {markup_escape(str(e))}[/red]")
        raise SystemExit(1)
    except DeltaDbError as e:
        # [SECURITY] mask_url always — DeltaDbError may embed connection string
        console.print(f"[red]Error: {markup_escape(mask_url(str(e)))}[/red]")
        raise SystemExit(1)
    except Exception as e:
        # [SECURITY] Always mask_url — fragile "://" check misses alternate credential formats
        safe_msg = mask_url(str(e))
        logger.error("Unexpected error: %s", safe_msg, exc_info=verbose)
        console.print("[red]Unexpected error. Use --verbose for details.[/red]")
        raise SystemExit(1)

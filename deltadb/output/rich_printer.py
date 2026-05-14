from rich.console import Console
from rich.markup import escape
from rich.table import Table

from deltadb.diff.changes import Change, ChangeType

_ADDED_TYPES = frozenset({
    ChangeType.TABLE_ADDED,
    ChangeType.COLUMN_ADDED,
    ChangeType.INDEX_ADDED,
    ChangeType.FK_ADDED,
    ChangeType.UNIQUE_CONSTRAINT_ADDED,
})
_DROPPED_TYPES = frozenset({
    ChangeType.TABLE_DROPPED,
    ChangeType.COLUMN_DROPPED,
    ChangeType.INDEX_DROPPED,
    ChangeType.FK_DROPPED,
    ChangeType.UNIQUE_CONSTRAINT_DROPPED,
})


def _row_style(change: Change) -> str:
    if change.type in _ADDED_TYPES:
        return "green"
    if change.type in _DROPPED_TYPES:
        return "red"
    return "yellow"


def print_diff(changes: list[Change], console: Console) -> None:
    if not changes:
        console.print("[green]✓ No differences found.[/green]")
        return

    tbl = Table(show_header=True, header_style="bold")
    tbl.add_column("Type", style="bold")
    tbl.add_column("Table")
    tbl.add_column("Column")
    tbl.add_column("Detail")

    for change in changes:
        style = _row_style(change)
        # [SECURITY] escape() prevents Rich markup injection from DB/YAML-sourced names
        tbl.add_row(
            f"[{style}]{change.type.value}[/{style}]",
            escape(change.table),
            escape(change.column or ""),
            escape(change.detail or ""),
        )

    console.print(tbl)

    destructive_count = sum(1 for c in changes if c.destructive)
    summary = f"[bold]{len(changes)} change(s)[/bold]"
    if destructive_count:
        summary += f"  [red bold]{destructive_count} destructive[/red bold]"
    console.print(summary)

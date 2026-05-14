import logging
from datetime import UTC, datetime
from typing import Literal

from jinja2 import PackageLoader
from jinja2.sandbox import SandboxedEnvironment

from deltadb.diff.changes import Change, ChangeType
from deltadb.exceptions import GeneratorError, SecurityError, TemplateRenderError
from deltadb.generator.dialects import Dialect
from deltadb.generator.topological import topological_sort_down, topological_sort_up
from deltadb.model.column import Column
from deltadb.model.constraint import PrimaryKey, UniqueConstraint
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table
from deltadb.security.identifiers import (
    quote_identifier,
    validate_column_type,
    validate_default,
)

# [SECURITY] Allowlist for ON DELETE / ON UPDATE referential actions.
# Any value not in this set is rejected before template rendering.
_VALID_ON_ACTIONS = frozenset({
    "CASCADE", "SET NULL", "SET DEFAULT", "RESTRICT", "NO ACTION",
})


def _validate_type_filter(type_str: str) -> str:
    # [SECURITY] validate_type Jinja2 filter — rejects injection in col.type / new_type
    validate_column_type(type_str)
    return type_str


def _safe_default_filter(value: object) -> str:
    # [SECURITY] safe_default Jinja2 filter — rejects SQL metacharacters in defaults
    s = str(value)
    validate_default(s)
    return s


def _safe_on_action_filter(value: str) -> str:
    # [SECURITY] safe_on_action Jinja2 filter — allowlist for ON DELETE / ON UPDATE
    upper = value.strip().upper()
    if upper not in _VALID_ON_ACTIONS:
        raise SecurityError(
            f"Invalid ON DELETE/UPDATE action '{value}'. "
            f"Allowed: {sorted(_VALID_ON_ACTIONS)}"
        )
    return upper

logger = logging.getLogger(__name__)

_CHANGE_TO_UP_TEMPLATE: dict[ChangeType, str] = {
    ChangeType.TABLE_ADDED: "create_table.sql.j2",
    ChangeType.TABLE_DROPPED: "drop_table.sql.j2",
    ChangeType.COLUMN_ADDED: "add_column.sql.j2",
    ChangeType.COLUMN_DROPPED: "drop_column.sql.j2",
    ChangeType.COLUMN_TYPE_CHANGED: "alter_column.sql.j2",
    ChangeType.COLUMN_NULLABLE_CHANGED: "alter_column_nullable.sql.j2",
    ChangeType.COLUMN_DEFAULT_CHANGED: "alter_column_default.sql.j2",
    # COLUMN_PRIMARY_KEY_CHANGED and COLUMN_AUTOINCREMENT_CHANGED are intentionally
    # absent — they require manual DDL that is highly dialect-specific.
    # _render_change emits a clearly labeled SQL comment instead of wrong SQL.
    ChangeType.INDEX_ADDED: "add_index.sql.j2",
    ChangeType.INDEX_DROPPED: "drop_index.sql.j2",
    ChangeType.FK_ADDED: "add_fk.sql.j2",
    ChangeType.FK_DROPPED: "drop_fk.sql.j2",
    ChangeType.UNIQUE_CONSTRAINT_ADDED: "add_unique.sql.j2",
    ChangeType.UNIQUE_CONSTRAINT_DROPPED: "drop_unique.sql.j2",
    ChangeType.TABLE_RENAMED: "rename_table.sql.j2",
    ChangeType.COLUMN_RENAMED: "rename_column.sql.j2",
}

_CHANGE_TO_DOWN_TEMPLATE: dict[ChangeType, str] = {
    ChangeType.TABLE_ADDED: "drop_table.sql.j2",
    ChangeType.TABLE_DROPPED: "create_table.sql.j2",
    ChangeType.COLUMN_ADDED: "drop_column.sql.j2",
    ChangeType.COLUMN_DROPPED: "add_column.sql.j2",
    ChangeType.COLUMN_TYPE_CHANGED: "alter_column.sql.j2",
    ChangeType.COLUMN_NULLABLE_CHANGED: "alter_column_nullable.sql.j2",
    ChangeType.COLUMN_DEFAULT_CHANGED: "alter_column_default.sql.j2",
    # COLUMN_PRIMARY_KEY_CHANGED and COLUMN_AUTOINCREMENT_CHANGED are intentionally absent.
    ChangeType.INDEX_ADDED: "drop_index.sql.j2",
    ChangeType.INDEX_DROPPED: "add_index.sql.j2",
    ChangeType.FK_ADDED: "drop_fk.sql.j2",
    ChangeType.FK_DROPPED: "add_fk.sql.j2",
    ChangeType.UNIQUE_CONSTRAINT_ADDED: "drop_unique.sql.j2",
    ChangeType.UNIQUE_CONSTRAINT_DROPPED: "add_unique.sql.j2",
    ChangeType.TABLE_RENAMED: "rename_table.sql.j2",
    ChangeType.COLUMN_RENAMED: "rename_column.sql.j2",
}


def _table_columns(table_obj: Table | None) -> tuple[Column, ...]:
    return table_obj.columns if table_obj else ()


def _table_pk(table_obj: Table | None) -> PrimaryKey | None:
    return table_obj.primary_key if table_obj else None


def _table_ucs(table_obj: Table | None) -> tuple[UniqueConstraint, ...]:
    return table_obj.unique_constraints if table_obj else ()


class SqlGenerator:
    def __init__(self, dialect: Dialect) -> None:
        self._dialect = dialect
        # [SECURITY] SandboxedEnvironment — prevents template injection via attribute traversal.
        # autoescape=False is intentional: HTML escaping corrupts SQL output.
        # ALL user-controlled values MUST pass through a registered filter (quote_id,
        # safe_default, validate_type, safe_on_action). Audit: grep -rn
        # '{{ [^|%][^}]*}}' deltadb/generator/templates/ --include="*.j2"
        try:
            self._env = SandboxedEnvironment(
                loader=PackageLoader("deltadb", f"generator/templates/{dialect.value}"),
                autoescape=False,
                keep_trailing_newline=True,
            )
        except Exception as exc:
            raise TemplateRenderError(
                f"Failed to initialize templates for dialect '{dialect.value}': {exc}"
            ) from exc
        # [SECURITY] quote_id filter — all identifiers in templates use this
        d = dialect.value
        self._env.filters["quote_id"] = lambda name: quote_identifier(name, d)
        # [SECURITY] validate_type filter — rejects col.type / new_type injection
        self._env.filters["validate_type"] = _validate_type_filter
        # [SECURITY] safe_default filter — rejects SQL metacharacters in DEFAULT values
        self._env.filters["safe_default"] = _safe_default_filter
        # [SECURITY] safe_on_action filter — allowlist for ON DELETE / ON UPDATE
        self._env.filters["safe_on_action"] = _safe_on_action_filter

    def generate(
        self,
        changes: list[Change],
        schema: SchemaModel,
        no_destructive: bool = False,
    ) -> str:
        working = changes
        if no_destructive:
            skipped = [c for c in working if c.destructive]
            for c in skipped:
                col_info = f".{c.column}" if c.column else ""
                logger.warning(
                    "Omitting destructive operation: %s on %s%s",
                    c.type.value, c.table, col_info,
                )
            working = [c for c in working if not c.destructive]

        sorted_up = topological_sort_up(working, schema)
        sorted_down = topological_sort_down(sorted_up)

        up_sql = self._render_all(sorted_up, direction="up")
        down_sql = self._render_all(sorted_down, direction="down")

        ts = datetime.now(UTC).isoformat()
        header = (
            f"-- Generated by deltadb\n"
            f"-- Dialect: {self._dialect.value}\n"
            f"-- Generated at: {ts}\n"
        )
        return (
            f"{header}\n"
            f"-- ============ UP (apply) ============\n\n"
            f"{up_sql}\n"
            f"-- ============ DOWN (revert) ============\n\n"
            f"{down_sql}"
        )

    def _render_all(
        self, changes: list[Change], direction: Literal["up", "down"]
    ) -> str:
        parts: list[str] = []
        for change in changes:
            stripped = self._render_change(change, direction).strip()
            if stripped:
                parts.append(stripped)
        return "\n\n".join(parts) + "\n" if parts else ""

    def _render_change(
        self, change: Change, direction: Literal["up", "down"]
    ) -> str:
        # These change types require manual DDL — emit a clear comment instead of wrong SQL
        if change.type in (ChangeType.COLUMN_PRIMARY_KEY_CHANGED, ChangeType.COLUMN_AUTOINCREMENT_CHANGED):
            label = "PRIMARY KEY" if change.type == ChangeType.COLUMN_PRIMARY_KEY_CHANGED else "AUTOINCREMENT"
            new_val = change.new_value if direction == "up" else change.old_value
            return (
                f"-- ⚠️  MANUAL MIGRATION REQUIRED: {label} changes cannot be auto-generated.\n"
                f"-- Table: {change.table}, Column: {change.column}\n"
                f"-- Target value: {new_val}\n"
                f"-- Apply the appropriate DDL for your database engine manually."
            )

        if direction == "up":
            template_map = _CHANGE_TO_UP_TEMPLATE
        else:
            template_map = _CHANGE_TO_DOWN_TEMPLATE
        template_name = template_map.get(change.type)
        if template_name is None:
            raise GeneratorError(f"No template for change type: {change.type}")

        ctx = self._build_context(change, direction)
        try:
            template = self._env.get_template(template_name)
            return template.render(**ctx)
        except SecurityError:
            # [SECURITY] Let security errors propagate unchanged — do not mask them
            raise
        except Exception as exc:
            raise TemplateRenderError(
                f"Template render failed for {change.type.value}"
                f" on {change.table}: {exc}"
            ) from exc

    def _build_context(  # noqa: C901
        self, change: Change, direction: Literal["up", "down"]
    ) -> dict[str, object]:
        ctx: dict = {"table": change.table, "dialect": self._dialect.value}
        ct = change.type

        if ct == ChangeType.TABLE_ADDED:
            obj = change.new_value
            if direction == "up":
                ctx["table_obj"] = obj
                ctx["columns"] = _table_columns(obj)
                ctx["primary_key"] = _table_pk(obj)
                ctx["unique_constraints"] = _table_ucs(obj)
            else:
                ctx["table_obj"] = obj

        elif ct == ChangeType.TABLE_DROPPED:
            obj = change.old_value
            ctx["table_obj"] = obj
            if direction == "down":
                ctx["columns"] = _table_columns(obj)
                ctx["primary_key"] = _table_pk(obj)
                ctx["unique_constraints"] = _table_ucs(obj)

        elif ct == ChangeType.COLUMN_ADDED:
            ctx["column"] = change.new_value

        elif ct == ChangeType.COLUMN_DROPPED:
            ctx["column"] = change.old_value

        elif ct == ChangeType.COLUMN_TYPE_CHANGED:
            if direction == "up":
                ctx["column"] = change.column
                ctx["new_type"] = change.new_value
                ctx["old_type"] = change.old_value
            else:
                ctx["column"] = change.column
                ctx["new_type"] = change.old_value
                ctx["old_type"] = change.new_value

        elif ct == ChangeType.COLUMN_NULLABLE_CHANGED:
            if direction == "up":
                ctx["column"] = change.column
                ctx["new_value"] = change.new_value
                ctx["old_value"] = change.old_value
            else:
                ctx["column"] = change.column
                ctx["new_value"] = change.old_value
                ctx["old_value"] = change.new_value

        elif ct == ChangeType.COLUMN_DEFAULT_CHANGED:
            if direction == "up":
                ctx["column"] = change.column
                ctx["new_default"] = change.new_value
                ctx["old_default"] = change.old_value
            else:
                ctx["column"] = change.column
                ctx["new_default"] = change.old_value
                ctx["old_default"] = change.new_value

        elif ct == ChangeType.INDEX_ADDED:
            ctx["index"] = change.new_value

        elif ct == ChangeType.INDEX_DROPPED:
            ctx["index"] = change.old_value

        elif ct == ChangeType.FK_ADDED:
            ctx["fk"] = change.new_value

        elif ct == ChangeType.FK_DROPPED:
            ctx["fk"] = change.old_value

        elif ct == ChangeType.UNIQUE_CONSTRAINT_ADDED:
            ctx["uc"] = change.new_value

        elif ct == ChangeType.UNIQUE_CONSTRAINT_DROPPED:
            ctx["uc"] = change.old_value

        elif ct == ChangeType.TABLE_RENAMED:
            if direction == "up":
                ctx["new_name"] = change.new_value
            else:
                ctx["new_name"] = change.table
                ctx["table"] = change.new_value

        elif ct == ChangeType.COLUMN_RENAMED:
            if direction == "up":
                ctx["column"] = change.column
                ctx["new_name"] = change.new_value
            else:
                ctx["column"] = change.new_value
                ctx["new_name"] = change.column

        return ctx

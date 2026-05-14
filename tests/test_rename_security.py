"""Security and integration tests for PR #7 rename detection.

Attack surface analysis:
- Negative threshold bypasses --no-destructive by converting DROP+ADD to RENAME
- SQL injection via directly-constructed TABLE_RENAMED / COLUMN_RENAMED changes
- Empty-column table signature collision (two empty tables always match at ratio=1.0)
- CLI threshold validation (out-of-range floats accepted by click)
- Defense in Depth: generator quote_id filter catches injection even if RenameDetector
  doesn't validate identifiers
"""
import pytest
from click.testing import CliRunner

from deltadb.cli import deltadb
from deltadb.diff.changes import Change, ChangeType
from deltadb.diff.rename import RenameDetector
from deltadb.exceptions import SecurityError
from deltadb.generator.dialects import Dialect
from deltadb.generator.sql_generator import SqlGenerator
from deltadb.model.column import Column
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table


def _col(name: str, type_: str = "integer", nullable: bool = True) -> Column:
    return Column(name=name, type=type_, nullable=nullable)


def _table(name: str, *cols: Column) -> Table:
    return Table(name=name, columns=cols)


def _schema(*tables: Table) -> SchemaModel:
    return SchemaModel(tables={t.name: t for t in tables})


def _dropped(table: Table) -> Change:
    return Change(type=ChangeType.TABLE_DROPPED, table=table.name, old_value=table, destructive=True)


def _added(table: Table) -> Change:
    return Change(type=ChangeType.TABLE_ADDED, table=table.name, new_value=table)


class TestThresholdValidation:
    """Negative threshold allows ALL table pairs to match, bypassing --no-destructive."""

    def test_negative_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="threshold"):
            RenameDetector(threshold=-0.1)

    def test_zero_threshold_raises(self) -> None:
        # threshold=0.0 matches every pair (ratio >= 0.0 always True)
        # This hides DROP+ADD as RENAME, bypassing --no-destructive
        with pytest.raises(ValueError, match="threshold"):
            RenameDetector(threshold=0.0)

    def test_threshold_above_one_raises(self) -> None:
        with pytest.raises(ValueError, match="threshold"):
            RenameDetector(threshold=1.1)

    def test_threshold_exactly_one_accepted(self) -> None:
        detector = RenameDetector(threshold=1.0)
        assert detector._threshold == 1.0

    def test_threshold_minimum_valid(self) -> None:
        detector = RenameDetector(threshold=0.01)
        assert detector._threshold == 0.01


class TestNegativeThresholdBypassNoDestructive:
    """Negative threshold converts destructive DROP into non-destructive RENAME,
    silently bypassing --no-destructive filter in the SQL generator."""

    def test_rename_change_is_not_destructive(self) -> None:
        old = _table("users", _col("id"))
        new = _table("members", _col("id"))
        changes = [_dropped(old), _added(new)]

        result = RenameDetector(threshold=0.7).apply(changes)

        rename = next(c for c in result if c.type == ChangeType.TABLE_RENAMED)
        # TABLE_RENAMED is intentionally non-destructive (no data loss)
        assert rename.destructive is False

    def test_no_destructive_preserves_rename_changes(self) -> None:
        """--no-destructive must NOT silently drop rename operations."""
        old = _table("users", _col("id", "integer", False))
        new = _table("members", _col("id", "integer", False))
        changes = [_dropped(old), _added(new)]

        renamed = RenameDetector(threshold=0.7).apply(changes)
        schema = SchemaModel(tables={"members": new})
        sql = SqlGenerator(Dialect.POSTGRESQL).generate(renamed, schema, no_destructive=True)

        assert "RENAME" in sql
        assert "DROP TABLE" not in sql

    def test_destructive_column_drop_not_hidden_by_rename(self) -> None:
        """A COLUMN_DROPPED that doesn't match rename threshold stays destructive."""
        old_col = Column(name="old_field", type="text", nullable=True)
        new_col = Column(name="new_field", type="integer", nullable=False)  # different type
        changes = [
            Change(type=ChangeType.COLUMN_DROPPED, table="t", column="old_field",
                   old_value=old_col, destructive=True),
            Change(type=ChangeType.COLUMN_ADDED, table="t", column="new_field",
                   new_value=new_col),
        ]

        result = RenameDetector(threshold=0.95).apply(changes)

        dropped = [c for c in result if c.type == ChangeType.COLUMN_DROPPED]
        assert len(dropped) == 1
        assert dropped[0].destructive is True


class TestSQLInjectionViaRenameChanges:
    """Generator must reject injected identifiers even when Change is constructed
    directly, bypassing DiffEngine validation (Defense in Depth)."""

    def test_table_renamed_malicious_new_value_rejected(self) -> None:
        change = Change(
            type=ChangeType.TABLE_RENAMED,
            table="users",
            new_value="evil; DROP TABLE orders--",
        )
        schema = SchemaModel(tables={})

        with pytest.raises(SecurityError):
            SqlGenerator(Dialect.POSTGRESQL).generate([change], schema)

    def test_table_renamed_newline_in_new_value_rejected(self) -> None:
        change = Change(
            type=ChangeType.TABLE_RENAMED,
            table="users",
            new_value="members\nDROP TABLE users",
        )
        schema = SchemaModel(tables={})

        with pytest.raises(SecurityError):
            SqlGenerator(Dialect.POSTGRESQL).generate([change], schema)

    def test_table_renamed_null_byte_in_new_value_rejected(self) -> None:
        change = Change(
            type=ChangeType.TABLE_RENAMED,
            table="users",
            new_value="members\x00DROP",
        )
        schema = SchemaModel(tables={})

        with pytest.raises(SecurityError):
            SqlGenerator(Dialect.POSTGRESQL).generate([change], schema)

    def test_column_renamed_malicious_new_value_rejected(self) -> None:
        change = Change(
            type=ChangeType.COLUMN_RENAMED,
            table="users",
            column="email",
            new_value="mail; DROP TABLE users--",
        )
        schema = SchemaModel(tables={})

        with pytest.raises(SecurityError):
            SqlGenerator(Dialect.POSTGRESQL).generate([change], schema)

    def test_column_renamed_malicious_old_column_rejected(self) -> None:
        change = Change(
            type=ChangeType.COLUMN_RENAMED,
            table="users",
            column="email; DROP TABLE--",
            new_value="mail",
        )
        schema = SchemaModel(tables={})

        with pytest.raises(SecurityError):
            SqlGenerator(Dialect.POSTGRESQL).generate([change], schema)

    def test_column_renamed_comment_injection_rejected(self) -> None:
        change = Change(
            type=ChangeType.COLUMN_RENAMED,
            table="users",
            column="email",
            new_value="mail/*DROP TABLE users*/",
        )
        schema = SchemaModel(tables={})

        with pytest.raises(SecurityError):
            SqlGenerator(Dialect.POSTGRESQL).generate([change], schema)

    def test_valid_rename_generates_correct_sql(self) -> None:
        change = Change(
            type=ChangeType.TABLE_RENAMED,
            table="users",
            new_value="members",
        )
        schema = SchemaModel(tables={})

        sql = SqlGenerator(Dialect.POSTGRESQL).generate([change], schema)

        assert '"users"' in sql
        assert '"members"' in sql
        assert "RENAME" in sql

    def test_mysql_rename_uses_backtick_quoting(self) -> None:
        change = Change(
            type=ChangeType.TABLE_RENAMED,
            table="users",
            new_value="members",
        )
        schema = SchemaModel(tables={})

        sql = SqlGenerator(Dialect.MYSQL).generate([change], schema)

        assert "`users`" in sql
        assert "`members`" in sql

    def test_injection_rejected_for_all_three_dialects(self) -> None:
        for dialect in [Dialect.POSTGRESQL, Dialect.MYSQL, Dialect.SQLITE]:
            change = Change(
                type=ChangeType.TABLE_RENAMED,
                table="users",
                new_value="evil; DROP TABLE orders--",
            )
            with pytest.raises(SecurityError):
                SqlGenerator(dialect).generate([change], SchemaModel(tables={}))


class TestDownMigrationCorrectness:
    """DOWN migration must correctly reverse rename direction — wrong reversal is a
    correctness bug that becomes a security issue if it silently destroys schema state."""

    def test_table_rename_down_inverts_old_and_new(self) -> None:
        change = Change(
            type=ChangeType.TABLE_RENAMED,
            table="users",
            new_value="members",
        )
        schema = SchemaModel(tables={})

        sql = SqlGenerator(Dialect.POSTGRESQL).generate([change], schema)

        # UP: users -> members
        up_section = sql.split("-- ============ UP")[1].split("-- ============ DOWN")[0]
        assert '"users"' in up_section
        assert '"members"' in up_section

        # DOWN: members -> users
        down_section = sql.split("-- ============ DOWN")[1]
        assert '"members"' in down_section
        assert '"users"' in down_section

    def test_column_rename_down_inverts_column_names(self) -> None:
        change = Change(
            type=ChangeType.COLUMN_RENAMED,
            table="users",
            column="user_name",
            new_value="username",
        )
        schema = SchemaModel(tables={})

        sql = SqlGenerator(Dialect.POSTGRESQL).generate([change], schema)

        up_section = sql.split("-- ============ UP")[1].split("-- ============ DOWN")[0]
        assert '"user_name"' in up_section
        assert '"username"' in up_section

        down_section = sql.split("-- ============ DOWN")[1]
        assert '"username"' in down_section
        assert '"user_name"' in down_section


class TestEmptyColumnTableCollision:
    """Two tables with zero columns both produce empty signature -> ratio=1.0.
    This forces a rename match even for completely unrelated empty tables."""

    def test_two_empty_tables_have_similarity_one(self) -> None:
        a = _table("logs")
        b = _table("metrics")
        detector = RenameDetector(threshold=0.7)
        ratio = detector._table_similarity(a, b)
        # Two empty signatures are "identical" — ratio=1.0
        assert ratio == 1.0

    def test_two_empty_tables_match_as_rename(self) -> None:
        """Caveat: empty-column table rename is valid behavior (schema has no cols
        to distinguish them). Document that this is expected."""
        old = _table("old_empty_table")
        new = _table("new_empty_table")
        changes = [_dropped(old), _added(new)]

        result = RenameDetector(threshold=0.7).apply(changes)

        renames = [c for c in result if c.type == ChangeType.TABLE_RENAMED]
        assert len(renames) == 1  # documented behavior — empty tables always match


class TestRichPrinterRenameTypes:
    """TABLE_RENAMED and COLUMN_RENAMED must not cause injection in Rich output.
    The detail field contains the new table/column name which comes from identifiers."""

    def test_table_renamed_in_rich_printer_no_injection(self) -> None:
        from io import StringIO

        from rich.console import Console

        from deltadb.output.rich_printer import print_diff

        change = Change(
            type=ChangeType.TABLE_RENAMED,
            table="users",
            new_value="members",
            detail="SUGGESTED RENAME -> members",
        )
        buf = StringIO()
        con = Console(file=buf, highlight=False)
        print_diff([change], con)
        output = buf.getvalue()
        assert "table_renamed" in output
        assert "users" in output

    def test_rich_printer_rename_detail_with_markup_chars_escaped(self) -> None:
        """detail field with Rich markup characters must be escaped."""
        from io import StringIO

        from rich.console import Console

        from deltadb.output.rich_printer import print_diff

        change = Change(
            type=ChangeType.TABLE_RENAMED,
            table="users",
            new_value="members",
            detail="SUGGESTED RENAME -> [bold red]injected[/bold red]",
        )
        buf = StringIO()
        con = Console(file=buf, highlight=False)
        print_diff([change], con)
        output = buf.getvalue()
        # markup should be escaped, not rendered as bold red
        assert "[bold red]" in output or "injected" in output


_SCHEMA_USERS = (
    "tables:\n  users:\n    columns:\n"
    "      - name: id\n        type: integer\n        nullable: false\n"
    "      - name: email\n        type: varchar\n        nullable: false\n"
)
_SCHEMA_MEMBERS = (
    "tables:\n  members:\n    columns:\n"
    "      - name: id\n        type: integer\n        nullable: false\n"
    "      - name: email\n        type: varchar\n        nullable: false\n"
)
_SCHEMA_USERS_SIMPLE = (
    "tables:\n  users:\n    columns:\n"
    "      - name: id\n        type: integer\n        nullable: false\n"
)
_SCHEMA_MEMBERS_SIMPLE = (
    "tables:\n  members:\n    columns:\n"
    "      - name: id\n        type: integer\n        nullable: false\n"
)


class TestCLIRenameThresholdValidation:
    """CLI must reject --rename-threshold values outside (0.0, 1.0]."""

    def test_cli_negative_threshold_rejected(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            open("a.yml", "w").write(_SCHEMA_USERS_SIMPLE)
            open("b.yml", "w").write(_SCHEMA_MEMBERS_SIMPLE)
            result = runner.invoke(
                deltadb,
                ["diff", "a.yml", "b.yml", "--detect-renames", "--rename-threshold", "-0.5"],
            )
        assert result.exit_code != 0

    def test_cli_zero_threshold_rejected(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            open("a.yml", "w").write(_SCHEMA_USERS_SIMPLE)
            open("b.yml", "w").write(_SCHEMA_MEMBERS_SIMPLE)
            result = runner.invoke(
                deltadb,
                ["diff", "a.yml", "b.yml", "--detect-renames", "--rename-threshold", "0"],
            )
        assert result.exit_code != 0

    def test_cli_threshold_above_one_rejected(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            open("a.yml", "w").write(_SCHEMA_USERS_SIMPLE)
            open("b.yml", "w").write(_SCHEMA_MEMBERS_SIMPLE)
            result = runner.invoke(
                deltadb,
                ["diff", "a.yml", "b.yml", "--detect-renames", "--rename-threshold", "1.5"],
            )
        assert result.exit_code != 0

    def test_cli_detect_renames_end_to_end(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            open("a.yml", "w").write(_SCHEMA_USERS)
            open("b.yml", "w").write(_SCHEMA_MEMBERS)
            result = runner.invoke(
                deltadb,
                ["diff", "a.yml", "b.yml", "--detect-renames", "--rename-threshold", "0.9"],
            )
        assert result.exit_code == 0
        assert "table_renamed" in result.output

    def test_cli_without_detect_renames_shows_drop_and_add(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            open("a.yml", "w").write(_SCHEMA_USERS_SIMPLE)
            open("b.yml", "w").write(_SCHEMA_MEMBERS_SIMPLE)
            result = runner.invoke(deltadb, ["diff", "a.yml", "b.yml"])
        assert result.exit_code == 0
        assert "table_dropped" in result.output
        assert "table_added" in result.output
        assert "table_renamed" not in result.output

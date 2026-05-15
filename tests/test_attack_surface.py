"""Attack surface tests — think like an attacker.

Each test documents a specific attack vector, whether it is blocked (must
stay blocked) or was open and has been fixed (regression guard).
"""
import os
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from deltadb.cli import deltadb
from deltadb.diff.changes import Change, ChangeType
from deltadb.exceptions import LoaderError, SecurityError
from deltadb.generator.dialects import Dialect
from deltadb.generator.sql_generator import SqlGenerator
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table
from deltadb.security.path_safety import validate_input_path, validate_output_path
from deltadb.security.yaml_safety import safe_load_yaml

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# ---------------------------------------------------------------------------
# ATTACK: YAML type:null bypass
# ---------------------------------------------------------------------------

class TestYamlTypeNull:
    """YAML key 'type: null' has the key present so the 'type not in col'
    check passes, then str(None)='None' passed the regex before the fix."""

    def test_null_type_rejected(self, tmp_path):
        f = tmp_path / "null_type.yml"
        f.write_text(
            "tables:\n"
            "  t:\n"
            "    columns:\n"
            "      - name: id\n"
            "        type: null\n"
        )
        with pytest.raises((LoaderError, SecurityError)):
            safe_load_yaml(str(f))

    def test_none_string_type_rejected(self, tmp_path):
        f = tmp_path / "none_type.yml"
        f.write_text(
            "tables:\n"
            "  t:\n"
            "    columns:\n"
            "      - name: id\n"
            "        type: None\n"
        )
        with pytest.raises((LoaderError, SecurityError)):
            safe_load_yaml(str(f))

    def test_empty_type_string_rejected(self, tmp_path):
        f = tmp_path / "empty_type.yml"
        f.write_text(
            "tables:\n"
            "  t:\n"
            "    columns:\n"
            "      - name: id\n"
            "        type: ''\n"
        )
        with pytest.raises((LoaderError, SecurityError)):
            safe_load_yaml(str(f))


# ---------------------------------------------------------------------------
# ATTACK: YAML anchor explosion (Billion Laughs style)
# ---------------------------------------------------------------------------

class TestYamlAnchorExplosion:
    """A small YAML file with many alias references can expand to an
    arbitrarily large in-memory structure after safe_load, bypassing the
    10MB file-size guard."""

    def _make_anchor_schema(self, n_tables: int, tmp_path: Path) -> str:
        content = (
            "tables:\n"
            "  base: &base\n"
            "    columns:\n"
            "      - name: id\n"
            "        type: integer\n"
        )
        for i in range(n_tables):
            content += f"  t{i}: *base\n"
        f = tmp_path / "anchors.yml"
        f.write_text(content)
        return str(f)

    def test_excessive_tables_rejected(self, tmp_path):
        path = self._make_anchor_schema(600, tmp_path)
        with pytest.raises((SecurityError, LoaderError), match="[Tt]able"):
            safe_load_yaml(path)

    def test_normal_table_count_accepted(self, tmp_path):
        path = self._make_anchor_schema(10, tmp_path)
        result = safe_load_yaml(path)
        assert len(result["tables"]) == 11  # base + 10


# ---------------------------------------------------------------------------
# ATTACK: Symlink traversal — output path
# ---------------------------------------------------------------------------

class TestSymlinkTraversalOutput:
    """An attacker pre-creates output/ as a symlink pointing OUTSIDE cwd.
    Without the fix, validate_output_path passes (no '..', not absolute) and
    SQL is written to an external directory (e.g. /tmp/attacker/ or /etc/)."""

    def test_symlink_output_dir_pointing_outside_cwd_rejected(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        # external dir is completely outside cwd (tmp_path)
        with tempfile.TemporaryDirectory() as external:
            external_path = Path(external)
            link = tmp_path / "output"
            link.symlink_to(external_path)
            with pytest.raises(SecurityError, match="[Ss]ymlink|traversal"):
                validate_output_path("output/evil.sql")

    def test_symlink_output_file_pointing_outside_cwd_rejected(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        with tempfile.NamedTemporaryFile(suffix=".sql", delete=False) as ef:
            external_file = Path(ef.name)
        try:
            link = tmp_path / "migration.sql"
            link.symlink_to(external_file)
            with pytest.raises(SecurityError, match="[Ss]ymlink|traversal"):
                validate_output_path("migration.sql")
        finally:
            external_file.unlink(missing_ok=True)

    def test_normal_output_path_accepted(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = validate_output_path("migrations/001.sql")
        assert result.suffix == ".sql"
        assert not result.is_symlink()


# ---------------------------------------------------------------------------
# ATTACK: Symlink traversal — input path
# ---------------------------------------------------------------------------

class TestSymlinkTraversalInput:
    """An attacker symlinks a YAML filename to a file outside cwd
    (e.g. /etc/shadow). validate_input_path passes the string check (no '..', not
    absolute) but without the fix the file read accesses the symlink target."""

    def test_symlink_input_pointing_outside_cwd_rejected(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        with tempfile.NamedTemporaryFile(
            suffix=".yml", mode="w", delete=False
        ) as ef:
            ef.write("secret: data")
            external_file = Path(ef.name)
        try:
            link = tmp_path / "schema.yml"
            link.symlink_to(external_file)
            with pytest.raises(SecurityError, match="[Ss]ymlink|traversal"):
                validate_input_path("schema.yml")
        finally:
            external_file.unlink(missing_ok=True)

    def test_normal_input_path_accepted(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "schema.yml"
        f.write_text("tables: {}")
        validate_input_path("schema.yml")


# ---------------------------------------------------------------------------
# ATTACK: Rich markup injection via CLI source/target display
# ---------------------------------------------------------------------------

class TestRichMarkupInjection:
    """When source or target is a file path containing Rich markup tags
    like [bold red], those tags must be escaped before console.print to
    prevent terminal control injection."""

    def test_rich_tags_in_source_path_escaped(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            schema_a = "tests/fixtures/schema_a.yml"
            evil_name = "[bold red]pwned[/bold red].yml"
            result = runner.invoke(
                deltadb,
                ["diff", schema_a, evil_name],
                catch_exceptions=False,
            )
            output = result.output
            assert "[bold red]" not in output
            assert "pwned" in output or result.exit_code != 0

    def test_rich_tags_in_output_path_escaped(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            schema_a = os.path.join(
                os.path.dirname(__file__), "fixtures", "schema_a.yml"
            )
            schema_b = os.path.join(
                os.path.dirname(__file__), "fixtures", "schema_b.yml"
            )
            result = runner.invoke(
                deltadb,
                ["diff", schema_a, schema_b, "--output",
                 "[bold]evil[/bold].sql"],
                catch_exceptions=False,
            )
            output = result.output
            assert "[bold]" not in output


# ---------------------------------------------------------------------------
# ATTACK: FK on_delete injection via case mismatch
# ---------------------------------------------------------------------------

class TestFKActionValidation:
    """on_delete and on_update must be validated against an allowlist.
    Lowercase values should be rejected or normalized safely."""

    def test_fk_action_lowercase_cascade_accepted_and_normalized(self, tmp_path):
        # Lowercase FK actions are normalized to uppercase — permissive for usability
        # but the sql_generator safe_on_action filter normalizes before rendering.
        f = tmp_path / "fk_lower.yml"
        f.write_text(
            "tables:\n"
            "  orders:\n"
            "    columns:\n"
            "      - name: id\n"
            "        type: integer\n"
            "      - name: user_id\n"
            "        type: integer\n"
            "    foreign_keys:\n"
            "      - name: fk_u\n"
            "        columns: [user_id]\n"
            "        referred_table: users\n"
            "        referred_columns: [id]\n"
            "        on_delete: CASCADE\n"
        )
        result = safe_load_yaml(str(f))
        fk = result["tables"]["orders"]["foreign_keys"][0]
        assert fk["on_delete"] == "CASCADE"

    def test_fk_action_injection_rejected(self, tmp_path):
        f = tmp_path / "fk_inject.yml"
        f.write_text(
            "tables:\n"
            "  orders:\n"
            "    columns:\n"
            "      - name: id\n"
            "        type: integer\n"
            "      - name: user_id\n"
            "        type: integer\n"
            "    foreign_keys:\n"
            "      - name: fk_u\n"
            "        columns: [user_id]\n"
            "        referred_table: users\n"
            "        referred_columns: [id]\n"
            "        on_delete: 'CASCADE; DROP TABLE users;--'\n"
        )
        with pytest.raises(SecurityError):
            safe_load_yaml(str(f))

    def test_sql_generator_on_action_injection_blocked(self):
        col = Column(name="user_id", type="integer", nullable=False)
        ref_col = Column(name="id", type="integer", nullable=False)
        fk = ForeignKey(
            name="fk_u",
            columns=("user_id",),
            referred_table="users",
            referred_columns=("id",),
            on_delete="CASCADE; DROP TABLE users;--",
        )
        tbl = Table(
            name="orders",
            columns=(col,),
            foreign_keys=(fk,),
        )
        schema = SchemaModel(
            tables={"orders": tbl, "users": Table(
                name="users", columns=(ref_col,)
            )}
        )
        change = Change(
            type=ChangeType.FK_ADDED,
            table="orders",
            new_value=fk,
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)


# ---------------------------------------------------------------------------
# ATTACK: Connection string with unsupported scheme
# ---------------------------------------------------------------------------

class TestConnectionStringScheme:
    """Only postgresql, mysql, sqlite are allowed. Other schemes (ftp, file,
    ldap, javascript) must be rejected before any connection attempt."""

    @pytest.mark.parametrize("scheme", [
        "ftp://user:pass@host/db",
        "file:///etc/passwd",
        "ldap://host/dc=evil",
        "javascript://host/;alert(1)",
        "http://attacker.com/evil",
    ])
    def test_unsupported_scheme_rejected(self, scheme):
        from deltadb.loader.db_loader import DbLoader
        with pytest.raises(SecurityError):
            DbLoader(scheme)


# ---------------------------------------------------------------------------
# ATTACK: Oversized column count per table
# ---------------------------------------------------------------------------

class TestColumnCountLimit:
    """A table with thousands of columns should be rejected to prevent
    memory exhaustion during diff and SQL generation."""

    def test_excessive_columns_rejected(self, tmp_path):
        cols = "\n".join(
            f"      - name: col_{i}\n        type: integer"
            for i in range(600)
        )
        f = tmp_path / "wide.yml"
        f.write_text(
            f"tables:\n  t:\n    columns:\n{cols}\n"
        )
        with pytest.raises((SecurityError, LoaderError), match="[Cc]olumn"):
            safe_load_yaml(str(f))


# ---------------------------------------------------------------------------
# ATTACK: JSON output via --output extension detection
# ---------------------------------------------------------------------------

class TestOutputExtensionHandling:
    """Uppercase extensions like .SQL or .JSON must be handled consistently —
    either accepted or rejected clearly, never silently misrouted."""

    def test_uppercase_sql_extension_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SecurityError, match="[Uu]nsupported"):
            validate_output_path("migration.SQL")

    def test_uppercase_json_extension_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SecurityError, match="[Uu]nsupported"):
            validate_output_path("report.JSON")

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from deltadb.cli import deltadb, _DiffCommand, _SnapshotCommand

# Relative from project root — validate_input_path rejects absolute paths
SCHEMA_A = "tests/fixtures/schema_a.yml"
SCHEMA_B = "tests/fixtures/schema_b.yml"


@pytest.fixture()
def runner():
    return CliRunner()


def test_diff_rich_output(runner):
    result = runner.invoke(deltadb, ["diff", SCHEMA_A, SCHEMA_B])
    assert result.exit_code == 0, result.output
    assert "table" in result.output.lower() or "change" in result.output.lower()


def test_diff_output_sql_file(runner):
    out = "output/test_cli_migration.sql"
    try:
        result = runner.invoke(deltadb, ["diff", SCHEMA_A, SCHEMA_B, "--output", out])
        assert result.exit_code == 0, result.output
        content = Path(out).read_text()
        assert "UP" in content
        assert "DOWN" in content
    finally:
        Path(out).unlink(missing_ok=True)


def test_diff_no_destructive(runner):
    # schema_b → schema_a: products TABLE_DROPPED and users.phone COLUMN_DROPPED (both destructive)
    out = "output/test_cli_nodestructive.sql"
    try:
        result = runner.invoke(
            deltadb, ["diff", SCHEMA_B, SCHEMA_A, "--no-destructive", "--output", out]
        )
        assert result.exit_code == 0, result.output
        content = Path(out).read_text()
        # TABLE_DROPPED and COLUMN_DROPPED must be omitted from UP block
        assert "DROP TABLE" not in content
        assert "DROP COLUMN" not in content
    finally:
        Path(out).unlink(missing_ok=True)


def test_diff_format_json_stdout(runner):
    result = runner.invoke(deltadb, ["diff", SCHEMA_A, SCHEMA_B, "--format", "json"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)
    assert len(parsed) > 0
    assert "type" in parsed[0]


def test_diff_no_differences(runner):
    result = runner.invoke(deltadb, ["diff", SCHEMA_A, SCHEMA_A])
    assert result.exit_code == 0, result.output
    assert "No differences found" in result.output


def test_diff_missing_file(runner):
    result = runner.invoke(deltadb, ["diff", "does_not_exist.yml", SCHEMA_B])
    assert result.exit_code == 1
    assert "error" in result.output.lower()


def test_diff_path_traversal_rejected(runner):
    result = runner.invoke(
        deltadb, ["diff", SCHEMA_A, SCHEMA_B, "--output", "../../etc/evil.sql"]
    )
    assert result.exit_code == 1
    assert "security" in result.output.lower() or "error" in result.output.lower()


def test_snapshot_sqlite_stdout(runner, tmp_path):
    db_path = tmp_path / "test.db"
    import sqlite3

    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()

    result = runner.invoke(
        deltadb, ["snapshot", f"sqlite:///{db_path}"]
    )
    assert result.exit_code == 0, result.output
    assert "items" in result.output


class TestSnapshotCommand:
    def test_returns_schema_and_yaml(self):
        schema, yml_str = _SnapshotCommand().execute(SCHEMA_A)
        assert "users" in schema.tables
        assert "tables:" in yml_str

    def test_invalid_source_raises(self):
        from deltadb.exceptions import DeltaDbError
        with pytest.raises(DeltaDbError):
            _SnapshotCommand().execute("nonexistent_file.yml")


class TestDiffCommand:
    def test_returns_changes_and_schemas(self):
        changes, source_schema, target_schema = _DiffCommand().execute(
            SCHEMA_A, SCHEMA_B, detect_renames=False, rename_threshold=0.7
        )
        assert isinstance(changes, list)
        assert "users" in source_schema.tables
        assert "users" in target_schema.tables

    def test_rename_threshold_out_of_range_raises(self):
        with pytest.raises(ValueError, match="rename-threshold"):
            _DiffCommand().execute(
                SCHEMA_A, SCHEMA_B, detect_renames=True, rename_threshold=0.0
            )

    def test_identical_schemas_no_changes(self):
        changes, _, _ = _DiffCommand().execute(
            SCHEMA_A, SCHEMA_A, detect_renames=False, rename_threshold=0.7
        )
        assert changes == []

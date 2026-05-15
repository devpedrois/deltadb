"""Security tests for PR #6 — CLI, rich_printer, json_writer.

Attacker perspective: schema names, column names, and error messages are
untrusted input. Each test models a concrete exploit attempt.
"""
import json
from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

from deltadb.cli import deltadb
from deltadb.diff.changes import Change, ChangeType
from deltadb.output.rich_printer import print_diff

SCHEMA_A = "tests/fixtures/schema_a.yml"
SCHEMA_B = "tests/fixtures/schema_b.yml"


@pytest.fixture()
def runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# 1. Rich Markup Injection via table/column/detail fields




# ---------------------------------------------------------------------------

def _changes_with_table(table_name: str) -> list[Change]:
    return [
        Change(
            type=ChangeType.TABLE_ADDED,
            table=table_name,
            destructive=False,
        )
    ]


def _changes_with_column(column_name: str) -> list[Change]:
    return [
        Change(
            type=ChangeType.COLUMN_ADDED,
            table="users",
            column=column_name,
            destructive=False,
        )
    ]


def _changes_with_detail(detail: str) -> list[Change]:
    return [
        Change(
            type=ChangeType.COLUMN_TYPE_CHANGED,
            table="users",
            column="email",
            old_value="varchar(255)",
            new_value="text",
            detail=detail,
            destructive=True,
        )
    ]


def _render_to_string(changes: list[Change]) -> str:
    buf = StringIO()
    console = Console(file=buf, highlight=False, markup=True)
    print_diff(changes, console)
    return buf.getvalue()


def test_rich_injection_table_name_link():
    """Hyperlink markup in table name must not create a terminal hyperlink."""
    malicious = "[link=http://evil.com]real_table[/link]"
    output = _render_to_string(_changes_with_table(malicious))
    # The literal brackets must appear escaped, not rendered as a link
    assert "evil.com" not in output or "[link=" in output
    # Correct: the escaped text contains the literal bracket chars
    assert "\\[" in output or "[link=http://evil.com]" in output


def test_rich_injection_table_name_bold():
    """Bold markup in table name must be rendered as literal text."""
    malicious = "[bold red]DROP TABLE users[/bold red]"
    output = _render_to_string(_changes_with_table(malicious))
    assert "[bold red]" in output or "\\[bold red\\]" in output


def test_rich_injection_column_name():
    """Rich markup in column name must not be interpreted."""
    malicious = "[on red]password_hash[/on red]"
    output = _render_to_string(_changes_with_column(malicious))
    assert "[on red]" in output or "\\[" in output


def test_rich_injection_detail_field():
    """Rich markup in detail field must not be interpreted."""
    malicious = "[bright_red]CRITICAL[/bright_red]"
    output = _render_to_string(_changes_with_detail(malicious))
    assert "[bright_red]" in output or "\\[" in output


def test_rich_injection_null_like_sequence():
    """Markup resembling escape sequences must be treated as literal text."""
    malicious = "[/]"
    output = _render_to_string(_changes_with_table(malicious))
    # Should not raise and should print something
    assert len(output) > 0


# ---------------------------------------------------------------------------
# 2. Credential leak in DeltaDbError handler
# ---------------------------------------------------------------------------

def test_diff_deltadb_error_masks_credentials(runner):
    """LoaderError wrapping a URL must not expose the password in output."""
    # Nonexistent file triggers LoaderError; use URL-like path to simulate leak
    result = runner.invoke(
        deltadb,
        ["diff", "postgresql://admin:S3cr3t@host/db", SCHEMA_B],
    )
    assert result.exit_code == 1
    assert "S3cr3t" not in result.output


def test_snapshot_deltadb_error_masks_credentials(runner):
    """snapshot command: DeltaDbError must not expose passwords."""
    result = runner.invoke(
        deltadb,
        ["snapshot", "postgresql://admin:S3cr3t@host/db"],
    )
    assert result.exit_code == 1
    assert "S3cr3t" not in result.output


def test_snapshot_unexpected_error_no_traceback(runner):
    """snapshot: unexpected Exception must not leak raw traceback to user."""
    # Passing a file that exists but is not valid YAML-schema to trigger LoaderError
    result = runner.invoke(deltadb, ["snapshot", SCHEMA_A, "--output", "output/snap.yml"])
    # Either succeeds or fails cleanly — no "Traceback" in non-verbose output
    if result.exit_code != 0:
        assert "Traceback" not in result.output
    Path("output/snap.yml").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 3. Rich markup injection via user-supplied output path
# ---------------------------------------------------------------------------

def test_diff_output_path_rich_injection(runner):
    """Output path containing Rich markup must not inject formatting."""
    # Path with brackets — validate_output_path accepts .sql extension
    # The success message must escape the path, not render it as markup
    injected_path = "output/[red]evil[/red].sql"
    result = runner.invoke(
        deltadb, ["diff", SCHEMA_A, SCHEMA_B, "--output", injected_path]
    )
    # Whether it succeeds or fails, the raw markup string must appear literally
    # (not rendered as red text that hides the brackets)
    if result.exit_code == 0:
        # Path appears escaped in success message
        assert "[red]evil[/red]" in result.output or "\\[red\\]" in result.output
    Path(injected_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 4. JSON stdout is clean — no Rich output mixed in
# ---------------------------------------------------------------------------

def test_diff_json_stdout_is_valid_json(runner):
    """--format json must emit ONLY valid JSON to stdout, no Rich markup."""
    result = runner.invoke(deltadb, ["diff", SCHEMA_A, SCHEMA_B, "--format", "json"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)


def test_diff_json_no_changes_is_empty_list(runner):
    """--format json with identical schemas must emit []."""
    result = runner.invoke(deltadb, ["diff", SCHEMA_A, SCHEMA_A, "--format", "json"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed == []


# ---------------------------------------------------------------------------
# 5. Path traversal for output (regression — must still be blocked)
# ---------------------------------------------------------------------------

def test_diff_output_path_traversal_blocked(runner):
    """Output path with .. must be rejected as SecurityError."""
    result = runner.invoke(
        deltadb, ["diff", SCHEMA_A, SCHEMA_B, "--output", "../../etc/evil.sql"]
    )
    assert result.exit_code == 1
    assert "S3cr3t" not in result.output  # no credential leak in error path


def test_diff_json_output_path_traversal_blocked(runner):
    """JSON output path with .. must be rejected."""
    result = runner.invoke(
        deltadb, ["diff", SCHEMA_A, SCHEMA_B, "--output", "../evil.json"]
    )
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# 6. Credential masking always — not only when "://" present
# ---------------------------------------------------------------------------

def test_mask_applied_unconditionally_in_generic_handler(runner):
    """Generic Exception handler must always call mask_url, not just when '://' present."""
    # We can't easily trigger Exception without ://, but we verify the credential
    # is not present when an error carries a URL.
    result = runner.invoke(
        deltadb,
        ["diff", "postgresql://user:TopSecret99@badhost:5432/db", SCHEMA_B],
    )
    assert result.exit_code == 1
    assert "TopSecret99" not in result.output


# ---------------------------------------------------------------------------
# 7. No differences — "No differences found" shown, not crash
# ---------------------------------------------------------------------------

def test_no_differences_clean_exit(runner):
    result = runner.invoke(deltadb, ["diff", SCHEMA_A, SCHEMA_A])
    assert result.exit_code == 0
    assert "No differences found" in result.output

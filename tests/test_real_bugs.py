"""
Bug-hunting tests — designed to find REAL failures, not confirm happy paths.

Each test documents the expected correct behavior and why the current code
violates it. Tests are grouped by bug. Run `pytest tests/test_real_bugs.py -v`
to see which bugs are still present.
"""

import pytest

from deltadb.exceptions import SecurityError
from deltadb.security.identifiers import (
    quote_identifier,
    validate_column_type,
    validate_identifier,
)
from deltadb.security.path_safety import validate_output_path

# ── Bug 1: xp_ false positive ────────────────────────────────────────────────
#
# DANGEROUS_PATTERNS includes "xp_" to block MSSQL xp_cmdshell.
# The substring check fires on ANY identifier containing "xp_" anywhere,
# blocking completely valid names like exp_date, my_exp_table.
# The regex ^[a-zA-Z_][a-zA-Z0-9_]*$ already blocks all real injection.
# xp_cmdshell would be quoted ("xp_cmdshell") and safe in generated SQL.
# The xp_ blocklist only produces false positives without adding real defense.


def test_identifier_exp_date_valid():
    """exp_date is a legitimate column name — must not be rejected."""
    validate_identifier("exp_date")


def test_identifier_my_exp_table_valid():
    """my_exp_table contains 'xp_' as a substring — false positive."""
    validate_identifier("my_exp_table")


def test_identifier_exp_value_valid():
    validate_identifier("exp_value")


def test_identifier_helper_exp_data_valid():
    validate_identifier("helper_exp_data")


def test_identifier_axp_foo_valid():
    """axp_foo contains 'xp_' starting at position 1 — should be valid."""
    validate_identifier("axp_foo")


def test_identifier_xp_cmdshell_rejected():
    """xp_cmdshell must still be rejected — starts with xp_ and is MSSQL-specific.

    This verifies the fix doesn't drop all xp_ protection. The correct fix is
    to block identifiers that START with 'xp_', not contain it anywhere.
    """
    with pytest.raises(SecurityError):
        validate_identifier("xp_cmdshell")


def test_identifier_xp_alone_rejected():
    """Pure xp_ prefix must remain blocked."""
    with pytest.raises(SecurityError):
        validate_identifier("xp_anything")


# ── Bug 2: Absolute path bypass in validate_output_path ──────────────────────
#
# validate_output_path only blocks '..' components. An absolute path like
# /etc/passwd.sql has no '..' but escapes the working directory entirely.
# The function should enforce that output paths are relative or within CWD.


def test_absolute_path_rejected():
    """/etc/evil.sql has a valid .sql extension and no '..' — but must be rejected."""
    with pytest.raises(SecurityError, match="[Aa]bsolute|[Pp]ath"):
        validate_output_path("/etc/evil.sql")


def test_absolute_path_tmp_rejected():
    with pytest.raises(SecurityError):
        validate_output_path("/tmp/migration.sql")


def test_absolute_path_var_rejected():
    with pytest.raises(SecurityError):
        validate_output_path("/var/evil.sql")


def test_double_slash_absolute_rejected():
    """//etc/evil.sql is still an absolute path."""
    with pytest.raises(SecurityError):
        validate_output_path("//etc/evil.sql")


def test_relative_path_still_accepted(tmp_path, monkeypatch):
    """Relative paths within a safe location must continue to work."""
    monkeypatch.chdir(tmp_path)
    result = validate_output_path("output/migration.sql")
    assert result.suffix == ".sql"


# ── Bug 3: SQL keyword injection in column types ──────────────────────────────
#
# validate_column_type uses a regex that allows spaces and uppercase letters,
# which are needed for types like "double precision" and "character varying".
# However, the regex also accepts arbitrary SQL keywords like "DROP TABLE".
# The dangerous-pattern blocklist only checks for ";", "--", etc., not keywords.
# Result: "integer DROP TABLE users" passes all validation.


def test_column_type_drop_keyword_rejected():
    """'integer DROP TABLE' is not a SQL type — must be rejected."""
    with pytest.raises(SecurityError):
        validate_column_type("integer DROP TABLE")


def test_column_type_union_select_rejected():
    """UNION SELECT in a type field is SQL injection — must be rejected."""
    with pytest.raises(SecurityError):
        validate_column_type("int UNION SELECT password FROM users")


def test_column_type_alter_keyword_rejected():
    with pytest.raises(SecurityError):
        validate_column_type("varchar ALTER TABLE users")


def test_column_type_delete_keyword_rejected():
    with pytest.raises(SecurityError):
        validate_column_type("text DELETE FROM secrets")


def test_column_type_double_precision_still_accepted():
    """'double precision' is a legitimate multi-word PostgreSQL type."""
    validate_column_type("double precision")


def test_column_type_character_varying_still_accepted():
    """'character varying(255)' is a legitimate PostgreSQL type."""
    validate_column_type("character varying(255)")


def test_column_type_timestamp_without_time_zone_still_accepted():
    """'timestamp without time zone' is a legitimate PostgreSQL type."""
    validate_column_type("timestamp without time zone")


# ── Bug 4: quote_identifier silent failure on unknown dialect ─────────────────
#
# quote_identifier falls through to double-quote if dialect is not "mysql".
# For an unknown dialect like "oracle" or a typo like "postgresq", the caller
# gets silently incorrect SQL instead of an error indicating the bug.


def test_quote_identifier_unknown_dialect_raises():
    """Unknown dialect must raise an error, not silently return double-quoted SQL."""
    with pytest.raises((SecurityError, ValueError, KeyError)):
        quote_identifier("users", "oracle")


def test_quote_identifier_typo_dialect_raises():
    with pytest.raises((SecurityError, ValueError, KeyError)):
        quote_identifier("users", "postgresq")


def test_quote_identifier_empty_dialect_raises():
    with pytest.raises((SecurityError, ValueError, KeyError)):
        quote_identifier("users", "")


def test_quote_identifier_postgresql_unchanged():
    """Confirmed-valid dialects must still produce correct output."""
    assert quote_identifier("users", "postgresql") == '"users"'


def test_quote_identifier_mysql_unchanged():
    assert quote_identifier("users", "mysql") == "`users`"


def test_quote_identifier_sqlite_unchanged():
    assert quote_identifier("users", "sqlite") == '"users"'

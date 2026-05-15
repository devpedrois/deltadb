"""
Adversarial Audit — Principal Security Engineer perspective.

Vectors covered:
  V1 [CRITICAL] Default validation gap: DbLoader allows quotes in reflected
      defaults (nextval('seq'::regclass)), DiffEngine rejects them → tool
      crashes on real PostgreSQL databases with SERIAL/SEQUENCE columns.

  V2 [CRITICAL] FK on_delete / on_update silently ignored in diff → migrations
      never update referential actions even when explicitly changed.

  V3 [HIGH] RenameDetector O(n²) algorithmic DoS → 100x100 tables × 200 cols
      = 33 s confirmed. At MAX_TABLES/2 × MAX_COLUMNS_PER_TABLE: minutes+.

  V4 [MEDIUM] mask_url exception swallowing — bare except returns raw URL,
      exposing credentials when the URL string is malformed in unusual ways.

  V5 [MEDIUM] validate_column_type regex allows hyphen (-) in base type,
      and keyword check splits on whitespace only — "integer-drop" bypasses it.

Property-based tests (Hypothesis):
  PB1  validate_identifier: any string matching VALID_IDENTIFIER_RE must pass;
       any with illegal chars must fail.
  PB2  mask_url: never raises, never returns plaintext password for well-formed
       connection strings.
  PB3  validate_column_type: never hangs / raises unexpected exceptions for
       arbitrary inputs — only SecurityError or nothing.
  PB4  validate_output_path: never writes outside cwd; always raises for '..'
       and absolute paths.
"""

import re
import time

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from deltadb.diff.changes import Change, ChangeType
from deltadb.diff.engine import DiffEngine
from deltadb.diff.rename import RenameDetector
from deltadb.exceptions import SecurityError
from deltadb.generator.dialects import Dialect
from deltadb.generator.sql_generator import SqlGenerator
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table
from deltadb.security.credentials import mask_url
from deltadb.security.identifiers import (
    validate_column_type,
    validate_identifier,
)
from deltadb.security.path_safety import validate_output_path

# ─────────────────────────────────────────────────────────────────────────────
# V1 — Default validation gap (CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

class TestDefaultValidationGap:
    """DbLoader allows quotes via validate_reflected_default; DiffEngine
    rejects them via validate_default. Real PostgreSQL serial columns break.

    [Vetor Crítico]: A tool that crashes on every PostgreSQL schema with a
    SERIAL/BIGSERIAL column provides zero practical value and no migration
    output. The inconsistency between the two validation layers is architectural:
    the same data object (Column.default) is validated with different rules
    depending on which code path reaches it first.

    [Patch de Hardening]: DiffEngine._validate_schema must call
    validate_reflected_default instead of validate_default because at that
    point the schema may already have been filtered by DbLoader's stricter-
    at-the-source layer. The statement-level injections (;, --, /*, null bytes)
    are blocked by both functions; only single/double quotes differ.
    """

    def _schema_with_default(self, default: str) -> SchemaModel:
        col = Column(
            name="id", type="integer", nullable=False,
            default=default, primary_key=True,
        )
        tbl = Table(name="users", columns=(col,))
        return SchemaModel(tables={"users": tbl}, dialect="postgresql")

    def test_sequence_default_accepted_by_diff_engine(self):
        """nextval('seq'::regclass) must pass DiffEngine after the patch."""
        schema = self._schema_with_default("nextval('users_id_seq'::regclass)")
        DiffEngine()._validate_schema(schema)  # must not raise

    def test_quoted_literal_default_accepted_by_diff_engine(self):
        """A reflected default with quotes must pass DiffEngine after the patch."""
        schema = self._schema_with_default("'active'")
        DiffEngine()._validate_schema(schema)  # must not raise

    def test_current_timestamp_default_is_safe(self):
        """CURRENT_TIMESTAMP has no quotes — must not raise."""
        schema = self._schema_with_default("CURRENT_TIMESTAMP")
        DiffEngine()._validate_schema(schema)  # must not raise

    def test_numeric_default_is_safe(self):
        """Pure numeric default must not raise."""
        schema = self._schema_with_default("0")
        DiffEngine()._validate_schema(schema)  # must not raise

    def test_sql_generator_still_rejects_injection_in_default(self):
        """
        The safe_default Jinja2 filter (validate_default) still blocks injection
        characters in defaults coming from YAML. Sequence expressions from DB
        reflection go through a different code path (DiffEngine now uses
        validate_reflected_default), but the template filter must remain strict.
        Semicolons and null bytes must still raise SecurityError at render time.
        """
        col = Column(
            name="id", type="integer", nullable=False,
            default="0; DROP TABLE users; --", primary_key=True,
        )
        tbl = Table(name="users", columns=(col,))
        schema = SchemaModel(tables={"users": tbl}, dialect="postgresql")
        change = Change(type=ChangeType.TABLE_ADDED, table="users", new_value=tbl)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    def test_diff_end_to_end_succeeds_on_pg_serial_schema(self):
        """
        End-to-end: after the patch, diffing a schema with a sequence default
        must succeed and produce SQL output containing CREATE TABLE.
        """
        schema = self._schema_with_default("nextval('users_id_seq'::regclass)")
        empty = SchemaModel(tables={}, dialect="postgresql")
        changes = DiffEngine().diff(empty, schema)
        assert len(changes) == 1
        assert changes[0].type == ChangeType.TABLE_ADDED


# ─────────────────────────────────────────────────────────────────────────────
# V2 — FK on_delete / on_update silently ignored (CRITICAL logic bug)
# ─────────────────────────────────────────────────────────────────────────────

class TestFKReferentialActionDiffGap:
    """compare_foreign_keys uses _fk_key = (columns, referred_table, referred_cols)
    which excludes on_delete / on_update. Changing CASCADE → RESTRICT generates
    zero changes: the migration omits the necessary DROP FK + ADD FK.

    [Vetor Crítico]: A DBA changes an FK from ON DELETE CASCADE (which deletes
    child rows automatically) to ON DELETE RESTRICT (which prevents parent
    deletion). deltadb computes zero changes and generates no migration SQL.
    The deployed database retains CASCADE semantics silently — a data integrity
    breach with no warning.

    [Patch de Hardening]: Add on_delete and on_update to _fk_key in
    comparators.py so that a change in referential action triggers DROP + ADD.
    Normalise both values to upper-case before comparison to avoid false
    positives when case differs between source and target schemas.
    """

    @staticmethod
    def _make_schema(on_delete: str) -> SchemaModel:
        ref_col = Column(name="id", type="integer", nullable=False, primary_key=True)
        fk_col = Column(name="user_id", type="integer", nullable=False)
        fk = ForeignKey(
            name="fk_orders_user",
            columns=("user_id",),
            referred_table="users",
            referred_columns=("id",),
            on_delete=on_delete,
        )
        return SchemaModel(tables={
            "users": Table(name="users", columns=(ref_col,)),
            "orders": Table(name="orders", columns=(ref_col, fk_col), foreign_keys=(fk,)),
        }, dialect="postgresql")

    def test_cascade_to_restrict_generates_drop_and_add(self):
        """After the patch: CASCADE → RESTRICT must generate DROP FK + ADD FK."""
        source = self._make_schema("CASCADE")
        target = self._make_schema("RESTRICT")
        changes = DiffEngine().diff(source, target)
        fk_changes = [c for c in changes if c.type in (ChangeType.FK_ADDED, ChangeType.FK_DROPPED)]
        assert len(fk_changes) == 2, (
            f"Expected DROP FK + ADD FK (2 changes), got {len(fk_changes)}: "
            f"{[c.type.value for c in fk_changes]}"
        )

    def test_set_null_to_no_action_generates_drop_and_add(self):
        """After the patch: SET NULL → NO ACTION must generate DROP FK + ADD FK."""
        source = self._make_schema("SET NULL")
        target = self._make_schema("NO ACTION")
        changes = DiffEngine().diff(source, target)
        fk_changes = [c for c in changes if c.type in (ChangeType.FK_ADDED, ChangeType.FK_DROPPED)]
        assert len(fk_changes) == 2, (
            f"Expected 2 FK changes, got {len(fk_changes)}"
        )

    def test_same_action_produces_no_changes(self):
        """Baseline: same action must correctly produce zero FK changes."""
        source = self._make_schema("CASCADE")
        target = self._make_schema("CASCADE")
        changes = DiffEngine().diff(source, target)
        fk_changes = [c for c in changes if c.type in (ChangeType.FK_ADDED, ChangeType.FK_DROPPED)]
        assert len(fk_changes) == 0

    def test_adding_on_delete_to_fk_without_it_is_now_detected(self):
        """After the patch: None → CASCADE on_delete must generate DROP FK + ADD FK."""
        ref_col = Column(name="id", type="integer", nullable=False, primary_key=True)
        fk_col = Column(name="user_id", type="integer", nullable=False)
        fk_no_action = ForeignKey(
            name="fk_orders_user", columns=("user_id",),
            referred_table="users", referred_columns=("id",), on_delete=None,
        )
        fk_cascade = ForeignKey(
            name="fk_orders_user", columns=("user_id",),
            referred_table="users", referred_columns=("id",), on_delete="CASCADE",
        )
        source = SchemaModel(tables={
            "users": Table(name="users", columns=(ref_col,)),
            "orders": Table(name="orders", columns=(ref_col, fk_col), foreign_keys=(fk_no_action,)),
        }, dialect="postgresql")
        target = SchemaModel(tables={
            "users": Table(name="users", columns=(ref_col,)),
            "orders": Table(name="orders", columns=(ref_col, fk_col), foreign_keys=(fk_cascade,)),
        }, dialect="postgresql")
        changes = DiffEngine().diff(source, target)
        fk_changes = [c for c in changes if c.type in (ChangeType.FK_ADDED, ChangeType.FK_DROPPED)]
        assert len(fk_changes) == 2, (
            f"Expected DROP FK + ADD FK (2 changes), got {len(fk_changes)}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# V3 — RenameDetector O(n²) algorithmic DoS (HIGH)
# ─────────────────────────────────────────────────────────────────────────────

class TestRenameDetectorDoS:
    """RenameDetector._detect_table_renames is O(n_dropped × n_added).
    Each comparison calls SequenceMatcher on signature strings of length
    O(n_columns × avg_sig_len). Real-world cost is O(n² × m²).

    [Vetor Crítico]: An attacker (or a real schema migration) provides a YAML
    with ~250 dropped tables and ~250 added tables, each with many columns.
    Within MAX_TABLES=500 and MAX_COLUMNS_PER_TABLE=300, the comparison takes
    minutes. Confirmed: 100×100 with 200 cols = 33 seconds.

    [Patch de Hardening]:
    1. Add a per-invocation timeout (e.g. 5 s via threading.Timer or signal).
    2. OR short-circuit: if n_dropped × n_added > RENAME_COMPARE_LIMIT (e.g.
       2500), skip rename detection and emit a warning.
    3. Pre-filter candidates using a fast heuristic (column-count equality)
       before running SequenceMatcher.
    """

    @staticmethod
    def _make_table(name: str, n_cols: int) -> Table:
        cols = tuple(
            Column(name=f"col_{i}", type="varchar(255)", nullable=True)
            for i in range(n_cols)
        )
        return Table(name=name, columns=cols)

    def test_moderate_load_completes_in_reasonable_time(self):
        """20×20 tables × 50 cols must finish under 2 s."""
        dropped = [
            Change(type=ChangeType.TABLE_DROPPED, table=f"src_{i}",
                   old_value=self._make_table(f"src_{i}", 50))
            for i in range(20)
        ]
        added = [
            Change(type=ChangeType.TABLE_ADDED, table=f"tgt_{i}",
                   new_value=self._make_table(f"tgt_{i}", 50))
            for i in range(20)
        ]
        start = time.monotonic()
        RenameDetector(threshold=0.7).apply(dropped + added)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"RenameDetector too slow at 20×20×50: {elapsed:.2f}s"

    def test_dos_blocked_above_pair_limit(self):
        """After the patch: 51×51 = 2601 pairs > MAX_RENAME_COMPARE_PAIRS(2500).
        RenameDetector must skip comparison and return no rename changes, not hang.
        """
        dropped = [
            Change(type=ChangeType.TABLE_DROPPED, table=f"src_{i}",
                   old_value=self._make_table(f"src_{i}", 200))
            for i in range(51)
        ]
        added = [
            Change(type=ChangeType.TABLE_ADDED, table=f"tgt_{i}",
                   new_value=self._make_table(f"tgt_{i}", 200))
            for i in range(51)
        ]
        start = time.monotonic()
        result = RenameDetector(threshold=0.7).apply(dropped + added)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"Pair-limit guard took too long: {elapsed:.2f}s"
        rename_changes = [c for c in result if c.type == ChangeType.TABLE_RENAMED]
        assert len(rename_changes) == 0

    def test_zero_threshold_rejected_by_detector(self):
        """threshold=0.0 would match every pair → disables destructive detection."""
        with pytest.raises(ValueError, match="threshold"):
            RenameDetector(threshold=0.0)

    def test_threshold_exactly_one_accepted(self):
        """threshold=1.0 (only identical signatures match) must be accepted."""
        RenameDetector(threshold=1.0)  # must not raise


# ─────────────────────────────────────────────────────────────────────────────
# V4 — mask_url exception swallowing (MEDIUM)
# ─────────────────────────────────────────────────────────────────────────────

class TestMaskUrlExceptionSwallowing:
    """mask_url wraps the entire body in try/except Exception: return str(url).
    If the URL is a non-string type that str() re-raises, or if an internal
    logic branch raises unexpectedly, the raw URL (with credentials) is returned.

    [Vetor Crítico]: Any code path that passes a non-string object to mask_url
    (e.g. a SQLAlchemy URL object, an Exception subclass whose str() embeds the
    URL) silently returns the raw representation including the password.

    [Patch de Hardening]: Remove the bare except and let callers handle errors
    explicitly. Replace with a narrow except on AttributeError/TypeError and
    log the failure, returning a generic placeholder like '[URL MASKED ERROR]'
    instead of str(url).
    """

    def test_mask_url_with_string_password_containing_slash(self):
        """Password with '/' inside must still be masked."""
        url = "postgresql://user:sec/ret@host/db"
        result = mask_url(url)
        assert "sec/ret" not in result
        assert "****" in result

    def test_mask_url_with_string_password_containing_at(self):
        """Password with '@' inside must be masked (last @ is the delimiter)."""
        url = "mysql://user:p@ss@host/db"
        result = mask_url(url)
        assert "p@ss" not in result
        assert "****" in result

    def test_mask_url_no_scheme_returns_raw(self):
        """Path without scheme has no credentials — return as-is."""
        result = mask_url("schema.yml")
        assert result == "schema.yml"

    def test_mask_url_non_string_object_returns_something_safe(self):
        """Non-string input must not raise and must return a string."""
        class WeirdObj:
            def __str__(self):
                return "postgresql://admin:WeirdSecret@host/db"
        result = mask_url(WeirdObj())  # type: ignore[arg-type]
        # Current behaviour: mask_url calls str(url) which triggers __str__,
        # then the URL is processed normally → password should be masked.
        assert "WeirdSecret" not in result

    def test_mask_url_exception_in_str_returns_safe_placeholder(self):
        """After the patch: when __str__ raises, mask_url returns a safe
        placeholder instead of re-raising and potentially exposing credentials.
        """
        class ExplodingStr:
            def __str__(self):
                raise RuntimeError("cannot stringify")

        result = mask_url(ExplodingStr())  # type: ignore[arg-type]
        assert isinstance(result, str)
        assert result == "[CREDENTIAL REDACTED]"


# ─────────────────────────────────────────────────────────────────────────────
# V5 — validate_column_type hyphen bypass (MEDIUM)
# ─────────────────────────────────────────────────────────────────────────────

class TestColumnTypeHyphenBypass:
    """VALID_TYPE_RE allows hyphens: [a-zA-Z][a-zA-Z0-9 _-]*.
    The SQL keyword check splits on whitespace, not hyphens.
    'integer-drop' passes the regex and the keyword split produces
    a single word 'integer-drop' which is not in _TYPE_SQL_KEYWORDS.

    [Vetor Crítico]: In practice, 'integer-drop' is not valid SQL — the
    generated DDL would be rejected by the database engine. However, the
    security claim is that all column type values are validated before SQL
    generation. 'integer-drop' bypasses the keyword check, invalidating
    the defense-in-depth claim and potentially causing confusing SQL errors
    rather than a clear SecurityError.

    [Patch de Hardening]: Split the keyword check on BOTH whitespace AND
    hyphens, or restrict the regex to not allow hyphens in base types
    (only valid in 'user-defined' SQLAlchemy reflected type strings, which
    can be handled as a specific allowlist entry rather than a general rule).
    """

    def test_hyphen_bypass_blocked_after_patch(self):
        """After the patch: 'integer-drop' must raise SecurityError because
        splitting on hyphens yields the token 'drop' which is in _TYPE_SQL_KEYWORDS.
        """
        with pytest.raises(SecurityError, match="drop"):
            validate_column_type("integer-drop")

    def test_hyphen_type_user_defined_legitimate(self):
        """'user-defined' is a legitimate SQLAlchemy reflected type — must pass."""
        validate_column_type("user-defined")  # must not raise (SQLAlchemy reflects this)

    def test_type_with_only_hyphens_rejected(self):
        """'---' has no letter prefix — rejected by regex."""
        with pytest.raises(SecurityError):
            validate_column_type("---")

    def test_type_starting_with_digit_rejected(self):
        """Column type cannot start with digit."""
        with pytest.raises(SecurityError):
            validate_column_type("1integer")


# ─────────────────────────────────────────────────────────────────────────────
# Property-Based Tests (Hypothesis)
# ─────────────────────────────────────────────────────────────────────────────

_VALID_ID_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")  # mirrors VALID_IDENTIFIER_RE

# Strategy: identifiers that match the allowlist regex exactly
_valid_identifier_strategy = st.from_regex(
    r"[a-zA-Z_][a-zA-Z0-9_]{0,50}", fullmatch=True
).filter(lambda s: not s.lower().startswith("xp_"))

# Strategy: strings that violate the allowlist (contain at least one bad char)
_invalid_identifier_strategy = st.text(
    alphabet=st.characters(
        blacklist_categories=("Lu", "Ll", "Nd"),
        blacklist_characters="_",
        whitelist_characters=";'\"/*\n\r\x00\\-+@!%^&()",
    ),
    min_size=1,
    max_size=30,
).filter(lambda s: s.strip() and not _VALID_ID_RE.match(s))


class TestIdentifierPropertyBased:
    """PB1 — validate_identifier must accept all strings that match the
    allowlist regex (minus the xp_ prefix) and reject all others."""

    @given(_valid_identifier_strategy)
    @settings(max_examples=500)
    def test_valid_identifiers_always_accepted(self, name: str):
        assume(len(name) <= 128)
        validate_identifier(name)  # must not raise

    @given(_invalid_identifier_strategy)
    @settings(max_examples=500)
    def test_invalid_identifiers_always_rejected(self, name: str):
        with pytest.raises(SecurityError):
            validate_identifier(name)

    @given(st.text(min_size=129, max_size=300))
    @settings(max_examples=200)
    def test_oversized_identifiers_always_rejected(self, name: str):
        with pytest.raises(SecurityError):
            validate_identifier(name)

    @given(st.just(""))
    def test_empty_string_rejected(self, name: str):
        with pytest.raises(SecurityError):
            validate_identifier(name)

    @given(st.text(alphabet="   \t\n\r", min_size=1, max_size=10))
    @settings(max_examples=50)
    def test_whitespace_only_rejected(self, name: str):
        with pytest.raises(SecurityError):
            validate_identifier(name)


class TestMaskUrlPropertyBased:
    """PB2 — mask_url must never raise and must never return a string that
    contains the plaintext password for well-formed connection URLs."""

    @given(
        # Restrict user/password/host to safe ASCII alnum to avoid false positives
        # from extremely unusual characters that confuse URL parsing heuristics.
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_", min_size=1, max_size=20),
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%^*",
            min_size=4,
            max_size=25,
        ),
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=3, max_size=20),
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=3, max_size=15),
        st.sampled_from(["postgresql", "mysql", "sqlite"]),
    )
    @settings(max_examples=300)
    def test_mask_url_never_raises(self, user, password, host, db, scheme):
        url = f"{scheme}://{user}:{password}@{host}/{db}"
        result = mask_url(url)
        assert isinstance(result, str)
        # The plaintext `:password` substring must not appear in the masked output.
        # We check the literal colon-prefix to avoid false positives when the password
        # string also appears in the username or database name fields.
        assert f":{password}@" not in result, (
            f"Password '{password}' leaked in masked URL: '{result}'"
        )

    @given(st.text(min_size=0, max_size=200))
    @settings(max_examples=200)
    def test_mask_url_arbitrary_input_never_raises(self, s: str):
        try:
            result = mask_url(s)
            assert isinstance(result, str)
        except Exception as exc:
            pytest.fail(f"mask_url raised {type(exc).__name__} on input {s!r}: {exc}")


class TestColumnTypePropertyBased:
    """PB3 — validate_column_type must never hang and must only raise SecurityError
    (never TypeError, RecursionError, or other unexpected exceptions)."""

    @given(st.text(min_size=0, max_size=200))
    @settings(max_examples=500, deadline=1000)
    def test_arbitrary_input_raises_only_security_error_or_nothing(self, s: str):
        try:
            validate_column_type(s)
        except SecurityError:
            pass
        except Exception as exc:
            pytest.fail(
                f"validate_column_type raised unexpected {type(exc).__name__} "
                f"on {s!r}: {exc}"
            )

    @given(
        st.from_regex(r"[a-zA-Z][a-zA-Z0-9]{1,20}", fullmatch=True)
    )
    @settings(max_examples=300)
    def test_simple_valid_types_accepted(self, t: str):
        # Simple word types (no SQL keywords) must be accepted
        assume(t.lower() not in {
            "drop", "delete", "insert", "update", "select", "union", "alter",
            "create", "truncate", "exec", "execute", "grant", "revoke",
            "table", "database", "schema", "index", "from", "where", "into",
            "join", "having", "order", "group", "by", "none", "null",
        })
        validate_column_type(t)  # must not raise


class TestOutputPathPropertyBased:
    """PB4 — validate_output_path must never write outside cwd. Any path with
    '..' or that is absolute must always raise SecurityError."""

    @given(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz_/", min_size=1, max_size=20),
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz_/", min_size=0, max_size=20),
    )
    @settings(max_examples=200)
    def test_path_with_dotdot_always_rejected(self, prefix: str, suffix: str):
        path = prefix + "/../" + suffix + "output.sql"
        with pytest.raises(SecurityError):
            validate_output_path(path)

    @given(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz_0123456789", min_size=1, max_size=30),
    )
    @settings(max_examples=200)
    def test_absolute_path_always_rejected(self, segment: str):
        abs_path = "/" + segment + ".sql"
        with pytest.raises(SecurityError):
            validate_output_path(abs_path)


# ─────────────────────────────────────────────────────────────────────────────
# Security Integration: Injection → Fail-Safe
# ─────────────────────────────────────────────────────────────────────────────

class TestFailSafeBehavior:
    """Verify the system fails loudly (SecurityError) rather than silently
    producing incorrect SQL when injected data reaches the generator layer."""

    def test_injected_table_name_in_change_raises_before_sql_render(self):
        """Change with injected table name must raise SecurityError, not emit SQL."""
        col = Column(name="id", type="integer", nullable=False, primary_key=True)
        tbl = Table(name="safe_table", columns=(col,))
        schema = SchemaModel(tables={"safe_table": tbl}, dialect="postgresql")
        injected_change = Change(
            type=ChangeType.TABLE_ADDED,
            table="safe_table; DROP TABLE users; --",
            new_value=tbl,
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([injected_change], schema)

    def test_injected_column_name_in_type_change_raises_before_sql_render(self):
        """For COLUMN_TYPE_CHANGED, change.column is placed directly into the
        template context as the identifier string. An injected column name here
        must raise SecurityError from the quote_id filter.
        """
        col = Column(name="id", type="integer", nullable=False, primary_key=True)
        tbl = Table(name="users", columns=(col,))
        schema = SchemaModel(tables={"users": tbl}, dialect="postgresql")
        injected_change = Change(
            type=ChangeType.COLUMN_TYPE_CHANGED,
            table="users",
            column="evil'; DROP TABLE users;--",
            old_value="integer",
            new_value="text",
            destructive=True,
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([injected_change], schema)

    def test_null_byte_in_table_name_raises_before_sql_render(self):
        """Null byte in table name must raise SecurityError, not produce SQL."""
        col = Column(name="id", type="integer", nullable=False, primary_key=True)
        tbl = Table(name="safe", columns=(col,))
        schema = SchemaModel(tables={"safe": tbl}, dialect="postgresql")
        change = Change(
            type=ChangeType.TABLE_ADDED,
            table="safe\x00evil",
            new_value=tbl,
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    def test_newline_in_column_type_raises_before_sql_render(self):
        """Newline in column type must raise SecurityError at validate_column_type."""
        with pytest.raises(SecurityError):
            validate_column_type("integer\nDROP TABLE users")

    def test_overlong_identifier_raises_before_sql_render(self):
        """Identifier over MAX_IDENTIFIER_LENGTH raises SecurityError."""
        with pytest.raises(SecurityError):
            validate_identifier("a" * 200)

    def test_xp_prefix_rejected(self):
        """MSSQL extended stored procedure prefix raises SecurityError."""
        with pytest.raises(SecurityError, match="xp_"):
            validate_identifier("xp_cmdshell")

    def test_diff_engine_validates_source_and_target_independently(self):
        """Even if source schema bypasses loader validation, DiffEngine re-validates."""
        # Construct a Table directly with an invalid column name (bypassing loader)
        bad_col = Column(name="id; DROP TABLE users", type="integer", nullable=False)
        bad_tbl = Table(name="users", columns=(bad_col,))
        bad_schema = SchemaModel(tables={"users": bad_tbl}, dialect="postgresql")
        empty_schema = SchemaModel(tables={}, dialect="postgresql")
        with pytest.raises(SecurityError):
            DiffEngine().diff(empty_schema, bad_schema)

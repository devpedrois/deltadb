"""
Adversarial bug-discovery tests.

Each test has a hypothesis: "the engine produces WRONG output here."
Tests that currently FAIL confirm the bug is real and unfixed.
After fixes, every test must pass — they define the correct contract.
"""
import pytest

from deltadb.diff.changes import ChangeType
from deltadb.diff.engine import DiffEngine
from deltadb.exceptions import DiffError, SecurityError
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, PrimaryKey, UniqueConstraint
from deltadb.model.index import Index
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _col(name: str, type_: str = "integer", **kw) -> Column:
    return Column(name=name, type=type_, **kw)


def _schema(*tables: Table) -> SchemaModel:
    return SchemaModel(tables={t.name: t for t in tables})


def _table(name: str, *cols: Column, **kw) -> Table:
    return Table(name=name, columns=tuple(cols), **kw)


EMPTY = SchemaModel(tables={})


@pytest.fixture
def engine() -> DiffEngine:
    return DiffEngine()


# ---------------------------------------------------------------------------
# BUG 1 — Named FK that changes columns silently generates 0 changes
#
# Hypothesis: DiffEngine matches named FKs by name only, never checks if the
# definition changed. A FK renamed to point at different columns produces 0
# FK changes. The SQL migration would be missing DROP + ADD, leaving the
# database with the wrong FK constraint.
# ---------------------------------------------------------------------------

class TestBug1_NamedFKModificationSilentlyIgnored:
    def test_named_fk_column_change_generates_drop_and_add(self, engine: DiffEngine) -> None:
        """Named FK 'fk_x' pointing at column 'a' changes to column 'b'.
        Must produce FK_DROPPED + FK_ADDED. Currently produces 0."""
        src_fk = ForeignKey(
            name="fk_x", columns=("a",),
            referred_table="users", referred_columns=("id",),
        )
        tgt_fk = ForeignKey(
            name="fk_x", columns=("b",),
            referred_table="users", referred_columns=("id",),
        )
        src = _schema(_table("orders", _col("a"), foreign_keys=(src_fk,)))
        tgt = _schema(_table("orders", _col("a"), _col("b"), foreign_keys=(tgt_fk,)))

        changes = engine.diff(src, tgt)

        fk_changes = [c for c in changes if "fk" in c.type.value]
        assert len(fk_changes) == 2, (
            f"Expected FK_DROPPED + FK_ADDED, got {len(fk_changes)}: {fk_changes}"
        )
        types = {c.type for c in fk_changes}
        assert ChangeType.FK_DROPPED in types
        assert ChangeType.FK_ADDED in types

    def test_named_fk_referred_table_change_generates_drop_and_add(self, engine: DiffEngine) -> None:
        """Named FK changes referred_table — must generate DROP + ADD."""
        src_fk = ForeignKey(
            name="fk_x", columns=("uid",),
            referred_table="users", referred_columns=("id",),
        )
        tgt_fk = ForeignKey(
            name="fk_x", columns=("uid",),
            referred_table="accounts", referred_columns=("id",),
        )
        src = _schema(_table("orders", _col("uid"), foreign_keys=(src_fk,)))
        tgt = _schema(_table("orders", _col("uid"), foreign_keys=(tgt_fk,)))

        changes = engine.diff(src, tgt)

        fk_changes = [c for c in changes if "fk" in c.type.value]
        assert len(fk_changes) == 2, f"Expected 2, got {fk_changes}"


# ---------------------------------------------------------------------------
# BUG 2 — Index modification (same name, different columns or uniqueness) ignored
#
# Hypothesis: compare_indexes only detects ADD (new name) and DROP (removed name).
# Two indexes with the same name but different columns or uniqueness flag are
# treated as identical. The migration misses DROP + ADD to apply the new definition.
# ---------------------------------------------------------------------------

class TestBug2_IndexModificationSilentlyIgnored:
    def test_index_column_change_generates_drop_and_add(self, engine: DiffEngine) -> None:
        """idx_x covers (email,) in source and (name,) in target.
        Must produce INDEX_DROPPED + INDEX_ADDED."""
        src_idx = Index(name="idx_x", columns=("email",), unique=False)
        tgt_idx = Index(name="idx_x", columns=("name",), unique=False)
        src = _schema(_table("users", _col("email"), _col("name"), indexes=(src_idx,)))
        tgt = _schema(_table("users", _col("email"), _col("name"), indexes=(tgt_idx,)))

        changes = engine.diff(src, tgt)

        idx_changes = [c for c in changes if "index" in c.type.value]
        assert len(idx_changes) == 2, f"Expected INDEX_DROPPED + INDEX_ADDED, got {idx_changes}"

    def test_index_uniqueness_toggle_generates_drop_and_add(self, engine: DiffEngine) -> None:
        """idx_x changes from non-unique to unique. Must produce DROP + ADD."""
        src_idx = Index(name="idx_x", columns=("email",), unique=False)
        tgt_idx = Index(name="idx_x", columns=("email",), unique=True)
        src = _schema(_table("users", _col("email"), indexes=(src_idx,)))
        tgt = _schema(_table("users", _col("email"), indexes=(tgt_idx,)))

        changes = engine.diff(src, tgt)

        idx_changes = [c for c in changes if "index" in c.type.value]
        assert len(idx_changes) == 2, f"Uniqueness toggle not detected: {idx_changes}"


# ---------------------------------------------------------------------------
# BUG 3 — Named UniqueConstraint modification silently ignored
#
# Same pattern as Bug 1/2: matched by name, definition changes never compared.
# ---------------------------------------------------------------------------

class TestBug3_NamedUCModificationSilentlyIgnored:
    def test_named_uc_column_change_generates_drop_and_add(self, engine: DiffEngine) -> None:
        """UC 'uq_x' on (email,) changes to (email, name). Must produce DROP + ADD."""
        src_uc = UniqueConstraint(name="uq_x", columns=("email",))
        tgt_uc = UniqueConstraint(name="uq_x", columns=("email", "name"))
        src = _schema(_table("users", _col("email"), _col("name"), unique_constraints=(src_uc,)))
        tgt = _schema(_table("users", _col("email"), _col("name"), unique_constraints=(tgt_uc,)))

        changes = engine.diff(src, tgt)

        uc_changes = [c for c in changes if "unique" in c.type.value]
        assert len(uc_changes) == 2, f"Expected DROP+ADD, got {uc_changes}"


# ---------------------------------------------------------------------------
# BUG 4 — _fk_key ignores referred_columns, causing collision
#
# Two unnamed FKs from the same source column(s) to different target columns
# of the same table have identical keys. One silently disappears in the dict.
# A real-world example: orders.user_id → users.id AND orders.user_id → users.email
# (composite key lookup on two different unique columns).
# ---------------------------------------------------------------------------

class TestBug4_FKKeyIgnoresReferredColumns:
    def test_two_unnamed_fks_different_referred_cols_both_detected(self, engine: DiffEngine) -> None:
        """Dropping one of two unnamed FKs with same (columns, referred_table)
        but different referred_columns must be detected."""
        fk1 = ForeignKey(
            name=None, columns=("uid",),
            referred_table="users", referred_columns=("id",),
        )
        fk2 = ForeignKey(
            name=None, columns=("uid",),
            referred_table="users", referred_columns=("email",),
        )
        src = _schema(_table("orders", _col("uid"), foreign_keys=(fk1, fk2)))
        tgt = _schema(_table("orders", _col("uid"), foreign_keys=(fk1,)))

        changes = engine.diff(src, tgt)

        fk_drops = [c for c in changes if c.type == ChangeType.FK_DROPPED]
        assert len(fk_drops) == 1, f"Expected 1 FK_DROPPED, got {fk_drops}"

    def test_fk_referred_column_change_detected_for_unnamed_fk(self, engine: DiffEngine) -> None:
        """Unnamed FK changing referred_columns from (id,) to (email,) must
        generate DROP + ADD, not 0 changes."""
        src_fk = ForeignKey(
            name=None, columns=("uid",),
            referred_table="users", referred_columns=("id",),
        )
        tgt_fk = ForeignKey(
            name=None, columns=("uid",),
            referred_table="users", referred_columns=("email",),
        )
        src = _schema(_table("orders", _col("uid"), foreign_keys=(src_fk,)))
        tgt = _schema(_table("orders", _col("uid"), foreign_keys=(tgt_fk,)))

        changes = engine.diff(src, tgt)

        fk_changes = [c for c in changes if "fk" in c.type.value]
        assert len(fk_changes) == 2, (
            f"FK referred_column change not detected: {fk_changes}"
        )


# ---------------------------------------------------------------------------
# BUG 5 — YAML integer/boolean default causes TypeError in DiffEngine
#
# YamlLoader stores col.get("default") as-is (int/bool) without str() conversion.
# Column.default is typed str | None, but Python allows the assignment.
# DiffEngine._validate_schema calls validate_default(col.default) which does
# len(value) — TypeError: object of type 'int' has no len().
# ---------------------------------------------------------------------------

class TestBug5_IntegerDefaultCausesTypeError:
    def test_integer_default_in_column_does_not_crash_diff_engine(self, engine: DiffEngine) -> None:
        """Column with integer default (as YAML would produce) must not TypeError."""
        col_with_int_default = Column(name="count", type="integer", default=0)
        schema = _schema(_table("t", col_with_int_default))
        changes = engine.diff(EMPTY, schema)
        assert any(c.table == "t" for c in changes)

    def test_boolean_default_in_column_does_not_crash_diff_engine(self, engine: DiffEngine) -> None:
        """Column with boolean default (as YAML would produce) must not TypeError."""
        col_with_bool_default = Column(name="active", type="boolean", default=True)
        schema = _schema(_table("t", col_with_bool_default))
        changes = engine.diff(EMPTY, schema)
        assert any(c.table == "t" for c in changes)

    def test_diff_with_none_to_int_default_change_does_not_crash(self, engine: DiffEngine) -> None:
        """COLUMN_DEFAULT_CHANGED where new_value is int must not TypeError."""
        src_col = Column(name="count", type="integer", default=None)
        tgt_col = Column(name="count", type="integer", default=0)
        src = _schema(_table("t", src_col))
        tgt = _schema(_table("t", tgt_col))
        changes = engine.diff(src, tgt)
        default_changes = [c for c in changes if c.type == ChangeType.COLUMN_DEFAULT_CHANGED]
        assert len(default_changes) == 1


# ---------------------------------------------------------------------------
# BUG 6 — PrimaryKey name and columns not validated in _validate_schema
#
# _validate_schema validates table names, column names, index names, FK names,
# and UC names — but skips table.primary_key entirely. A malicious PK name
# bypasses the independent trust boundary established by the diff engine.
# ---------------------------------------------------------------------------

class TestBug6_PrimaryKeyNotValidated:
    def test_malicious_pk_name_rejected_by_diff_engine(self, engine: DiffEngine) -> None:
        """PK name with SQL injection must be caught by _validate_schema."""
        evil_pk = PrimaryKey(name="pk; DROP TABLE users; --", columns=("id",))
        t = _table("users", _col("id"), primary_key=evil_pk)
        schema = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, schema)

    def test_malicious_pk_column_name_rejected_by_diff_engine(self, engine: DiffEngine) -> None:
        """PK columns with injection must be caught even if col.name passes."""
        evil_pk = PrimaryKey(name="pk_users", columns=("id; DROP TABLE x",))
        t = _table("users", _col("id"), primary_key=evil_pk)
        schema = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, schema)

    def test_valid_pk_passes_validation(self, engine: DiffEngine) -> None:
        """A legitimate PK must still work."""
        pk = PrimaryKey(name="pk_users", columns=("id",))
        t = _table("users", _col("id"), primary_key=pk)
        schema = _schema(t)
        changes = engine.diff(EMPTY, schema)
        assert len(changes) == 1


# ---------------------------------------------------------------------------
# BUG 7 — Duplicate FK names silently drop one, no DiffError raised
#
# compare_columns and compare_indexes call _check_duplicate_names, but
# compare_foreign_keys does not. When two FKs share a name, dict construction
# keeps only the last one. The first FK becomes invisible to the diff.
# ---------------------------------------------------------------------------

class TestBug7_DuplicateFKNamesNotDetected:
    def test_duplicate_fk_names_in_source_raises_diff_error(self, engine: DiffEngine) -> None:
        """Two FKs with the same name in source must raise DiffError.
        Silently keeping only one hides real schema changes."""
        fk1 = ForeignKey(
            name="fk_x", columns=("a",),
            referred_table="users", referred_columns=("id",),
        )
        fk2 = ForeignKey(
            name="fk_x", columns=("b",),
            referred_table="groups", referred_columns=("id",),
        )
        t = Table(
            name="orders",
            columns=(_col("a"), _col("b")),
            foreign_keys=(fk1, fk2),
        )
        schema = _schema(t)
        with pytest.raises(DiffError, match="[Dd]uplicate"):
            engine.diff(EMPTY, schema)

    def test_duplicate_uc_names_raises_diff_error(self, engine: DiffEngine) -> None:
        """Two UCs with the same name must raise DiffError."""
        uc1 = UniqueConstraint(name="uq_x", columns=("email",))
        uc2 = UniqueConstraint(name="uq_x", columns=("name",))
        t = Table(
            name="users",
            columns=(_col("email"), _col("name")),
            unique_constraints=(uc1, uc2),
        )
        schema = _schema(t)
        with pytest.raises(DiffError, match="[Dd]uplicate"):
            engine.diff(EMPTY, schema)


# ---------------------------------------------------------------------------
# BUG 8 — Column primary_key flag change not detected
#
# compare_columns compares type, nullable, and default. It does NOT compare
# primary_key or autoincrement. A column promoted to PK (or demoted) produces
# 0 changes, leaving the schema out of sync.
# ---------------------------------------------------------------------------

class TestBug8_ColumnPKFlagChangeNotDetected:
    def test_column_promoted_to_primary_key_detected(self, engine: DiffEngine) -> None:
        """Column changing from primary_key=False to True must generate a change."""
        src_col = Column(name="id", type="integer", primary_key=False)
        tgt_col = Column(name="id", type="integer", primary_key=True)
        src = _schema(_table("users", src_col))
        tgt = _schema(_table("users", tgt_col))

        changes = engine.diff(src, tgt)

        assert len(changes) > 0, "PK flag change produced 0 changes — schema will be wrong"

    def test_column_demoted_from_primary_key_detected(self, engine: DiffEngine) -> None:
        """Column changing from primary_key=True to False must generate a change."""
        src_col = Column(name="id", type="integer", primary_key=True)
        tgt_col = Column(name="id", type="integer", primary_key=False)
        src = _schema(_table("users", src_col))
        tgt = _schema(_table("users", tgt_col))

        changes = engine.diff(src, tgt)

        assert len(changes) > 0, "PK demotion produced 0 changes — schema will be wrong"


# ---------------------------------------------------------------------------
# BUG 9 — Named→unnamed FK produces FK_ADDED without FK_DROPPED
#
# Source has named FK 'fk_x'. Target has equivalent unnamed FK (same columns,
# same referred_table). The named FK is not in target_by_name so unmatched,
# but its key exists in target_by_key so it's not dropped. The unnamed target
# FK is not in source_by_key so it's added. Net result: FK_ADDED without
# FK_DROPPED. The SQL will fail — the unnamed FK already exists as 'fk_x'.
# ---------------------------------------------------------------------------

class TestBug9_NamedToUnnamedFKTransitionBroken:
    def test_removing_fk_name_does_not_generate_spurious_add(self, engine: DiffEngine) -> None:
        """Changing a named FK to unnamed (same columns, same target) should
        generate DROP + ADD (to rename) or 0 changes (if treated as equivalent).
        Getting only FK_ADDED without FK_DROPPED is a bug — SQL would fail."""
        named_fk = ForeignKey(
            name="fk_x", columns=("uid",),
            referred_table="users", referred_columns=("id",),
        )
        unnamed_fk = ForeignKey(
            name=None, columns=("uid",),
            referred_table="users", referred_columns=("id",),
        )
        src = _schema(_table("orders", _col("uid"), foreign_keys=(named_fk,)))
        tgt = _schema(_table("orders", _col("uid"), foreign_keys=(unnamed_fk,)))

        changes = engine.diff(src, tgt)

        fk_adds = [c for c in changes if c.type == ChangeType.FK_ADDED]
        fk_drops = [c for c in changes if c.type == ChangeType.FK_DROPPED]

        if fk_adds:
            assert fk_drops, (
                "FK_ADDED generated without FK_DROPPED — SQL will fail because "
                f"the named FK still exists. adds={fk_adds}, drops={fk_drops}"
            )

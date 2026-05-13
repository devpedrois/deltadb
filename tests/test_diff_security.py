"""
Security tests for the diff engine — Defense in Depth layer.

The diff engine is an independent trust boundary. Even if a loader already
validated identifiers, code that constructs SchemaModel directly (tests,
future loaders, adversarial input) must be caught here.
"""
import pytest

from deltadb.diff.engine import DiffEngine
from deltadb.exceptions import DiffError, SecurityError
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, UniqueConstraint
from deltadb.model.index import Index
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _schema(*tables: Table) -> SchemaModel:
    return SchemaModel(tables={t.name: t for t in tables})


def _table(name: str, *cols: Column, **kwargs) -> Table:
    return Table(name=name, columns=tuple(cols), **kwargs)


def _col(name: str, type_: str = "integer", nullable: bool = True, default=None) -> Column:
    return Column(name=name, type=type_, nullable=nullable, default=default)


EMPTY = SchemaModel(tables={})


@pytest.fixture
def engine() -> DiffEngine:
    return DiffEngine()


# ---------------------------------------------------------------------------
# 1. Table name validation — Defense in Depth
# ---------------------------------------------------------------------------

class TestTableNameValidation:
    def test_sql_injection_semicolon_in_table_name_rejected(self, engine: DiffEngine) -> None:
        evil = SchemaModel(tables={"users; DROP TABLE orders;--": _table("users; DROP TABLE orders;--")})
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_sql_comment_injection_in_table_name_rejected(self, engine: DiffEngine) -> None:
        evil = SchemaModel(tables={"users--drop": _table("users--drop")})
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_newline_in_table_name_rejected(self, engine: DiffEngine) -> None:
        evil = SchemaModel(tables={"users\nDROP TABLE x": _table("users\nDROP TABLE x")})
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_null_byte_in_table_name_rejected(self, engine: DiffEngine) -> None:
        evil = SchemaModel(tables={"\x00users": _table("\x00users")})
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_empty_table_name_rejected(self, engine: DiffEngine) -> None:
        evil = SchemaModel(tables={"": _table("")})
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_table_name_starting_with_digit_rejected(self, engine: DiffEngine) -> None:
        evil = SchemaModel(tables={"1_users": _table("1_users")})
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_too_long_table_name_rejected(self, engine: DiffEngine) -> None:
        long_name = "a" * 200
        evil = SchemaModel(tables={long_name: _table(long_name)})
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_malicious_source_table_also_rejected(self, engine: DiffEngine) -> None:
        good = _schema(_table("users", _col("id")))
        evil = SchemaModel(tables={"users; DROP TABLE orders": _table("users; DROP TABLE orders")})
        with pytest.raises(SecurityError):
            engine.diff(evil, good)

    def test_valid_table_name_passes(self, engine: DiffEngine) -> None:
        valid = _schema(_table("user_accounts_2024", _col("id")))
        changes = engine.diff(EMPTY, valid)
        assert len(changes) == 1


# ---------------------------------------------------------------------------
# 2. Column name validation — Defense in Depth
# ---------------------------------------------------------------------------

class TestColumnNameValidation:
    def test_sql_injection_in_column_name_rejected(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="col; DROP TABLE x", type="integer"))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_comment_in_column_name_rejected(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="col--inject", type="integer"))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_null_byte_in_column_name_rejected(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="\x00col", type="integer"))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_empty_column_name_rejected(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="", type="integer"))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)


# ---------------------------------------------------------------------------
# 3. Column type validation — Defense in Depth
# ---------------------------------------------------------------------------

class TestColumnTypeValidation:
    def test_sql_injection_in_column_type_rejected(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="age", type="integer; DROP TABLE users"))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_comment_in_column_type_rejected(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="age", type="integer--"))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_null_byte_in_column_type_rejected(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="age", type="\x00integer"))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_empty_column_type_rejected(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="age", type=""))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_valid_column_type_passes(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="age", type="integer"))
        valid = _schema(t)
        engine.diff(EMPTY, valid)


# ---------------------------------------------------------------------------
# 4. Column default validation — Defense in Depth
# ---------------------------------------------------------------------------

class TestColumnDefaultValidation:
    def test_sql_injection_in_default_rejected(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="status", type="text", default="'; DROP TABLE users; --"))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_none_default_is_allowed(self, engine: DiffEngine) -> None:
        t = _table("users", Column(name="status", type="text", default=None))
        valid = _schema(t)
        engine.diff(EMPTY, valid)


# ---------------------------------------------------------------------------
# 5. FK identifier validation — referred_table and referred_columns
# ---------------------------------------------------------------------------

class TestFKIdentifierValidation:
    def test_malicious_fk_referred_table_rejected(self, engine: DiffEngine) -> None:
        fk = ForeignKey(
            name="fk_orders_user",
            columns=("user_id",),
            referred_table="users; DROP TABLE orders",
            referred_columns=("id",),
        )
        t = _table("orders", _col("user_id"), foreign_keys=(fk,))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_malicious_fk_name_rejected(self, engine: DiffEngine) -> None:
        fk = ForeignKey(
            name="fk--inject",
            columns=("user_id",),
            referred_table="users",
            referred_columns=("id",),
        )
        t = _table("orders", _col("user_id"), foreign_keys=(fk,))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_malicious_fk_column_rejected(self, engine: DiffEngine) -> None:
        fk = ForeignKey(
            name="fk_x",
            columns=("user_id; DROP TABLE x",),
            referred_table="users",
            referred_columns=("id",),
        )
        t = _table("orders", _col("user_id"), foreign_keys=(fk,))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_malicious_fk_referred_column_rejected(self, engine: DiffEngine) -> None:
        fk = ForeignKey(
            name="fk_x",
            columns=("user_id",),
            referred_table="users",
            referred_columns=("id; DROP TABLE users",),
        )
        t = _table("orders", _col("user_id"), foreign_keys=(fk,))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)


# ---------------------------------------------------------------------------
# 6. Index identifier validation
# ---------------------------------------------------------------------------

class TestIndexIdentifierValidation:
    def test_malicious_index_name_rejected(self, engine: DiffEngine) -> None:
        idx = Index(name="idx--inject; DROP TABLE x", columns=("email",))
        t = _table("users", _col("email"), indexes=(idx,))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_malicious_index_column_name_rejected(self, engine: DiffEngine) -> None:
        idx = Index(name="idx_email", columns=("email; DROP TABLE x",))
        t = _table("users", _col("email"), indexes=(idx,))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)


# ---------------------------------------------------------------------------
# 7. Unique constraint identifier validation
# ---------------------------------------------------------------------------

class TestUniqueConstraintIdentifierValidation:
    def test_malicious_uc_name_rejected(self, engine: DiffEngine) -> None:
        uc = UniqueConstraint(name="uq--inject; DROP TABLE x", columns=("email",))
        t = _table("users", _col("email"), unique_constraints=(uc,))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)

    def test_malicious_uc_column_rejected(self, engine: DiffEngine) -> None:
        uc = UniqueConstraint(name="uq_email", columns=("email; DROP TABLE x",))
        t = _table("users", _col("email"), unique_constraints=(uc,))
        evil = _schema(t)
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil)


# ---------------------------------------------------------------------------
# 8. Data integrity — duplicate identifiers must be rejected
# ---------------------------------------------------------------------------

class TestDuplicateIdentifiers:
    def test_duplicate_column_names_in_source_raises_diff_error(self, engine: DiffEngine) -> None:
        """Silent dict collision would hide column changes — must be caught."""
        t = Table(
            name="users",
            columns=(
                Column(name="col_a", type="integer"),
                Column(name="col_a", type="text"),  # duplicate — last would silently win
            ),
        )
        source = _schema(t)
        target = _schema(_table("users", _col("col_a")))
        with pytest.raises(DiffError, match="[Dd]uplicate"):
            engine.diff(source, target)

    def test_duplicate_column_names_in_target_raises_diff_error(self, engine: DiffEngine) -> None:
        t = Table(
            name="users",
            columns=(
                Column(name="col_a", type="integer"),
                Column(name="col_a", type="text"),
            ),
        )
        source = _schema(_table("users", _col("col_a")))
        target = _schema(t)
        with pytest.raises(DiffError, match="[Dd]uplicate"):
            engine.diff(source, target)

    def test_duplicate_index_names_raises_diff_error(self, engine: DiffEngine) -> None:
        t = Table(
            name="users",
            columns=(_col("email"),),
            indexes=(
                Index(name="idx_email", columns=("email",)),
                Index(name="idx_email", columns=("email",)),
            ),
        )
        source = _schema(t)
        target = _schema(_table("users", _col("email")))
        with pytest.raises(DiffError, match="[Dd]uplicate"):
            engine.diff(source, target)


# ---------------------------------------------------------------------------
# 9. Defense in Depth — loader bypass scenario
# ---------------------------------------------------------------------------

class TestDefenseInDepth:
    def test_direct_construction_bypassing_loader_still_rejected(self, engine: DiffEngine) -> None:
        """
        A malicious actor constructs SchemaModel directly, skipping all loaders.
        The diff engine must be an independent trust boundary.
        """
        # Simulate attacker who bypassed YamlLoader and DbLoader
        malicious_table = Table(
            name="accounts",  # valid name
            columns=(
                Column(name="id; DROP TABLE accounts;--", type="integer"),
            ),
        )
        evil_schema = SchemaModel(tables={"accounts": malicious_table})
        with pytest.raises(SecurityError):
            engine.diff(EMPTY, evil_schema)

    def test_valid_full_schema_passes_all_validation(self, engine: DiffEngine) -> None:
        fk = ForeignKey(
            name="fk_orders_user",
            columns=("user_id",),
            referred_table="users",
            referred_columns=("id",),
        )
        idx = Index(name="idx_user_id", columns=("user_id",))
        uc = UniqueConstraint(name="uq_email", columns=("email",))
        users = _table("users", _col("id", "integer"), _col("email", "varchar"), unique_constraints=(uc,))
        orders = Table(
            name="orders",
            columns=(_col("id", "integer"), _col("user_id", "integer")),
            foreign_keys=(fk,),
            indexes=(idx,),
        )
        source = _schema(users)
        target = _schema(users, orders)
        changes = engine.diff(source, target)
        assert any(c.table == "orders" for c in changes)

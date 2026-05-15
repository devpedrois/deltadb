"""
Security tests for the SQL generator — Defense in Depth layer.

These tests verify that SqlGenerator is an independent trust boundary.
Malicious input must be rejected even if DiffEngine was bypassed.

Attack surface:
- col.type: raw SQL type interpolated in templates
- col.default: raw default value interpolated in templates
- fk.on_delete / fk.on_update: raw action values in ADD FK
- new_type / old_type in COLUMN_TYPE_CHANGED
- Circular FK dependency in topological sort
"""
import pytest

from deltadb.diff.changes import Change, ChangeType
from deltadb.exceptions import GeneratorError, SecurityError
from deltadb.generator.dialects import Dialect
from deltadb.generator.sql_generator import SqlGenerator
from deltadb.generator.topological import topological_sort_up
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table


def _schema(*tables: Table) -> SchemaModel:
    return SchemaModel(tables={t.name: t for t in tables})


def _bare_table(name: str, col_type: str = "integer") -> Table:
    return Table(
        name=name,
        columns=(Column(name="id", type=col_type),),
    )


# ── col.type injection ────────────────────────────────────────────────────────

class TestColumnTypeInjection:
    """col.type flows into CREATE TABLE and ADD COLUMN templates raw."""

    @pytest.mark.parametrize("evil_type", [
        "integer; DROP TABLE users--",
        "integer\nDROP TABLE evil",
        "integer/*DROP TABLE*/",
        "integer\x00DROP",
        "varchar(255); DELETE FROM users--",
    ])
    def test_create_table_rejects_malicious_col_type(self, evil_type):
        # [SECURITY] col.type bypasses DiffEngine when SchemaModel built directly
        col = Column(name="id", type=evil_type)
        table = Table(name="victims", columns=(col,))
        schema = _schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="victims", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    @pytest.mark.parametrize("evil_type", [
        "integer; DROP TABLE users--",
        "text\nDROP TABLE evil",
    ])
    def test_add_column_rejects_malicious_col_type(self, evil_type):
        col = Column(name="evil_col", type=evil_type)
        schema = _schema(_bare_table("users"))
        change = Change(
            type=ChangeType.COLUMN_ADDED, table="users", column="evil_col", new_value=col
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    @pytest.mark.parametrize("evil_type", [
        "integer; DROP TABLE users--",
        "text\nDROP TABLE evil",
    ])
    def test_alter_column_type_rejects_malicious_new_type(self, evil_type):
        schema = _schema(_bare_table("users"))
        change = Change(
            type=ChangeType.COLUMN_TYPE_CHANGED,
            table="users", column="age",
            old_value="integer", new_value=evil_type,
            destructive=True,
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    def test_valid_type_passes_through(self):
        col = Column(name="score", type="integer")
        table = Table(name="stats", columns=(col,))
        schema = _schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="stats", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "integer" in sql

    def test_parameterized_type_passes_through(self):
        col = Column(name="email", type="varchar(255)")
        table = Table(name="users", columns=(col,))
        schema = _schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="users", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "varchar(255)" in sql


# ── col.default injection ─────────────────────────────────────────────────────

class TestColumnDefaultInjection:
    """col.default flows into CREATE TABLE and ADD COLUMN templates raw."""

    @pytest.mark.parametrize("evil_default", [
        "0; DROP TABLE users--",
        "''; DELETE FROM sessions--",
        "1\nDROP TABLE evil",
        "0/*injection*/",
    ])
    def test_create_table_rejects_malicious_default(self, evil_default):
        # [SECURITY] default not validated in generator trust boundary
        col = Column(name="score", type="integer", default=evil_default)
        table = Table(name="victims", columns=(col,))
        schema = _schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="victims", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    @pytest.mark.parametrize("evil_default", [
        "0; DROP TABLE users--",
        "1\nDROP TABLE evil",
    ])
    def test_add_column_rejects_malicious_default(self, evil_default):
        col = Column(name="score", type="integer", default=evil_default)
        schema = _schema(_bare_table("users"))
        change = Change(
            type=ChangeType.COLUMN_ADDED, table="users", column="score", new_value=col
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    def test_valid_integer_default_passes(self):
        col = Column(name="score", type="integer", default="0")
        table = Table(name="users", columns=(col,))
        schema = _schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="users", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "DEFAULT 0" in sql

    def test_none_default_skipped(self):
        col = Column(name="score", type="integer", default=None)
        table = Table(name="users", columns=(col,))
        schema = _schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="users", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "DEFAULT" not in sql.split("UP (apply)")[1].split("DOWN (revert)")[0]


# ── FK on_delete / on_update injection ───────────────────────────────────────

class TestFKActionInjection:
    """fk.on_delete and fk.on_update flow into ADD FK template raw."""

    @pytest.mark.parametrize("evil_action", [
        "CASCADE; DROP TABLE users--",
        "SET NULL\nDROP TABLE evil",
        "RESTRICT/*DROP*/",
        "EXPLODE",
        "UNDEFINED_ACTION",
    ])
    def test_add_fk_rejects_malicious_on_delete(self, evil_action):
        fk = ForeignKey(
            name="fk_test", columns=("user_id",),
            referred_table="users", referred_columns=("id",),
            on_delete=evil_action,
        )
        schema = _schema(
            _bare_table("users"),
            _bare_table("orders"),
        )
        change = Change(type=ChangeType.FK_ADDED, table="orders", new_value=fk)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    @pytest.mark.parametrize("evil_action", [
        "CASCADE; DROP TABLE users--",
        "SET NULL\nDROP TABLE evil",
    ])
    def test_add_fk_rejects_malicious_on_update(self, evil_action):
        fk = ForeignKey(
            name="fk_test", columns=("user_id",),
            referred_table="users", referred_columns=("id",),
            on_update=evil_action,
        )
        schema = _schema(_bare_table("users"), _bare_table("orders"))
        change = Change(type=ChangeType.FK_ADDED, table="orders", new_value=fk)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    @pytest.mark.parametrize("valid_action", [
        "CASCADE", "SET NULL", "SET DEFAULT", "RESTRICT", "NO ACTION",
    ])
    def test_valid_on_delete_passes(self, valid_action):
        fk = ForeignKey(
            name="fk_test", columns=("user_id",),
            referred_table="users", referred_columns=("id",),
            on_delete=valid_action,
        )
        schema = _schema(_bare_table("users"), _bare_table("orders"))
        change = Change(type=ChangeType.FK_ADDED, table="orders", new_value=fk)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert valid_action in sql

    def test_no_on_delete_no_restriction(self):
        fk = ForeignKey(
            name="fk_test", columns=("user_id",),
            referred_table="users", referred_columns=("id",),
            on_delete=None,
        )
        schema = _schema(_bare_table("users"), _bare_table("orders"))
        change = Change(type=ChangeType.FK_ADDED, table="orders", new_value=fk)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "ON DELETE" not in sql


# ── Circular FK detection ─────────────────────────────────────────────────────

class TestCircularFKDetection:
    """Circular FK refs in topological sort must raise, not silently mis-order."""

    def test_circular_fk_raises_generator_error(self):
        # a -> b -> a (circular)
        fk_a = ForeignKey(name="fk_a_b", columns=("b_id",), referred_table="b", referred_columns=("id",))
        fk_b = ForeignKey(name="fk_b_a", columns=("a_id",), referred_table="a", referred_columns=("id",))
        table_a = Table(name="a", columns=(Column(name="id", type="integer"),), foreign_keys=(fk_a,))
        table_b = Table(name="b", columns=(Column(name="id", type="integer"),), foreign_keys=(fk_b,))
        schema = _schema(table_a, table_b)
        changes = [
            Change(type=ChangeType.TABLE_ADDED, table="a", new_value=table_a),
            Change(type=ChangeType.TABLE_ADDED, table="b", new_value=table_b),
        ]
        with pytest.raises(GeneratorError, match="[Cc]ircular"):
            topological_sort_up(changes, schema)

    def test_self_referential_fk_not_flagged_as_cycle(self):
        fk_self = ForeignKey(
            name="fk_self", columns=("parent_id",),
            referred_table="nodes", referred_columns=("id",),
        )
        table = Table(
            name="nodes",
            columns=(Column(name="id", type="integer"),),
            foreign_keys=(fk_self,),
        )
        schema = _schema(table)
        changes = [Change(type=ChangeType.TABLE_ADDED, table="nodes", new_value=table)]
        result = topological_sort_up(changes, schema)
        assert len(result) == 1


# ── MySQL dialect same protections ───────────────────────────────────────────

class TestMySQLDialectSecurity:
    def test_mysql_col_type_injection_blocked(self):
        col = Column(name="id", type="int; DROP TABLE evil--")
        table = Table(name="hack", columns=(col,))
        schema = _schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="hack", new_value=table)
        gen = SqlGenerator(Dialect.MYSQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    def test_mysql_fk_on_delete_injection_blocked(self):
        fk = ForeignKey(
            name="fk_x", columns=("uid",),
            referred_table="users", referred_columns=("id",),
            on_delete="CASCADE; TRUNCATE TABLE users--",
        )
        schema = _schema(_bare_table("users"), _bare_table("orders"))
        change = Change(type=ChangeType.FK_ADDED, table="orders", new_value=fk)
        gen = SqlGenerator(Dialect.MYSQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)


# ── Defense in Depth: generator validates independently of DiffEngine ─────────

class TestDefenseInDepth:
    """Bypass DiffEngine entirely. Generator MUST still reject malicious input."""

    def test_generator_rejects_without_diff_engine(self):
        # Skip DiffEngine._validate_schema() entirely
        col = Column(name="id", type="integer; DROP TABLE users--")
        table = Table(name="users", columns=(col,))
        schema = SchemaModel(tables={"users": table})
        change = Change(type=ChangeType.TABLE_ADDED, table="users", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        # [SECURITY] Generator is independent trust boundary — must not trust pre-validated input
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

    def test_generator_rejects_default_without_diff_engine(self):
        col = Column(name="score", type="integer", default="'; DROP TABLE users--")
        table = Table(name="users", columns=(col,))
        schema = SchemaModel(tables={"users": table})
        change = Change(type=ChangeType.TABLE_ADDED, table="users", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        with pytest.raises(SecurityError):
            gen.generate([change], schema)

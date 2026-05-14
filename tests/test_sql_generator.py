import pytest

from deltadb.diff.changes import Change, ChangeType
from deltadb.exceptions import SecurityError
from deltadb.generator.dialects import Dialect
from deltadb.generator.sql_generator import SqlGenerator
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, PrimaryKey, UniqueConstraint
from deltadb.model.index import Index
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table


def _make_schema(*tables: Table) -> SchemaModel:
    return SchemaModel(tables={t.name: t for t in tables})


def _make_table(name: str, cols: list[Column], fks: list[ForeignKey] = None) -> Table:
    return Table(
        name=name,
        columns=tuple(cols),
        foreign_keys=tuple(fks or []),
    )


def _make_col(name: str, type_: str = "integer", nullable: bool = True) -> Column:
    return Column(name=name, type=type_)


class TestDialectQuoting:
    def test_postgresql_double_quotes(self):
        table = _make_table("users", [_make_col("id", "integer"), _make_col("email", "varchar(255)")])
        schema = _make_schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="users", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert '"users"' in sql
        assert '"id"' in sql
        assert '"email"' in sql

    def test_mysql_backtick_quotes(self):
        table = _make_table("users", [_make_col("id", "int"), _make_col("email", "varchar(255)")])
        schema = _make_schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="users", new_value=table)
        gen = SqlGenerator(Dialect.MYSQL)
        sql = gen.generate([change], schema)
        assert "`users`" in sql
        assert "`id`" in sql
        assert "`email`" in sql

    def test_sqlite_double_quotes(self):
        table = _make_table("items", [_make_col("id", "integer")])
        schema = _make_schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="items", new_value=table)
        gen = SqlGenerator(Dialect.SQLITE)
        sql = gen.generate([change], schema)
        assert '"items"' in sql


class TestTableAdded:
    def test_create_table_postgresql(self):
        col_id = Column(name="id", type="integer", nullable=False, primary_key=True)
        col_name = Column(name="name", type="varchar(255)", nullable=True)
        pk = PrimaryKey(name="pk_users", columns=("id",))
        table = Table(name="users", columns=(col_id, col_name), primary_key=pk)
        schema = _make_schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="users", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "CREATE TABLE" in sql
        assert '"users"' in sql
        assert '"id"' in sql
        assert "NOT NULL" in sql
        assert "PRIMARY KEY" in sql

    def test_create_table_has_up_and_down(self):
        table = _make_table("orders", [_make_col("id", "integer")])
        schema = _make_schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="orders", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "UP (apply)" in sql
        assert "DOWN (revert)" in sql

    def test_create_table_down_drops_table(self):
        table = _make_table("orders", [_make_col("id", "integer")])
        schema = _make_schema(table)
        change = Change(type=ChangeType.TABLE_ADDED, table="orders", new_value=table)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        down_section = sql.split("DOWN (revert)")[1]
        assert "DROP TABLE" in down_section
        assert '"orders"' in down_section


class TestTableDropped:
    def test_drop_table_is_destructive(self):
        table = _make_table("old_table", [_make_col("id", "integer")])
        schema = _make_schema()
        change = Change(
            type=ChangeType.TABLE_DROPPED, table="old_table", old_value=table, destructive=True
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "DROP TABLE" in sql
        assert "DESTRUCTIVE" in sql

    def test_drop_table_no_destructive_skips(self):
        table = _make_table("old_table", [_make_col("id", "integer")])
        schema = _make_schema()
        change = Change(
            type=ChangeType.TABLE_DROPPED, table="old_table", old_value=table, destructive=True
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema, no_destructive=True)
        assert "DROP TABLE" not in sql.split("UP (apply)")[1].split("DOWN (revert)")[0]


class TestColumnDropped:
    def test_drop_column_destructive_marker(self):
        col = Column(name="old_col", type="text")
        schema = _make_schema(_make_table("users", [_make_col("id", "integer")]))
        change = Change(
            type=ChangeType.COLUMN_DROPPED, table="users", column="old_col",
            old_value=col, destructive=True,
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "DROP COLUMN" in sql
        assert "DESTRUCTIVE" in sql

    def test_drop_column_no_destructive_omits(self):
        col = Column(name="old_col", type="text")
        schema = _make_schema(_make_table("users", [_make_col("id", "integer")]))
        change = Change(
            type=ChangeType.COLUMN_DROPPED, table="users", column="old_col",
            old_value=col, destructive=True,
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema, no_destructive=True)
        up_section = sql.split("UP (apply)")[1].split("DOWN (revert)")[0]
        assert "DROP COLUMN" not in up_section


class TestColumnAdded:
    def test_add_column_postgresql(self):
        col = Column(name="age", type="integer", nullable=True)
        schema = _make_schema(_make_table("users", [_make_col("id", "integer")]))
        change = Change(type=ChangeType.COLUMN_ADDED, table="users", column="age", new_value=col)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "ADD COLUMN" in sql
        assert '"age"' in sql
        assert '"users"' in sql

    def test_add_column_not_null(self):
        col = Column(name="email", type="varchar(255)", nullable=False)
        schema = _make_schema(_make_table("users", [_make_col("id", "integer")]))
        change = Change(type=ChangeType.COLUMN_ADDED, table="users", column="email", new_value=col)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "NOT NULL" in sql


class TestAlterColumnType:
    def test_type_change_is_destructive(self):
        schema = _make_schema(_make_table("users", [_make_col("id", "integer")]))
        change = Change(
            type=ChangeType.COLUMN_TYPE_CHANGED, table="users", column="age",
            old_value="integer", new_value="bigint", destructive=True,
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "DESTRUCTIVE" in sql
        assert "bigint" in sql

    def test_type_change_down_reverts(self):
        schema = _make_schema(_make_table("users", [_make_col("id", "integer")]))
        change = Change(
            type=ChangeType.COLUMN_TYPE_CHANGED, table="users", column="age",
            old_value="integer", new_value="bigint", destructive=True,
        )
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        down_section = sql.split("DOWN (revert)")[1]
        assert "integer" in down_section


class TestIndexOperations:
    def test_add_index(self):
        idx = Index(name="idx_users_email", columns=("email",), unique=True)
        schema = _make_schema(_make_table("users", [_make_col("id", "integer")]))
        change = Change(type=ChangeType.INDEX_ADDED, table="users", new_value=idx)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "CREATE UNIQUE INDEX" in sql
        assert '"idx_users_email"' in sql

    def test_drop_index_postgresql(self):
        idx = Index(name="idx_old", columns=("col",))
        schema = _make_schema(_make_table("users", [_make_col("id", "integer")]))
        change = Change(type=ChangeType.INDEX_DROPPED, table="users", old_value=idx)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "DROP INDEX" in sql
        assert '"idx_old"' in sql

    def test_drop_index_mysql_includes_table(self):
        idx = Index(name="idx_old", columns=("col",))
        schema = _make_schema(_make_table("products", [_make_col("id", "integer")]))
        change = Change(type=ChangeType.INDEX_DROPPED, table="products", old_value=idx)
        gen = SqlGenerator(Dialect.MYSQL)
        sql = gen.generate([change], schema)
        assert "DROP INDEX" in sql
        assert "`products`" in sql


class TestForeignKeyOperations:
    def test_add_fk(self):
        fk = ForeignKey(
            name="fk_orders_user", columns=("user_id",),
            referred_table="users", referred_columns=("id",), on_delete="CASCADE",
        )
        schema = _make_schema(
            _make_table("users", [_make_col("id", "integer")]),
            _make_table("orders", [_make_col("id", "integer"), _make_col("user_id", "integer")]),
        )
        change = Change(type=ChangeType.FK_ADDED, table="orders", new_value=fk)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "FOREIGN KEY" in sql
        assert '"fk_orders_user"' in sql
        assert "CASCADE" in sql

    def test_drop_fk(self):
        fk = ForeignKey(
            name="fk_orders_user", columns=("user_id",),
            referred_table="users", referred_columns=("id",),
        )
        schema = _make_schema(_make_table("orders", [_make_col("id", "integer")]))
        change = Change(type=ChangeType.FK_DROPPED, table="orders", old_value=fk)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "DROP CONSTRAINT" in sql


class TestUniqueConstraint:
    def test_add_unique(self):
        uc = UniqueConstraint(name="uq_users_email", columns=("email",))
        schema = _make_schema(_make_table("users", [_make_col("id", "integer")]))
        change = Change(type=ChangeType.UNIQUE_CONSTRAINT_ADDED, table="users", new_value=uc)
        gen = SqlGenerator(Dialect.POSTGRESQL)
        sql = gen.generate([change], schema)
        assert "UNIQUE" in sql
        assert '"uq_users_email"' in sql


class TestSecurityIdentifierInjection:
    def test_injection_via_table_name_raises(self):
        # [SECURITY] Test: identifier injection via generator
        # validate_identifier fires inside quote_id filter
        from deltadb.security.identifiers import validate_identifier
        with pytest.raises(SecurityError):
            validate_identifier("evil; DROP TABLE x")

    def test_injection_newline_raises(self):
        from deltadb.security.identifiers import validate_identifier
        with pytest.raises(SecurityError):
            validate_identifier("col\nDROP TABLE x")

    def test_injection_sql_comment_raises(self):
        from deltadb.security.identifiers import validate_identifier
        with pytest.raises(SecurityError):
            validate_identifier("col'--")

    def test_injection_null_byte_raises(self):
        from deltadb.security.identifiers import validate_identifier
        with pytest.raises(SecurityError):
            validate_identifier("\x00col")

    def test_injection_starts_with_number_raises(self):
        from deltadb.security.identifiers import validate_identifier
        with pytest.raises(SecurityError):
            validate_identifier("1_invalid")

    def test_valid_identifier_passes(self):
        from deltadb.security.identifiers import validate_identifier
        validate_identifier("valid_table_2024")

    def test_generate_with_malicious_table_name_raises(self):
        # [SECURITY] Malicious table name must raise SecurityError before template renders
        from deltadb.security.identifiers import validate_identifier
        with pytest.raises(SecurityError):
            validate_identifier("evil; DROP TABLE x")

    def test_quote_identifier_postgresql(self):
        from deltadb.security.identifiers import quote_identifier
        assert quote_identifier("users", "postgresql") == '"users"'

    def test_quote_identifier_mysql(self):
        from deltadb.security.identifiers import quote_identifier
        assert quote_identifier("users", "mysql") == "`users`"


class TestGeneratorInit:
    def test_invalid_dialect_templates_raises_template_render_error(self):
        from unittest.mock import patch
        from deltadb.exceptions import TemplateRenderError
        from deltadb.generator.dialects import Dialect

        with patch("deltadb.generator.sql_generator.PackageLoader", side_effect=ValueError("no such dir")):
            with pytest.raises(TemplateRenderError, match="Failed to initialize templates"):
                SqlGenerator(Dialect.POSTGRESQL)

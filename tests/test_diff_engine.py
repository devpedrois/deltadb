import pytest

from deltadb.diff.changes import ChangeType
from deltadb.diff.engine import DiffEngine
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, UniqueConstraint
from deltadb.model.index import Index
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table


def make_table(name: str, columns: list[Column] | None = None, **kwargs) -> Table:
    return Table(
        name=name,
        columns=tuple(columns or []),
        **kwargs,
    )


def make_col(name: str, type_: str = "integer", nullable: bool = True, default=None) -> Column:
    return Column(name=name, type=type_, nullable=nullable, default=default)


def make_schema(*tables: Table) -> SchemaModel:
    return SchemaModel(tables={t.name: t for t in tables})


@pytest.fixture
def engine() -> DiffEngine:
    return DiffEngine()


class TestTableChanges:
    def test_table_added(self, engine: DiffEngine) -> None:
        source = make_schema()
        target = make_schema(make_table("users", [make_col("id")]))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.TABLE_ADDED
        assert changes[0].table == "users"
        assert changes[0].destructive is False

    def test_table_dropped_is_destructive(self, engine: DiffEngine) -> None:
        source = make_schema(make_table("users", [make_col("id")]))
        target = make_schema()

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.TABLE_DROPPED
        assert changes[0].table == "users"
        assert changes[0].destructive is True

    def test_identical_schemas_produce_no_changes(self, engine: DiffEngine) -> None:
        table = make_table("users", [make_col("id"), make_col("email", "varchar(255)")])
        source = make_schema(table)
        target = make_schema(table)

        changes = engine.diff(source, target)

        assert changes == []


class TestColumnChanges:
    def test_column_added(self, engine: DiffEngine) -> None:
        source = make_schema(make_table("users", [make_col("id")]))
        target = make_schema(make_table("users", [make_col("id"), make_col("email", "text")]))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.COLUMN_ADDED
        assert changes[0].column == "email"
        assert changes[0].destructive is False

    def test_column_dropped_is_destructive(self, engine: DiffEngine) -> None:
        source = make_schema(make_table("users", [make_col("id"), make_col("email", "text")]))
        target = make_schema(make_table("users", [make_col("id")]))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.COLUMN_DROPPED
        assert changes[0].column == "email"
        assert changes[0].destructive is True

    def test_column_type_changed_is_destructive(self, engine: DiffEngine) -> None:
        source = make_schema(make_table("users", [make_col("age", "integer")]))
        target = make_schema(make_table("users", [make_col("age", "bigint")]))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.COLUMN_TYPE_CHANGED
        assert changes[0].old_value == "integer"
        assert changes[0].new_value == "bigint"
        assert changes[0].destructive is True

    def test_column_nullable_changed(self, engine: DiffEngine) -> None:
        source = make_schema(make_table("users", [make_col("email", nullable=True)]))
        target = make_schema(make_table("users", [make_col("email", nullable=False)]))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.COLUMN_NULLABLE_CHANGED
        assert changes[0].old_value is True
        assert changes[0].new_value is False
        assert changes[0].destructive is False

    def test_column_default_changed(self, engine: DiffEngine) -> None:
        source = make_schema(make_table("users", [make_col("status", default="active")]))
        target = make_schema(make_table("users", [make_col("status", default="inactive")]))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.COLUMN_DEFAULT_CHANGED
        assert changes[0].old_value == "active"
        assert changes[0].new_value == "inactive"


class TestIndexChanges:
    def test_index_added(self, engine: DiffEngine) -> None:
        idx = Index(name="idx_email", columns=("email",), unique=True)
        source = make_schema(make_table("users", [make_col("email")]))
        target = make_schema(make_table("users", [make_col("email")], indexes=(idx,)))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.INDEX_ADDED
        assert changes[0].table == "users"

    def test_index_dropped(self, engine: DiffEngine) -> None:
        idx = Index(name="idx_email", columns=("email",), unique=False)
        source = make_schema(make_table("users", [make_col("email")], indexes=(idx,)))
        target = make_schema(make_table("users", [make_col("email")]))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.INDEX_DROPPED


class TestForeignKeyChanges:
    def test_fk_added(self, engine: DiffEngine) -> None:
        fk = ForeignKey(
            name="fk_orders_user",
            columns=("user_id",),
            referred_table="users",
            referred_columns=("id",),
        )
        source = make_schema(make_table("orders", [make_col("user_id")]))
        target = make_schema(make_table("orders", [make_col("user_id")], foreign_keys=(fk,)))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.FK_ADDED
        assert changes[0].table == "orders"

    def test_fk_dropped(self, engine: DiffEngine) -> None:
        fk = ForeignKey(
            name="fk_orders_user",
            columns=("user_id",),
            referred_table="users",
            referred_columns=("id",),
        )
        source = make_schema(make_table("orders", [make_col("user_id")], foreign_keys=(fk,)))
        target = make_schema(make_table("orders", [make_col("user_id")]))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.FK_DROPPED


class TestUniqueConstraintChanges:
    def test_unique_constraint_added(self, engine: DiffEngine) -> None:
        uc = UniqueConstraint(name="uq_email", columns=("email",))
        source = make_schema(make_table("users", [make_col("email")]))
        target = make_schema(make_table("users", [make_col("email")], unique_constraints=(uc,)))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.UNIQUE_CONSTRAINT_ADDED

    def test_unique_constraint_dropped(self, engine: DiffEngine) -> None:
        uc = UniqueConstraint(name="uq_email", columns=("email",))
        source = make_schema(make_table("users", [make_col("email")], unique_constraints=(uc,)))
        target = make_schema(make_table("users", [make_col("email")]))

        changes = engine.diff(source, target)

        assert len(changes) == 1
        assert changes[0].type == ChangeType.UNIQUE_CONSTRAINT_DROPPED


class TestMultipleChanges:
    def test_multiple_changes_across_tables(self, engine: DiffEngine) -> None:
        source = make_schema(
            make_table("users", [make_col("id"), make_col("name")]),
            make_table("posts", [make_col("id")]),
        )
        target = make_schema(
            make_table("users", [make_col("id"), make_col("email", "text")]),
            make_table("comments", [make_col("id")]),
        )

        changes = engine.diff(source, target)

        types = {c.type for c in changes}
        assert ChangeType.TABLE_ADDED in types
        assert ChangeType.TABLE_DROPPED in types
        assert ChangeType.COLUMN_ADDED in types
        assert ChangeType.COLUMN_DROPPED in types

        dropped = [c for c in changes if c.type == ChangeType.TABLE_DROPPED]
        assert all(c.destructive for c in dropped)

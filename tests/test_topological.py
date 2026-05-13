import pytest

from deltadb.diff.changes import Change, ChangeType
from deltadb.generator.topological import topological_sort_down, topological_sort_up
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table


def _col(name: str) -> Column:
    return Column(name=name, type="integer")


def _table(name: str, fks: list[ForeignKey] = None) -> Table:
    return Table(name=name, columns=(_col("id"),), foreign_keys=tuple(fks or []))


def _schema(*tables: Table) -> SchemaModel:
    return SchemaModel(tables={t.name: t for t in tables})


def _added(table_obj: Table) -> Change:
    return Change(type=ChangeType.TABLE_ADDED, table=table_obj.name, new_value=table_obj)


def _dropped(table_obj: Table) -> Change:
    return Change(
        type=ChangeType.TABLE_DROPPED, table=table_obj.name, old_value=table_obj, destructive=True
    )


class TestTopologicalSortUp:
    def test_independent_tables_added_sorted_alphabetically(self):
        users = _table("users")
        items = _table("items")
        changes = [_added(users), _added(items)]
        schema = _schema(users, items)
        result = topological_sort_up(changes, schema)
        names = [c.table for c in result if c.type == ChangeType.TABLE_ADDED]
        assert set(names) == {"users", "items"}

    def test_fk_dependency_referenced_table_first(self):
        users = _table("users")
        fk = ForeignKey(name="fk_orders_user", columns=("user_id",), referred_table="users", referred_columns=("id",))
        orders = _table("orders", fks=[fk])
        changes = [_added(orders), _added(users)]
        schema = _schema(users, orders)
        result = topological_sort_up(changes, schema)
        names = [c.table for c in result if c.type == ChangeType.TABLE_ADDED]
        assert names.index("users") < names.index("orders")

    def test_fk_added_after_table_added(self):
        users = _table("users")
        fk = ForeignKey(name="fk_x", columns=("user_id",), referred_table="users", referred_columns=("id",))
        fk_change = Change(type=ChangeType.FK_ADDED, table="orders", new_value=fk)
        tbl_change = _added(users)
        changes = [fk_change, tbl_change]
        schema = _schema(users)
        result = topological_sort_up(changes, schema)
        types = [c.type for c in result]
        assert types.index(ChangeType.TABLE_ADDED) < types.index(ChangeType.FK_ADDED)

    def test_fk_dropped_before_table_dropped(self):
        users = _table("users")
        fk = ForeignKey(name="fk_x", columns=("user_id",), referred_table="users", referred_columns=("id",))
        fk_drop = Change(type=ChangeType.FK_DROPPED, table="orders", old_value=fk)
        tbl_drop = _dropped(users)
        changes = [tbl_drop, fk_drop]
        schema = _schema()
        result = topological_sort_up(changes, schema)
        types = [c.type for c in result]
        assert types.index(ChangeType.FK_DROPPED) < types.index(ChangeType.TABLE_DROPPED)

    def test_dependent_table_dropped_before_referenced(self):
        users = _table("users")
        fk = ForeignKey(name="fk_orders_user", columns=("user_id",), referred_table="users", referred_columns=("id",))
        orders = _table("orders", fks=[fk])
        changes = [_dropped(users), _dropped(orders)]
        schema = _schema()
        result = topological_sort_up(changes, schema)
        names = [c.table for c in result if c.type == ChangeType.TABLE_DROPPED]
        assert names.index("orders") < names.index("users")

    def test_no_changes_returns_empty(self):
        schema = _schema()
        result = topological_sort_up([], schema)
        assert result == []

    def test_non_table_changes_preserved(self):
        col_change = Change(type=ChangeType.COLUMN_ADDED, table="users", column="age", new_value=_col("age"))
        schema = _schema(_table("users"))
        result = topological_sort_up([col_change], schema)
        assert len(result) == 1
        assert result[0].type == ChangeType.COLUMN_ADDED


class TestTopologicalSortDown:
    def test_down_reverses_up(self):
        users = _table("users")
        fk = ForeignKey(name="fk_orders_user", columns=("user_id",), referred_table="users", referred_columns=("id",))
        orders = _table("orders", fks=[fk])
        changes = [_added(users), _added(orders)]
        schema = _schema(users, orders)
        up = topological_sort_up(changes, schema)
        down = topological_sort_down(up)
        assert [c.table for c in down] == [c.table for c in reversed(up)]

    def test_down_drop_orders_before_users(self):
        users = _table("users")
        fk = ForeignKey(name="fk_orders_user", columns=("user_id",), referred_table="users", referred_columns=("id",))
        orders = _table("orders", fks=[fk])
        # UP creates users first, then orders
        changes = [_added(users), _added(orders)]
        schema = _schema(users, orders)
        up = topological_sort_up(changes, schema)
        down = topological_sort_down(up)
        # DOWN should drop orders before users
        names = [c.table for c in down]
        assert names.index("orders") < names.index("users")

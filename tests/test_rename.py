import pytest

from deltadb.diff.changes import Change, ChangeType
from deltadb.diff.rename import RenameDetector
from deltadb.model.column import Column
from deltadb.model.schema import SchemaModel
from deltadb.model.table import Table


def _col(name: str, type_: str = "integer", nullable: bool = True) -> Column:
    return Column(name=name, type=type_, nullable=nullable)


def _table(name: str, *cols: Column) -> Table:
    return Table(name=name, columns=cols)


def _schema(*tables: Table) -> SchemaModel:
    return SchemaModel(tables={t.name: t for t in tables})


def _dropped(table: Table) -> Change:
    return Change(
        type=ChangeType.TABLE_DROPPED,
        table=table.name,
        old_value=table,
        destructive=True,
    )


def _added(table: Table) -> Change:
    return Change(
        type=ChangeType.TABLE_ADDED,
        table=table.name,
        new_value=table,
    )


def _col_dropped(table_name: str, col: Column) -> Change:
    return Change(
        type=ChangeType.COLUMN_DROPPED,
        table=table_name,
        column=col.name,
        old_value=col,
        destructive=True,
    )


def _col_added(table_name: str, col: Column) -> Change:
    return Change(
        type=ChangeType.COLUMN_ADDED,
        table=table_name,
        column=col.name,
        new_value=col,
    )


class TestTableRenameDetection:
    def test_detects_table_rename_above_threshold(self) -> None:
        old = _table("users", _col("id", "integer", False), _col("email", "varchar", False))
        new = _table("accounts", _col("id", "integer", False), _col("email", "varchar", False))
        changes = [_dropped(old), _added(new)]

        result = RenameDetector(threshold=0.7).apply(changes)

        rename_changes = [c for c in result if c.type == ChangeType.TABLE_RENAMED]
        assert len(rename_changes) == 1
        assert rename_changes[0].table == "users"
        assert rename_changes[0].new_value == "accounts"

    def test_does_not_detect_rename_below_threshold(self) -> None:
        old = _table("users", _col("id"), _col("email"))
        new = _table("products", _col("sku", "varchar"), _col("price", "numeric"), _col("stock", "integer"))
        changes = [_dropped(old), _added(new)]

        result = RenameDetector(threshold=0.9).apply(changes)

        rename_changes = [c for c in result if c.type == ChangeType.TABLE_RENAMED]
        assert len(rename_changes) == 0
        # original DROP and ADD preserved
        assert any(c.type == ChangeType.TABLE_DROPPED for c in result)
        assert any(c.type == ChangeType.TABLE_ADDED for c in result)

    def test_rename_removes_original_drop_and_add(self) -> None:
        old = _table("users", _col("id", "integer", False), _col("email", "varchar", False))
        new = _table("members", _col("id", "integer", False), _col("email", "varchar", False))
        changes = [_dropped(old), _added(new)]

        result = RenameDetector(threshold=0.7).apply(changes)

        assert not any(c.type == ChangeType.TABLE_DROPPED for c in result)
        assert not any(c.type == ChangeType.TABLE_ADDED for c in result)
        assert len(result) == 1

    def test_one_to_one_match_with_multiple_candidates(self) -> None:
        a = _table("users", _col("id", "integer", False), _col("email", "varchar", False))
        b = _table("orders", _col("order_id", "integer", False), _col("amount", "numeric"))
        x = _table("members", _col("id", "integer", False), _col("email", "varchar", False))
        y = _table("purchases", _col("order_id", "integer", False), _col("amount", "numeric"))
        changes = [_dropped(a), _dropped(b), _added(x), _added(y)]

        result = RenameDetector(threshold=0.7).apply(changes)

        renames = {c.table: c.new_value for c in result if c.type == ChangeType.TABLE_RENAMED}
        assert renames["users"] == "members"
        assert renames["orders"] == "purchases"
        assert len(renames) == 2

    def test_unmatched_tables_preserved_as_drop_and_add(self) -> None:
        similar = _table("users", _col("id", "integer", False), _col("email", "varchar", False))
        renamed = _table("members", _col("id", "integer", False), _col("email", "varchar", False))
        unrelated_drop = _table("old_logs", _col("msg", "text"))
        unrelated_add = _table("new_metrics", _col("val", "float"))

        changes = [
            _dropped(similar), _dropped(unrelated_drop),
            _added(renamed), _added(unrelated_add),
        ]
        result = RenameDetector(threshold=0.7).apply(changes)

        assert sum(1 for c in result if c.type == ChangeType.TABLE_RENAMED) == 1
        assert sum(1 for c in result if c.type == ChangeType.TABLE_DROPPED) == 1
        assert sum(1 for c in result if c.type == ChangeType.TABLE_ADDED) == 1


class TestColumnRenameDetection:
    def test_detects_column_rename_same_type(self) -> None:
        old_col = _col("user_name", "varchar", False)
        new_col = _col("username", "varchar", False)
        changes = [
            _col_dropped("users", old_col),
            _col_added("users", new_col),
        ]

        result = RenameDetector(threshold=0.7).apply(changes)

        renames = [c for c in result if c.type == ChangeType.COLUMN_RENAMED]
        assert len(renames) == 1
        assert renames[0].table == "users"
        assert renames[0].column == "user_name"
        assert renames[0].new_value == "username"

    def test_does_not_detect_column_rename_different_type(self) -> None:
        old_col = _col("status", "integer")
        new_col = _col("state", "text")
        changes = [
            _col_dropped("users", old_col),
            _col_added("users", new_col),
        ]

        result = RenameDetector(threshold=0.95).apply(changes)

        renames = [c for c in result if c.type == ChangeType.COLUMN_RENAMED]
        assert len(renames) == 0

    def test_column_rename_removes_original_drop_and_add(self) -> None:
        old_col = _col("created_ts", "timestamp", False)
        new_col = _col("created_at", "timestamp", False)
        changes = [
            _col_dropped("events", old_col),
            _col_added("events", new_col),
        ]

        result = RenameDetector(threshold=0.7).apply(changes)

        assert not any(c.type == ChangeType.COLUMN_DROPPED for c in result)
        assert not any(c.type == ChangeType.COLUMN_ADDED for c in result)

    def test_column_rename_only_matches_within_same_table(self) -> None:
        col_a = _col("email", "varchar", False)
        col_b = _col("mail", "varchar", False)
        changes = [
            _col_dropped("users", col_a),
            _col_added("orders", col_b),
        ]

        result = RenameDetector(threshold=0.7).apply(changes)

        renames = [c for c in result if c.type == ChangeType.COLUMN_RENAMED]
        assert len(renames) == 0


class TestNoDetectRenamesFlag:
    def test_without_detector_original_changes_unchanged(self) -> None:
        old = _table("users", _col("id", "integer", False))
        new = _table("members", _col("id", "integer", False))
        original_changes = [_dropped(old), _added(new)]

        # No RenameDetector applied
        result = original_changes

        types = {c.type for c in result}
        assert ChangeType.TABLE_DROPPED in types
        assert ChangeType.TABLE_ADDED in types
        assert ChangeType.TABLE_RENAMED not in types

    def test_threshold_exactly_at_boundary_matches(self) -> None:
        old = _table("users", _col("id", "integer", False), _col("email", "varchar", False))
        new = _table("members", _col("id", "integer", False), _col("email", "varchar", False))
        changes = [_dropped(old), _added(new)]

        detector = RenameDetector(threshold=0.7)
        result = detector.apply(changes)
        ratio = detector._table_similarity(old, new)

        assert ratio >= 0.7
        assert any(c.type == ChangeType.TABLE_RENAMED for c in result)

    def test_non_rename_changes_pass_through_unchanged(self) -> None:
        col_change = Change(
            type=ChangeType.COLUMN_TYPE_CHANGED,
            table="users",
            column="age",
            old_value="integer",
            new_value="bigint",
            destructive=True,
        )
        changes = [col_change]

        result = RenameDetector(threshold=0.7).apply(changes)

        assert result == [col_change]

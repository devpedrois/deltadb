from collections.abc import Callable
from typing import TypeVar

from deltadb.diff.changes import Change, ChangeType
from deltadb.exceptions import DiffError
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, UniqueConstraint
from deltadb.model.index import Index

_C = TypeVar("_C")


def _check_duplicate_names(
    names: list[str | None], label: str, table_name: str
) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for name in names:
        if name is None:
            continue
        if name in seen:
            duplicates.add(name)
        seen.add(name)
    if duplicates:
        raise DiffError(
            f"Duplicate {label} names in table '{table_name}': {sorted(duplicates)}. "
            "Duplicate names would silently hide schema changes."
        )


def _compare_named_constraints(
    table_name: str,
    source_items: tuple[_C, ...],
    target_items: tuple[_C, ...],
    label: str,
    key_fn: Callable[[_C], tuple],
    name_fn: Callable[[_C], str | None],
    dropped_type: ChangeType,
    added_type: ChangeType,
) -> list[Change]:
    """Generic comparison for named+unnamed constraints (FK, UniqueConstraint).

    Matches named constraints by name and unnamed ones by structural key.
    Same name does not imply same definition — definitions are compared via key_fn.
    """
    changes: list[Change] = []

    named_source = [c for c in source_items if name_fn(c)]
    named_target = [c for c in target_items if name_fn(c)]
    _check_duplicate_names([name_fn(c) for c in named_source], label, table_name)
    _check_duplicate_names([name_fn(c) for c in named_target], label, table_name)

    source_by_name = {name_fn(c): c for c in source_items if name_fn(c)}
    target_by_name = {name_fn(c): c for c in target_items if name_fn(c)}

    unnamed_source = [c for c in source_items if not name_fn(c)]
    unnamed_target = [c for c in target_items if not name_fn(c)]
    source_by_key = {key_fn(c): c for c in unnamed_source}
    target_by_key = {key_fn(c): c for c in unnamed_target}

    matched_source_ids: set[int] = set()
    matched_target_ids: set[int] = set()

    for name in source_by_name.keys() & target_by_name.keys():
        src = source_by_name[name]
        tgt = target_by_name[name]
        matched_source_ids.add(id(src))
        matched_target_ids.add(id(tgt))
        if key_fn(src) != key_fn(tgt):
            changes.append(Change(type=dropped_type, table=table_name, old_value=src))
            changes.append(Change(type=added_type, table=table_name, new_value=tgt))

    for item in source_items:
        if id(item) in matched_source_ids:
            continue
        if name_fn(item):
            changes.append(Change(type=dropped_type, table=table_name, old_value=item))
        elif key_fn(item) not in target_by_key:
            changes.append(Change(type=dropped_type, table=table_name, old_value=item))

    for item in target_items:
        if id(item) in matched_target_ids:
            continue
        if name_fn(item):
            changes.append(Change(type=added_type, table=table_name, new_value=item))
        elif key_fn(item) not in source_by_key:
            changes.append(Change(type=added_type, table=table_name, new_value=item))

    return changes


def compare_columns(
    table_name: str,
    source_cols: tuple[Column, ...],
    target_cols: tuple[Column, ...],
) -> list[Change]:
    changes: list[Change] = []
    _check_duplicate_names([c.name for c in source_cols], "column", table_name)
    _check_duplicate_names([c.name for c in target_cols], "column", table_name)
    source_map = {c.name: c for c in source_cols}
    target_map = {c.name: c for c in target_cols}

    for name in sorted(target_map.keys() - source_map.keys()):
        changes.append(Change(
            type=ChangeType.COLUMN_ADDED,
            table=table_name,
            column=name,
            new_value=target_map[name],
        ))

    for name in sorted(source_map.keys() - target_map.keys()):
        changes.append(Change(
            type=ChangeType.COLUMN_DROPPED,
            table=table_name,
            column=name,
            old_value=source_map[name],
            destructive=True,
        ))

    for name in sorted(source_map.keys() & target_map.keys()):
        src = source_map[name]
        tgt = target_map[name]

        if src.type != tgt.type:
            changes.append(Change(
                type=ChangeType.COLUMN_TYPE_CHANGED,
                table=table_name,
                column=name,
                old_value=src.type,
                new_value=tgt.type,
                destructive=True,
            ))

        if src.nullable != tgt.nullable:
            changes.append(Change(
                type=ChangeType.COLUMN_NULLABLE_CHANGED,
                table=table_name,
                column=name,
                old_value=src.nullable,
                new_value=tgt.nullable,
            ))

        if src.default != tgt.default:
            changes.append(Change(
                type=ChangeType.COLUMN_DEFAULT_CHANGED,
                table=table_name,
                column=name,
                old_value=src.default,
                new_value=tgt.default,
            ))

        if src.primary_key != tgt.primary_key:
            changes.append(Change(
                type=ChangeType.COLUMN_PRIMARY_KEY_CHANGED,
                table=table_name,
                column=name,
                old_value=src.primary_key,
                new_value=tgt.primary_key,
                destructive=not tgt.primary_key,
            ))

        if src.autoincrement != tgt.autoincrement:
            changes.append(Change(
                type=ChangeType.COLUMN_AUTOINCREMENT_CHANGED,
                table=table_name,
                column=name,
                old_value=src.autoincrement,
                new_value=tgt.autoincrement,
            ))

    return changes


def compare_indexes(
    table_name: str,
    source_indexes: tuple[Index, ...],
    target_indexes: tuple[Index, ...],
) -> list[Change]:
    changes: list[Change] = []
    _check_duplicate_names([i.name for i in source_indexes], "index", table_name)
    _check_duplicate_names([i.name for i in target_indexes], "index", table_name)
    source_map = {i.name: i for i in source_indexes}
    target_map = {i.name: i for i in target_indexes}

    for name in sorted(target_map.keys() - source_map.keys()):
        changes.append(Change(
            type=ChangeType.INDEX_ADDED,
            table=table_name,
            new_value=target_map[name],
        ))

    for name in sorted(source_map.keys() - target_map.keys()):
        changes.append(Change(
            type=ChangeType.INDEX_DROPPED,
            table=table_name,
            old_value=source_map[name],
        ))

    # Bug fix: compare matched indexes — same name does not mean same definition.
    # Different columns or uniqueness flag = DROP old + ADD new.
    for name in sorted(source_map.keys() & target_map.keys()):
        src = source_map[name]
        tgt = target_map[name]
        if src.columns != tgt.columns or src.unique != tgt.unique:
            changes.append(Change(
                type=ChangeType.INDEX_DROPPED,
                table=table_name,
                old_value=src,
            ))
            changes.append(Change(
                type=ChangeType.INDEX_ADDED,
                table=table_name,
                new_value=tgt,
            ))

    return changes


def _fk_key(fk: ForeignKey) -> tuple:
    # Bug fix: include referred_columns in key — two FKs from the same source
    # columns to different target columns of the same table are not equivalent.
    return (tuple(fk.columns), fk.referred_table, tuple(fk.referred_columns))


def compare_foreign_keys(
    table_name: str,
    source_fks: tuple[ForeignKey, ...],
    target_fks: tuple[ForeignKey, ...],
) -> list[Change]:
    return _compare_named_constraints(
        table_name=table_name,
        source_items=source_fks,
        target_items=target_fks,
        label="foreign key",
        key_fn=_fk_key,
        name_fn=lambda fk: fk.name,
        dropped_type=ChangeType.FK_DROPPED,
        added_type=ChangeType.FK_ADDED,
    )


def _uc_key(uc: UniqueConstraint) -> tuple:
    # Column order preserved — (a, b) and (b, a) are different indexes at the DB level
    return tuple(uc.columns)


def compare_unique_constraints(
    table_name: str,
    source_ucs: tuple[UniqueConstraint, ...],
    target_ucs: tuple[UniqueConstraint, ...],
) -> list[Change]:
    return _compare_named_constraints(
        table_name=table_name,
        source_items=source_ucs,
        target_items=target_ucs,
        label="unique constraint",
        key_fn=_uc_key,
        name_fn=lambda uc: uc.name,
        dropped_type=ChangeType.UNIQUE_CONSTRAINT_DROPPED,
        added_type=ChangeType.UNIQUE_CONSTRAINT_ADDED,
    )

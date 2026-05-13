from deltadb.diff.changes import Change, ChangeType
from deltadb.exceptions import DiffError
from deltadb.model.column import Column
from deltadb.model.constraint import ForeignKey, UniqueConstraint
from deltadb.model.index import Index


def _check_duplicate_names(names: list[str], label: str, table_name: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for name in names:
        if name in seen:
            duplicates.add(name)
        seen.add(name)
    if duplicates:
        raise DiffError(
            f"Duplicate {label} names in table '{table_name}': {sorted(duplicates)}. "
            "Duplicate names would silently hide schema changes."
        )


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
    changes: list[Change] = []

    named_source = [fk for fk in source_fks if fk.name]
    named_target = [fk for fk in target_fks if fk.name]
    _check_duplicate_names([fk.name for fk in named_source], "foreign key", table_name)  # type: ignore[arg-type]
    _check_duplicate_names([fk.name for fk in named_target], "foreign key", table_name)  # type: ignore[arg-type]

    source_by_name = {fk.name: fk for fk in source_fks if fk.name}
    target_by_name = {fk.name: fk for fk in target_fks if fk.name}

    # Unnamed FKs matched by structural key (columns + referred_table + referred_columns)
    source_unnamed = [fk for fk in source_fks if not fk.name]
    target_unnamed = [fk for fk in target_fks if not fk.name]
    source_by_key = {_fk_key(fk): fk for fk in source_unnamed}
    target_by_key = {_fk_key(fk): fk for fk in target_unnamed}

    matched_source_ids: set[int] = set()
    matched_target_ids: set[int] = set()

    # Named FKs present in both: compare definitions — same name ≠ same definition.
    for name in source_by_name.keys() & target_by_name.keys():
        src = source_by_name[name]
        tgt = target_by_name[name]
        matched_source_ids.add(id(src))
        matched_target_ids.add(id(tgt))
        if _fk_key(src) != _fk_key(tgt):
            # Definition changed — must drop old and add new
            changes.append(Change(
                type=ChangeType.FK_DROPPED,
                table=table_name,
                old_value=src,
            ))
            changes.append(Change(
                type=ChangeType.FK_ADDED,
                table=table_name,
                new_value=tgt,
            ))

    # Named FKs in source not in target = dropped
    for fk in source_fks:
        if id(fk) in matched_source_ids:
            continue
        if fk.name:
            # Named FK not matched by name = dropped regardless of unnamed targets
            changes.append(Change(
                type=ChangeType.FK_DROPPED,
                table=table_name,
                old_value=fk,
            ))
        else:
            # Unnamed FK: match by structural key against unnamed targets only
            if _fk_key(fk) not in target_by_key:
                changes.append(Change(
                    type=ChangeType.FK_DROPPED,
                    table=table_name,
                    old_value=fk,
                ))

    # Named FKs in target not in source = added
    for fk in target_fks:
        if id(fk) in matched_target_ids:
            continue
        if fk.name:
            # Named FK not matched by name = added regardless of unnamed sources
            changes.append(Change(
                type=ChangeType.FK_ADDED,
                table=table_name,
                new_value=fk,
            ))
        else:
            # Unnamed FK: match by structural key against unnamed sources only
            if _fk_key(fk) not in source_by_key:
                changes.append(Change(
                    type=ChangeType.FK_ADDED,
                    table=table_name,
                    new_value=fk,
                ))

    return changes


def _uc_key(uc: UniqueConstraint) -> tuple:
    return tuple(sorted(uc.columns))


def compare_unique_constraints(
    table_name: str,
    source_ucs: tuple[UniqueConstraint, ...],
    target_ucs: tuple[UniqueConstraint, ...],
) -> list[Change]:
    changes: list[Change] = []

    named_source = [uc for uc in source_ucs if uc.name]
    named_target = [uc for uc in target_ucs if uc.name]
    _check_duplicate_names([uc.name for uc in named_source], "unique constraint", table_name)  # type: ignore[arg-type]
    _check_duplicate_names([uc.name for uc in named_target], "unique constraint", table_name)  # type: ignore[arg-type]

    source_by_name = {uc.name: uc for uc in source_ucs if uc.name}
    target_by_name = {uc.name: uc for uc in target_ucs if uc.name}

    source_unnamed = [uc for uc in source_ucs if not uc.name]
    target_unnamed = [uc for uc in target_ucs if not uc.name]
    source_by_key = {_uc_key(uc): uc for uc in source_unnamed}
    target_by_key = {_uc_key(uc): uc for uc in target_unnamed}

    matched_source_ids: set[int] = set()
    matched_target_ids: set[int] = set()

    # Named UCs present in both: compare column sets
    for name in source_by_name.keys() & target_by_name.keys():
        src = source_by_name[name]
        tgt = target_by_name[name]
        matched_source_ids.add(id(src))
        matched_target_ids.add(id(tgt))
        if _uc_key(src) != _uc_key(tgt):
            changes.append(Change(
                type=ChangeType.UNIQUE_CONSTRAINT_DROPPED,
                table=table_name,
                old_value=src,
            ))
            changes.append(Change(
                type=ChangeType.UNIQUE_CONSTRAINT_ADDED,
                table=table_name,
                new_value=tgt,
            ))

    for uc in source_ucs:
        if id(uc) in matched_source_ids:
            continue
        if uc.name:
            changes.append(Change(
                type=ChangeType.UNIQUE_CONSTRAINT_DROPPED,
                table=table_name,
                old_value=uc,
            ))
        else:
            if _uc_key(uc) not in target_by_key:
                changes.append(Change(
                    type=ChangeType.UNIQUE_CONSTRAINT_DROPPED,
                    table=table_name,
                    old_value=uc,
                ))

    for uc in target_ucs:
        if id(uc) in matched_target_ids:
            continue
        if uc.name:
            changes.append(Change(
                type=ChangeType.UNIQUE_CONSTRAINT_ADDED,
                table=table_name,
                new_value=uc,
            ))
        else:
            if _uc_key(uc) not in source_by_key:
                changes.append(Change(
                    type=ChangeType.UNIQUE_CONSTRAINT_ADDED,
                    table=table_name,
                    new_value=uc,
                ))

    return changes

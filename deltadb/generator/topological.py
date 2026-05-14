from collections import defaultdict, deque

from deltadb.diff.changes import Change, ChangeType
from deltadb.exceptions import GeneratorError
from deltadb.model.schema import SchemaModel


def _build_fk_deps(changes: list[Change], schema: SchemaModel) -> dict[str, set[str]]:
    """Return {table: {tables_it_depends_on}} for TABLE_ADDED changes."""
    added_tables = {c.table for c in changes if c.type == ChangeType.TABLE_ADDED}
    deps: dict[str, set[str]] = {t: set() for t in added_tables}

    for change in changes:
        if change.type != ChangeType.TABLE_ADDED:
            continue
        table_obj = change.new_value
        if table_obj is None:
            continue
        for fk in table_obj.foreign_keys:
            ref = fk.referred_table
            if ref in added_tables and ref != change.table:
                deps[change.table].add(ref)

    return deps


def _topo_sort_tables(deps: dict[str, set[str]]) -> list[str]:
    """Kahn's algorithm — referenced tables first."""
    in_degree = {t: 0 for t in deps}
    dependents: dict[str, list[str]] = {t: [] for t in deps}

    for table, table_deps in deps.items():
        for dep in table_deps:
            if dep in in_degree:
                in_degree[table] += 1
                dependents[dep].append(table)

    queue: deque[str] = deque(sorted(t for t, d in in_degree.items() if d == 0))
    result: list[str] = []

    while queue:
        node = queue.popleft()
        result.append(node)
        for dependent in sorted(dependents[node]):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)

    if len(result) != len(deps):
        # [SECURITY] Circular FK — fail loudly, not silently mis-order
        remaining = sorted(set(deps) - set(result))
        raise GeneratorError(
            f"Circular FK dependency detected between tables: {remaining}. "
            "Cannot determine safe migration order."
        )

    return result


def topological_sort_up(changes: list[Change], schema: SchemaModel) -> list[Change]:
    """Order UP changes for safe migration execution.

    Ordering:
    1. TABLE_ADDED — referenced tables first (topological by FK)
    2. COLUMN_ADDED, INDEX_ADDED, UNIQUE_CONSTRAINT_ADDED, COLUMN_* changes
    3. FK_ADDED — after all tables exist
    4. FK_DROPPED — before DROP TABLE
    5. INDEX_DROPPED, UNIQUE_CONSTRAINT_DROPPED
    6. COLUMN_DROPPED
    7. TABLE_DROPPED — dependents before referenced (reverse topo)
    """
    _bucketed_types = {
        ChangeType.TABLE_ADDED, ChangeType.TABLE_DROPPED,
        ChangeType.FK_ADDED, ChangeType.FK_DROPPED,
        ChangeType.COLUMN_DROPPED, ChangeType.INDEX_DROPPED,
        ChangeType.UNIQUE_CONSTRAINT_DROPPED,
    }
    buckets: dict[ChangeType, list[Change]] = defaultdict(list)
    other: list[Change] = []
    for c in changes:
        if c.type in _bucketed_types:
            buckets[c.type].append(c)
        else:
            other.append(c)

    table_added = buckets[ChangeType.TABLE_ADDED]
    table_dropped = buckets[ChangeType.TABLE_DROPPED]
    fk_added = buckets[ChangeType.FK_ADDED]
    fk_dropped = buckets[ChangeType.FK_DROPPED]
    col_dropped = buckets[ChangeType.COLUMN_DROPPED]
    idx_dropped = buckets[ChangeType.INDEX_DROPPED]
    uc_dropped = buckets[ChangeType.UNIQUE_CONSTRAINT_DROPPED]

    deps = _build_fk_deps(table_added, schema)
    sorted_names = _topo_sort_tables(deps)

    name_to_added = {c.table: c for c in table_added}
    sorted_names_set = set(sorted_names)
    sorted_added = [name_to_added[n] for n in sorted_names if n in name_to_added]
    # Tables not in topo output (e.g. added after deps changed): append in stable order
    unsorted_added = [c for c in table_added if c.table not in sorted_names_set]
    sorted_added = sorted_added + unsorted_added

    dropped_deps = _build_dropped_fk_deps(table_dropped, schema)
    sorted_dropped_names = _topo_sort_tables(dropped_deps)
    sorted_dropped_names_set = set(sorted_dropped_names)
    name_to_dropped = {c.table: c for c in table_dropped}
    sorted_dropped = [
        name_to_dropped[n] for n in sorted_dropped_names if n in name_to_dropped
    ]
    unsorted_dropped = [c for c in table_dropped if c.table not in sorted_dropped_names_set]
    sorted_dropped = list(reversed(sorted_dropped + unsorted_dropped))

    return (
        sorted_added + other + fk_added
        + fk_dropped + idx_dropped + uc_dropped + col_dropped
        + sorted_dropped
    )


def _build_dropped_fk_deps(
    dropped_changes: list[Change], schema: SchemaModel
) -> dict[str, set[str]]:
    """Return FK deps for tables being dropped (from old_value)."""
    dropped_tables = {c.table for c in dropped_changes}
    deps: dict[str, set[str]] = {t: set() for t in dropped_tables}

    for change in dropped_changes:
        table_obj = change.old_value
        if table_obj is None:
            continue
        for fk in table_obj.foreign_keys:
            ref = fk.referred_table
            if ref in dropped_tables and ref != change.table:
                deps[change.table].add(ref)

    return deps


def topological_sort_down(up_changes: list[Change]) -> list[Change]:
    """Reverse UP order to produce safe DOWN (revert) sequence."""
    return list(reversed(up_changes))

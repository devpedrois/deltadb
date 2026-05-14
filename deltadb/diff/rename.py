from difflib import SequenceMatcher

from deltadb.config import DEFAULT_RENAME_THRESHOLD
from deltadb.diff.changes import Change, ChangeType
from deltadb.model.table import Table


class RenameDetector:
    def __init__(self, threshold: float = DEFAULT_RENAME_THRESHOLD) -> None:
        if not (0.0 < threshold <= 1.0):
            raise ValueError(
                f"threshold must be in range (0.0, 1.0], got {threshold!r}. "
                "threshold=0.0 would match every table pair regardless of similarity, "
                "potentially converting destructive DROP operations into non-destructive RENAMEs."
            )
        self._threshold = threshold

    def _table_sig(self, table: Table) -> str:
        return "|".join(
            sorted(f"{c.name}:{c.type}:{c.nullable}" for c in table.columns)
        )

    def _col_sig(self, col) -> str:
        return f"{col.type}:{col.nullable}"

    def _table_similarity(self, a: Table, b: Table) -> float:
        return SequenceMatcher(None, self._table_sig(a), self._table_sig(b)).ratio()

    def _detect_table_renames(
        self, dropped: list[Change], added: list[Change]
    ) -> list[tuple[Change, Change]]:
        candidates = [
            (d, a, self._table_similarity(d.old_value, a.new_value))
            for d in dropped
            for a in added
            if self._table_similarity(d.old_value, a.new_value) >= self._threshold
        ]
        candidates.sort(key=lambda x: x[2], reverse=True)

        matched: list[tuple[Change, Change]] = []
        used_dropped: set[str] = set()
        used_added: set[str] = set()
        for d, a, _ in candidates:
            if d.table not in used_dropped and a.table not in used_added:
                matched.append((d, a))
                used_dropped.add(d.table)
                used_added.add(a.table)
        return matched

    def _detect_column_renames(
        self, col_dropped: list[Change], col_added: list[Change]
    ) -> list[tuple[Change, Change]]:
        candidates = [
            (d, a, SequenceMatcher(None, self._col_sig(d.old_value), self._col_sig(a.new_value)).ratio())
            for d in col_dropped
            for a in col_added
            if d.table == a.table
            and SequenceMatcher(None, self._col_sig(d.old_value), self._col_sig(a.new_value)).ratio() >= self._threshold
        ]
        candidates.sort(key=lambda x: x[2], reverse=True)

        matched: list[tuple[Change, Change]] = []
        used_dropped: set[str] = set()
        used_added: set[str] = set()
        for d, a, _ in candidates:
            key_d = (d.table, d.column)
            key_a = (a.table, a.column)
            if key_d not in used_dropped and key_a not in used_added:
                matched.append((d, a))
                used_dropped.add(key_d)
                used_added.add(key_a)
        return matched

    def apply(self, changes: list[Change]) -> list[Change]:
        dropped = [c for c in changes if c.type == ChangeType.TABLE_DROPPED]
        added = [c for c in changes if c.type == ChangeType.TABLE_ADDED]
        col_dropped = [c for c in changes if c.type == ChangeType.COLUMN_DROPPED]
        col_added = [c for c in changes if c.type == ChangeType.COLUMN_ADDED]

        table_renames = self._detect_table_renames(dropped, added)
        col_renames = self._detect_column_renames(col_dropped, col_added)

        excluded: set[int] = set()
        rename_changes: list[Change] = []

        for d, a in table_renames:
            excluded.add(id(d))
            excluded.add(id(a))
            rename_changes.append(Change(
                type=ChangeType.TABLE_RENAMED,
                table=d.table,
                new_value=a.table,
                detail=f"SUGGESTED RENAME -> {a.table}",
            ))

        for d, a in col_renames:
            excluded.add(id(d))
            excluded.add(id(a))
            rename_changes.append(Change(
                type=ChangeType.COLUMN_RENAMED,
                table=d.table,
                column=d.column,
                new_value=a.column,
                detail=f"SUGGESTED RENAME -> {a.column}",
            ))

        result = [c for c in changes if id(c) not in excluded]
        return result + rename_changes

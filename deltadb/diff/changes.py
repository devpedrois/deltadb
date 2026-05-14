from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from deltadb.model.column import Column
    from deltadb.model.constraint import ForeignKey, UniqueConstraint
    from deltadb.model.index import Index
    from deltadb.model.table import Table

ChangeValue = Union[
    "Table", "Column", "Index", "ForeignKey", "UniqueConstraint", str, bool, None
]


class ChangeType(Enum):
    TABLE_ADDED = "table_added"
    TABLE_DROPPED = "table_dropped"
    COLUMN_ADDED = "column_added"
    COLUMN_DROPPED = "column_dropped"
    COLUMN_TYPE_CHANGED = "column_type_changed"
    COLUMN_NULLABLE_CHANGED = "column_nullable_changed"
    COLUMN_DEFAULT_CHANGED = "column_default_changed"
    COLUMN_PRIMARY_KEY_CHANGED = "column_primary_key_changed"
    COLUMN_AUTOINCREMENT_CHANGED = "column_autoincrement_changed"
    INDEX_ADDED = "index_added"
    INDEX_DROPPED = "index_dropped"
    FK_ADDED = "fk_added"
    FK_DROPPED = "fk_dropped"
    UNIQUE_CONSTRAINT_ADDED = "unique_constraint_added"
    UNIQUE_CONSTRAINT_DROPPED = "unique_constraint_dropped"
    TABLE_RENAMED = "table_renamed"
    COLUMN_RENAMED = "column_renamed"


@dataclass(frozen=True)
class Change:
    type: ChangeType
    table: str
    column: str | None = None
    old_value: ChangeValue = field(default=None, compare=True, hash=False)
    new_value: ChangeValue = field(default=None, compare=True, hash=False)
    destructive: bool = False
    detail: str = ""
